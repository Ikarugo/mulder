"""Shared helper functions for MCP tool modules.

Convention: elapsed_ms is recorded in the audit log for every tool call.
It should NOT be included in the response dict unless wall-clock time
is meaningful to the consumer (e.g. verify_evidence_integrity).
"""

from __future__ import annotations

import functools
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ParamSpec
from urllib.parse import quote
from uuid import uuid4

from mulder.server.app import get_ctx, has_ctx

current_batch_id: ContextVar[str | None] = ContextVar("current_batch_id", default=None)

TOOL_TIMEOUT: int = 600
"""Default subprocess timeout (seconds) shared across extraction tools."""

_GIB_THRESHOLD = 4
"""File size (GiB) below which no extra time is added."""


def readonly_sqlite_uri(db_path: Path | str) -> str:
    """Build a read-only ``file:`` URI for *db_path*, escaping URI syntax.

    ``f"file:{db_path}?mode=ro"`` is not safe for a path that came out of an
    evidence tree, because the filename is pasted into a URI without being
    escaped. Filenames like these are ordinary, not hostile:

    ``sms#2024-03-12.db``
        ``#`` opens a URI fragment, so the path is truncated to ``sms`` and
        ``?mode=ro`` lands inside the discarded fragment. SQLite then creates
        and opens an empty ``sms`` **inside the evidence directory**, and the
        caller reports that the database has no tables.

    ``chat?mode=rwc.db``
        ``?`` starts the query, so the caller's parameters are appended to the
        attacker's and the connection is refused outright -- the database is
        silently dropped from the analysis by the surrounding
        ``except sqlite3.Error``.

    ``report%20final.db``
        SQLite percent-decodes the path when ``%`` is followed by two hex
        digits, so this names a file called ``report final.db`` -- a different
        file, and usually one that does not exist. (``100%_full.db`` is fine:
        ``%_f`` is not a valid escape and is left alone. The bug is not "any
        percent sign", it is a percent sign in front of two hex digits.)

    ``//tmp/case/sms.db``
        A path may legally begin with exactly two slashes, and ``file://`` is
        the start of a URI authority. SQLite reads ``tmp`` as a hostname and
        refuses the connection with ``invalid uri authority: tmp``. This is
        why the separators have to be escaped as well -- ``quote`` leaves
        ``/`` alone by default, which fixes the filename but not the path.

    Escaping the whole path fixes all four: the file that is opened is the
    file that was named, it is opened read-only, and nothing is written into
    the evidence tree. SQLite percent-decodes the path before using it, so
    ``file:%2Ftmp%2Fcase%2Fsms.db`` names ``/tmp/case/sms.db`` exactly.

    Args:
        db_path: Path to the SQLite database.

    Returns:
        A ``file:`` URI to pass to ``sqlite3.connect(..., uri=True)``.
    """
    return "file:" + quote(str(db_path), safe="") + "?mode=ro"


def adaptive_timeout(
    file_path: str | Path,
    base: int = 600,
    per_gib: int = 120,
    cap: int = 28800,
) -> int:
    """Compute a timeout that scales with file size.

    For files under 4 GiB, returns the base timeout. For larger files,
    adds *per_gib* seconds for each GiB above 4, capped at *cap* seconds.
    Returns the base timeout if the file doesn't exist or can't be stat'd.

    Args:
        file_path: Path to the evidence file being processed.
        base: Minimum timeout in seconds (default 600 = 10 min).
        per_gib: Additional seconds per GiB above 4 GiB (default 120 = 2 min/GiB).
        cap: Maximum timeout in seconds (default 28800 = 8 hours).

    Returns:
        Timeout in seconds, between *base* and *cap*.
    """
    try:
        size_bytes = Path(file_path).stat().st_size
    except OSError:
        return base
    gib = size_bytes / (1024**3)
    return min(base + int(max(0, gib - _GIB_THRESHOLD) * per_gib), cap)


def require_binary(name: str) -> str | None:
    """Return the absolute path to *name* if found on PATH, else None."""
    return shutil.which(name)


def interpreter_candidates() -> list[str]:
    """Python interpreters to probe, most-likely-correct first.

    ``sys.executable`` is mulder's own interpreter: under ``pipx install`` /
    ``uv tool install`` it is the only one that can see dependencies injected
    into mulder's venv.  The PATH interpreters follow because several helper
    tools (plaso, pyhindsight, ALEAPP, iLEAPP) are *not* mulder dependencies
    and on SIFT live in the system interpreter or a separate venv.  Order
    matters; duplicates are dropped so a probe never runs twice against the
    same binary.
    """
    seen: set[str] = set()
    out: list[str] = []
    for cand in (sys.executable, shutil.which("python3"), shutil.which("python")):
        if cand and cand not in seen:
            seen.add(cand)
            out.append(cand)
    return out


def run_subprocess(
    cmd: list[str],
    *,
    timeout: int = TOOL_TIMEOUT,
    text: bool = True,
) -> subprocess.CompletedProcess[str] | str:
    """Run a subprocess with standardized timeout handling.

    Returns the CompletedProcess on success, or an error message string
    on timeout/OS failure. Callers check ``isinstance(result, str)`` to
    detect failures. Standard input is closed so a tool that prompts (an
    encrypted archive, a confirmation) fails instead of reading the MCP
    server's own stdin.
    """
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=text,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return f"{cmd[0]} timed out after {timeout}s"
    except OSError as exc:
        return f"Failed to run {cmd[0]}: {exc}"


def output_tail(stdout: str | None, stderr: str | None, lines: int = 15) -> str:
    """The last non-empty lines a tool printed (stdout then stderr), for error messages."""
    text = "\n".join(part for part in (stdout, stderr) if part)
    kept = [line.rstrip() for line in text.splitlines() if line.strip()]
    return "\n".join(kept[-lines:])[-2000:]


@dataclass
class ToolRun:
    """What one run of an external program did.

    Most tool wrappers used to call ``subprocess.run`` themselves and index
    whatever stdout held, without looking at the exit code or stderr: a
    tool that could not open its input was reported as a successful run
    that found nothing. ``run_tool`` returns this record instead, and
    :meth:`failed` / :meth:`describe` give every wrapper the same rules.
    """

    binary: str
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    launch_error: str | None = None
    timeout: int = 0

    @property
    def ok(self) -> bool:
        """Exit code 0, no timeout, and the program started."""
        return self.returncode == 0 and not self.timed_out and self.launch_error is None

    @property
    def has_output(self) -> bool:
        """Something other than whitespace on stdout."""
        return bool(self.stdout.strip())

    @property
    def failed(self) -> bool:
        """Did not complete and left nothing usable on stdout.

        A non-zero exit after real output is not a failure: many tools
        stop on one bad input after writing results for the others (see
        :meth:`warning`).
        """
        return not self.ok and not self.has_output

    @property
    def error_type(self) -> str:
        """``error_type`` for :func:`error_response`."""
        if self.timed_out:
            return "timeout"
        if self.launch_error is not None:
            return "binary_missing" if "No such file" in self.launch_error else "tool_failed"
        return "tool_failed"

    def tail(self, lines: int = 15) -> str:
        """The last lines the program printed."""
        return output_tail(self.stdout, self.stderr, lines)

    def describe(self) -> str:
        """One message with the exit status and the program's own last lines."""
        if self.launch_error is not None:
            return f"{self.binary} could not be started: {self.launch_error}"
        if self.timed_out:
            message = f"{self.binary} timed out after {self.timeout}s"
        else:
            message = f"{self.binary} exited {self.returncode}"
        tail = self.tail()
        return message + (f". Tool output (last lines):\n{tail}" if tail else " with no output")

    def warning(self) -> str | None:
        """For a run that did not complete but produced output: say so."""
        if self.ok or not self.has_output:
            return None
        return (
            f"{self.describe()}\nThe output written before that was indexed; it may be incomplete."
        )


def run_tool(
    cmd: Sequence[str],
    *,
    timeout: int = TOOL_TIMEOUT,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> ToolRun:
    """Run an external program and return a :class:`ToolRun`; never raises.

    Output is decoded as UTF-8 with replacement (a tool printing a Windows
    path in cp1252 must not crash the wrapper), and standard input is
    closed unless *input_text* is given.
    """
    binary = Path(str(cmd[0])).name if cmd else "?"
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            cwd=cwd,
            env=dict(env) if env is not None else None,
            input=input_text,
            stdin=None if input_text is not None else subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        return ToolRun(
            binary,
            None,
            _as_text(exc.stdout),
            _as_text(exc.stderr),
            timed_out=True,
            timeout=timeout,
        )
    except OSError as exc:
        return ToolRun(binary, None, launch_error=str(exc), timeout=timeout)
    return ToolRun(binary, proc.returncode, proc.stdout or "", proc.stderr or "", timeout=timeout)


def _as_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value if isinstance(value, str) else ""


# ---------------------------------------------------------------------------
# Failure memory: do not run the same failing command twice
# ---------------------------------------------------------------------------


def failure_key(tool_name: str, evidence: str, *parts: object) -> str:
    """Key under which a failure of *tool_name* on *evidence* is remembered."""
    suffix = ":".join(str(p) for p in parts if p not in (None, ""))
    return f"tool_failed:{tool_name}:{evidence}" + (f":{suffix}" if suffix else "")


def previous_failure(key: str) -> str | None:
    """The message of an earlier failure recorded under *key*, if any."""
    if not has_ctx():
        return None
    try:
        value = get_ctx().db.get_kv(key)
    except Exception:
        return None
    return str(value) if value else None


def remember_failure(key: str, message: str) -> None:
    """Record that a run failed, so an identical run is not attempted again."""
    if not has_ctx():
        return
    try:
        get_ctx().db.set_kv(key, message[:2000])
    except Exception:  # noqa: BLE001 - memory is best effort
        return


def repeated_failure_response(
    tc_id: str,
    tool_name: str,
    params: Mapping[str, object],
    key: str,
    t0: float | None = None,
) -> dict[str, object] | None:
    """An error response when the same run already failed, unless ``force`` is set."""
    if params.get("force"):
        return None
    previous = previous_failure(key)
    if not previous:
        return None
    return error_response(
        tc_id,
        tool_name,
        params,
        f"Not run again: this already failed on the same input. {previous}",
        (time.monotonic() - t0) * 1000 if t0 is not None else 0,
        error_type="tool_failed",
        suggestion=(
            "Running it again on the same input fails the same way. Record the gap and "
            "use other sources, or pass force=True after changing the input or the setup."
        ),
    )


def run_failure_response(
    tc_id: str,
    tool_name: str,
    params: Mapping[str, object],
    run: ToolRun,
    t0: float | None = None,
    *,
    memory_key: str | None = None,
    context: str = "",
    suggestion: str | None = None,
) -> dict[str, object]:
    """The error response for a failed :class:`ToolRun`, remembered under *memory_key*.

    A missing binary and a timeout are not remembered: installing the tool
    or a machine under less load makes the same run succeed (the job runner
    retries timed-out jobs with the same arguments).
    """
    message = (f"{context}: " if context else "") + run.describe()
    if memory_key is not None and run.error_type not in ("binary_missing", "timeout"):
        remember_failure(memory_key, message)
    return error_response(
        tc_id,
        tool_name,
        params,
        message,
        (time.monotonic() - t0) * 1000 if t0 is not None else 0,
        error_type=run.error_type,
        suggestion=suggestion,
    )


def make_tool_call_id() -> str:
    """Generate a short unique identifier for a tool invocation."""
    return f"tc_{uuid4().hex[:8]}"


_P = ParamSpec("_P")


def audited_tool(
    tool_name: str,
) -> Callable[[Callable[_P, dict[str, object]]], Callable[_P, dict[str, object]]]:
    """Decorator that handles tool_call_id generation, timing, and audit logging.

    Wraps an MCP tool function to automatically:
      - Generate a unique ``tool_call_id``
      - Time the function execution
      - Log the call to the audit trail
      - Inject ``tool_call_id`` into the returned dict

    The wrapped function must return a ``dict[str, object]``.  The decorator
    adds ``"tool_call_id"`` to it before returning.  The original function
    signature is preserved so MCPServer introspection continues to work.

    Args:
        tool_name: The tool name recorded in the audit log.
    """

    def decorator(
        func: Callable[_P, dict[str, object]],
    ) -> Callable[_P, dict[str, object]]:
        @functools.wraps(func)
        def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> dict[str, object]:
            ctx = get_ctx()
            tc_id = make_tool_call_id()
            t0 = time.monotonic()
            try:
                result = func(*args, **kwargs)
                elapsed = (time.monotonic() - t0) * 1000
                ctx.audit.log_tool_call(
                    tool_call_id=tc_id,
                    tool_name=tool_name,
                    params=dict(kwargs),
                    output_hash=hash_output(result),
                    duration_ms=elapsed,
                )
                result["tool_call_id"] = tc_id
                return result
            except Exception:
                elapsed = (time.monotonic() - t0) * 1000
                ctx.audit.log_tool_call(
                    tool_call_id=tc_id,
                    tool_name=tool_name,
                    params=dict(kwargs),
                    output_hash="error",
                    duration_ms=elapsed,
                )
                raise

        return wrapper

    return decorator


_PREVIEW_CHAR_LIMIT = 500
_HINT_CHAR_LIMIT = 200
_DEFAULT_SEARCH_LIMIT = 50
_FILE_LIST_CAP = 500

_HASH_PREFIX = "blake2b:"
_HASH_DIGEST_SIZE = 32


def _blake2b_hex(data: bytes) -> str:
    return _HASH_PREFIX + hashlib.blake2b(data, digest_size=_HASH_DIGEST_SIZE).hexdigest()


def hash_output(output: object) -> str:
    """Return a BLAKE2b commitment to the complete JSON form of *output*."""
    raw = json.dumps(output, sort_keys=True, default=str)
    return _blake2b_hex(raw.encode())


_DEFAULT_WINDOW_CAP = 20
_DEFAULT_TEXT_CAP = 300


_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def detect_text_encoding(sample: bytes) -> str:
    """Name the text encoding of *sample*: utf-8, utf-16-le, utf-16-be, cp1252 or binary.

    Windows writes many logs in UTF-16 (Defender MPDetection/MPLog,
    PowerShell transcripts, setupapi, CryptnetUrlCache fields). Decoded as
    UTF-8 they look binary, and a reader that stops there hides their
    content: on a real case a certutil download line in the Defender log
    went unread and the agent ruled the download out.
    """
    if not sample:
        return "utf-8"
    if sample.startswith(b"\xef\xbb\xbf"):
        return "utf-8"
    if sample.startswith(b"\xff\xfe"):
        return "utf-16-le"
    if sample.startswith(b"\xfe\xff"):
        return "utf-16-be"
    pairs = len(sample) // 2
    if pairs >= 4:
        even, odd = sample[0 : pairs * 2 : 2], sample[1 : pairs * 2 : 2]
        if odd.count(0) >= 0.4 * pairs and sum(b in _PRINTABLE for b in even) >= 0.7 * pairs:
            return "utf-16-le"
        if even.count(0) >= 0.4 * pairs and sum(b in _PRINTABLE for b in odd) >= 0.7 * pairs:
            return "utf-16-be"
    try:
        sample.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError as exc:
        # A multi-byte character cut at the end of the sample is still UTF-8.
        if exc.start >= len(sample) - 3:
            return "utf-8"
    controls = sum(b < 0x20 and b not in (0x09, 0x0A, 0x0D) for b in sample[:1024])
    if controls > 0.02 * min(len(sample), 1024):
        return "binary"
    return "cp1252"


_ASCII_STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16_STRING_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def extract_strings(data: bytes, limit: int = 2000) -> list[str]:
    """ASCII and UTF-16LE strings of at least 6 characters, in file order."""
    found: list[tuple[int, str]] = [
        (m.start(), m.group().decode("ascii")) for m in _ASCII_STRING_RE.finditer(data)
    ]
    found += [(m.start(), m.group().decode("utf-16-le")) for m in _UTF16_STRING_RE.finditer(data)]
    found.sort()
    return [text for _pos, text in found[:limit]]


def truncate_raw_text(d: dict[str, Any], cap: int = _DEFAULT_TEXT_CAP) -> None:
    """Truncate ``raw_text`` in a window dict in-place if it exceeds *cap*."""
    raw = d.get("raw_text", "")
    if cap and len(raw) > cap:
        d["raw_text"] = raw[:cap] + f" [...{len(raw) - cap} more chars not shown...]"
        d["full_text_available"] = True


def serialize_windows(
    windows: Sequence[Any],
    cap: int = _DEFAULT_WINDOW_CAP,
    text_cap: int = _DEFAULT_TEXT_CAP,
) -> list[dict[str, Any]]:
    """Convert Pydantic window models to dicts, capped for token efficiency.

    Returns at most *cap* windows with ``raw_text`` truncated to
    *text_cap* characters.  Callers should check
    ``len(result) < len(windows)`` and include ``total_windows`` /
    ``truncated`` in the response so the agent knows to use
    ``search()`` or ``get_raw_output()`` for the full data.
    """
    capped = windows[:cap] if len(windows) > cap else windows
    result: list[dict[str, Any]] = []
    for w in capped:
        d: dict[str, Any] = w.model_dump() if hasattr(w, "model_dump") else dict(w)
        truncate_raw_text(d, text_cap)
        result.append(d)
    return result


def windowed_response(
    tc_id: str,
    windows: Sequence[Any],
    source: str,
    tool_name: str,
    params: Mapping[str, object],
    elapsed_ms: float,
    cap: int = _DEFAULT_WINDOW_CAP,
    text_cap: int = _DEFAULT_TEXT_CAP,
) -> dict[str, object]:
    """Build a standard response for tools that return serialized windows.

    Caps the result, truncates ``raw_text``, includes truncation metadata,
    and logs the audit entry.
    """
    total = len(windows)
    results = serialize_windows(windows, cap=cap, text_cap=text_cap)

    if has_ctx():
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name=tool_name,
            params=params,
            output_hash=hash_output({"total": total, "returned": len(results)}),
            duration_ms=elapsed_ms,
            batch_id=current_batch_id.get(),
        )
    resp: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "results": results,
        "source": source,
        "result_count": len(results),
        "total_windows": total,
    }
    text_cut = sum(1 for r in results if r.get("full_text_available"))
    if total > cap or text_cut:
        resp["truncated"] = True
        resp["windows_not_shown"] = max(0, total - cap)
        resp["windows_with_text_cut"] = text_cut
        resp["hint"] = (
            f"PARTIAL VIEW: {len(results)} of {total} windows shown"
            + (f", {text_cut} of them cut to {text_cap} chars" if text_cut else "")
            + ". Absence from this view proves nothing: use "
            f"search(query, source='{source}') or get_raw_output('{source}') "
            "for the full data."
        )
    return resp


def slim_window(w: Any) -> dict[str, Any]:
    """Return window metadata without raw_text for compact tool output.

    The agent can retrieve full text via ``get_raw_output`` or ``search``.
    """
    d: dict[str, Any] = w.model_dump() if hasattr(w, "model_dump") else dict(w)
    d.pop("raw_text", None)
    return d


def tool_response(
    tc_id: str,
    tool_name: str,
    params: Mapping[str, object],
    results: dict[str, object] | list[object],
    source: str | None = None,
    elapsed_ms: float = 0,
) -> dict[str, object]:
    """Build an audited success response and log the tool call.

    When *source* is provided (indicating data has been indexed into the
    case DB), returns a compact response with only a preview of the output.
    The agent should use ``search()`` or ``get_raw_output()`` to access
    the full data.

    When *source* is None, returns the full results (for read/reference
    tools whose output is not indexed elsewhere).
    """
    if has_ctx():
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name=tool_name,
            params=params,
            output_hash=hash_output(results),
            duration_ms=elapsed_ms,
            batch_id=current_batch_id.get(),
        )

    if source is None:
        full: dict[str, object] = {
            "tool_call_id": tc_id,
            "status": "success",
            "results": results,
            "source": source,
        }
        if isinstance(results, dict):
            _propagate_status(full, results)
        return full

    line_count: int | None = None
    windows_indexed: int | None = None
    if isinstance(results, dict):
        lc = results.get("line_count")
        if isinstance(lc, int):
            line_count = lc
        wi = results.get("windows_indexed")
        if isinstance(wi, int):
            windows_indexed = wi

    preview, preview_truncated = _result_preview(results)
    resp: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "source": source,
        "preview": preview,
    }
    if preview_truncated:
        resp["preview_truncated"] = True
    inner_status = results.get("status") if isinstance(results, dict) else None
    if isinstance(results, dict) and inner_status == "skipped":
        resp["hint"] = _skipped_hint(results, params, source)
    elif windows_indexed == 0:
        resp["hint"] = (
            f"Nothing was indexed as '{source}': the tool ran and produced no output "
            "for this input."
        )
    else:
        resp["hint"] = (
            f"Full output indexed as '{source}'. "
            f"Use search(query, source='{source}') or "
            f"get_raw_output('{source}') to access."
        )
    if preview_truncated:
        resp["hint"] = str(resp["hint"]) + (
            " The preview above is cut: fields that are not in the indexed output may be "
            "incomplete there."
        )
    if isinstance(results, dict):
        _propagate_status(resp, results)
    if line_count is not None:
        resp["line_count"] = line_count
    if windows_indexed is not None:
        resp["windows_indexed"] = windows_indexed
    return resp


_RESULT_PREVIEW_BUDGET = 4000
_PREVIEW_LIST_ITEMS = 25
_PREVIEW_STRING_CHARS = 800


def _shrink_for_preview(value: object, depth: int = 0) -> object:
    """Cut long lists and strings, saying how much was left out."""
    if isinstance(value, dict):
        return {k: _shrink_for_preview(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple):
        items = [_shrink_for_preview(v, depth + 1) for v in value[:_PREVIEW_LIST_ITEMS]]
        if len(value) > _PREVIEW_LIST_ITEMS:
            items.append(f"[... {len(value) - _PREVIEW_LIST_ITEMS} more items not shown]")
        return items
    if isinstance(value, str) and len(value) > _PREVIEW_STRING_CHARS:
        return value[:_PREVIEW_STRING_CHARS] + (
            f" [...{len(value) - _PREVIEW_STRING_CHARS} more chars not shown...]"
        )
    return value


def _result_preview(results: object) -> tuple[str, bool]:
    """JSON of *results* for the response, and whether any of it was cut.

    The preview used to be the first 500 characters of the JSON. Fields a
    tool computed but did not index (alerts, per-mode errors, detections,
    hints) were then invisible past that point, with nothing saying so.
    """
    text = results if isinstance(results, str) else json.dumps(results, default=str)
    if len(text) <= _RESULT_PREVIEW_BUDGET:
        return text, False
    if not isinstance(results, str):
        text = json.dumps(_shrink_for_preview(results), default=str)
    if len(text) > _RESULT_PREVIEW_BUDGET:
        text = text[:_RESULT_PREVIEW_BUDGET] + (
            f" [...{len(text) - _RESULT_PREVIEW_BUDGET} more chars not shown...]"
        )
    return text, True


#: Statuses a tool puts in its result dict that must not surface as success.
_ERROR_STATUSES = frozenset({"error", "failed"})
_PARTIAL_STATUSES = frozenset({"partial", "header_only"})


def _propagate_status(resp: dict[str, object], results: Mapping[str, object]) -> None:
    """Lift an error or partial status out of *results* to the response.

    Tools that index what they got still describe failures in their result
    dict (a Volatility plugin error, a hive that failed, an external tool
    that exited non-zero after partial output). The response said
    ``success`` regardless, and the batch runner marked such jobs completed.
    """
    inner = results.get("status")
    if inner in _ERROR_STATUSES:
        resp["status"] = "error"
        resp["error_type"] = str(results.get("error_type") or "tool_failed")
        resp["error_message"] = str(
            results.get("error_message") or results.get("error") or "the tool reported an error"
        )
    elif inner in _PARTIAL_STATUSES or results.get("tool_warning"):
        resp["status"] = "partial"
    if results.get("tool_warning"):
        resp["tool_warning"] = results["tool_warning"]


def _skipped_hint(
    results: Mapping[str, object], params: Mapping[str, object], source: str | None
) -> str:
    existing = results.get("existing_sources")
    if not existing:
        # A skip for another reason (not applicable to this evidence...).
        reason = results.get("reason") or results.get("message")
        return f"Not run: {reason}" if reason else f"Not run; nothing was indexed as '{source}'."
    names = ", ".join(str(e) for e in existing) if isinstance(existing, list) else source
    hint = (
        f"Not run again: {names} already indexed from this evidence. "
        f"Query it with search(query, source=...) or get_raw_output(...)."
    )
    if "force" in params:
        hint += " Pass force=True to run it again (for example with other parameters)."
    return hint


def error_response(
    tc_id: str,
    tool_name: str,
    params: Mapping[str, object],
    error: str,
    elapsed_ms: float = 0,
    error_type: str = "unknown",
    suggestion: str | None = None,
) -> dict[str, object]:
    """Build an audited error response and log the tool call."""
    if has_ctx():
        ctx = get_ctx()
        ctx.audit.log_tool_call(
            tool_call_id=tc_id,
            tool_name=tool_name,
            params=params,
            output_hash=hash_output({"error": error}),
            duration_ms=elapsed_ms,
            batch_id=current_batch_id.get(),
        )
    result: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "error",
        "error_type": error_type,
        "error_message": error,
    }
    if suggestion:
        result["suggestion"] = suggestion
    return result


_PID_RE = re.compile(r"(?:^|\t)(\d{1,6})(?:\t|$)")
_MODULE_NAME_RE = re.compile(r"^([^\t]+\.sys)", re.IGNORECASE)


def extract_pid(text: str) -> int | None:
    """The first PID value in *text*.

    Prefer :func:`extract_pids` when *text* is a whole window: a window holds
    many records, and "the first one" is rarely the question being asked.
    """
    for line in text.splitlines():
        m = _PID_RE.search(line)
        if m:
            val = int(m.group(1))
            if val > 0:
                return val
    return None


def extract_pids(text: str) -> list[int]:
    """Every PID in *text*, one per record, in order and without duplicates.

    One window holds many records. Reading only the first -- which is what
    ``re.search`` over the whole window did -- means a window of forty
    processes contributes exactly one of them and the other thirty-nine are
    invisible to every correlation built on top: process trees miss parents,
    "hidden process" diffs compare two differently-sampled sets and report
    processes that are in both, and per-PID lookups silently return nothing.

    Which column holds the PID still varies by Volatility plugin
    (``windows.pslist`` puts it first, ``windows.netscan`` eighth), so the
    per-line match is deliberately unchanged from what it always was. Only
    the number of lines examined changes: all of them, rather than one.
    """
    seen: dict[int, None] = {}
    for line in text.splitlines():
        m = _PID_RE.search(line)
        if m:
            val = int(m.group(1))
            if val > 0:
                seen.setdefault(val, None)
    return list(seen)


def window_has_pid(text: str, pid: int) -> bool:
    """Whether *text* contains a record for *pid*."""
    return pid in extract_pids(text)


def extract_pids_from_windows(windows: Sequence[Any]) -> dict[int, list[Any]]:
    """Map every PID in every window to the windows that mention it."""
    pid_map: dict[int, list[Any]] = defaultdict(list)
    for w in windows:
        for pid in extract_pids(w.raw_text):
            pid_map[pid].append(w)
    return dict(pid_map)


def extract_module_names(windows: Sequence[Any]) -> dict[str, list[Any]]:
    """Map every kernel module name in every window to the windows naming it."""
    mod_map: dict[str, list[Any]] = defaultdict(list)
    for w in windows:
        seen: set[str] = set()
        for line in w.raw_text.splitlines():
            m = _MODULE_NAME_RE.match(line)
            if not m:
                continue
            name = m.group(1).strip().lower()
            if name not in seen:
                seen.add(name)
                mod_map[name].append(w)
    return dict(mod_map)


def sources_already_indexed(
    source_prefixes: list[str],
    evidence_path: str | None = None,
) -> list[str]:
    """Return source names matching any prefix that already have indexed data.

    Used by extraction tools to skip re-running when data already exists
    in the case database.  Returns an empty list (proceed normally) when
    no case context is loaded, so callers never need to guard separately.

    When *evidence_path* is provided, only sources whose ``source_path``
    matches the given evidence file are considered. This ensures that
    adding new evidence (e.g. a second memory dump) is not blocked by
    sources produced from different evidence files.

    Args:
        source_prefixes: List of source name prefixes to check
            (e.g. ``["bulk."]``, ``["evtx."]``).
        evidence_path: If provided, only count sources originating from
            this specific evidence file path.

    Returns:
        List of existing source names that match any of the given prefixes.
        An empty list means no prior extraction data exists.
    """
    if not has_ctx():
        return []
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    existing: list[str] = []
    for src in sources:
        if evidence_path and src.source_path != evidence_path:
            continue
        if src.line_count == 0:
            # An empty source is a run that indexed nothing: often a failure
            # recorded as a result. It must not stop the tool from running.
            continue
        for prefix in source_prefixes:
            if src.source_name.startswith(prefix):
                existing.append(src.source_name)
                break
    return existing


TOOL_SOURCE_PREFIXES: dict[str, list[str]] = {
    "run_fls": ["tsk.filelist"],
    "run_hayabusa": ["hayabusa."],
    "run_prefetch_parser": ["prefetch.", "ez.prefetch"],
    "run_amcache_parser": ["amcache.", "ez.amcache"],
    "run_shimcache_parser": ["shimcache.", "ez.shimcache"],
    "run_mft_parser": ["mft.", "ez.mft"],
    "run_usn_parser": ["ez.usnjrnl"],
    "run_lnk_parser": ["ez.lnkfiles"],
    "run_jumplist_parser": ["ez.jumplists"],
    "run_shellbags_parser": ["ez.shellbags"],
    "run_srum_parser": ["ez.srum"],
    "parse_cryptnet_url_cache": ["cryptnet.urlcache"],
    "parse_scheduled_tasks": ["tasks.scheduled"],
    "parse_windows_search": ["windows.search"],
    "parse_autoruns": ["autoruns."],
}
"""Maps extraction tool names to the source prefixes they produce.

Used by ``start_extraction_batch`` to skip submitting jobs for tools
whose output sources already exist in the case database. Tools not
listed here are always submitted (they either lack idempotency checks
or produce unique per-invocation sources).

Tools whose own skip depends on their parameters are deliberately not
listed, so the batch lets the tool decide: Volatility (per plugin), the
registry parser (per hive), Chainsaw (per mode), Zircolite (per log
format), bulk_extractor (a timed-out run must be re-run) and the EVTX
parser (its extracted files may be gone). A prefix match here used to
skip them all as soon as any one of their sources existed.
"""


def tool_already_indexed(tool_name: str, evidence_path: str | None = None) -> list[str]:
    """Check whether a tool's output sources already exist in the case DB.

    Looks up the tool's known source prefixes in ``TOOL_SOURCE_PREFIXES``
    and delegates to ``sources_already_indexed``. Returns an empty list
    for tools without a known mapping or when no case context is loaded.

    When *evidence_path* is provided, only sources produced from that
    specific evidence file are considered. This allows the same tool to
    run on new evidence without being blocked by prior results from
    different evidence files.

    Args:
        tool_name: MCP tool function name (e.g. ``"run_fls"``).
        evidence_path: If provided, scope the check to sources from
            this evidence file only.

    Returns:
        List of existing source names, or empty if none found.
    """
    prefixes = TOOL_SOURCE_PREFIXES.get(tool_name)
    if not prefixes:
        return []
    return sources_already_indexed(prefixes, evidence_path=evidence_path)


def run_cli_tool(
    *,
    binary: str,
    cmd: list[str],
    tool_name: str,
    params: dict[str, object],
    source_name: str,
    source_path: str,
    extractor_label: str,
    timeout: int = TOOL_TIMEOUT,
    check_exists: str | None = None,
) -> dict[str, object]:
    """Run a CLI forensic tool and index its stdout output.

    Handles binary availability check, subprocess execution with timeout,
    error reporting, extract-and-index, and audit logging in a single call.

    Args:
        binary: Name of the required binary (checked via require_binary).
        cmd: Full command list to pass to subprocess.run.
        tool_name: MCP tool name for audit logging.
        params: Tool parameters dict for audit logging.
        source_name: Source label for indexing (e.g. "strings.output").
        source_path: Evidence file path for source registration.
        extractor_label: Short extractor name for the DB record.
        timeout: Subprocess timeout in seconds.
        check_exists: Optional file path to verify exists before running.

    Returns:
        Standardized tool response dict (success or error). A tool that exits
        non-zero without writing anything to stdout is reported as an error
        rather than indexed as an empty result.
    """
    import time

    from mulder.server.extract_helpers import extract_and_index

    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    if not require_binary(binary):
        return error_response(
            tc_id,
            tool_name,
            params,
            f"{binary} not found on PATH",
            error_type="binary_missing",
        )

    if check_exists and not Path(check_exists).exists():
        return error_response(
            tc_id,
            tool_name,
            params,
            f"File not found: {check_exists}",
            error_type="file_not_found",
        )

    run = run_tool(cmd, timeout=timeout)
    if run.failed:
        return run_failure_response(tc_id, tool_name, params, run, t0)

    summary = extract_and_index(run.stdout.strip(), source_name, source_path, extractor_label)
    if (warning := run.warning()) is not None:
        summary["tool_warning"] = warning
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, tool_name, params, summary, source_name, elapsed)
