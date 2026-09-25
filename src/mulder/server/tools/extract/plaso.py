"""Plaso (log2timeline) super-timeline MCP tools."""

from __future__ import annotations

import logging
import shutil
import tempfile
import time
from pathlib import Path
from typing import Protocol

from mulder.server.app import get_cfg, get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    _PREVIEW_CHAR_LIMIT,
    ToolRun,
    adaptive_timeout,
    error_response,
    failure_key,
    interpreter_candidates,
    make_tool_call_id,
    remember_failure,
    repeated_failure_response,
    run_tool,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = [
    "run_plaso",
]

logger = logging.getLogger(__name__)

_PLASO_TIMEOUT = 3600

# Never wait on stdin: -u makes plaso abort instead of prompting, and the
# explicit partition/volume/VSS selections are what it would otherwise ask for.
# --storage_file has been the only accepted form since plaso dropped the
# positional storage file argument years ago; current plaso rejects the positional
# form with "unrecognized arguments".
_L2T_FLAGS = [
    "--status_view",
    "none",
    "-u",
    "--partitions",
    "all",
    "--volumes",
    "all",
    "--vss_stores",
    "none",
]

_L2TCSV_HEADER = "date,time,timezone,MACB,"


class _ProcessOutput(Protocol):
    """What :func:`_failure_detail` reads: a CompletedProcess or a ToolRun."""

    @property
    def returncode(self) -> int | None: ...

    @property
    def stdout(self) -> str | None: ...

    @property
    def stderr(self) -> str | None: ...


def _failure_detail(name: str, proc: _ProcessOutput) -> str:
    """Summarise a failed plaso process: exit code plus the tail of its output.

    The informative line is always last: argparse prints its usage banner then
    ``prog: error: ...`` on stderr, while plaso's own failures (``No supported
    file system found in source.``) go to stdout after the dependency check.
    """
    tails = []
    for stream in (proc.stdout, proc.stderr):
        lines = [ln.strip() for ln in (stream or "").splitlines() if ln.strip()]
        tails.extend(lines[-2:])
    return f"{name} exited {proc.returncode}: " + " | ".join(tails)[-_PREVIEW_CHAR_LIMIT:]


def _run_detail(name: str, run: ToolRun) -> str:
    """:func:`_failure_detail` for a :class:`ToolRun`, including timeouts and launch errors.

    *name* is used rather than ``run.binary``, which is ``python3`` when plaso
    is reached through ``-m plaso.cli.<tool>``.
    """
    if run.launch_error is not None:
        return f"{name} could not be started: {run.launch_error}"
    if run.timed_out:
        tail = " | ".join(run.tail(3).splitlines())[-_PREVIEW_CHAR_LIMIT:]
        return f"{name} timed out after {run.timeout}s" + (f": {tail}" if tail else "")
    return _failure_detail(name, run)


def _find_plaso_cmd(tool: str) -> list[str] | None:
    """Locate a Plaso CLI tool, trying multiple install conventions.

    pip-installed plaso may use ``log2timeline.py``, ``log2timeline``,
    or only be reachable via ``-m plaso.cli.<tool>`` on a probed Python
    interpreter.
    """
    module_map = {
        "log2timeline": "plaso.cli.log2timeline",
        "psort": "plaso.cli.psort",
        "pinfo": "plaso.cli.pinfo",
    }
    base = tool.removesuffix(".py")
    for name in (f"{base}.py", base):
        path = shutil.which(name)
        if path:
            return [path]
    mod = module_map.get(base)
    if mod:
        for py in interpreter_candidates():
            if run_tool([py, "-m", mod, "--version"], timeout=10).ok:
                return [py, "-m", mod]
    return None


def _date_filter(time_range: str) -> str:
    """psort event filter for events after *time_range*.

    Current plaso compares the ``timestamp`` attribute against a
    ``DATETIME(...)`` value; the legacy ``date > '...'`` form names an
    attribute events no longer have, so it silently matched nothing.
    DATETIME takes ISO 8601, which uses ``T`` between date and time.
    """
    value = time_range.strip().replace(" ", "T", 1).replace("'", "")
    return f"timestamp > DATETIME('{value}')"


def _count_events(timeline_text: str) -> int:
    lines = [ln for ln in timeline_text.splitlines() if ln.strip()]
    if lines and lines[0].startswith(_L2TCSV_HEADER):
        return len(lines) - 1
    return len(lines)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_plaso(
    evidence_path: str,
    parsers: str | None = None,
    time_range: str | None = None,
    force: bool = False,
) -> dict[str, object]:
    """Run log2timeline (Plaso) against an evidence file to build a super-timeline.

    This is the most expensive extraction tool.  Use targeted parsers and
    time ranges when possible to reduce runtime.

    Args:
        evidence_path: Path to a disk image or directory.
        parsers: Comma-separated list of Plaso parsers to run (e.g.
            "winevtx,prefetch,pe").  Runs all parsers if omitted.
        time_range: Date filter passed to psort (e.g. "2015-08-01"): only
            events after it are exported.
        force: Run again although log2timeline already failed on this
            evidence with the same parsers.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "evidence_path": evidence_path,
        "parsers": parsers,
        "time_range": time_range,
        "force": force,
    }

    def _elapsed() -> float:
        return (time.monotonic() - t0) * 1000

    l2t_cmd_prefix = _find_plaso_cmd("log2timeline")
    if not l2t_cmd_prefix:
        return error_response(
            tc_id,
            "run_plaso",
            params,
            (
                "log2timeline not found (tried log2timeline.py, log2timeline, and "
                "-m plaso.cli.log2timeline on every probed Python interpreter)"
            ),
            error_type="binary_missing",
        )
    # Checked before log2timeline runs for hours: without psort nothing it
    # produces can be read back.
    psort_prefix = _find_plaso_cmd("psort")
    if not psort_prefix:
        return error_response(
            tc_id,
            "run_plaso",
            params,
            (
                "psort not found (tried psort.py, psort, and -m plaso.cli.psort on every "
                "probed Python interpreter); log2timeline was not run"
            ),
            error_type="binary_missing",
        )

    # log2timeline runs for up to hours: never repeat one that already failed
    # on the same evidence with the same parsers (unless force=True).
    memory_key = failure_key("run_plaso", evidence_path, parsers, time_range)
    repeated = repeated_failure_response(tc_id, "run_plaso", params, memory_key, t0)
    if repeated is not None:
        return repeated

    cfg = get_cfg()
    ctx = get_ctx()
    persistent_plaso = cfg.db_dir / f"{ctx.case_id}.plaso"
    notes: dict[str, object] = {}

    with tempfile.TemporaryDirectory(prefix="mulder_plaso_") as tmpdir:
        plaso_file = Path(tmpdir) / "timeline.plaso"

        l2t_cmd = [*l2t_cmd_prefix, "--storage_file", str(plaso_file), *_L2T_FLAGS]
        if parsers:
            l2t_cmd.extend(["--parsers", parsers])
        l2t_cmd.append(evidence_path)

        plaso_timeout = adaptive_timeout(evidence_path, base=_PLASO_TIMEOUT)
        l2t = run_tool(l2t_cmd, timeout=plaso_timeout)

        storage_written = plaso_file.is_file() and plaso_file.stat().st_size > 0
        if not storage_written:
            if l2t.ok:
                message = "log2timeline exited 0 but wrote no storage file: " + (
                    " | ".join(l2t.tail(4).splitlines()) or "no output"
                )
            else:
                message = _run_detail("log2timeline", l2t)
            if l2t.error_type not in ("binary_missing", "timeout"):
                remember_failure(memory_key, message)
            return error_response(
                tc_id,
                "run_plaso",
                params,
                message,
                _elapsed(),
                error_type=l2t.error_type,
            )
        l2t_problem = None if l2t.ok else _run_detail("log2timeline", l2t)

        try:
            shutil.copy2(str(plaso_file), str(persistent_plaso))
        except OSError as exc:
            notes["plaso_storage_error"] = (
                f"Could not keep the .plaso storage file at {persistent_plaso}: {exc}. "
                "filter_timeline and export_timeline_slice will not find it."
            )

        # l2tcsv refuses to write to stdout ("requires an output file"), and
        # stdout would carry psort's own diagnostics anyway.
        csv_file = Path(tmpdir) / "timeline.csv"
        psort_cmd = [
            *psort_prefix,
            "--status_view",
            "none",
            "-u",
            "-o",
            "l2tcsv",
            "-w",
            str(csv_file),
            str(plaso_file),
        ]
        if time_range:
            psort_cmd.append(_date_filter(time_range))

        psort = run_tool(psort_cmd, timeout=plaso_timeout)

        timeline_text = csv_file.read_text(errors="replace").strip() if csv_file.exists() else ""
        if not psort.ok and not timeline_text:
            kept = (
                f" The log2timeline storage file was kept at {persistent_plaso}."
                if persistent_plaso.exists()
                else ""
            )
            also = f" log2timeline had also failed: {l2t_problem}." if l2t_problem else ""
            return error_response(
                tc_id,
                "run_plaso",
                params,
                _run_detail("psort", psort) + "." + also + kept,
                _elapsed(),
                error_type=psort.error_type,
            )
        event_count = _count_events(timeline_text)
        if event_count == 0 and l2t_problem:
            # A timeline log2timeline did not finish, with nothing in it, is a
            # failure: not a machine on which nothing happened.
            message = f"{l2t_problem}. The storage file it left holds no events" + (
                " after the time_range filter." if time_range else "."
            )
            if not l2t.timed_out:
                remember_failure(memory_key, message)
            return error_response(
                tc_id, "run_plaso", params, message, _elapsed(), error_type=l2t.error_type
            )

        warnings: list[str] = []
        if l2t_problem:
            warnings.append(
                f"{l2t_problem}\nlog2timeline did not complete: the timeline was exported "
                "from the storage file it left and may be missing events."
            )
        if not psort.ok:
            warnings.append(
                f"{_run_detail('psort', psort)}\nThe CSV psort wrote before that was indexed; "
                "it may be incomplete."
            )

        stats_text = ""
        pinfo_prefix = _find_plaso_cmd("pinfo")
        if pinfo_prefix:
            pinfo = run_tool([*pinfo_prefix, "-v", str(plaso_file)], timeout=60)
            stats_text = pinfo.stdout.strip()
            if not pinfo.ok:
                notes["stats_error"] = _run_detail("pinfo", pinfo)

    indexed: list[object] = []
    timeline_summary: dict[str, object] = {}
    if event_count:
        timeline_summary = extract_and_index(
            timeline_text, "plaso.timeline", evidence_path, "plaso"
        )
        indexed.append(timeline_summary)
    if stats_text:
        indexed.append(
            extract_and_index(
                stats_text,
                "plaso.stats",
                str(persistent_plaso) if persistent_plaso.exists() else evidence_path,
                "plaso",
            )
        )

    windows = timeline_summary.get("windows_indexed")
    lines = timeline_summary.get("line_count")
    result: dict[str, object] = {
        "events": event_count,
        "windows_indexed": windows if isinstance(windows, int) else 0,
        "line_count": lines if isinstance(lines, int) else 0,
        "indexed": indexed,
        **notes,
    }
    if event_count == 0:
        result["note"] = (
            "psort exported no events"
            + (f" after {time_range}" if time_range else "")
            + ": nothing was indexed as plaso.timeline."
        )
    if warnings:
        result["tool_warning"] = "\n".join(warnings)
    return tool_response(tc_id, "run_plaso", params, result, "plaso.timeline", _elapsed())
