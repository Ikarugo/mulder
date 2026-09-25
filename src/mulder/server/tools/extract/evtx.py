"""Windows Event Log (EVTX) extraction and indexing MCP tools."""

from __future__ import annotations

import atexit
import contextlib
import importlib.util
import logging
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import cast

from mulder.patterns import fls_file_entries
from mulder.server.app import get_cfg, get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    ToolRun,
    adaptive_timeout,
    error_response,
    failure_key,
    make_tool_call_id,
    remember_failure,
    repeated_failure_response,
    require_binary,
    run_failure_response,
    run_tool,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.misc import _DOTNET, _find_ez_tool
from mulder.server.tools.extract.tsk import (
    BULK_ICAT_TIMEOUT,
    IcatFailure,
    _collect_fls_chunks,
    _tsk_extract_dirs,
    _tsk_lock,
    extraction_failure_fields,
    icat_file,
)
from mulder.triage import is_triage_root, iter_tree_files

__all__ = [
    "_cleanup_temp_dirs",
    "_evtx_extract_dirs",
    "index_evtx_file",
    "run_evtx_parser",
]

logger = logging.getLogger(__name__)

_evtx_extract_dirs: dict[str, str] = {}
_evtx_lock = threading.Lock()


def _extract_evtx_from_image(
    image_path: str,
    dest_dir: str,
    failures: list[IcatFailure] | None = None,
    problems: list[str] | None = None,
) -> list[Path]:
    """Extract .evtx files from a disk image to *dest_dir* using TSK icat.

    Searches all indexed ``tsk.filelist*`` sources (primary and secondary
    partitions) to locate EVTX inodes, then extracts each with ``icat``
    using the correct partition offset.  Falls back to running fls inline
    on the primary partition when no indexed sources exist.

    Works on E01 and raw images without mounting.

    Args:
        image_path: Path to the disk image.
        dest_dir: Directory to write extracted .evtx files to.
        failures: When given, receives the logs icat could not read.
        problems: When given, receives why no file listing could be built
            (fls/mmls failure), so "no EVTX found" is not reported for an
            image that was never listed.

    Returns:
        List of paths to extracted .evtx files.
    """
    if is_triage_root(image_path):
        return _copy_evtx_from_tree(image_path, dest_dir)

    chunk_groups = _collect_fls_chunks(image_path, problems)
    if not chunk_groups:
        return []

    extracted: list[Path] = []
    seen: set[str] = set()
    for chunks, offset in chunk_groups:
        for chunk in chunks:
            for entry in fls_file_entries(chunk):
                if not entry.path.lower().endswith(".evtx"):
                    continue
                inode_str = entry.base_inode
                dedup_key = f"{offset}:{inode_str}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                safe_name = entry.path.replace("/", "_").replace("\\", "_")
                out_path = Path(dest_dir) / safe_name
                ok, reason = icat_file(
                    image_path, offset, inode_str, out_path, timeout=BULK_ICAT_TIMEOUT
                )
                if ok:
                    extracted.append(out_path)
                elif reason is not None and not entry.deleted:
                    logger.warning("Cannot extract %s: %s", entry.path, reason)
                    if failures is not None:
                        failures.append(IcatFailure(entry.path, inode_str, reason))
    return extracted


def _copy_evtx_from_tree(root: str, dest_dir: str) -> list[Path]:
    """``_extract_evtx_from_image`` for a triage root: copy every ``.evtx`` file.

    Uses the same flattened names as the TSK path so the manifest,
    ``index_evtx_file`` and Hayabusa see an identical extraction directory.
    """
    copied: list[Path] = []
    for rel_path, src in iter_tree_files(root):
        if not rel_path.lower().endswith(".evtx"):
            continue
        out_path = Path(dest_dir) / rel_path.replace("/", "_")
        try:
            shutil.copyfile(src, out_path)
        except OSError:
            logger.warning("Could not copy %s from triage root %s", rel_path, root)
            continue
        copied.append(out_path)
    return copied


def _find_carved_evtx(dest_dir: str) -> list[Path]:
    """Scan bulk_extractor output for carved .evtx files as a fallback.

    When the TSK path (fls + icat) fails, bulk_extractor may have
    carved EVTX fragments.  This checks the case DB for bulk_extractor
    output paths and copies any .evtx files to *dest_dir*.
    """
    ctx = get_ctx()
    cfg = get_cfg()
    found: list[Path] = []
    search_dirs: list[Path] = []

    sources = ctx.db.get_sources()
    for s in sources:
        if s.source_name.startswith("bulk."):
            src_path = Path(s.source_path)
            if src_path.is_dir():
                search_dirs.append(src_path)
            elif src_path.parent.is_dir():
                search_dirs.append(src_path.parent)

    if cfg.db_dir.is_dir():
        search_dirs.append(cfg.db_dir)

    seen: set[str] = set()
    for d in search_dirs:
        for evtx in d.rglob("*.evtx"):
            if evtx.name in seen:
                continue
            seen.add(evtx.name)
            dest = Path(dest_dir) / evtx.name
            try:
                shutil.copy2(str(evtx), str(dest))
                found.append(dest)
            except OSError:
                continue
    return found


def _cleanup_temp_dirs() -> None:
    """Remove all extraction temp directories."""
    with _evtx_lock:
        dirs = list(_evtx_extract_dirs.values())
        _evtx_extract_dirs.clear()
    for path in dirs:
        shutil.rmtree(path, ignore_errors=True)
    with _tsk_lock:
        tsk_dirs = list(_tsk_extract_dirs)
        _tsk_extract_dirs.clear()
    for path in tsk_dirs:
        shutil.rmtree(path, ignore_errors=True)


atexit.register(_cleanup_temp_dirs)

_HIGH_PRIORITY_KEYWORDS = (
    "security.evtx",
    "system.evtx",
    "powershell",
    "sysmon",
    "taskscheduler",
    "winrm",
    "rdp",
)


def _build_evtx_priority_manifest(evtx_files: list[Path]) -> list[dict[str, object]]:
    """Score EVTX files by forensic priority and build a manifest.

    Files matching known forensic sources (Security, System, PowerShell,
    Sysmon, TaskScheduler, WinRM, RDP) are scored HIGH. Files over 1 MB
    are MEDIUM; the rest are LOW. Results are sorted by size descending.

    Args:
        evtx_files: Extracted EVTX file paths to evaluate.

    Returns:
        Manifest entries with filename, size, human-readable size,
        and priority.
    """
    manifest: list[dict[str, object]] = []
    for ef in sorted(evtx_files, key=lambda p: p.stat().st_size, reverse=True):
        size = ef.stat().st_size
        name = ef.name
        priority = (
            "HIGH"
            if any(k in name.lower() for k in _HIGH_PRIORITY_KEYWORDS)
            else "MEDIUM"
            if size > 1_000_000
            else "LOW"
        )
        manifest.append(
            {
                "filename": name,
                "size_bytes": size,
                "size_human": f"{size / 1_048_576:.1f} MB"
                if size > 1_048_576
                else f"{size / 1024:.0f} KB",
                "priority": priority,
            }
        )
    return manifest


def _parse_evtx_with_eztools(
    evtx_path: str, evtx_dir: str | None, problems: list[str] | None = None
) -> dict[str, object] | None:
    """Parse EVTX files using EZTools EvtxECmd.

    Attempts to locate EvtxECmd.dll and the dotnet runtime. If available,
    runs EvtxECmd to produce CSV output and indexes the combined result.

    Args:
        evtx_path: Path to a single EVTX file (used when evtx_dir is None).
        evtx_dir: Path to a directory of EVTX files, or None for single file.

    Returns:
        Indexed summary dict on success, or None if EZTools is unavailable
        or produces no output.

    Raises:
        subprocess.TimeoutExpired: If EvtxECmd exceeds the timeout.
    """
    dll = _find_ez_tool("EvtxECmd.dll")
    if not (dll and require_binary(_DOTNET)):
        return None

    with tempfile.TemporaryDirectory(prefix="mulder_evtx_csv_") as csv_dir:
        if evtx_dir:
            cmd = [_DOTNET, dll, "-d", evtx_dir, "--csv", csv_dir]
        else:
            cmd = [_DOTNET, dll, "-f", evtx_path, "--csv", csv_dir]

        run = run_tool(cmd, timeout=adaptive_timeout(evtx_path))
        if run.timed_out:
            if problems is not None:
                problems.append(f"EvtxECmd: {run.describe()}")
            raise subprocess.TimeoutExpired(cmd, run.timeout)

        combined = ""
        for csv_file in sorted(Path(csv_dir).glob("*.csv")):
            with contextlib.suppress(OSError):
                combined += csv_file.read_text(encoding="utf-8", errors="replace")

        if combined:
            summary = extract_and_index(combined, "ez.evtx", evtx_path, "eztools")
            if (warning := run.warning()) is not None:
                summary["tool_warning"] = warning
            return summary
        if problems is not None:
            problems.append(_evtx_run_problem(run))
    return None


def _evtxecmd_unavailable() -> str | None:
    """Why EvtxECmd cannot run, or None when it can."""
    if _find_ez_tool("EvtxECmd.dll") is None:
        return "EvtxECmd not run: EvtxECmd.dll not found (run 'mulder setup')"
    if not require_binary(_DOTNET):
        return f"EvtxECmd not run: {_DOTNET} not found on PATH"
    return None


def _ez_reasons(problems: list[str]) -> list[str]:
    """What happened to EvtxECmd, for an error message: its failure or why it did not run."""
    if problems:
        return problems
    unavailable = _evtxecmd_unavailable()
    return [unavailable] if unavailable else []


def _python_evtx_missing() -> str | None:
    """The reason python-evtx cannot run, or None when it is installed.

    ``_parse_evtx_file`` returns empty text when the ``Evtx`` package is
    missing, which is otherwise indistinguishable from a log with no events.
    """
    try:
        found = importlib.util.find_spec("Evtx") is not None
    except (ImportError, ValueError):
        found = False
    return None if found else "python-evtx is not installed"


#: Signature that starts every event record inside an EVTX chunk.
_EVTX_RECORD_MAGIC = b"\x2a\x2a\x00\x00"
#: File header (4 KiB) plus the first chunk header (512 bytes).
_EVTX_FIRST_RECORD_OFFSET = 0x1200


def _evtx_has_records(path: Path) -> bool:
    """Whether an EVTX file holds at least one event record.

    Most channels under ``winevt\\Logs`` are empty: a 68 KiB file with a
    header and an empty chunk. Parsing them yields nothing, which is not a
    parser failure. When unsure (unreadable file, stray signature bytes)
    this answers True, so a real failure is never hidden.
    """
    try:
        with path.open("rb") as fh:
            fh.seek(_EVTX_FIRST_RECORD_OFFSET)
            tail = b""
            while block := fh.read(1 << 20):
                if _EVTX_RECORD_MAGIC in tail + block:
                    return True
                tail = block[-3:]
    except OSError:
        return True
    return False


def _evtx_run_problem(run: ToolRun) -> str:
    """One line on an EvtxECmd run that left no CSV."""
    return f"EvtxECmd produced no CSV: {run.describe()}"


def _parse_evtx_with_python_fallback(
    evtx_path: str,
    evtx_dir: str | None,
    empty: list[str] | None = None,
    no_records: list[str] | None = None,
) -> list[object]:
    """Parse EVTX files using the pure-Python python-evtx library.

    Used as a fallback when EZTools is unavailable or produces no output.

    Args:
        evtx_path: Path to a single EVTX file (used when evtx_dir is None).
        evtx_dir: Path to a directory of EVTX files, or None for single file.

    Returns:
        List of indexed summary dicts, one per successfully parsed file.

    Raises:
        ImportError: If python-evtx is not installed.
    """
    from mulder.extractors.disk import _parse_evtx_file

    results: list[object] = []
    files = sorted(Path(evtx_dir).rglob("*.evtx")) if evtx_dir else [Path(evtx_path)]
    for ef in files:
        channel, text = _parse_evtx_file(ef)
        if text:
            summary = extract_and_index(text, f"evtx.{channel}", str(ef), "python-evtx")
            results.append(summary)
        elif not _evtx_has_records(ef):
            if no_records is not None:
                no_records.append(ef.name)
        elif empty is not None:
            empty.append(ef.name)
    return results


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_evtx_parser(evtx_path: str, force: bool = False) -> dict[str, object]:
    """Extract .evtx files from a disk image and return a prioritized manifest.

    Call after run_fls on disk images. For disk images, extracts all .evtx
    files but does NOT parse them; use index_evtx_file selectively on the
    most relevant logs. For directories or single .evtx files, parses
    immediately.

    Returns a manifest with filenames, sizes, and priority ratings (HIGH
    for Security/System/PowerShell/Sysmon). Follow up with
    index_evtx_file on HIGH priority files first.

    Args:
        evtx_path: Path to an EVTX file, directory, or disk image.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"evtx_path": evtx_path, "force": force}

    if not force:
        existing = sources_already_indexed(["evtx.", "ez.evtx"], evidence_path=evtx_path)
        if set(existing) == {"evtx.manifest"} and not _extraction_dir_alive(evtx_path):
            # Only the manifest was indexed and its extracted files are gone
            # (they are deleted at exit): index_evtx_file has nothing to read,
            # so extract again instead of answering "already done".
            existing = []
        if existing:
            return tool_response(
                tc_id,
                "run_evtx_parser",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "evtx",
                0.0,
            )

    target = Path(evtx_path)
    if not target.exists():
        return error_response(tc_id, "run_evtx_parser", params, f"Path not found: {evtx_path}")

    is_image = target.suffix.lower() in (
        ".e01",
        ".dd",
        ".img",
        ".raw",
        ".001",
    ) or is_triage_root(target)

    if is_image:
        extract_dir = tempfile.mkdtemp(prefix="mulder_evtx_extract_")
        with _evtx_lock:
            _evtx_extract_dirs[evtx_path] = extract_dir
        ctx = get_ctx()
        ctx.db.set_kv("evtx_extract_dir", extract_dir)
        ctx.db.set_kv(f"evtx_extract_dir:{evtx_path}", extract_dir)
        failures: list[IcatFailure] = []
        listing_problems: list[str] = []
        evtx_files = _extract_evtx_from_image(evtx_path, extract_dir, failures, listing_problems)
        if not evtx_files:
            evtx_files = _find_carved_evtx(extract_dir)
        if not evtx_files:
            shutil.rmtree(extract_dir, ignore_errors=True)
            with _evtx_lock:
                _evtx_extract_dirs.pop(evtx_path, None)
            if failures:
                listed = "; ".join(f"{f.path}: {f.reason}" for f in failures[:5])
                return error_response(
                    tc_id,
                    "run_evtx_parser",
                    params,
                    f"{len(failures)} EVTX file(s) exist in the image but none could be read: "
                    f"{listed}",
                    (time.monotonic() - t0) * 1000,
                    error_type="extraction_failed",
                    suggestion="A read failure, not an absence of logs: record the gap.",
                )
            if listing_problems:
                return error_response(
                    tc_id,
                    "run_evtx_parser",
                    params,
                    "No EVTX files extracted: the image's file listing could not be built "
                    f"({'; '.join(listing_problems)})",
                    (time.monotonic() - t0) * 1000,
                    error_type="extraction_failed",
                    suggestion=(
                        "A listing failure, not an absence of logs. Run run_mmls and run_fls "
                        "with the right partition_offset, or run_bulk_extractor to carve EVTX."
                    ),
                )
            return error_response(
                tc_id,
                "run_evtx_parser",
                params,
                "No EVTX files found in disk image. "
                "Ensure run_fls has been called first, or run run_bulk_extractor "
                "which can carve EVTX fragments even when fls fails.",
                (time.monotonic() - t0) * 1000,
                error_type="artifact_missing",
            )

        manifest = _build_evtx_priority_manifest(evtx_files)
        high_count = sum(1 for m in manifest if m["priority"] == "HIGH")
        total_size: int = sum(cast(int, m["size_bytes"]) for m in manifest)

        manifest_text = "\n".join(
            f"{m['filename']}\t{m['size_human']}\t{m['priority']}" for m in manifest
        )
        extract_and_index(manifest_text, "evtx.manifest", evtx_path, "evtx-extract")

        result = {
            "extract_dir": extract_dir,
            "total_files": len(manifest),
            "total_size_human": f"{total_size / 1_073_741_824:.1f} GB"
            if total_size > 1_073_741_824
            else f"{total_size / 1_048_576:.0f} MB",
            "high_priority_count": high_count,
            "manifest": manifest,
            "hint": (
                f"Extracted {len(manifest)} EVTX files ({total_size / 1_048_576:.0f} MB total). "
                f"{high_count} are HIGH priority. Use index_evtx_file(filename) to parse "
                f"specific logs. Start with Security, System, PowerShell, and Sysmon. "
                f"Only index archived logs (Archive-Security-*) if you need historical data."
            ),
        }
        if failures:
            result.update(extraction_failure_fields(failures))
            result["tool_warning"] = result["extraction_note"]

        elapsed = (time.monotonic() - t0) * 1000
        return tool_response(tc_id, "run_evtx_parser", params, result, "evtx.manifest", elapsed)

    evtx_dir = evtx_path if target.is_dir() else None

    problems: list[str] = []
    try:
        ez_result = _parse_evtx_with_eztools(evtx_path, evtx_dir, problems)
        if ez_result is not None:
            elapsed = (time.monotonic() - t0) * 1000
            return tool_response(tc_id, "run_evtx_parser", params, ez_result, "ez.evtx", elapsed)
    except subprocess.TimeoutExpired:
        return error_response(
            tc_id,
            "run_evtx_parser",
            params,
            "; ".join(problems) or "EvtxECmd timed out",
            (time.monotonic() - t0) * 1000,
            error_type="timeout",
        )

    if evtx_dir and not any(Path(evtx_dir).rglob("*.evtx")):
        return error_response(
            tc_id,
            "run_evtx_parser",
            params,
            f"No .evtx files under {evtx_dir}" + (f" ({'; '.join(problems)})" if problems else ""),
            (time.monotonic() - t0) * 1000,
            error_type="artifact_missing",
        )

    missing = _python_evtx_missing()
    if missing is not None:
        return error_response(
            tc_id,
            "run_evtx_parser",
            params,
            "No EVTX parser available: " + "; ".join([*_ez_reasons(problems), missing]),
            (time.monotonic() - t0) * 1000,
            error_type="binary_missing",
        )

    empty: list[str] = []
    no_records: list[str] = []
    try:
        results = _parse_evtx_with_python_fallback(evtx_path, evtx_dir, empty, no_records)
    except ImportError as exc:
        return error_response(
            tc_id,
            "run_evtx_parser",
            params,
            "No EVTX parser available: "
            + "; ".join([*_ez_reasons(problems), f"python-evtx: {exc}"]),
            error_type="binary_missing",
        )

    elapsed = (time.monotonic() - t0) * 1000
    if not results and no_records and not empty:
        # Every log is empty (no event record at all): a fact, not a failure.
        return tool_response(
            tc_id,
            "run_evtx_parser",
            params,
            {
                "status": "no_records",
                "logs_without_records": no_records[:50],
                "logs_without_records_count": len(no_records),
                "message": f"The {len(no_records)} EVTX file(s) hold no event record.",
            },
            None,
            elapsed,
        )
    if not results:
        # Nothing parsed: say so instead of a success with an empty list.
        return error_response(
            tc_id,
            "run_evtx_parser",
            params,
            "; ".join(
                [
                    *_ez_reasons(problems),
                    f"python-evtx also parsed no events from {len(empty)} EVTX file(s)"
                    + (f" ({', '.join(empty[:10])})" if empty else ""),
                ]
            ),
            elapsed,
            error_type="tool_failed",
            suggestion=(
                "The logs may be empty, corrupt or not EVTX. Check their size with "
                "list_directory and record the gap if they cannot be read."
            ),
        )
    if empty or problems:
        notes = []
        if problems:
            notes.extend(problems)
        if empty:
            notes.append(
                f"no events parsed from {len(empty)} file(s) that hold event records: "
                f"{', '.join(empty[:10])}"
            )
        payload: dict[str, object] = {"parsed": results, "tool_warning": "; ".join(notes)}
        if no_records:
            payload["logs_without_records_count"] = len(no_records)
        return tool_response(tc_id, "run_evtx_parser", params, payload, "evtx", elapsed)
    if no_records:
        return tool_response(
            tc_id,
            "run_evtx_parser",
            params,
            {"parsed": results, "logs_without_records_count": len(no_records)},
            "evtx",
            elapsed,
        )
    return tool_response(tc_id, "run_evtx_parser", params, results, "evtx", elapsed)


def _extraction_dir_alive(evtx_path: str) -> bool:
    """Whether the files extracted by an earlier run_evtx_parser are still on disk."""
    with _evtx_lock:
        extract_dir = _evtx_extract_dirs.get(evtx_path)
    if extract_dir is None:
        try:
            value = get_ctx().db.get_kv(f"evtx_extract_dir:{evtx_path}")
        except Exception:
            value = None
        extract_dir = str(value) if value else None
    return bool(extract_dir) and Path(str(extract_dir)).is_dir()


_COMPANION_LOG_PATTERNS: tuple[tuple[str, str], ...] = (
    ("system", "evtx.system"),
    ("powershell%4operational", "evtx.powershell-operational"),
    ("microsoft-windows-powershell%4operational", "evtx.powershell-operational"),
)


def _is_security_log(filename: str) -> bool:
    """Return True if *filename* refers to a Security event log."""
    return "security" in filename.lower().replace(" ", "").replace("-", "")


def _run_evtxecmd_file(
    evtx_file: Path, event_ids: list[int] | None = None
) -> tuple[ToolRun | None, str]:
    """Run EvtxECmd on one file and return ``(run, combined CSV text)``.

    ``run`` is None when EvtxECmd or dotnet is not installed.
    """
    dll = _find_ez_tool("EvtxECmd.dll")
    if not (dll and require_binary(_DOTNET)):
        return None, ""
    with tempfile.TemporaryDirectory(prefix="mulder_evtx_csv_") as csv_dir:
        cmd = [_DOTNET, dll, "-f", str(evtx_file), "--csv", csv_dir]
        if event_ids:
            cmd.extend(["--inc", ",".join(str(eid) for eid in event_ids)])
        run = run_tool(cmd, timeout=adaptive_timeout(str(evtx_file)))
        combined = ""
        for csv_file in sorted(Path(csv_dir).glob("*.csv")):
            with contextlib.suppress(OSError):
                combined += csv_file.read_text(encoding="utf-8", errors="replace")
    return run, combined


def _auto_index_companion_logs(
    extract_dir: str,
    image_path: str,
    failures: list[dict[str, object]] | None = None,
) -> list[dict[str, object]]:
    """Index System.evtx and PowerShell logs alongside a Security log.

    Checks for companion logs in the same extraction directory. Skips
    any that are already indexed. Returns summaries of newly indexed logs.
    Companions that could not be indexed are appended to *failures* as
    ``{"file", "error"}`` entries (when given) instead of only being logged.
    """
    ctx = get_ctx()
    existing_sources = {s.source_name for s in ctx.db.get_sources()}
    indexed: list[dict[str, object]] = []

    def _failed(candidate: Path, error: str) -> None:
        logger.warning("Auto-index of %s failed: %s", candidate.name, error)
        if failures is not None:
            failures.append({"file": candidate.name, "error": error})

    extract_path = Path(extract_dir)
    available_files = {f.name.lower(): f for f in extract_path.glob("*.evtx")}

    for pattern, source_name in _COMPANION_LOG_PATTERNS:
        if source_name in existing_sources:
            continue

        candidate = next(
            (path for name, path in available_files.items() if pattern in name),
            None,
        )
        if candidate is None:
            continue

        run, combined = _run_evtxecmd_file(candidate)
        if run is not None and run.timed_out:
            _failed(candidate, f"EvtxECmd: {run.describe()}")
            continue
        if combined:
            sname = "evtx." + candidate.stem.lower().replace(" ", "-").replace("%", "")
            summary = extract_and_index(combined, sname, str(candidate), "eztools")
            if (warning := run.warning() if run is not None else None) is not None:
                summary["tool_warning"] = warning
            indexed.append({"source": sname, "file": candidate.name, "summary": summary})
            existing_sources.add(sname)
            continue

        reasons = [_evtx_run_problem(run)] if run is not None else []
        missing = _python_evtx_missing()
        if missing is not None:
            _failed(candidate, "; ".join([*reasons, missing]))
            continue
        try:
            from mulder.extractors.disk import _parse_evtx_file
        except ImportError as exc:
            _failed(candidate, "; ".join([*reasons, f"python-evtx: {exc}"]))
            continue

        channel, text = _parse_evtx_file(candidate)
        if text:
            sname = f"evtx.{channel}"
            summary = extract_and_index(text, sname, str(candidate), "python-evtx")
            indexed.append({"source": sname, "file": candidate.name, "summary": summary})
            existing_sources.add(sname)
        elif _evtx_has_records(candidate):
            _failed(candidate, "; ".join([*reasons, "python-evtx parsed no events"]))
        # else: the companion log is empty (no event record): nothing to index.

    return indexed


def _with_companions(
    summary: dict[str, object], filename: str, extract_dir: str, image_path: str
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Auto-index the companions of a Security log; note failures in *summary*."""
    if not _is_security_log(filename):
        return [], []
    failures: list[dict[str, object]] = []
    auto_indexed = _auto_index_companion_logs(extract_dir, image_path, failures)
    if failures:
        summary["companion_failures"] = failures
        warning = (
            f"{len(failures)} companion log(s) could not be auto-indexed "
            f"({', '.join(str(f['file']) for f in failures)}); see companion_failures. "
            "Index them with index_evtx_file or record the gap."
        )
        earlier = summary.get("tool_warning")
        summary["tool_warning"] = f"{earlier}\n{warning}" if earlier else warning
    return auto_indexed, failures


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def index_evtx_file(
    filename: str,
    event_ids: list[int] | None = None,
    image_path: str = "",
    force: bool = False,
) -> dict[str, object]:
    """Parse and index a specific EVTX file from a prior run_evtx_parser extraction.

    Call only after run_evtx_parser has extracted .evtx files from a disk
    image. The filename must match one from the manifest. Pass event_ids
    for dramatically faster parsing (seconds vs minutes on large logs).

    Indexes as ``evtx.<channel>`` (e.g. ``evtx.security``). Searchable
    via search() and get_raw_output(). Recommended order: Security,
    System, PowerShell, Sysmon, then WinRM/TaskScheduler/RDP.

    When indexing a Security log, automatically indexes System.evtx and
    PowerShell operational logs from the same directory (if present and
    not already indexed) for persistence and execution coverage.

    Args:
        filename: Name of the .evtx file to parse (from the manifest).
        event_ids: Optional list of Event IDs to extract.  When provided,
            only events matching these IDs are parsed and indexed.
            When omitted, all events are extracted.  Choose IDs based
            on the log type and what you're investigating.
        image_path: Disk image path passed to ``run_evtx_parser``.
            Required when multiple images have been extracted in the
            same session; omit for single-image cases.
        force: Parse again a file whose parsing already failed with the
            same event_ids (by default the earlier failure is returned).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "filename": filename,
        "event_ids": event_ids,
        "image_path": image_path,
        "force": force,
    }

    with _evtx_lock:
        if image_path and image_path in _evtx_extract_dirs:
            extract_dir = _evtx_extract_dirs[image_path]
        elif _evtx_extract_dirs:
            extract_dir = next(reversed(_evtx_extract_dirs.values()))
        else:
            extract_dir = ""

    if not extract_dir:
        ctx = get_ctx()
        if image_path:
            extract_dir = ctx.db.get_kv(f"evtx_extract_dir:{image_path}") or ""
        if not extract_dir:
            extract_dir = ctx.db.get_kv("evtx_extract_dir") or ""

    if not extract_dir or not Path(extract_dir).is_dir():
        return error_response(
            tc_id,
            "index_evtx_file",
            params,
            "No EVTX extraction directory found. Call run_evtx_parser on a disk image first.",
        )

    evtx_path = Path(extract_dir) / filename
    if not evtx_path.exists():
        candidates = sorted(Path(extract_dir).glob(f"*{filename}*"))
        if candidates:
            evtx_path = candidates[0]
        else:
            available = [f.name for f in sorted(Path(extract_dir).glob("*.evtx"))[:10]]
            return error_response(
                tc_id,
                "index_evtx_file",
                params,
                f"File not found: {filename}. Available files include: {', '.join(available)}",
            )

    memory_key = failure_key(
        "index_evtx_file", str(evtx_path), ",".join(str(e) for e in sorted(event_ids or []))
    )
    repeated = repeated_failure_response(tc_id, "index_evtx_file", params, memory_key, t0)
    if repeated is not None:
        return repeated

    run, combined = _run_evtxecmd_file(evtx_path, event_ids)
    if run is not None and run.timed_out:
        return run_failure_response(
            tc_id,
            "index_evtx_file",
            params,
            run,
            t0,
            memory_key=memory_key,
            context=f"EvtxECmd on {evtx_path.name}",
        )
    if combined:
        source_name = "evtx." + evtx_path.stem.lower().replace(" ", "-").replace("%", "")
        summary = extract_and_index(combined, source_name, str(evtx_path), "eztools")
        if run is not None and (warning := run.warning()) is not None:
            summary["tool_warning"] = warning
        return _index_response(
            tc_id, params, summary, source_name, filename, extract_dir, image_path, t0
        )

    reasons = [_evtx_run_problem(run)] if run is not None else _ez_reasons([])
    missing = _python_evtx_missing()
    if missing is not None:
        return error_response(
            tc_id,
            "index_evtx_file",
            params,
            f"No EVTX parser available for {evtx_path.name}: " + "; ".join([*reasons, missing]),
            (time.monotonic() - t0) * 1000,
            error_type="binary_missing",
        )
    try:
        from mulder.extractors.disk import _parse_evtx_file
    except ImportError as exc:
        return error_response(
            tc_id,
            "index_evtx_file",
            params,
            "No EVTX parser available: " + "; ".join([*reasons, f"python-evtx: {exc}"]),
            (time.monotonic() - t0) * 1000,
            error_type="binary_missing",
        )

    id_filter = set(event_ids) if event_ids else None
    channel, text = _parse_evtx_file(evtx_path, event_ids=id_filter)
    if text:
        summary = extract_and_index(text, f"evtx.{channel}", str(evtx_path), "python-evtx")
        if run is not None:
            # EvtxECmd failed but python-evtx read the log: the events are all
            # there, in python-evtx's format under evtx.<channel>.
            summary["parser_note"] = f"{reasons[0]}. Parsed with python-evtx instead."
        return _index_response(
            tc_id, params, summary, f"evtx.{channel}", filename, extract_dir, image_path, t0
        )

    size = evtx_path.stat().st_size if evtx_path.exists() else 0
    if not id_filter and not _evtx_has_records(evtx_path):
        return tool_response(
            tc_id,
            "index_evtx_file",
            params,
            {
                "status": "no_records",
                "message": (
                    f"{evtx_path.name} ({size} bytes) holds no event record: the channel is "
                    "empty (never written to, or cleared and not written to since)."
                ),
            },
            None,
            (time.monotonic() - t0) * 1000,
        )
    message = (
        f"No events parsed from {evtx_path.name} ({size} bytes): "
        + "; ".join(reasons)
        + "; python-evtx also parsed no events"
        + (f" matching event_ids {sorted(event_ids)}" if event_ids else "")
    )
    remember_failure(memory_key, message)
    return error_response(
        tc_id,
        "index_evtx_file",
        params,
        message,
        (time.monotonic() - t0) * 1000,
        error_type="tool_failed",
        suggestion=(
            "The log may be empty, corrupt or not EVTX"
            + (", or no event has these IDs" if event_ids else "")
            + ". Running it again fails the same way (pass force=True after changing the "
            "setup); record the gap or use run_hayabusa on the extraction directory."
        ),
    )


def _index_response(
    tc_id: str,
    params: dict[str, object],
    summary: dict[str, object],
    source_name: str,
    filename: str,
    extract_dir: str,
    image_path: str,
    t0: float,
) -> dict[str, object]:
    """The index_evtx_file response for an indexed log, with its companions."""
    auto_indexed, companion_failures = _with_companions(summary, filename, extract_dir, image_path)
    elapsed = (time.monotonic() - t0) * 1000
    response = tool_response(tc_id, "index_evtx_file", params, summary, source_name, elapsed)
    if auto_indexed:
        response["auto_indexed_companions"] = auto_indexed
    if companion_failures:
        response["companion_failures"] = companion_failures
    return response
