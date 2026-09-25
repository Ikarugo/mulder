"""Hayabusa MCP tools for Sigma-rule EVTX detection.

Runs Hayabusa against extracted EVTX files and indexes the resulting
detection alerts into the case database.  All tools are read-only
with respect to evidence files.
"""

from __future__ import annotations

import csv
import io
import logging
import os
import re
import shutil
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import NamedTuple

from mulder.assets.paths import asset_path, asset_search_summary
from mulder.patterns import DISK_IMAGE_EXTS
from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    ToolRun,
    adaptive_timeout,
    error_response,
    failure_key,
    make_tool_call_id,
    repeated_failure_response,
    run_failure_response,
    run_tool,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.triage import is_triage_root

logger = logging.getLogger(__name__)

_HAYABUSA_DIRNAME = "hayabusa"
_HAYABUSA_TIMEOUT = 300


def _hayabusa_binary() -> str | None:
    """Resolve the Hayabusa executable: asset root first, then PATH.

    Asset root wins because the image and ``mulder setup`` both install a
    version-matched binary there, while a stray PATH entry may be anything.
    """
    candidate = asset_path(_HAYABUSA_DIRNAME, "hayabusa")
    if candidate is not None and os.access(candidate, os.X_OK):
        return str(candidate)
    return shutil.which("hayabusa")


_VALID_SEVERITIES = ("informational", "low", "medium", "high", "critical")


def _dir_has_evtx(directory: str) -> bool:
    """Return True if *directory* contains at least one ``.evtx`` file."""
    return next(Path(directory).rglob("*.evtx"), None) is not None


def _resolve_evtx_dir(
    evtx_dir: str | None, image_path: str | None = None, *, extract: bool = True
) -> str | None:
    """Return a valid EVTX directory path, or None.

    Each candidate is validated to contain at least one ``.evtx`` file
    before being accepted, so stale or empty extraction directories are
    skipped automatically.

    Resolution order:
    1. Explicit *evtx_dir* if it exists and contains EVTX files.
    2. Prior extraction from ``run_evtx_parser`` keyed by *image_path*
       (in-memory cache).
    3. Any prior extraction directory (newest first) that still has files
       (in-memory cache).
    4. DB ``kv_store`` fallback (``evtx_extract_dir:{image_path}`` then
       ``evtx_extract_dir``), for cross-process persistence when the
       server restarts between orchestrator phases.
    5. Inline EVTX extraction from *image_path* using the same TSK +
       carved-EVTX strategy as ``run_evtx_parser`` (only when *extract*).

    Args:
        evtx_dir: Explicit directory containing ``.evtx`` files.
        image_path: Disk image path; used for lookup or inline extraction.
        extract: False to look up existing directories only (steps 1-4),
            e.g. to find what a previous run registered as its source.

    Returns:
        Path to a directory containing EVTX files, or None.
    """
    if evtx_dir and Path(evtx_dir).is_dir() and _dir_has_evtx(evtx_dir):
        return evtx_dir

    from mulder.server.tools.extract.evtx import _evtx_extract_dirs

    if image_path and image_path in _evtx_extract_dirs:
        d = _evtx_extract_dirs[image_path]
        if Path(d).is_dir() and _dir_has_evtx(d):
            return d

    for d in reversed(list(_evtx_extract_dirs.values())):
        if Path(d).is_dir() and _dir_has_evtx(d):
            return d

    try:
        ctx = get_ctx()
        if image_path:
            db_dir = ctx.db.get_kv(f"evtx_extract_dir:{image_path}")
            if db_dir and Path(db_dir).is_dir() and _dir_has_evtx(db_dir):
                return db_dir
        db_dir = ctx.db.get_kv("evtx_extract_dir") or ""
        if db_dir and Path(db_dir).is_dir() and _dir_has_evtx(db_dir):
            return db_dir
    except Exception:
        logger.debug("Failed to read evtx_extract_dir from DB kv_store", exc_info=True)

    if (
        extract
        and image_path
        and Path(image_path).exists()
        and (Path(image_path).suffix.lower() in DISK_IMAGE_EXTS or is_triage_root(image_path))
    ):
        return _extract_evtx_inline(image_path)

    return None


def _extract_evtx_inline(image_path: str) -> str | None:
    """Extract EVTX files from a disk image for Hayabusa analysis.

    Uses the same two-stage strategy as ``run_evtx_parser``: TSK
    icat extraction first, then a bulk_extractor carved-EVTX fallback.
    The extracted directory is registered in ``_evtx_extract_dirs`` so
    subsequent tools can reuse it.

    Args:
        image_path: Path to a disk image (E01, raw, dd).

    Returns:
        Path to the extraction directory, or None if no EVTX files found.
    """
    from mulder.server.tools.extract.evtx import (
        _evtx_extract_dirs,
        _extract_evtx_from_image,
        _find_carved_evtx,
    )

    logger.info(
        "Hayabusa: no prior EVTX extraction found; extracting inline from %s",
        image_path,
    )
    extract_dir = tempfile.mkdtemp(prefix="mulder_hayabusa_evtx_")
    evtx_files = _extract_evtx_from_image(image_path, extract_dir)
    if not evtx_files:
        evtx_files = _find_carved_evtx(extract_dir)
    if evtx_files:
        _evtx_extract_dirs[image_path] = extract_dir
        logger.info(
            "Hayabusa: extracted %d EVTX files from %s",
            len(evtx_files),
            image_path,
        )
        return extract_dir

    shutil.rmtree(extract_dir, ignore_errors=True)
    return None


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_hayabusa(
    evtx_dir: str = "",
    min_severity: str = "medium",
    image_path: str = "",
    force: bool = False,
) -> dict[str, object]:
    """Detect threats in EVTX files using 3,700+ Sigma rules via Hayabusa.

    Call immediately after run_evtx_parser to get a prioritized list of
    suspicious events with MITRE ATT&CK technique mappings. Automatically
    locates the EVTX extraction directory from the prior run_evtx_parser
    call. If no prior extraction exists and image_path is a disk image,
    extracts EVTX files inline.

    Indexes as ``hayabusa.alerts``; returns severity breakdown, top rules,
    and MITRE technique IDs. Use search(source='hayabusa.alerts') for
    detailed alert inspection.

    Args:
        evtx_dir: Directory containing ``.evtx`` files.  If empty, falls
            back to the directory created by ``run_evtx_parser``.
        min_severity: Minimum alert severity to include.  One of
            ``"informational"``, ``"low"``, ``"medium"`` (default),
            ``"high"``, ``"critical"``.
        image_path: Path to the disk image whose extracted EVTX directory
            should be used.  Only needed when *evtx_dir* is empty and
            multiple images have been processed.  Matches the path
            previously passed to ``run_evtx_parser``.
        force: Re-run extraction even if sources already exist, or after an
            earlier run on the same directory failed.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {
        "evtx_dir": evtx_dir,
        "min_severity": min_severity,
        "image_path": image_path,
        "force": force,
    }
    tool_name = "run_hayabusa"

    severity = min_severity.lower()
    if severity not in _VALID_SEVERITIES:
        severity = "medium"

    if not force:
        skipped = _already_indexed_response(tc_id, params, evtx_dir, image_path)
        if skipped is not None:
            return skipped

    hayabusa_bin = _hayabusa_binary()
    if hayabusa_bin is None:
        return error_response(
            tc_id,
            tool_name,
            params,
            "Hayabusa binary not found on PATH or under "
            f"{asset_search_summary(_HAYABUSA_DIRNAME, 'hayabusa')}. Run 'mulder setup'.",
            elapsed_ms=(time.monotonic() - t0) * 1000,
            error_type="binary_missing",
        )

    resolved_dir = _resolve_evtx_dir(evtx_dir or None, image_path=image_path or None)
    if not resolved_dir:
        return error_response(
            tc_id,
            tool_name,
            params,
            "No EVTX directory found. Run run_evtx_parser on a disk image "
            "first, or provide an explicit evtx_dir path.",
            elapsed_ms=(time.monotonic() - t0) * 1000,
        )

    evtx_files = list(Path(resolved_dir).rglob("*.evtx"))
    if not evtx_files:
        return error_response(
            tc_id,
            tool_name,
            params,
            f"No .evtx files found in {resolved_dir}",
            elapsed_ms=(time.monotonic() - t0) * 1000,
        )

    # A Hayabusa run takes minutes: do not repeat one that already failed on
    # the same directory with the same severity floor.
    memory_key = failure_key(tool_name, resolved_dir, severity)
    repeated = repeated_failure_response(tc_id, tool_name, params, memory_key, t0)
    if repeated is not None:
        return repeated

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        out_path = tmp.name

    cmd = [
        hayabusa_bin,
        "csv-timeline",
        "-d",
        resolved_dir,
        "-o",
        out_path,
        # out_path is pre-created above by NamedTemporaryFile, and Hayabusa
        # refuses to write over an existing file unless --clobber is given:
        # it prints "The file ... already exists" to stderr, writes nothing,
        # and still exits 0. Without this flag no scan ever runs.
        "--clobber",
        "-p",
        "super-verbose",
        "--no-wizard",
        "-m",
        severity,
    ]

    timeout = adaptive_timeout(image_path or resolved_dir, base=_HAYABUSA_TIMEOUT)
    try:
        run = run_tool(cmd, timeout=timeout)
        try:
            csv_text = Path(out_path).read_text(errors="replace")
        except OSError:
            csv_text = ""
    finally:
        Path(out_path).unlink(missing_ok=True)

    report = _parse_run_report(run.stdout)
    warnings: list[str] = []

    if not csv_text.strip():
        # The output path is pre-created above, so "the file exists" says
        # nothing about whether Hayabusa ran. A non-zero exit that wrote no
        # timeline produced no evidence and must not be reported as a scan
        # that found nothing.
        if not run.ok:
            return run_failure_response(
                tc_id,
                tool_name,
                params,
                run,
                t0,
                memory_key=memory_key,
                context=f"Hayabusa wrote no timeline for {resolved_dir}",
            )
        # Exit 0 is not enough either: Hayabusa exits 0 when it refuses to
        # run (existing output file, no rules, no .evtx found). Only its own
        # report ("Total event log files", "Results Summary") shows that the
        # logs were actually scanned and simply matched no rule.
        if not report.processed:
            message = (
                f"Hayabusa exited 0 but did not report scanning any event log in "
                f"{resolved_dir} ({report.describe()}); no alert count can be given. "
                + _tail_message(run)
            )
            # Not remembered: this rests on reading Hayabusa's console report,
            # whose wording can change between versions.
            return error_response(
                tc_id,
                tool_name,
                params,
                message,
                elapsed_ms=(time.monotonic() - t0) * 1000,
                error_type="tool_failed",
                suggestion=(
                    "Check the Hayabusa output above (rules missing: run 'mulder setup'; "
                    "unreadable directory: pass another evtx_dir), then pass force=True."
                ),
            )
        if report.total_events == 0:
            warnings.append(
                f"Hayabusa scanned {report.files} event log file(s) in {resolved_dir} but "
                "read 0 events: the logs may be empty, unreadable, or of channels no rule "
                "targets. Zero alerts here does not mean the host is clean. " + _tail_message(run)
            )
        warnings.extend(_error_log_warning(report))
        result: dict[str, object] = {
            "total_alerts": 0,
            "by_severity": {},
            "top_rules": [],
            "mitre_techniques": [],
            "evtx_dir": resolved_dir,
            "evtx_file_count": len(evtx_files),
            **report.as_result(),
            "windows_indexed": 0,
        }
        if warnings:
            result["tool_warning"] = "\n".join(warnings)
        elapsed = (time.monotonic() - t0) * 1000
        return tool_response(tc_id, tool_name, params, result, "hayabusa.alerts", elapsed)

    if not run.ok:
        # Hayabusa can stop on one unreadable EVTX after writing detections
        # for the others: keep them, but say the scan did not complete.
        warnings.append(
            f"{run.describe()}\nThe alerts written before that were indexed; "
            "they may be incomplete."
        )
    warnings.extend(_error_log_warning(report))

    alerts = _parse_hayabusa_csv(csv_text)

    index_result = extract_and_index(
        raw_output=csv_text,
        source_name="hayabusa.alerts",
        source_path=resolved_dir,
        extractor_name="hayabusa",
    )

    severity_counts: Counter[str] = Counter()
    rule_counts: Counter[str] = Counter()
    techniques: set[str] = set()

    for alert in alerts:
        sev = alert.get("Level", "unknown").lower()
        severity_counts[sev] += 1

        rule = alert.get("RuleTitle", "")
        if rule:
            rule_counts[rule] += 1

        mitre = alert.get("MitreAttack", "") or alert.get("MITRE ATT&CK", "")
        if mitre:
            for part in mitre.split(","):
                tid = part.strip()
                if tid:
                    techniques.add(tid)

    top_rules = [{"rule": name, "count": count} for name, count in rule_counts.most_common(10)]

    elapsed = (time.monotonic() - t0) * 1000
    result = {
        "total_alerts": len(alerts),
        "by_severity": dict(severity_counts),
        "top_rules": top_rules,
        "mitre_techniques": sorted(techniques),
        "evtx_dir": resolved_dir,
        "evtx_file_count": len(evtx_files),
        "index": index_result,
        **report.as_result(),
    }
    if warnings:
        result["tool_warning"] = "\n".join(warnings)

    return tool_response(tc_id, tool_name, params, result, "hayabusa.alerts", elapsed)


def _already_indexed_response(
    tc_id: str, params: dict[str, object], evtx_dir: str, image_path: str
) -> dict[str, object] | None:
    """The "skipped" response when this directory's alerts are already indexed.

    ``hayabusa.alerts`` is registered with the *resolved* EVTX directory as
    its source path, so that is what must be compared: keying on the raw
    ``evtx_dir or image_path`` never matched an image path, and with both
    empty the unscoped check skipped the run because of alerts from another
    piece of evidence. Only directories found without extracting anything
    are considered; with none, there is nothing to compare and the tool runs.
    """
    candidates = [
        d
        for d in dict.fromkeys(
            (_resolve_evtx_dir(evtx_dir or None, image_path or None, extract=False), evtx_dir)
        )
        if d
    ]
    existing: list[str] = []
    for directory in candidates:
        for name in sources_already_indexed(["hayabusa."], evidence_path=directory):
            if name not in existing:
                existing.append(name)
    if not existing:
        return None
    return tool_response(
        tc_id,
        "run_hayabusa",
        params,
        {
            "status": "skipped",
            "reason": (
                f"Hayabusa alerts are already indexed for {', '.join(candidates)}. "
                "Pass force=True to scan again (for example with another min_severity)."
            ),
            "existing_sources": existing,
            "evtx_dir": candidates[0],
        },
        "hayabusa.alerts",
        0.0,
    )


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_FILES_RE = re.compile(r"Total event log files:\s*([\d,]+)")
_EVENTS_RE = re.compile(r"Events with hits\s*/\s*Total events:\s*([\d,]+)\s*/\s*([\d,]+)")
_ERROR_LOG_RE = re.compile(r"Errors were generated\. Please check (\S+?) for details")


class _RunReport(NamedTuple):
    """What Hayabusa's own console report says it scanned.

    Hayabusa prints ``Total event log files: N`` before scanning and a
    ``Results Summary:`` with ``Events with hits / Total events: X / Y``
    after it, in colour even when not on a terminal.
    """

    files: int | None
    summary: bool
    events_with_hits: int | None
    total_events: int | None
    error_log: str | None

    @property
    def processed(self) -> bool:
        """Hayabusa reports having scanned at least one event log file."""
        return bool(self.files) and (self.summary or self.total_events is not None)

    def describe(self) -> str:
        if self.files is None:
            return "no 'Total event log files' line"
        if not self.files:
            return "it found 0 event log files"
        return "no 'Results Summary'"

    def as_result(self) -> dict[str, object]:
        out: dict[str, object] = {}
        if self.files is not None:
            out["event_log_files_scanned"] = self.files
        if self.total_events is not None:
            out["events_scanned"] = self.total_events
        return out


def _count(text: str) -> int:
    return int(text.replace(",", ""))


def _parse_run_report(stdout: str) -> _RunReport:
    """Read the processed-file and event counts from Hayabusa's console output."""
    text = _ANSI_RE.sub("", stdout)
    files_match = _FILES_RE.search(text)
    events_match = _EVENTS_RE.search(text)
    log_match = _ERROR_LOG_RE.search(text)
    return _RunReport(
        files=_count(files_match.group(1)) if files_match else None,
        summary="Results Summary" in text,
        events_with_hits=_count(events_match.group(1)) if events_match else None,
        total_events=_count(events_match.group(2)) if events_match else None,
        error_log=log_match.group(1) if log_match else None,
    )


def _tail_message(run: ToolRun) -> str:
    tail = run.tail()
    return f"Tool output (last lines):\n{tail}" if tail else "Hayabusa printed nothing."


def _error_log_warning(report: _RunReport) -> list[str]:
    """Hayabusa writes per-file errors (unreadable EVTX...) to a log it only names."""
    if not report.error_log:
        return []
    log_path = Path(report.error_log)
    if not log_path.is_absolute():
        log_path = Path.cwd() / log_path
    detail = ""
    try:
        lines = [ln for ln in log_path.read_text(errors="replace").splitlines()[1:] if ln.strip()]
        if lines:
            shown = "\n".join(lines[:10])
            more = f"\n... {len(lines) - 10} more" if len(lines) > 10 else ""
            detail = f":\n{shown}{more}"
    except OSError:
        detail = " (the log could not be read)"
    return [
        f"Hayabusa reported errors while scanning (see {log_path}){detail}\n"
        "Files it could not read were not scanned."
    ]


def _parse_hayabusa_csv(csv_text: str) -> list[dict[str, str]]:
    """Parse Hayabusa CSV output into a list of alert dicts."""
    reader = csv.DictReader(io.StringIO(csv_text))
    alerts: list[dict[str, str]] = []
    for row in reader:
        alerts.append(dict(row))
    return alerts
