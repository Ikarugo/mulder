"""MVT MCP tools for mobile spyware detection.

Wraps the Mobile Verification Toolkit (MVT) from Amnesty International
to detect traces of known spyware (Pegasus, Predator, etc.) on Android
and iOS devices.  Supports backup analysis and filesystem dump analysis
with optional STIX2 IOC matching.
"""

from __future__ import annotations

import contextlib
import json
import logging
import shutil
import tempfile
import time
from pathlib import Path

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    ToolRun,
    error_response,
    make_tool_call_id,
    run_failure_response,
    run_tool,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

logger = logging.getLogger(__name__)

_MVT_TIMEOUT = 600


def _iocs_error(
    tc_id: str, tool_name: str, params: dict[str, object], iocs: str
) -> dict[str, object] | None:
    """An error when *iocs* names a file that does not exist.

    The flag used to be dropped silently while the response still echoed
    ``iocs_file``: a scan with no indicators loaded then read as "checked
    against these IOCs, nothing matched".
    """
    if not iocs or Path(iocs).is_file():
        return None
    return error_response(
        tc_id,
        tool_name,
        params,
        f"IOC file not found: {iocs}. The scan was not run, so no indicator was checked.",
        error_type="file_not_found",
        suggestion="Pass the path of an existing STIX2 file, or iocs='' to scan without IOCs.",
    )


def _partial_warning(run: ToolRun) -> str | None:
    """For a run that exited non-zero after MVT wrote some module results."""
    if run.ok:
        return None
    return (
        f"{run.describe()}\nThe module results written before that were indexed; modules "
        "that did not run are missing, so absence of detections is not conclusive."
    )


def _collect_mvt_results(output_dir: str) -> tuple[str, dict[str, int]]:
    """Read JSON result files from MVT output and return combined text + counts."""
    parts: list[str] = []
    module_counts: dict[str, int] = {}

    for result_file in sorted(Path(output_dir).rglob("*.json")):
        if not result_file.is_file() or result_file.stat().st_size == 0:
            continue
        with contextlib.suppress(OSError, json.JSONDecodeError):
            data = json.loads(result_file.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, list):
                module_counts[result_file.stem] = len(data)
                # Every counted record must reach the index: module_counts is
                # reported to the analyst as the number of findings, so any
                # record dropped here becomes a detection that is claimed but
                # cannot be found by search().
                parts.extend(json.dumps(item, default=str) for item in data)
            elif isinstance(data, dict):
                module_counts[result_file.stem] = 1
                parts.append(json.dumps(data, default=str))

    for timeline_file in sorted(Path(output_dir).rglob("*.csv")):
        if not timeline_file.is_file() or timeline_file.stat().st_size == 0:
            continue
        with contextlib.suppress(OSError):
            text = timeline_file.read_text(encoding="utf-8", errors="replace")
            parts.append(f"=== {timeline_file.name} ===\n{text}")

    return "\n".join(parts), module_counts


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_mvt_android(
    evidence_path: str,
    iocs: str = "",
) -> dict[str, object]:
    """Scan Android device backup for spyware indicators using MVT.

    Mobile Verification Toolkit detects traces of known spyware
    (Pegasus, Predator, etc.) on mobile devices.  Supports Android
    backup directories and bugreport files.

    Args:
        evidence_path: Path to Android backup directory or bugreport.
        iocs: Path to STIX2 IOC file for indicator matching (optional).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"evidence_path": evidence_path, "iocs": iocs}
    tool_name = "run_mvt_android"

    if not shutil.which("mvt-android"):
        return error_response(
            tc_id,
            tool_name,
            params,
            "mvt-android not found on PATH. Install with: pip install mvt",
            error_type="binary_missing",
        )

    if not Path(evidence_path).exists():
        return error_response(
            tc_id,
            tool_name,
            params,
            f"Evidence path not found: {evidence_path}",
            error_type="file_not_found",
        )

    if (iocs_error := _iocs_error(tc_id, tool_name, params, iocs)) is not None:
        return iocs_error

    with tempfile.TemporaryDirectory(prefix="mulder_mvt_android_") as tmpdir:
        if Path(evidence_path).is_dir():
            cmd = ["mvt-android", "check-backup", "-o", tmpdir, evidence_path]
        else:
            cmd = ["mvt-android", "check-bugreport", "-o", tmpdir, evidence_path]

        if iocs:
            cmd.extend(["--iocs", iocs])

        run = run_tool(cmd, timeout=_MVT_TIMEOUT)

        raw_output, module_counts = _collect_mvt_results(tmpdir)

        if not raw_output.strip():
            if not run.ok:
                # MVT wrote no JSON: what it printed is its own error, not
                # device evidence, and a scan that never ran is not clean.
                return run_failure_response(
                    tc_id, tool_name, params, run, t0, context="mvt-android produced no results"
                )
            raw_output = run.stdout.strip() or run.stderr.strip()

    warning = _partial_warning(run)
    index_result = extract_and_index(
        raw_output,
        "mvt.android",
        evidence_path,
        "mvt",
    )

    detections = sum(
        c
        for name, c in module_counts.items()
        if "detected" in name.lower() or "warning" in name.lower()
    )

    elapsed = (time.monotonic() - t0) * 1000
    result: dict[str, object] = {
        "evidence_path": evidence_path,
        "modules_run": list(module_counts.keys()),
        "module_counts": module_counts,
        "total_indicators": sum(module_counts.values()),
        "detections": detections,
        "iocs_file": iocs or None,
        "index": index_result,
    }
    if warning is not None:
        result["tool_warning"] = warning

    return tool_response(tc_id, tool_name, params, result, "mvt.android", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_mvt_ios(
    evidence_path: str,
    iocs: str = "",
    mode: str = "backup",
) -> dict[str, object]:
    """Scan iOS backup or filesystem dump for spyware indicators using MVT.

    Supports both iTunes/Finder backup directories and full filesystem
    dumps from jailbroken or acquired devices.

    Args:
        evidence_path: Path to iOS backup directory or filesystem dump.
        iocs: Path to STIX2 IOC file for indicator matching (optional).
        mode: Analysis mode, either "backup" (default) or "fs" (filesystem dump).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "evidence_path": evidence_path,
        "iocs": iocs,
        "mode": mode,
    }
    tool_name = "run_mvt_ios"

    if not shutil.which("mvt-ios"):
        return error_response(
            tc_id,
            tool_name,
            params,
            "mvt-ios not found on PATH. Install with: pip install mvt",
            error_type="binary_missing",
        )

    if not Path(evidence_path).exists():
        return error_response(
            tc_id,
            tool_name,
            params,
            f"Evidence path not found: {evidence_path}",
            error_type="file_not_found",
        )

    if (iocs_error := _iocs_error(tc_id, tool_name, params, iocs)) is not None:
        return iocs_error

    with tempfile.TemporaryDirectory(prefix="mulder_mvt_ios_") as tmpdir:
        subcommand = "check-fs" if mode == "fs" else "check-backup"
        cmd = ["mvt-ios", subcommand, "-o", tmpdir, evidence_path]

        if iocs:
            cmd.extend(["--iocs", iocs])

        run = run_tool(cmd, timeout=_MVT_TIMEOUT)

        raw_output, module_counts = _collect_mvt_results(tmpdir)

        if not raw_output.strip():
            if not run.ok:
                # MVT wrote no JSON: what it printed is its own error, not
                # device evidence, and a scan that never ran is not clean.
                return run_failure_response(
                    tc_id, tool_name, params, run, t0, context="mvt-ios produced no results"
                )
            raw_output = run.stdout.strip() or run.stderr.strip()

    warning = _partial_warning(run)
    index_result = extract_and_index(
        raw_output,
        "mvt.ios",
        evidence_path,
        "mvt",
    )

    detections = sum(
        c
        for name, c in module_counts.items()
        if "detected" in name.lower() or "warning" in name.lower()
    )

    elapsed = (time.monotonic() - t0) * 1000
    result: dict[str, object] = {
        "evidence_path": evidence_path,
        "mode": mode,
        "modules_run": list(module_counts.keys()),
        "module_counts": module_counts,
        "total_indicators": sum(module_counts.values()),
        "detections": detections,
        "iocs_file": iocs or None,
        "index": index_result,
    }
    if warning is not None:
        result["tool_warning"] = warning

    return tool_response(tc_id, tool_name, params, result, "mvt.ios", elapsed)
