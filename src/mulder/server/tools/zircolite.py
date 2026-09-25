"""Zircolite MCP tool for Linux Sigma detection on Auditd/Sysmon logs."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Literal

from mulder.assets.paths import asset_display_path, asset_path, asset_search_summary
from mulder.server.app import get_ctx, has_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    ToolRun,
    error_response,
    failure_key,
    make_tool_call_id,
    remember_failure,
    repeated_failure_response,
    run_failure_response,
    run_tool,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

__all__ = [
    "run_zircolite",
]

logger = logging.getLogger(__name__)

_ZIRCOLITE_TIMEOUT = 600
_ZIRCOLITE_DIRNAME = "zircolite"
# Case-DB key listing the log formats zircolite.detections was indexed with,
# per evidence path. The source name alone does not say which --auditd /
# --sysmon4linux / --jsononly run produced it.
_FORMATS_KV_PREFIX = "zircolite_formats:"


def _zircolite_script() -> Path | None:
    """The Zircolite entry point, or None if it is not installed."""
    return asset_path(_ZIRCOLITE_DIRNAME, "zircolite.py")


def _default_linux_rules() -> Path:
    """The Linux Sigma rules ``mulder setup`` copies in beside Zircolite."""
    return asset_display_path(_ZIRCOLITE_DIRNAME, "rules", "linux")


# Zircolite 2.20.0's unguarded top-level third-party imports, i.e. the modules
# without which zircolite.py cannot start at all.  Every other import in
# Zircolite (aiohttp, evtx, lxml, requests, elasticsearch, pysigma, yaml,
# jinja2) sits inside a try/except feeding its own ImportErrorHandler and is
# optional.  Inside the container these come from the Dockerfile's pip install;
# under ``pipx install mulder-dfir`` they come from the ``forensics`` extra.
# Keep this list short: a missing entry only weakens the preflight, an extra
# entry blocks a working install.
_ZIRCOLITE_MODULES = ("orjson", "xxhash", "colorama", "tqdm")

_FORMAT_FLAGS: dict[str, list[str]] = {
    "auditd": ["--auditd"],
    "sysmon_linux": ["--sysmon4linux"],
    "json": ["--jsononly"],
    "evtx": [],
}

_LEVEL_ORDER = ["informational", "low", "medium", "high", "critical"]

# How many detections the tool response carries back. The index is not bounded
# by this: every detection is indexed, and the list is truncated only for the
# response, which tool_response reduces to a preview anyway.
_MAX_RESPONSE_DETECTIONS = 500

# Field order for the indexed lines. Timestamp first, so the per-window
# timestamp extraction in extract_and_index picks up the detection's own time
# rather than the first timestamp that happens to appear in the window.
_DETECTION_FIELDS = (
    "timestamp",
    "rule_level",
    "rule_title",
    "rule_id",
    "count",
    "mitre_attack",
    "rule_description",
    "matched_fields",
)

# matched_fields carries the whole matched event. Long enough to keep the
# fields an analyst searches for (process image, command line, user), short
# enough that one detection cannot fill a 4096-character index window.
_FIELD_CHARS = 2000


def _detection_field(value: object) -> str:
    """Render one detection field as a single-line, bounded string."""
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    elif isinstance(value, bool | int | float):
        text = str(value)
    else:
        text = json.dumps(value, default=str, separators=(",", ":"), sort_keys=True)
    return text.replace("\t", " ").replace("\r", " ").replace("\n", " ")[:_FIELD_CHARS]


def _detection_lines(detections: list[dict[str, Any]]) -> list[str]:
    """Render detections as one tab-separated line each, for indexing.

    ``extract_and_index`` stores exactly the text it is handed, so handing it a
    count stored a count. One line per detection matters twice over: the window
    builder splits on line boundaries, so no detection is cut in half, and
    timestamp extraction runs per window rather than finding a single timestamp
    for a whole summary.
    """
    return [
        "\t".join(_detection_field(d.get(name)) for name in _DETECTION_FIELDS) for d in detections
    ]


def _missing_zircolite_modules() -> list[str]:
    """Return Zircolite dependencies not importable from mulder's interpreter."""
    return [m for m in _ZIRCOLITE_MODULES if importlib.util.find_spec(m) is None]


def _indexed_formats(events_path: str) -> set[str]:
    """Log formats a previous run on *events_path* was indexed with."""
    if not has_ctx():
        return set()
    try:
        value = get_ctx().db.get_kv(_FORMATS_KV_PREFIX + events_path)
        formats = json.loads(value) if value else []
    except Exception:  # noqa: BLE001 - unknown means "not known to be indexed"
        return set()
    return {str(f) for f in formats} if isinstance(formats, list) else set()


def _remember_indexed_format(events_path: str, log_format: str) -> None:
    """Record that *events_path* was indexed with *log_format*."""
    if not has_ctx():
        return
    formats = sorted(_indexed_formats(events_path) | {log_format})
    try:
        get_ctx().db.set_kv(_FORMATS_KV_PREFIX + events_path, json.dumps(formats))
    except Exception:  # noqa: BLE001 - best effort, only affects the skip
        return


def _run_zircolite_process(
    script: str,
    events_path: Path,
    log_format: str,
    ruleset_path: Path,
    output_dir: Path,
) -> tuple[Path, ToolRun]:
    """Execute Zircolite against event logs.

    Args:
        script: Resolved path to ``zircolite.py``.
        events_path: Path to input log file(s).
        log_format: Log format identifier.
        ruleset_path: Path to the Sigma ruleset directory.
        output_dir: Output directory for results.

    Returns:
        Tuple of (path to the JSON results file, the run). The caller needs
        the run to tell a genuinely empty ruleset match from a Zircolite run
        that never produced results.
    """
    output_file = output_dir / "zircolite_results.json"
    format_flags = _FORMAT_FLAGS.get(log_format, [])

    cmd = [
        sys.executable,
        script,
        "--events",
        str(events_path),
        "--ruleset",
        str(ruleset_path),
        "--outfile",
        str(output_file),
        *format_flags,
    ]

    return output_file, run_tool(cmd, timeout=_ZIRCOLITE_TIMEOUT)


def _build_detection_timeline(
    detections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build a chronological timeline from detections.

    Args:
        detections: List of detection dicts with timestamps.

    Returns:
        Sorted list of timeline entries.
    """
    timeline: list[dict[str, Any]] = []
    for d in detections:
        ts = d.get("timestamp", "")
        if ts:
            timeline.append(
                {
                    "timestamp": ts,
                    "rule_title": d.get("rule_title", ""),
                    "rule_level": d.get("rule_level", ""),
                }
            )
    return sorted(timeline, key=lambda x: x.get("timestamp", ""))


def _parse_zircolite_output(
    results_path: Path,
    events_path: str,
    log_format: str,
    level_filter: str | None = None,
) -> dict[str, Any]:
    """Parse Zircolite JSON output into structured results.

    Args:
        results_path: Path to the Zircolite JSON output file.
        events_path: Original events path for reference.
        log_format: Log format used.
        level_filter: Minimum level to include.

    Returns:
        Dict with filtered and structured detections.
    """
    if not results_path.exists():
        return {
            "events_path": events_path,
            "log_format": log_format,
            "detections": [],
            "total_detections": 0,
            "total_events_processed": None,
            "total_matches_all_levels": 0,
            "level_counts": {},
            "mitre_coverage": {},
            "timeline": [],
        }

    try:
        raw_results = json.loads(results_path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError) as exc:
        # Not "0 detections": the results could not be read at all. The
        # caller turns this into an error instead of indexing an empty scan.
        return {
            "events_path": events_path,
            "log_format": log_format,
            "detections": [],
            "total_detections": 0,
            "total_events_processed": None,
            "total_matches_all_levels": 0,
            "level_counts": {},
            "mitre_coverage": {},
            "timeline": [],
            "parse_error": f"{type(exc).__name__}: {exc}",
        }

    if not isinstance(raw_results, list):
        raw_results = [raw_results] if raw_results else []

    min_idx = (
        _LEVEL_ORDER.index(level_filter) if level_filter and level_filter in _LEVEL_ORDER else 0
    )

    detections: list[dict[str, Any]] = []
    level_counts: dict[str, int] = {}
    mitre_coverage: dict[str, list[str]] = {}

    for entry in raw_results:
        level = entry.get("rule_level", "informational")
        level_counts[level] = level_counts.get(level, 0) + 1

        level_idx = _LEVEL_ORDER.index(level) if level in _LEVEL_ORDER else 0
        if level_idx < min_idx:
            continue

        mitre_refs = entry.get("rule_mitre", [])
        if isinstance(mitre_refs, list):
            for ref in mitre_refs:
                if isinstance(ref, dict):
                    tactic = ref.get("tactic", "unknown")
                    technique = ref.get("technique", "")
                    if tactic not in mitre_coverage:
                        mitre_coverage[tactic] = []
                    if technique and technique not in mitre_coverage[tactic]:
                        mitre_coverage[tactic].append(technique)

        mitre_attack: list[str] = []
        if isinstance(mitre_refs, list):
            for r in mitre_refs:
                if isinstance(r, dict):
                    mitre_attack.append(f"{r.get('technique', '')} ({r.get('tactic', '')})")

        detections.append(
            {
                "timestamp": entry.get("timestamp", ""),
                "rule_title": entry.get("rule_title", ""),
                "rule_id": entry.get("rule_id", ""),
                "rule_level": level,
                "rule_description": entry.get("rule_description", ""),
                "mitre_attack": mitre_attack,
                "matched_fields": entry.get("matched_fields", {}),
                "count": entry.get("count", 1),
            }
        )

    timeline = _build_detection_timeline(detections)

    return {
        "events_path": events_path,
        "log_format": log_format,
        # Not truncated here: run_zircolite indexes every detection before
        # bounding the list for the response.
        "detections": detections,
        "total_detections": len(detections),
        # Zircolite's JSON holds rule matches only; the number of events it
        # read is not in it. This used to hold the match count under an
        # "events processed" label.
        "total_events_processed": None,
        "total_matches_all_levels": sum(level_counts.values()),
        "level_counts": level_counts,
        "mitre_coverage": mitre_coverage,
        "timeline": timeline[:200],
    }


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_zircolite(
    events_path: str,
    log_format: Literal["auditd", "sysmon_linux", "json", "evtx"] = "auditd",
    ruleset_path: str | None = None,
    sigma_level_filter: Literal["informational", "low", "medium", "high", "critical"]
    | None = "medium",
    force: bool = False,
) -> dict[str, object]:
    """Apply Sigma detection rules to Linux logs using Zircolite.

    Evaluates Sigma rules against Auditd, Sysmon for Linux, or
    JSON-formatted event logs. Fills the Linux detection gap that
    Windows-only tools (Hayabusa, Chainsaw) cannot address.

    Args:
        events_path: Path to the log file or directory of log files
            to analyze.
        log_format: Format of the input logs. "auditd" for Linux
            Audit daemon logs, "sysmon_linux" for Sysmon for Linux
            JSON output, "json" for generic JSON event streams,
            "evtx" for Windows EVTX (fallback use case).
        ruleset_path: Path to a custom ruleset directory. If None,
            uses the Linux Sigma rules installed alongside Zircolite by
            'mulder setup'.
        sigma_level_filter: Minimum Sigma rule level to include in
            results. Rules below this level are excluded. Set None
            to include all levels.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "events_path": events_path,
        "log_format": log_format,
        "ruleset_path": ruleset_path,
        "sigma_level_filter": sigma_level_filter,
        "force": force,
    }

    previous_formats: set[str] = set()
    if not force:
        existing = sources_already_indexed(["zircolite."], evidence_path=events_path)
        previous_formats = _indexed_formats(events_path) if existing else set()
        # Only a run with the same log_format is a repeat: a run with the
        # wrong format (the default is auditd) must not block the right one.
        if existing and log_format in previous_formats:
            return tool_response(
                tc_id,
                "run_zircolite",
                params,
                {
                    "status": "skipped",
                    "reason": (
                        f"Zircolite already ran on this evidence with log_format={log_format}. "
                        "Pass force=True to run it again (e.g. with another ruleset or level)."
                    ),
                    "existing_sources": existing,
                    "indexed_log_formats": sorted(previous_formats),
                },
                "zircolite",
                0.0,
            )

    missing = _missing_zircolite_modules()
    if missing:
        return error_response(
            tc_id,
            "run_zircolite",
            params,
            f"Zircolite dependencies not importable: {', '.join(missing)}",
            error_type="binary_missing",
            suggestion=(
                "Install the forensics extra: pipx install 'mulder-dfir[forensics]' "
                "(or: pipx inject mulder-dfir " + " ".join(missing) + ")"
            ),
        )

    script = _zircolite_script()
    if script is None:
        return error_response(
            tc_id,
            "run_zircolite",
            params,
            "Zircolite script not found under any of: "
            f"{asset_search_summary(_ZIRCOLITE_DIRNAME, 'zircolite.py')}",
            error_type="binary_missing",
            suggestion="Run 'mulder setup' (installs Zircolite 2.20.0 and its Linux Sigma rules).",
        )

    if not Path(events_path).exists():
        return error_response(
            tc_id,
            "run_zircolite",
            params,
            f"Path not found: {events_path}",
            error_type="file_not_found",
        )

    effective_ruleset = Path(ruleset_path) if ruleset_path else _default_linux_rules()
    if not effective_ruleset.exists():
        return error_response(
            tc_id,
            "run_zircolite",
            params,
            f"Ruleset path not found: {effective_ruleset}",
            error_type="file_not_found",
        )

    if log_format not in _FORMAT_FLAGS:
        return error_response(
            tc_id,
            "run_zircolite",
            params,
            f"Invalid log_format: {log_format}. Valid: {list(_FORMAT_FLAGS.keys())}",
            error_type="invalid_argument",
        )

    memory_key = failure_key("run_zircolite", events_path, log_format, str(effective_ruleset))
    if (
        repeated := repeated_failure_response(tc_id, "run_zircolite", params, memory_key, t0)
    ) is not None:
        return repeated

    with tempfile.TemporaryDirectory(prefix="mulder_zircolite_") as tmpdir:
        output_dir = Path(tmpdir)
        results_path, run = _run_zircolite_process(
            str(script),
            Path(events_path),
            log_format,
            effective_ruleset,
            output_dir,
        )

        if not run.ok and not results_path.exists():
            return run_failure_response(
                tc_id,
                "run_zircolite",
                params,
                run,
                t0,
                memory_key=memory_key,
                context="Zircolite wrote no results file",
                suggestion=(
                    "Check that log_format matches the log (auditd, sysmon_linux, json, evtx) "
                    "and that the ruleset loads."
                ),
            )

        result = _parse_zircolite_output(results_path, events_path, log_format, sigma_level_filter)
        if parse_error := result.get("parse_error"):
            # An unreadable results file is not "0 detections".
            message = f"Zircolite's results file could not be parsed ({parse_error})"
            if not run.ok:
                message += f"; {run.describe()}"
            remember_failure(memory_key, message)
            return error_response(
                tc_id,
                "run_zircolite",
                params,
                message,
                (time.monotonic() - t0) * 1000,
                error_type="tool_failed",
                suggestion="Check log_format and the ruleset; pass force=True to retry.",
            )

        text_parts = [
            f"Zircolite {log_format} analysis of {events_path}",
            f"Total detections: {result['total_detections']}",
            f"Rule matches before level filter: {result['total_matches_all_levels']}",
        ]
        for level, count in result.get("level_counts", {}).items():
            text_parts.append(f"  {level}: {count}")
        if result.get("mitre_coverage"):
            text_parts.append("MITRE coverage:")
            for tactic, techniques in result["mitre_coverage"].items():
                text_parts.append(f"  {tactic}: {', '.join(techniques[:5])}")

        # Index the detections themselves, not just how many there were: the
        # source is called "zircolite.detections", so a search over the case
        # must be able to find a rule title, a MITRE technique or a matched
        # field, none of which the header lines above contain.
        detections: list[dict[str, Any]] = result["detections"]
        text_parts.extend(_detection_lines(detections))

        summary = extract_and_index(
            "\n".join(text_parts), "zircolite.detections", events_path, "zircolite"
        )

        _remember_indexed_format(events_path, log_format)

        # The index holds every detection; the response stays bounded.
        result["detections"] = detections[:_MAX_RESPONSE_DETECTIONS]
        summary.update(result)
        if previous_formats:
            summary["previous_log_formats"] = sorted(previous_formats)
        if not run.ok:
            summary["tool_warning"] = (
                f"{run.describe()}\nThe detections written before that were indexed; they may "
                "be incomplete."
            )

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_zircolite", params, summary, "zircolite.detections", elapsed)
