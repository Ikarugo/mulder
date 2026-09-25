"""Plaso MCP tools for timeline analysis.

Ingest-time tools query pre-extracted Plaso data from the case database.
Query-time tools shell out to ``psort.py`` for ad-hoc filtered queries
against the stored ``.plaso`` file.  All tools are read-only.
"""

from __future__ import annotations

import csv
import logging
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path

from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    ToolRun,
    error_response,
    hash_output,
    make_tool_call_id,
    run_tool,
    windowed_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.plaso import _find_plaso_cmd

logger = logging.getLogger(__name__)

_SRC_PLASO_STATS = "plaso.stats"
_SRC_PLASO_TIMELINE = "plaso.timeline"

_PSORT_TIMEOUT = 300  # 5 minutes for filtered queries
_SLICE_SIZE_MINUTES = 5  # psort --slice_size: minutes either side of the timestamp


def _find_plaso_file() -> str:
    """Locate the persistent ``.plaso`` file from source metadata.

    Checks the ``plaso.stats`` source first (whose ``source_path`` points
    directly at the ``.plaso`` file).  Falls back to the DB-path convention
    ``{db_dir}/{case_id}.plaso``.
    """
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    for s in sources:
        if s.source_name == _SRC_PLASO_STATS:
            path = Path(s.source_path)
            if path.exists():
                return str(path)

    fallback = ctx.db.db_path.with_suffix(".plaso")
    if fallback.exists():
        return str(fallback)

    raise RuntimeError("No .plaso storage file found. Was this case ingested with Plaso?")


def _plaso_error(
    tc_id: str,
    tool_name: str,
    params: Mapping[str, object],
    error: str,
    t0: float,
    error_type: str = "unknown",
) -> dict[str, object]:
    """Build an audited plaso error response with empty results metadata."""
    resp = error_response(
        tc_id, tool_name, params, error, (time.monotonic() - t0) * 1000, error_type=error_type
    )
    resp.update({"results": [], "source": _SRC_PLASO_TIMELINE, "result_count": 0})
    return resp


def _run_psort(
    psort: list[str], plaso_path: str, *options: str, filter_expr: str | None = None
) -> tuple[ToolRun, str | None]:
    """Run psort to an l2tcsv file; return the run and the CSV (None if none was written).

    l2tcsv only writes to a file: without ``-w`` psort prints
    ``ERROR: Output format: l2tcsv requires an output file`` (on stdout) and
    exits 1, and it refuses an output file that already exists, hence the
    fresh directory.
    """
    with tempfile.TemporaryDirectory(prefix="mulder_psort_") as tmpdir:
        csv_file = Path(tmpdir) / "psort.csv"
        cmd = [
            *psort,
            "--status_view",
            "none",
            "-u",
            "-o",
            "l2tcsv",
            "-w",
            str(csv_file),
            *options,
            plaso_path,
        ]
        if filter_expr:
            cmd.append(filter_expr)
        run = run_tool(cmd, timeout=_PSORT_TIMEOUT)
        text = csv_file.read_text(errors="replace").strip() if csv_file.exists() else None
    return run, text


def _psort_failure(run: ToolRun, text: str | None) -> str | None:
    """Why a psort run produced nothing usable, or None when its CSV can be used."""
    if text is None and run.ok:
        tail = run.tail()
        return "psort exited 0 but wrote no output file" + (
            f". Tool output (last lines):\n{tail}" if tail else ""
        )
    if not text and not run.ok:
        return run.describe()
    return None


def _psort_warning(run: ToolRun) -> str | None:
    if run.ok:
        return None
    return (
        f"{run.describe()}\nThe events psort wrote before that were indexed; "
        "they may be incomplete."
    )


def _iso(value: str) -> str:
    """ISO 8601 for plaso: ``T`` between date and time, no quotes."""
    return value.strip().replace(" ", "T", 1).replace("'", "")


def _reduce_or_return(output: str) -> list[dict[str, str | int]]:
    """Return timeline output as a single-item result list."""
    return [{"timeline_text": output, "line_count": output.count("\n") + 1}]


def _resolve_psort_prerequisites(
    tc_id: str, tool_name: str, params: Mapping[str, object], t0: float
) -> tuple[list[str], str] | dict[str, object]:
    """Find psort and locate the .plaso file.

    Returns ``(psort command prefix, plaso file path)``, or an error response.
    """
    psort = _find_plaso_cmd("psort")
    if not psort:
        return _plaso_error(
            tc_id,
            tool_name,
            params,
            "psort not found (tried psort.py, psort, and -m plaso.cli.psort on every "
            "probed Python interpreter)",
            t0,
            error_type="binary_missing",
        )
    try:
        return psort, _find_plaso_file()
    except RuntimeError as exc:
        return _plaso_error(tc_id, tool_name, params, str(exc), t0, error_type="file_not_found")


def _query_response(
    ctx_tc: tuple[str, str, dict[str, object], float],
    run: ToolRun,
    output: str,
    source_name: str,
    plaso_path: str,
    empty_hint: str,
) -> dict[str, object]:
    """Index *output* (if any events) and build the audited response."""
    tc_id, tool_name, params, t0 = ctx_tc
    ctx = get_ctx()
    result_count = 0
    index_summary: dict[str, object] = {}
    if output:
        result_count = len(output.splitlines()) - 1
    if result_count > 0:
        index_summary = extract_and_index(output, source_name, str(plaso_path), "psort")

    elapsed = (time.monotonic() - t0) * 1000
    ctx.audit.log_tool_call(
        tool_call_id=tc_id,
        tool_name=tool_name,
        params=params,
        output_hash=hash_output({"result_count": result_count}),
        duration_ms=elapsed,
    )
    resp: dict[str, object] = {
        "tool_call_id": tc_id,
        "status": "success",
        "source": _SRC_PLASO_TIMELINE,
        "source_name": source_name,
        "result_count": result_count,
        "windows_indexed": index_summary.get("windows_indexed", 0),
        "hint": (
            f"Use search(query, source='{source_name}') or "
            f"get_raw_output('{source_name}') to read timeline events."
            if result_count > 0
            else empty_hint
        ),
    }
    warning = _psort_warning(run)
    if warning:
        resp["status"] = "partial"
        resp["tool_warning"] = warning
    return resp


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR)
def get_plaso_stats() -> dict[str, object]:
    """Return Plaso parser hit statistics collected during ingest.

    Shows which parsers fired and how many events each produced.
    Useful for understanding which artifact types are available in
    the case timeline.  Read-only.
    """
    ctx = get_ctx()
    tc_id = make_tool_call_id()
    t0 = time.monotonic()

    windows = ctx.db.get_windows_by_source(_SRC_PLASO_STATS)
    elapsed = (time.monotonic() - t0) * 1000
    return windowed_response(tc_id, windows, _SRC_PLASO_STATS, "get_plaso_stats", {}, elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR | Role.CROSS_ANALYST)
def filter_timeline(
    t_start: str,
    t_end: str,
    keyword: str | None = None,
    parser: str | None = None,
) -> dict[str, object]:
    """Query the Plaso timeline with time range and optional filters.

    Runs ``psort.py`` against the stored ``.plaso`` file with a date
    filter expression.  Optionally narrow results to a specific
    *parser* (e.g. ``"winevtx"``) or grep for *keyword* in the output.
    Read-only.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "t_start": t_start,
        "t_end": t_end,
        "keyword": keyword,
        "parser": parser,
    }

    prereq = _resolve_psort_prerequisites(tc_id, "filter_timeline", params, t0)
    if isinstance(prereq, dict):
        return prereq
    psort, plaso_path = prereq

    # plaso filters compare the ``timestamp`` attribute with DATETIME(); the
    # legacy ``date > '...'`` form matches nothing in current plaso, and the
    # ``parser`` attribute was removed from event filters in 2023, so the
    # parser is matched on the l2tcsv ``format`` column (the parser chain).
    filter_expr = (
        f"timestamp >= DATETIME('{_iso(t_start)}') AND timestamp <= DATETIME('{_iso(t_end)}')"
    )
    run, text = _run_psort(psort, plaso_path, filter_expr=filter_expr)
    failure = _psort_failure(run, text)
    if failure is not None:
        return _plaso_error(
            tc_id, "filter_timeline", params, failure, t0, error_type=run.error_type
        )

    output = text or ""
    if output and parser:
        output = _apply_parser_filter(output, parser)
    if output and keyword:
        output = _apply_keyword_filter(output, keyword)

    narrowed = ", ".join(
        part
        for part in (f"parser {parser}" if parser else "", f"keyword {keyword}" if keyword else "")
        if part
    )
    return _query_response(
        (tc_id, "filter_timeline", params, t0),
        run,
        output,
        "plaso.filtered",
        plaso_path,
        (
            f"psort ran and the timeline holds no event between {t_start} and {t_end}"
            + (f" matching {narrowed}" if narrowed else "")
            + ": nothing was indexed as 'plaso.filtered'."
        ),
    )


def _apply_keyword_filter(output: str, keyword: str) -> str:
    """Keep only L2T CSV lines containing *keyword* (case-insensitive)."""
    kw_lower = keyword.lower()
    lines = output.splitlines()
    header = lines[0] if lines else ""
    filtered = [ln for ln in lines[1:] if kw_lower in ln.lower()]
    return "\n".join([header, *filtered]) if filtered else ""


def _apply_parser_filter(output: str, parser: str) -> str:
    """Keep only L2T CSV rows whose ``format`` column (parser chain) names *parser*."""
    lines = output.splitlines()
    if not lines:
        return ""
    header = lines[0]
    columns = next(csv.reader([header]), [])
    wanted = parser.lower()
    if "format" not in columns:
        filtered = [ln for ln in lines[1:] if wanted in ln.lower()]
    else:
        idx = columns.index("format")
        filtered = []
        for ln in lines[1:]:
            row = next(csv.reader([ln]), [])
            if len(row) > idx and wanted in row[idx].lower():
                filtered.append(ln)
    return "\n".join([header, *filtered]) if filtered else ""


@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR)
def export_timeline_slice(timestamp: str) -> dict[str, object]:
    """Export a 5-minute timeline slice centred on a timestamp.

    Runs ``psort.py --slice`` to produce a narrow window of events around
    the given *timestamp* (ISO-8601 format, e.g. ``2024-01-15T14:30:00``):
    the events within 5 minutes either side of it.
    Useful for quickly pivoting around a known event of interest.
    Read-only.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"timestamp": timestamp}

    prereq = _resolve_psort_prerequisites(tc_id, "export_timeline_slice", params, t0)
    if isinstance(prereq, dict):
        return prereq
    psort, plaso_path = prereq

    # --slice_size is in minutes (plaso's default is 5): the slice runs from
    # timestamp - size to timestamp + size. psort rejects a space in --slice.
    run, text = _run_psort(
        psort,
        plaso_path,
        "--slice",
        _iso(timestamp),
        "--slice_size",
        str(_SLICE_SIZE_MINUTES),
    )
    failure = _psort_failure(run, text)
    if failure is not None:
        return _plaso_error(
            tc_id, "export_timeline_slice", params, failure, t0, error_type=run.error_type
        )

    return _query_response(
        (tc_id, "export_timeline_slice", params, t0),
        run,
        text or "",
        "plaso.slice",
        plaso_path,
        (
            f"psort ran and the timeline holds no event within {_SLICE_SIZE_MINUTES} minutes "
            f"of {timestamp}: nothing was indexed as 'plaso.slice'."
        ),
    )
