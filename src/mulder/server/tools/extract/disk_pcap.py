"""Disk-embedded PCAP discovery and analysis MCP tool.

Discovers packet capture files stored within disk images, extracts
them via TSK icat, and runs tshark protocol analysis with optional
credential extraction for cleartext protocols.
"""

from __future__ import annotations

import logging
import tempfile
import time
from pathlib import Path
from typing import Any

from mulder.patterns import fls_file_entries
from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    ToolRun,
    error_response,
    make_tool_call_id,
    require_binary,
    run_tool,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.tsk import (
    _collect_fls_chunks,
    _triage_redirect,
    icat_file,
)

__all__ = ["analyze_disk_pcaps"]

logger = logging.getLogger(__name__)

_PCAP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".cap",
        ".pcap",
        ".pcapng",
        ".eth",
        ".snoop",
    }
)

_ICAT_TIMEOUT = 60
_TSHARK_TIMEOUT = 120
_CREDENTIAL_TIMEOUT = 30


_CREDENTIAL_FILTERS: dict[str, str] = {
    "ftp_credentials": "ftp.request.command == USER || ftp.request.command == PASS",
    "http_basic_auth": 'http.authorization contains "Basic"',
    "smtp_auth": "smtp.req.command == AUTH",
    "telnet_data": "telnet.data",
    "pop3_credentials": "pop.request.command == USER || pop.request.command == PASS",
    "imap_login": 'imap.request contains "LOGIN"',
}


def _discover_pcap_files(
    fls_chunks: list[str],
    offset: int,
) -> list[tuple[str, str, int]]:
    """Search TSK file listing for packet capture files.

    Scans fls output for files with recognized PCAP extensions,
    returning their inodes, paths, and partition offsets.

    Args:
        fls_chunks: Text chunks from the TSK file listing.
        offset: Partition sector offset for icat extraction.

    Returns:
        List of (inode_str, relative_path, partition_offset) tuples.
    """
    matches: list[tuple[str, str, int]] = []
    seen: set[str] = set()

    for chunk in fls_chunks:
        for entry in fls_file_entries(chunk):
            rel_path = entry.path
            dot = rel_path.rfind(".")
            if dot < 0 or rel_path[dot:].lower() not in _PCAP_EXTENSIONS:
                continue
            inode_str = entry.base_inode

            dedup_key = f"{offset}:{inode_str}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            matches.append((inode_str, rel_path, offset))

    return matches


def _extract_pcap_via_icat(
    image_path: str,
    inode_str: str,
    offset: int,
    dest_path: Path,
) -> bool:
    """Extract a PCAP file from a disk image via icat.

    Args:
        image_path: Path to the disk image.
        inode_str: TSK inode identifier for the PCAP file.
        offset: Partition sector offset.
        dest_path: Destination path for the extracted file.

    Returns:
        True if extraction succeeded with non-empty output.
    """
    ok, reason = icat_file(image_path, offset, inode_str, dest_path, timeout=_ICAT_TIMEOUT)
    if reason is not None:
        logger.warning("icat extraction failed for inode %s: %s", inode_str, reason)
    return ok


def _run_tshark_summary(pcap_path: Path, errors: list[dict[str, str]] | None = None) -> str:
    """Run tshark protocol hierarchy and conversation summary.

    Args:
        pcap_path: Path to the extracted PCAP file.
        errors: Receives one ``{"step", "error"}`` entry per tshark run that
            failed or stopped early. Failures are not part of the returned
            text: that text is indexed as the capture's content.

    Returns:
        Combined tshark output text (empty when every run failed).
    """
    parts: list[str] = []

    for args, label in [
        (["-q", "-z", "io,phs"], "Protocol Hierarchy"),
        (["-q", "-z", "conv,ip"], "IP Conversations"),
        (["-q", "-z", "dns,tree"], "DNS Summary"),
    ]:
        run = run_tool(["tshark", "-r", str(pcap_path), *args], timeout=_TSHARK_TIMEOUT)
        if run.failed:
            if errors is not None:
                errors.append({"step": f"tshark {label}", "error": run.describe()})
            continue
        if not run.ok and errors is not None:
            errors.append({"step": f"tshark {label}", "error": _incomplete(run)})
        parts.append(f"=== {label} ===\n{run.stdout.strip()}")

    return "\n\n".join(parts)


def _incomplete(run: ToolRun) -> str:
    """Message for a run that stopped early after writing output that was kept."""
    return f"{run.describe()}\nThe output written before that was kept; it may be incomplete."


def _extract_credentials(
    pcap_path: Path, errors: list[dict[str, str]] | None = None
) -> list[dict[str, str]]:
    """Extract cleartext credentials from a PCAP using tshark filters.

    Runs targeted tshark display filters against the PCAP to identify
    FTP, HTTP Basic Auth, SMTP AUTH, Telnet, POP3, and IMAP login
    credentials transmitted in cleartext.

    Args:
        pcap_path: Path to the PCAP file.
        errors: Receives one ``{"step", "error"}`` entry per filter whose
            tshark run failed or stopped early, so that "0 credentials" is
            not reported for a protocol that was never searched.

    Returns:
        List of dicts with keys: protocol, raw_data, source_ip,
        dest_ip, timestamp.
    """
    credentials: list[dict[str, str]] = []

    for protocol, display_filter in _CREDENTIAL_FILTERS.items():
        cmd = [
            "tshark",
            "-r",
            str(pcap_path),
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-e",
            "frame.time",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "text",
        ]
        run = run_tool(cmd, timeout=_CREDENTIAL_TIMEOUT)
        if run.failed:
            if errors is not None:
                errors.append({"step": f"credentials:{protocol}", "error": run.describe()})
            continue
        if not run.ok and errors is not None:
            errors.append({"step": f"credentials:{protocol}", "error": _incomplete(run)})

        for line in run.stdout.strip().splitlines():
            fields = line.split("\t")
            credentials.append(
                {
                    "protocol": protocol,
                    "timestamp": fields[0] if len(fields) > 0 else "",
                    "source_ip": fields[1] if len(fields) > 1 else "",
                    "dest_ip": fields[2] if len(fields) > 2 else "",
                    "raw_data": fields[3] if len(fields) > 3 else "",
                }
            )

    return credentials


def _analyze_single_pcap(
    pcap_path: Path,
    filename: str,
    case_id: str,
    run_ids: bool,
    extract_credentials: bool,
    image_path: str,
) -> dict[str, Any]:
    """Run analysis tools against a single extracted PCAP file.

    Executes tshark protocol analysis, optionally Suricata IDS, and
    optionally credential extraction against the given PCAP.

    Args:
        pcap_path: Path to the extracted PCAP file on disk.
        filename: Original filename from the disk image (for labeling).
        case_id: Active case identifier.
        run_ids: Whether to run Suricata analysis.
        extract_credentials: Whether to run credential extraction.
        image_path: Path to the source disk image (for indexing).

    Returns:
        Dict with protocol_summary, ids_alerts (if requested),
        credentials (if requested), file metadata, and ``errors`` (one
        entry per tool run that failed or stopped early) when any.
    """
    source_name = f"pcap.disk.{Path(filename).stem}"
    result: dict[str, Any] = {
        "filename": filename,
        "source_name": source_name,
        "file_size_bytes": pcap_path.stat().st_size,
    }
    errors: list[dict[str, str]] = []

    protocol_output = _run_tshark_summary(pcap_path, errors)
    if protocol_output:
        index_summary = extract_and_index(protocol_output, source_name, image_path, "tshark")
        result["protocol_summary"] = index_summary
    elif errors:
        # Nothing indexed: tshark could not read this capture.
        result["protocol_summary"] = {"status": "error", "errors": list(errors)}
    else:
        result["protocol_summary"] = {"status": "no_output"}

    from mulder.server.tools.extract.pcap import (
        _parse_eve_json,
        _run_suricata_process,
        _suricata_binary,
        _suricata_failure,
        _suricata_rules_warning,
    )

    # Gate on the resolved value and exec that same value: gating on
    # require_binary and then exec'ing /usr/bin/suricata reports
    # "[Errno 2]" on any host that installs it anywhere else.
    suricata_bin = _suricata_binary() if run_ids else None
    if suricata_bin is not None:
        with tempfile.TemporaryDirectory(prefix="mulder_suri_disk_") as suri_dir:
            eve_path, run = _run_suricata_process(suricata_bin, pcap_path, Path(suri_dir))
            failure = _suricata_failure(eve_path, run)
            if failure is not None:
                result["ids_alerts"] = {"error": failure}
                errors.append({"step": "suricata", "error": failure})
            else:
                ids_result = _parse_eve_json(eve_path)
                result["ids_alerts"] = {
                    "total_alerts": ids_result["statistics"]["total_alerts"],
                    "top_signatures": ids_result["statistics"]["top_signatures"][:5],
                }
                if not run.ok:
                    result["ids_alerts"]["warning"] = _incomplete(run)
                    errors.append({"step": "suricata", "error": _incomplete(run)})
                rules_warning = _suricata_rules_warning(run, Path(suri_dir))
                if rules_warning is not None:
                    result["ids_alerts"]["warning"] = rules_warning
                    errors.append({"step": "suricata", "error": rules_warning})
    elif run_ids:
        result["ids_alerts"] = {"skipped": "suricata not available"}

    if extract_credentials:
        cred_errors: list[dict[str, str]] = []
        creds = _extract_credentials(pcap_path, cred_errors)
        result["credentials"] = creds
        if cred_errors:
            result["credential_errors"] = cred_errors
            errors.extend(cred_errors)

    if errors:
        result["errors"] = errors
    return result


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def analyze_disk_pcaps(
    case_id: str,
    image_path: str,
    max_pcap_size_mb: int = 100,
    run_ids: bool = True,
    extract_credentials: bool = True,
) -> dict[str, Any]:
    """Discover and analyze packet captures stored on a disk image.

    Searches the TSK file listing for PCAP files (.cap, .pcap,
    .pcapng, .eth, .snoop), extracts them via icat, and runs
    tshark protocol analysis against each. Optionally runs Suricata
    IDS rules and extracts cleartext credentials from captured traffic.

    Args:
        case_id: Active case identifier.
        image_path: Path to the disk image containing PCAP files.
        max_pcap_size_mb: Skip PCAPs larger than this threshold to
            avoid excessive processing time. Defaults to 100 MB.
        run_ids: Whether to run Suricata IDS analysis on discovered
            PCAPs. Defaults to True.
        extract_credentials: Whether to extract cleartext credentials
            (FTP, HTTP Basic, SMTP, Telnet) from captured traffic.
            Defaults to True.

    Returns:
        Dict containing count of PCAPs discovered and analyzed, per-file
        analysis summaries, any IDS alerts, and extracted credentials.
    """
    tc_id = make_tool_call_id()
    redirect = _triage_redirect(
        tc_id,
        "analyze_disk_pcaps",
        {"image_path": image_path},
        image_path,
        "PCAP files in a triage collection are catalogued as network captures; "
        "run run_pcap_analysis on them directly.",
    )
    if redirect is not None:
        return redirect
    t0 = time.monotonic()
    params: dict[str, Any] = {
        "case_id": case_id,
        "image_path": image_path,
        "max_pcap_size_mb": max_pcap_size_mb,
        "run_ids": run_ids,
        "extract_credentials": extract_credentials,
    }

    ctx = get_ctx()
    _ = ctx.case_id

    if not require_binary("tshark"):
        return error_response(
            tc_id,
            "analyze_disk_pcaps",
            params,
            "tshark not found on PATH",
            error_type="binary_missing",
            suggestion="Install tshark: apt-get install tshark",
        )

    if not require_binary("icat"):
        return error_response(
            tc_id,
            "analyze_disk_pcaps",
            params,
            "icat not found on PATH (SleuthKit required)",
            error_type="binary_missing",
            suggestion="Install SleuthKit: apt-get install sleuthkit",
        )

    chunk_groups = _collect_fls_chunks(image_path)
    if not chunk_groups:
        return error_response(
            tc_id,
            "analyze_disk_pcaps",
            params,
            "No TSK file listing available. Run run_fls on this image first.",
            error_type="no_filelist",
        )

    all_pcaps: list[tuple[str, str, int]] = []
    for chunks, offset in chunk_groups:
        discovered = _discover_pcap_files(chunks, offset)
        all_pcaps.extend(discovered)

    if not all_pcaps:
        elapsed = (time.monotonic() - t0) * 1000
        return tool_response(
            tc_id,
            "analyze_disk_pcaps",
            params,
            {
                "pcaps_discovered": 0,
                "pcaps_analyzed": 0,
                "message": "No packet capture files found in the TSK file listing.",
            },
            source=None,
            elapsed_ms=elapsed,
        )

    max_size_bytes = max_pcap_size_mb * 1024 * 1024
    pcaps_analyzed: list[dict[str, Any]] = []
    pcaps_skipped_size: list[str] = []
    pcaps_failed: list[dict[str, str]] = []
    all_credentials: list[dict[str, str]] = []

    with tempfile.TemporaryDirectory(prefix="mulder_disk_pcap_") as tmpdir:
        tmp_path = Path(tmpdir)

        for inode_str, rel_path, offset in all_pcaps:
            safe_name = rel_path.replace("/", "_").replace("\\", "_")
            dest = tmp_path / safe_name

            if not _extract_pcap_via_icat(image_path, inode_str, offset, dest):
                pcaps_failed.append(
                    {
                        "filename": rel_path,
                        "reason": "icat extraction failed",
                    }
                )
                continue

            file_size = dest.stat().st_size
            if file_size > max_size_bytes:
                pcaps_skipped_size.append(rel_path)
                logger.info(
                    "Skipping oversized PCAP %s (%d MB > %d MB limit)",
                    rel_path,
                    file_size // (1024 * 1024),
                    max_pcap_size_mb,
                )
                continue

            if file_size == 0:
                pcaps_failed.append(
                    {
                        "filename": rel_path,
                        "reason": "empty file",
                    }
                )
                continue

            try:
                analysis = _analyze_single_pcap(
                    pcap_path=dest,
                    filename=rel_path,
                    case_id=case_id,
                    run_ids=run_ids,
                    extract_credentials=extract_credentials,
                    image_path=image_path,
                )
                pcaps_analyzed.append(analysis)

                if extract_credentials and analysis.get("credentials"):
                    all_credentials.extend(analysis["credentials"])
            except Exception as exc:
                logger.exception("Failed to analyze PCAP %s", rel_path)
                pcaps_failed.append(
                    {
                        "filename": rel_path,
                        "reason": str(exc)[:200],
                    }
                )

    elapsed = (time.monotonic() - t0) * 1000
    results: dict[str, Any] = {
        "pcaps_discovered": len(all_pcaps),
        "pcaps_analyzed": len(pcaps_analyzed),
        "pcaps_skipped_oversize": pcaps_skipped_size,
        "pcaps_failed": pcaps_failed,
        "analyses": pcaps_analyzed,
        "total_credentials_found": len(all_credentials),
        "credentials": all_credentials[:100],
    }

    with_errors = [a for a in pcaps_analyzed if a.get("errors")]
    if with_errors:
        cred_failures = sum(len(a.get("credential_errors", [])) for a in pcaps_analyzed)
        results["pcaps_with_tool_errors"] = len(with_errors)
        if cred_failures:
            results["credential_searches_failed"] = cred_failures
        details = [
            f"{a['filename']}: {e['step']}: {e['error'].splitlines()[0]}"
            for a in with_errors
            for e in a["errors"]
        ]
        results["tool_warning"] = (
            f"Tool runs failed on {len(with_errors)} of {len(pcaps_analyzed)} analyzed "
            "capture(s): the summaries, alerts or credentials of those steps are missing, "
            "not empty (see errors in each analysis).\n" + "\n".join(details[:10])
        )
    unreadable = [
        a["filename"]
        for a in pcaps_analyzed
        if a.get("protocol_summary", {}).get("status") == "error"
    ]
    if pcaps_analyzed and len(unreadable) == len(pcaps_analyzed):
        results["status"] = "error"
        results["error_message"] = (
            f"tshark could not read any of the {len(unreadable)} extracted capture(s): "
            f"{', '.join(unreadable[:10])}. Nothing was indexed."
        )

    return tool_response(
        tc_id,
        "analyze_disk_pcaps",
        params,
        results,
        source=None,
        elapsed_ms=elapsed,
    )
