"""File carving and bulk extraction MCP tools."""

from __future__ import annotations

import contextlib
import functools
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import cast

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    _FILE_LIST_CAP,
    ToolRun,
    adaptive_timeout,
    error_response,
    failure_key,
    make_tool_call_id,
    previous_failure,
    remember_failure,
    repeated_failure_response,
    require_binary,
    run_failure_response,
    run_tool,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.tsk import _triage_redirect

__all__ = [
    "run_binwalk",
    "run_bulk_extractor",
    "run_foremost",
    "run_photorec",
    "run_scalpel",
]

logger = logging.getLogger(__name__)

_STDERR_PREVIEW_CHARS = 500
_BULK_TIMEOUT = 1800
_SCALPEL_TIMEOUT = 1800
_PHOTOREC_TIMEOUT = 3600
_MAX_FEATURE_FILE_SIZE = 256 * 1024 * 1024  # 256 MiB read cap per feature file
_MIN_FREE_SPACE_BYTES = 1024 * 1024 * 1024  # 1 GiB absolute minimum
# scalpel with every file type commented out in scalpel.conf (the packaged default).
_SCALPEL_NO_TYPES_RE = re.compile(r"didn't specify any file types|no file types", re.IGNORECASE)


def _check_disk_space(image_path: str, multiplier: float = 0.1) -> str | None:
    """Verify sufficient temp-partition space before running a carving tool.

    Estimates needed space as *multiplier* times the image file size
    (minimum 1 GiB) and compares against free space on the temp
    filesystem.

    Args:
        image_path: Path to the disk image.
        multiplier: Fraction of image size to require as free space.

    Returns:
        An error message when space is insufficient, None otherwise.
    """
    try:
        image_size = Path(image_path).stat().st_size
    except OSError:
        return None
    needed = max(int(image_size * multiplier), _MIN_FREE_SPACE_BYTES)
    try:
        usage = shutil.disk_usage(tempfile.gettempdir())
    except OSError:
        return None
    if usage.free < needed:
        free_gib = usage.free / (1024**3)
        needed_gib = needed / (1024**3)
        return (
            f"Insufficient disk space: {free_gib:.1f} GiB free, "
            f"estimated {needed_gib:.1f} GiB needed"
        )
    return None


def _bulk_page_size() -> int:
    """Pick bulk_extractor page size based on available system memory.

    Allocates roughly 1/4 of available memory across threads (bulk_extractor
    needs ~2-3x page size per thread for decompression buffers).  Clamped
    between 16 MiB and 512 MiB, rounded down to a power of 2.  Adapts
    automatically to small containers and large servers.
    """
    _16M = 16 * 1024 * 1024
    avail = 0
    try:
        import psutil

        avail = psutil.virtual_memory().available
    except (ImportError, AttributeError):
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        avail = int(line.split()[1]) * 1024
                        break
        except OSError:
            pass
    if avail <= 0:
        return _16M
    ncpu = os.cpu_count() or 2
    per_thread = avail // (ncpu * 4)
    page = max(_16M, min(per_thread, 512 * 1024 * 1024))
    page = 1 << (page.bit_length() - 1)
    return page


_SCANNER_ALIASES: dict[str, str] = {
    # Names models reach for that bulk_extractor does not have.
    "url": "email",
    "urls": "email",
    "emails": "email",
    "domain": "net",
    "domains": "net",
    "ip": "net",
    "ips": "net",
    "ipv4": "net",
    "ipv6": "net",
    "network": "net",
    "tcp": "net",
    "http": "httplogs",
    "ccn": "accts",
    "cc": "accts",
    "card": "accts",
    "cards": "accts",
    "credit": "accts",
    "creditcard": "accts",
    "credit_card": "accts",
    "creditcards": "accts",
    "credit_cards": "accts",
    "ssn": "accts",
    "pii": "accts",
    "phone": "accts",
    "phones": "accts",
    "telephone": "accts",
    "jpeg": "exif",
    "jpg": "exif",
    "images": "exif",
    "lnk": "winlnk",
    "prefetch": "winprefetch",
    "exe": "winpe",
    "pe": "winpe",
    "mft": "ntfsmft",
    "usn": "ntfsusn",
    "sql": "sqlite",
    "sqlite3": "sqlite",
    "evt": "evtx",
    "eventlog": "evtx",
    "xml": "msxml",
    "kml": "kml_carved",
    "vcard": "vcard_carved",
    # bulk_extractor 1.x names.
    "email_lg": "email",
    "accts_lg": "accts",
    "gps_lg": "gps",
    "base16_lg": "base64",
    "httpheader_lg": "httplogs",
}

# Scanner list of bulk_extractor 2.2.1 as built by the Dockerfile.  Only used
# when ``bulk_extractor -h`` cannot be run or parsed (see _known_scanners).
_FALLBACK_SCANNERS: frozenset[str] = frozenset(
    {
        "accts", "aes", "base16", "base64", "elf", "email", "evtx", "exif",
        "facebook", "find", "gps", "gzip", "hiberfile", "httplogs", "json",
        "kml_carved", "msxml", "net", "ntfsindx", "ntfslogfile", "ntfsmft",
        "ntfsusn", "outlook", "pdf", "rar", "rtti", "sqlite", "utmp",
        "vcard_carved", "vin", "windirs", "winlnk", "winpe", "winprefetch",
        "wordlist", "xor", "zip",
    }
)  # fmt: skip

# ``bulk_extractor -h`` lists every scanner as "-x NAME - disable scanner NAME"
# (enabled by default) or "-e NAME - enable scanner NAME" (opt-in).
_SCANNER_HELP_RE = re.compile(r"^\s+-[xe] (\S+) - (?:dis|en)able scanner", re.MULTILINE)


def _parse_scanner_help(help_text: str) -> frozenset[str]:
    """Extract scanner names from ``bulk_extractor -h`` output."""
    return frozenset(_SCANNER_HELP_RE.findall(help_text))


@functools.lru_cache(maxsize=1)
def _known_scanners() -> frozenset[str]:
    """Scanner names the installed bulk_extractor accepts.

    Parsed from ``bulk_extractor -h`` on first use so the set tracks the
    installed version; falls back to ``_FALLBACK_SCANNERS`` when the binary
    cannot be run or prints help in an unexpected format.
    """
    try:
        # -h exits non-zero and prints to stdout.
        proc = subprocess.run(
            ["bulk_extractor", "-h"], capture_output=True, text=True, timeout=30, check=False
        )
        parsed = _parse_scanner_help(proc.stdout + proc.stderr)
    except (OSError, subprocess.TimeoutExpired):
        parsed = frozenset()
    if not parsed:
        logger.warning("Could not parse scanner list from bulk_extractor -h; using built-in list")
        return _FALLBACK_SCANNERS
    return parsed


def _resolve_scanners(scanners: list[str]) -> list[str]:
    """Map scanner names through aliases (case-insensitively) and dedupe."""
    return list(dict.fromkeys(_SCANNER_ALIASES.get(s.lower(), s.lower()) for s in scanners))


_FEATURE_SOURCE_MAP: dict[str, str] = {
    "email": "bulk.email",
    "url": "bulk.url",
    "domain": "bulk.domain",
    "ip": "bulk.ip",
    "telephone": "bulk.telephone",
    "find": "bulk.find",
    "pii": "bulk.pii",
    "elf": "bulk.elf",
    "exe": "bulk.exe",
    "json": "bulk.json",
    "winpe": "bulk.winpe",
    "winlnk": "bulk.winlnk",
}


def _build_bulk_extractor_cmd(
    image_path: str,
    outdir: str,
    scanners: list[str] | None,
    depth: int | None,
) -> list[str]:
    """Build the bulk_extractor command line.

    Configures thread count from available CPUs, page size from available
    memory, scanner selection via aliases, and recursion depth.

    Args:
        image_path: Path to the disk image to scan.
        outdir: Output directory for feature files.
        scanners: Scanner names to enable (resolved through aliases).
            When None, all scanners run.
        depth: Maximum recursion depth, or None for the default.

    Returns:
        Complete argument list ready for subprocess.run.
    """
    ncpu = os.cpu_count() or 2
    page_size = _bulk_page_size()
    cmd = ["bulk_extractor", "-j", str(ncpu), "-G", str(page_size), "-o", outdir]

    if depth is not None:
        cmd.extend(["-M", str(depth)])

    if scanners:
        deduped = _resolve_scanners(scanners)
        cmd.extend(["-E", deduped[0]])
        for s in deduped[1:]:
            cmd.extend(["-e", s])

    cmd.append(image_path)
    return cmd


def _read_capped_feature_file(feature_file: Path) -> tuple[str | None, int]:
    """Read a single feature file, capped at ``_MAX_FEATURE_FILE_SIZE`` bytes.

    A file over the cap is cut at the last complete line before it.

    Args:
        feature_file: Path to a bulk_extractor feature file.

    Returns:
        ``(text, bytes_dropped)``: the stripped content (None on read failure
        or empty content) and how many bytes of the file were not read.
    """
    try:
        file_size = feature_file.stat().st_size
        with open(feature_file, "rb") as fh:
            data = fh.read(_MAX_FEATURE_FILE_SIZE)
    except OSError:
        return None, 0
    dropped = 0
    if file_size > len(data):
        cut = data.rfind(b"\n")
        if cut >= 0:
            data = data[: cut + 1]
        dropped = file_size - len(data)
        logger.warning(
            "Feature file %s is %d bytes; indexing first %d only",
            feature_file.name,
            file_size,
            len(data),
        )
    text = data.decode("utf-8", errors="replace").strip()
    return text or None, dropped


def _stream_and_index_features(
    outdir: str,
    features: list[str] | None,
    image_path: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Read, index, and discard each feature file sequentially.

    Bounds peak memory to a single feature file (capped at
    ``_MAX_FEATURE_FILE_SIZE`` bytes) rather than all combined.
    Safely handles a missing or empty output directory so that partial
    results can be collected after a timeout.

    Args:
        outdir: bulk_extractor output directory.
        features: Feature stems to include, or None for all.
        image_path: Disk image path for source registration.

    Returns:
        ``(per_feature, truncated)``: per-feature index summary dicts, and
        one entry per feature file that was cut before indexing.
    """
    results: list[dict[str, object]] = []
    truncated: list[dict[str, object]] = []
    out_path = Path(outdir)
    if not out_path.is_dir():
        return results, truncated
    for feature_file in sorted(out_path.iterdir()):
        if not feature_file.is_file() or feature_file.suffix == ".xml":
            continue
        stem = feature_file.stem.replace("_histogram", "").replace("_find", "find")
        if "histogram" in feature_file.name:
            continue
        if features and stem not in features:
            continue

        text, dropped = _read_capped_feature_file(feature_file)
        if text is None:
            continue

        source_name = _FEATURE_SOURCE_MAP.get(stem, f"bulk.{stem}")
        if dropped:
            file_bytes = feature_file.stat().st_size
            truncated.append(
                {
                    "feature": stem,
                    "source_name": source_name,
                    "file_bytes": file_bytes,
                    "bytes_indexed": file_bytes - dropped,
                    "bytes_dropped": dropped,
                }
            )
        summary = extract_and_index(text, source_name, image_path, "bulk_extractor")
        results.append(summary)
        del text

    return results, truncated


def _incomplete_warning(run: ToolRun) -> str:
    """Warning for a run that did not complete but left output files that were indexed."""
    return f"{run.describe()}\nThe output written before that was indexed; it may be incomplete."


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_bulk_extractor(
    image_path: str,
    features: list[str] | None = None,
    scanners: list[str] | None = None,
    max_depth: int | None = None,
    force: bool = False,
) -> dict[str, object]:
    """Carve IOCs (URLs, emails, domains, IPs) from a disk image using bulk_extractor.

    Call on any disk image or raw partition. No prerequisite tools
    required. Pass specific scanners for faster runs (e.g.
    ``scanners=["email", "net", "httplogs"]``). Use max_depth=2 for a
    quick first pass.

    Scanner names: accts (credit cards, SSNs, phone numbers; there is no
    "ccn" scanner), aes, base16, base64, elf, email (also yields URLs;
    there is no "url" scanner), evtx, exif, facebook, find, gps, gzip,
    hiberfile, httplogs, json, kml_carved, msxml, net (IPs, domains,
    packets), ntfsindx, ntfslogfile, ntfsmft, ntfsusn, outlook, pdf, rar,
    rtti, sqlite, utmp, vcard_carved, vin, windirs, winlnk, winpe,
    winprefetch, wordlist, xor, zip.  Unknown names are rejected before
    the binary runs.

    Indexes each feature type as ``bulk.<feature>`` (e.g. ``bulk.email``,
    ``bulk.url``). Use get_carved_iocs() for a summary or search() to
    query specific features.

    Args:
        image_path: Path to the disk image.
        features: Optional list of feature types to index from the
            output (e.g. ["email", "url"]).  Indexes all if omitted.
        scanners: Optional list of bulk_extractor scanner names to
            enable (see list above).  When provided, ONLY these
            scanners run (uses -E/-e flags).  When omitted, all
            scanners run.
        max_depth: Maximum recursion depth for decompressing nested
            archives (default: 12).  Use ``max_depth=2`` for a faster
            first-pass scan: most forensic artifacts are at depth
            0-1.  Re-run with full depth on specific images if you
            suspect nested compressed content.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    redirect = _triage_redirect(
        tc_id,
        "run_bulk_extractor",
        {"image_path": image_path},
        image_path,
        "Carving needs a raw image. On a triage collection use yara_scan_files on this "
        "path and search() over the indexed artifacts.",
    )
    if redirect is not None:
        return redirect
    t0 = time.monotonic()
    params: dict[str, object] = {
        "image_path": image_path,
        "features": features,
        "scanners": scanners,
        "max_depth": max_depth,
        "force": force,
    }

    if not force:
        existing = sources_already_indexed(["bulk."], evidence_path=image_path)
        partial = previous_failure(failure_key("run_bulk_extractor", image_path, "partial"))
        if existing and partial is None:
            return tool_response(
                tc_id,
                "run_bulk_extractor",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "bulk",
                0.0,
            )

    if not require_binary("bulk_extractor"):
        return error_response(
            tc_id, "run_bulk_extractor", params, "bulk_extractor not found on PATH"
        )

    if scanners:
        known = _known_scanners()
        unknown = [s for s in _resolve_scanners(scanners) if s not in known]
        if unknown:
            return error_response(
                tc_id,
                "run_bulk_extractor",
                params,
                f"Unknown bulk_extractor scanner(s): {', '.join(unknown)}",
                error_type="invalid_scanner",
                suggestion=f"Accepted scanners: {', '.join(sorted(known))}",
            )

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_bulk_extractor",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    space_err = _check_disk_space(image_path)
    if space_err:
        return error_response(
            tc_id, "run_bulk_extractor", params, space_err, error_type="disk_space"
        )

    memory_key = failure_key(
        "run_bulk_extractor",
        image_path,
        ",".join(_resolve_scanners(scanners)) if scanners else "",
        max_depth,
    )
    repeated = repeated_failure_response(tc_id, "run_bulk_extractor", params, memory_key, t0)
    if repeated is not None:
        return repeated

    timeout = adaptive_timeout(image_path, base=_BULK_TIMEOUT)

    with tempfile.TemporaryDirectory(prefix="mulder_bulk_") as tmpdir:
        cmd = _build_bulk_extractor_cmd(image_path, tmpdir, scanners, max_depth)
        run = run_tool(cmd, timeout=timeout)

        if not run.ok and not run.timed_out:
            logger.error("bulk_extractor failed: %s", run.describe())
            return run_failure_response(
                tc_id,
                "run_bulk_extractor",
                params,
                run,
                t0,
                memory_key=memory_key,
                suggestion=(
                    "Nothing was indexed. Read the tool output above; fix the input or the "
                    "scanner list and pass force=True to run it again."
                ),
            )
        if run.timed_out:
            logger.warning(
                "bulk_extractor timed out after %ds on %s; salvaging partial results",
                timeout,
                image_path,
            )

        results, truncated = _stream_and_index_features(tmpdir, features, image_path)

    if run.timed_out and not results:
        return run_failure_response(
            tc_id,
            "run_bulk_extractor",
            params,
            run,
            t0,
            memory_key=memory_key,
            context="bulk_extractor wrote no feature file before it was stopped",
            suggestion=(
                "Nothing was indexed. Retry with fewer scanners (scanners=[...]) or "
                "max_depth=2, and force=True."
            ),
        )

    partial_key = failure_key("run_bulk_extractor", image_path, "partial")
    total_windows = sum(cast(int, r.get("windows_indexed", 0)) for r in results)
    for r in results:
        r.pop("source_id", None)

    elapsed = (time.monotonic() - t0) * 1000
    response_data: dict[str, object] = {
        "features_indexed": len(results),
        "total_windows_indexed": total_windows,
        "per_feature": results,
    }
    warnings: list[str] = []
    if run.timed_out:
        response_data["partial"] = True
        response_data["status"] = "partial"
        response_data["warning"] = (
            f"bulk_extractor timed out after {timeout}s; "
            f"indexed {len(results)} partial feature file(s)"
        )
        warnings.append(
            f"bulk_extractor timed out after {timeout}s: the {len(results)} bulk.* feature "
            "source(s) indexed are incomplete (features found later in the image are "
            "missing). A later run_bulk_extractor call on this image runs again instead "
            "of skipping; use fewer scanners or max_depth=2 so it can finish."
        )
        # Sources from this run exist now; record that they are partial so the
        # skip check does not treat them as a completed extraction.
        remember_failure(partial_key, warnings[-1])
    else:
        remember_failure(partial_key, "")
    if truncated:
        response_data["truncated_features"] = truncated
        cut = ", ".join(
            f"{t['source_name']} ({t['bytes_dropped']} of {t['file_bytes']} bytes dropped)"
            for t in truncated
        )
        warnings.append(
            f"Feature files over {_MAX_FEATURE_FILE_SIZE // (1024 * 1024)} MiB were cut "
            f"before indexing: {cut}. Features past the cut are not searchable."
        )
    if warnings:
        response_data["tool_warning"] = "\n".join(warnings)

    return tool_response(
        tc_id,
        "run_bulk_extractor",
        params,
        response_data,
        "bulk",
        elapsed,
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_foremost(image_path: str) -> dict[str, object]:
    """Carve files from a disk image using foremost.

    Recovers deleted files by scanning for file headers and footers
    in the raw disk image.  Indexes an audit summary of carved files.

    Args:
        image_path: Path to the disk image.
    """
    tc_id = make_tool_call_id()
    redirect = _triage_redirect(
        tc_id,
        "run_foremost",
        {"image_path": image_path},
        image_path,
        "Carving needs a raw image. On a triage collection use yara_scan_files on this path.",
    )
    if redirect is not None:
        return redirect
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path}

    if not require_binary("foremost"):
        return error_response(tc_id, "run_foremost", params, "foremost not found on PATH")

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_foremost",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    space_err = _check_disk_space(image_path, multiplier=0.5)
    if space_err:
        return error_response(tc_id, "run_foremost", params, space_err, error_type="disk_space")

    timeout = adaptive_timeout(image_path, base=_BULK_TIMEOUT)

    with tempfile.TemporaryDirectory(prefix="mulder_foremost_") as parent:
        outdir = os.path.join(parent, "output")
        run = run_tool(["foremost", "-i", image_path, "-o", outdir, "-T"], timeout=timeout)

        audit_text = ""
        for audit_file in Path(parent).rglob("audit.txt"):
            with contextlib.suppress(OSError):
                audit_text += audit_file.read_text(encoding="utf-8", errors="replace")

    if not run.ok and not audit_text.strip():
        return run_failure_response(
            tc_id,
            "run_foremost",
            params,
            run,
            t0,
            context="foremost wrote no audit.txt",
            suggestion="Nothing was indexed: this is not a carve that found no files.",
        )

    summary = extract_and_index(
        audit_text or "No files carved", "foremost.audit", image_path, "foremost"
    )
    if not run.ok:
        summary["tool_warning"] = _incomplete_warning(run)
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_foremost", params, summary, "foremost.audit", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_scalpel(image_path: str) -> dict[str, object]:
    """Carve files from a disk image or partition using Scalpel.

    Scalpel recovers files based on header/footer signatures.  More
    configurable than foremost: edit /etc/scalpel/scalpel.conf to
    enable specific file types before running.

    Args:
        image_path: Path to the disk image or raw partition.
    """
    tc_id = make_tool_call_id()
    redirect = _triage_redirect(
        tc_id,
        "run_scalpel",
        {"image_path": image_path},
        image_path,
        "Carving needs a raw image. On a triage collection use yara_scan_files on this path.",
    )
    if redirect is not None:
        return redirect
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path}

    if not require_binary("scalpel"):
        return error_response(
            tc_id,
            "run_scalpel",
            params,
            "scalpel not found on PATH",
            error_type="binary_missing",
        )

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_scalpel",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    space_err = _check_disk_space(image_path, multiplier=0.5)
    if space_err:
        return error_response(tc_id, "run_scalpel", params, space_err, error_type="disk_space")

    timeout = adaptive_timeout(image_path, base=_SCALPEL_TIMEOUT)

    with tempfile.TemporaryDirectory(prefix="mulder_scalpel_") as parent:
        outdir = os.path.join(parent, "output")
        cmd = ["scalpel", "-o", outdir, image_path]
        run = run_tool(cmd, timeout=timeout)

        audit_path = Path(outdir) / "audit.txt"
        audit_text = ""
        if audit_path.exists():
            audit_text = audit_path.read_text(errors="replace")

    if not audit_text.strip() and _SCALPEL_NO_TYPES_RE.search(run.stdout + run.stderr):
        return error_response(
            tc_id,
            "run_scalpel",
            params,
            "scalpel carved nothing: its configuration enables no file type. " + run.describe(),
            (time.monotonic() - t0) * 1000,
            error_type="tool_failed",
            suggestion=(
                "Uncomment the wanted file types in /etc/scalpel/scalpel.conf, or use "
                "run_foremost / run_photorec. Nothing was indexed."
            ),
        )
    if not audit_text.strip() and (not run.ok or not run.has_output):
        return run_failure_response(
            tc_id,
            "run_scalpel",
            params,
            run,
            t0,
            context="scalpel wrote no audit.txt",
            suggestion="Nothing was indexed: this is not a carve that found no files.",
        )

    summary = extract_and_index(
        audit_text if audit_text.strip() else run.stdout.strip(),
        "scalpel.audit",
        image_path,
        "scalpel",
    )
    if not run.ok:
        summary["tool_warning"] = _incomplete_warning(run)

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_scalpel", params, summary, "scalpel.audit", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_binwalk(target_path: str, extract: bool = False) -> dict[str, object]:
    """Scan a file for embedded files, firmware headers, and compressed archives.

    binwalk identifies embedded content by signature.  Use extract=True
    to also extract discovered embedded files into a temp directory.

    Args:
        target_path: Path to the file to scan.
        extract: If True, extract embedded files (``binwalk -e``).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"target_path": target_path, "extract": extract}

    if not require_binary("binwalk"):
        return error_response(
            tc_id,
            "run_binwalk",
            params,
            "binwalk not found on PATH",
            error_type="binary_missing",
        )

    if not Path(target_path).exists():
        return error_response(
            tc_id,
            "run_binwalk",
            params,
            f"File not found: {target_path}",
            error_type="file_not_found",
        )

    if extract:
        space_err = _check_disk_space(target_path, multiplier=0.5)
        if space_err:
            return error_response(tc_id, "run_binwalk", params, space_err, error_type="disk_space")

    cmd = ["binwalk"]
    if extract:
        cmd.append("-e")
    cmd.append(target_path)

    run = run_tool(cmd, timeout=adaptive_timeout(target_path))
    if run.failed:
        return run_failure_response(
            tc_id,
            "run_binwalk",
            params,
            run,
            t0,
            suggestion="Nothing was indexed: this is not a scan that found no signature.",
        )

    summary = extract_and_index(run.stdout.strip(), "binwalk.scan", target_path, "binwalk")
    if (warning := run.warning()) is not None:
        summary["tool_warning"] = warning
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_binwalk", params, summary, "binwalk.scan", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_photorec(image_path: str) -> dict[str, object]:
    """Recover deleted files from a disk image using PhotoRec.

    PhotoRec recovers files by signature (480+ file types) from disk
    images, partitions, or raw devices.  Runs in non-interactive mode.

    Args:
        image_path: Path to the disk image or partition.
    """
    tc_id = make_tool_call_id()
    redirect = _triage_redirect(
        tc_id,
        "run_photorec",
        {"image_path": image_path},
        image_path,
        "Carving needs a raw image. On a triage collection use yara_scan_files on this path.",
    )
    if redirect is not None:
        return redirect
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path}

    if not require_binary("photorec"):
        return error_response(
            tc_id,
            "run_photorec",
            params,
            "photorec not found on PATH",
            error_type="binary_missing",
            suggestion="Install testdisk package: apt-get install testdisk",
        )

    if not Path(image_path).exists():
        return error_response(
            tc_id,
            "run_photorec",
            params,
            f"File not found: {image_path}",
            error_type="file_not_found",
        )

    space_err = _check_disk_space(image_path, multiplier=0.5)
    if space_err:
        return error_response(tc_id, "run_photorec", params, space_err, error_type="disk_space")

    timeout = adaptive_timeout(image_path, base=_PHOTOREC_TIMEOUT)

    with tempfile.TemporaryDirectory(prefix="mulder_photorec_") as tmpdir:
        cmd = [
            "photorec",
            "/cmd",
            image_path,
            "fileopt,everything,enable",
            f"search,{tmpdir}/",
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return error_response(
                tc_id,
                "run_photorec",
                params,
                f"photorec timed out after {timeout}s",
                error_type="timeout",
            )

        report_path = Path(tmpdir) / "report.xml"
        recovered_anything = report_path.exists() or any(
            f.is_file() for f in Path(tmpdir).rglob("*")
        )
        if proc.returncode != 0 and not recovered_anything:
            detail = (proc.stderr.strip() or proc.stdout.strip())[:_STDERR_PREVIEW_CHARS]
            return error_response(
                tc_id,
                "run_photorec",
                params,
                f"photorec exited {proc.returncode} and carved nothing: {detail}",
                (time.monotonic() - t0) * 1000,
                error_type="tool_failed",
            )

        report_text = ""
        if report_path.exists():
            report_text = report_path.read_text(errors="replace")

        if not report_text.strip():
            recovered = list(Path(tmpdir).rglob("*"))
            file_list = [str(f.relative_to(tmpdir)) for f in recovered if f.is_file()]
            report_text = f"PhotoRec recovered {len(file_list)} file(s):\n" + "\n".join(
                file_list[:_FILE_LIST_CAP]
            )
            if len(file_list) > _FILE_LIST_CAP:
                report_text += f"\n... and {len(file_list) - _FILE_LIST_CAP} more"

        summary = extract_and_index(report_text, "photorec.report", image_path, "photorec")

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_photorec", params, summary, "photorec.report", elapsed)
