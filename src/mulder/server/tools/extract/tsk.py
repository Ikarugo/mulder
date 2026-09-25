"""SleuthKit (TSK) filesystem analysis MCP tools."""

from __future__ import annotations

import contextlib
import logging
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from mulder.extractors.optical import probe_optical
from mulder.patterns import fls_file_entries, parse_mmls_rows
from mulder.server.app import get_ctx, mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    TOOL_TIMEOUT,
    ToolRun,
    error_response,
    make_tool_call_id,
    require_binary,
    run_tool,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.triage import is_triage_root, iter_tree_files

__all__ = [
    "IcatFailure",
    "_cleanup_tsk_extract_dir",
    "_collect_fls_chunks",
    "_detect_partition_offset",
    "_partition_table_text",
    "_parse_all_partitions",
    "_parse_partition_offset",
    "_resolve_partition_offset",
    "_run_fls_inline",
    "_tsk_extract_dirs",
    "_tsk_extract_files",
    "_tsk_lock",
    "_triage_extract_files",
    "_triage_redirect",
    "add_extraction_failures",
    "extraction_failure_fields",
    "icat_file",
    "nothing_extracted_response",
    "run_fls",
    "run_fsstat",
    "run_mactime",
    "run_mmls",
]

logger = logging.getLogger(__name__)


_NTFS_INDICATORS = ("ntfs", "0x07", "win95 fat", "0x0b", "0x0c", "basic data")
_LINUX_INDICATORS = ("linux", "0x83", "ext", "0x8e")

_MIN_PARTITION_SECTORS = 204800
"""Minimum partition size in 512-byte sectors (~100 MB).

Partitions smaller than this threshold are skipped during multi-partition
analysis to avoid indexing tiny boot, EFI, or recovery stubs.
"""


def _note(problems: list[str] | None, message: str) -> None:
    """Append *message* to *problems* when the caller asked for them."""
    if problems is not None:
        problems.append(message)


def _add_warning(summary: dict[str, object], warning: str | None) -> None:
    """Add *warning* to ``summary["tool_warning"]``, keeping any earlier one."""
    if not warning:
        return
    earlier = summary.get("tool_warning")
    summary["tool_warning"] = f"{earlier}\n{warning}" if earlier else warning


def _run_mmls_text(image_path: str, timeout: int, problems: list[str] | None) -> str:
    """Live mmls output for *image_path*, or "" with the reason added to *problems*."""
    if not require_binary("mmls"):
        _note(problems, "partition table not read: mmls not found on PATH")
        return ""
    run = run_tool(["mmls", image_path], timeout=timeout)
    if run.ok:
        return run.stdout
    _note(problems, f"partition table not read: {run.describe()}")
    return ""


def _detect_partition_offset(image_path: str, problems: list[str] | None = None) -> int:
    """Run mmls to find the main partition offset (in sectors).

    Returns 0 when mmls fails; the reason is appended to *problems* when
    given, so a caller that then fails at offset 0 can say why.
    """
    return _parse_partition_offset(_run_mmls_text(image_path, 30, problems))


def _parse_partition_offset(mmls_text: str) -> int:
    """Parse the primary data partition offset (in sectors) from mmls output.

    Searches for NTFS/Windows partitions first, then Linux, then falls
    back to the largest partition by sector count.
    """
    rows = parse_mmls_rows(mmls_text)
    if not rows:
        return 0

    # Find the LARGEST NTFS/Windows partition (not just the first)
    ntfs_parts = [
        (start, length, desc)
        for start, length, desc in rows
        if any(ind in desc for ind in _NTFS_INDICATORS) and length > 0
    ]
    if ntfs_parts:
        biggest_ntfs = max(ntfs_parts, key=lambda t: t[1])
        return biggest_ntfs[0]

    linux_parts = [
        (start, length, desc)
        for start, length, desc in rows
        if any(ind in desc for ind in _LINUX_INDICATORS) and length > 0
    ]
    if linux_parts:
        biggest_linux = max(linux_parts, key=lambda t: t[1])
        return biggest_linux[0]

    biggest = max(rows, key=lambda t: t[1])
    return biggest[0] if biggest[1] > 0 else 0


def _parse_all_partitions(mmls_text: str) -> list[tuple[int, int, str]]:
    """Parse all non-trivial data partitions from mmls output.

    Returns NTFS/Linux/data partitions above ``_MIN_PARTITION_SECTORS``
    sorted by sector count descending (largest first).  The first element
    is the primary partition used by downstream tools.

    Args:
        mmls_text: Raw stdout from ``mmls``.

    Returns:
        List of ``(start_sector, length, description)`` tuples.
    """
    rows = parse_mmls_rows(mmls_text)
    if not rows:
        return []

    data_parts: list[tuple[int, int, str]] = []
    for start, length, desc in rows:
        if length < _MIN_PARTITION_SECTORS:
            continue
        is_data = any(ind in desc for ind in _NTFS_INDICATORS) or any(
            ind in desc for ind in _LINUX_INDICATORS
        )
        if is_data:
            data_parts.append((start, length, desc))

    data_parts.sort(key=lambda t: t[1], reverse=True)
    return data_parts


_KV_OFFSET_PREFIX = "tsk_partition_offset:"
"""DB kv_store key prefix for persisted partition offsets."""

_KV_SOURCE_OFFSET_PREFIX = "tsk_source_offset:"
"""DB kv_store key mapping indexed source names to their partition offset.

Keys follow the pattern ``tsk_source_offset:{source_name}:{image_path}``.
"""


def _resolve_partition_offset(image_path: str, problems: list[str] | None = None) -> int:
    """Resolve the partition offset for *image_path* using all available sources.

    Checks, in order:
      1. The DB ``kv_store`` (set by a prior successful ``run_fls``).
      2. The ``tsk.partitions`` source indexed for this image, else live
         mmls (``_partition_table_text``).

    This ensures that when ``run_fls`` was called with an explicit offset
    (e.g. on multi-segment E01 images where mmls may not work),
    downstream icat extractions reuse the same working offset.

    When the partition table cannot be read the offset falls back to 0 and
    the reason is appended to *problems* (when given).
    """
    ctx = get_ctx()

    stored = ctx.db.get_kv(f"{_KV_OFFSET_PREFIX}{image_path}")
    if stored is not None:
        with contextlib.suppress(ValueError):
            return int(stored)

    return _parse_partition_offset(_partition_table_text(image_path, problems))


_tsk_extract_dirs: list[str] = []
_tsk_lock = threading.Lock()


def _cleanup_tsk_extract_dir(dir_path: str) -> None:
    """Remove a TSK extraction temp directory and deregister it.

    Callers should invoke this after consuming extracted files so that
    disk space is reclaimed promptly rather than at process exit.

    Args:
        dir_path: Absolute path to the temp directory to remove.
    """
    shutil.rmtree(dir_path, ignore_errors=True)
    with _tsk_lock, contextlib.suppress(ValueError):
        _tsk_extract_dirs.remove(dir_path)


def _run_fls_inline(image_path: str, problems: list[str] | None = None) -> str:
    """Run fls directly and return the output text without indexing to DB.

    Used when the pre-indexed ``tsk.filelist`` is not yet available
    (e.g. when extraction tools run concurrently with ``run_fls``).
    Persists the detected partition offset to the kv_store so that
    subsequent icat calls can reuse it.

    Returns "" when fls could not list the image; the reason (with the
    partition lookup problem, if the offset fell back to 0) is appended to
    *problems* when given. A listing fls cut short is returned, with a note.
    """
    if not require_binary("fls"):
        _note(problems, "file listing not built: fls not found on PATH")
        return ""
    lookup: list[str] = []
    offset = _resolve_partition_offset(image_path, lookup)
    cmd = ["fls", "-r", "-p"]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.append(image_path)
    run = run_tool(cmd, timeout=TOOL_TIMEOUT)
    if run.ok:
        get_ctx().db.set_kv(f"{_KV_OFFSET_PREFIX}{image_path}", str(offset))
        return run.stdout
    if run.has_output:
        _note(problems, f"file listing incomplete (partition offset {offset}): {run.warning()}")
        return run.stdout
    _note(
        problems,
        f"file listing not built: fls failed at partition offset {offset}: {run.describe()}"
        + (f" ({'; '.join(lookup)})" if lookup else ""),
    )
    return ""


def _collect_fls_chunks(
    image_path: str, problems: list[str] | None = None
) -> list[tuple[list[str], int]]:
    """Collect fls text chunks paired with their partition offsets.

    Gathers output from all indexed ``tsk.filelist*`` sources (primary
    and secondary partitions).  Each returned element is a ``(chunks,
    offset)`` pair representing one partition's file listing and the
    sector offset required for ``icat`` extraction.

    Falls back to ``_run_fls_inline`` on the primary partition when no
    indexed sources exist.

    Args:
        image_path: Path to the disk image.
        problems: When given, receives why the inline fls listing could
            not be built (an empty result is then a failure, not an image
            without files).

    Returns:
        List of ``(text_chunks, sector_offset)`` pairs, one per partition.
    """
    ctx = get_ctx()
    sources = ctx.db.get_sources()
    fls_sources = sorted(
        [s for s in sources if s.source_name.startswith("tsk.filelist")],
        key=lambda s: s.source_name,
    )

    if fls_sources:
        result: list[tuple[list[str], int]] = []
        for src in fls_sources:
            windows = ctx.db.get_windows_by_source(src.source_name)
            chunks = [w.raw_text for w in windows]
            if not chunks:
                continue

            stored = ctx.db.get_kv(f"{_KV_SOURCE_OFFSET_PREFIX}{src.source_name}:{image_path}")
            if stored is not None:
                with contextlib.suppress(ValueError):
                    offset = int(stored)
                    result.append((chunks, offset))
                    continue
            result.append((chunks, _resolve_partition_offset(image_path)))
        return result

    inline_output = _run_fls_inline(image_path, problems)
    if inline_output:
        offset = _resolve_partition_offset(image_path)
        return [([inline_output], offset)]
    return []


def _discover_partitions(
    image_path: str, problems: list[str] | None = None
) -> list[tuple[int, int, str]]:
    """Discover all non-trivial partitions for *image_path*.

    Checks the indexed ``tsk.partitions`` source first, then falls back
    to running ``mmls`` directly.

    Args:
        image_path: Path to the disk image.
        problems: When given, receives why the partition table could not
            be read.

    Returns:
        List of ``(start_sector, length, description)`` from
        ``_parse_all_partitions``, largest first.
    """
    return _parse_all_partitions(_partition_table_text(image_path, problems))


def _partition_table_text(image_path: str, problems: list[str] | None = None) -> str:
    """Raw mmls output for *image_path* alone: its ``tsk.partitions`` source, else live mmls.

    ``run_mmls`` indexes every image's table under the same source name, so
    the windows are filtered to the source whose ``source_path`` is this
    image.  Reading them all hands one image another image's offsets: on a
    three-image case RM2 was scanned at RM1's sector 32, where TSK finds a
    phantom FAT with no real files, and reported a clean image (#227).

    Returns "" when live mmls fails; the reason is appended to *problems*
    when given (callers then fall back to offset 0 and can say why).
    """
    ctx = get_ctx()
    src = next(
        (
            s
            for s in ctx.db.get_sources()
            if s.source_name == "tsk.partitions" and s.source_path == image_path
        ),
        None,
    )
    if src is not None:
        windows = ctx.db.get_windows_by_source("tsk.partitions")
        return "\n".join(w.raw_text for w in windows if w.source_id == src.source_id)
    return _run_mmls_text(image_path, 30, problems)


def _index_secondary_partitions(
    image_path: str,
    primary_offset: int,
    failures: list[dict[str, object]] | None = None,
    problems: list[str] | None = None,
) -> list[dict[str, object]]:
    """Run fls on non-primary partitions and index their output.

    Each secondary partition is indexed as ``tsk.filelist.p{i}`` with
    its sector offset stored in the kv_store for downstream extraction.

    Args:
        image_path: Path to the disk image.
        primary_offset: Sector offset of the primary (largest) partition,
            used to exclude it from the secondary list.
        failures: When given, receives one ``{"partition_offset",
            "description", "error"}`` entry per secondary partition fls
            could not list (or listed only in part).
        problems: When given, receives why the partition table could not
            be read (no secondary partition was then scanned).

    Returns:
        List of ``extract_and_index`` summary dicts, one per indexed
        secondary partition.
    """
    all_parts = _discover_partitions(image_path, problems)
    secondary_parts = [
        (start, length, desc) for start, length, desc in all_parts if start != primary_offset
    ]
    if not secondary_parts:
        return []

    ctx = get_ctx()
    summaries: list[dict[str, object]] = []
    for i, (start, _length, desc) in enumerate(secondary_parts, 1):
        source_name = f"tsk.filelist.p{i}"
        run = run_tool(["fls", "-r", "-p", "-o", str(start), image_path], timeout=TOOL_TIMEOUT)
        if run.failed:
            logger.warning(
                "fls failed on secondary partition at offset %d (%s): %s",
                start,
                desc,
                run.describe(),
            )
            if failures is not None:
                failures.append(
                    {"partition_offset": start, "description": desc, "error": run.describe()}
                )
            continue

        stdout_text = run.stdout.strip()
        if not stdout_text:
            continue
        warning = run.warning()
        if warning is not None and failures is not None:
            failures.append(
                {
                    "partition_offset": start,
                    "description": desc,
                    "error": warning,
                    "indexed_partial": True,
                }
            )

        ctx.db.set_kv(
            f"{_KV_SOURCE_OFFSET_PREFIX}{source_name}:{image_path}",
            str(start),
        )
        summary = extract_and_index(stdout_text, source_name, image_path, "sleuthkit")
        summary["partition_offset"] = start
        summary["partition_description"] = desc
        if warning is not None:
            summary["tool_warning"] = warning
        summaries.append(summary)
        logger.info(
            "Indexed secondary partition %s: offset=%d, desc=%s",
            source_name,
            start,
            desc,
        )

    return summaries


#: icat streams to disk, so the timeout only has to cover slow images.
ICAT_TIMEOUT = TOOL_TIMEOUT
#: Per-file timeout when many files are extracted by pattern (hives, logs,
#: prefetch...): a damaged image must not stall a tool for hours.
BULK_ICAT_TIMEOUT = 180


@dataclass(frozen=True)
class IcatFailure:
    """A file seen in the fls listing that could not be read out of the image."""

    path: str
    inode: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        """JSON form for tool responses."""
        return {"path": self.path, "inode": self.inode, "reason": self.reason}


def icat_file(
    image_path: str,
    offset: int,
    inode: str,
    dest: Path,
    *,
    skip_holes: bool = False,
    timeout: int = ICAT_TIMEOUT,
) -> tuple[bool, str | None]:
    """Stream the content of *inode* into *dest* with ``icat``.

    Returns ``(True, None)`` when a non-empty file was written,
    ``(False, None)`` when the file is empty, and ``(False, reason)`` when
    icat failed, with the reason taken from its stderr.

    The eight copies this replaces held the whole file in memory with a
    30-second timeout and dropped failures silently: a hive or event log
    icat could not read was then reported as "not found", which an agent
    reads as "not on this system".
    """
    cmd = ["icat"]
    if skip_holes:
        cmd.append("-h")
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.extend([image_path, inode])
    ok, reason = _icat_to(cmd, dest, timeout)
    if not ok:
        with contextlib.suppress(OSError):
            dest.unlink()  # never leave an empty or partial file for a parser to read
    return ok, reason


def _icat_to(cmd: list[str], dest: Path, timeout: int) -> tuple[bool, str | None]:
    try:
        with dest.open("wb") as out:
            proc = subprocess.run(
                cmd,
                stdout=out,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
    except subprocess.TimeoutExpired:
        return False, f"icat timed out after {timeout}s"
    except OSError as exc:
        return False, f"icat could not run: {exc}"
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
        return False, f"icat exited {proc.returncode}" + (f": {err[-300:]}" if err else "")
    try:
        size = dest.stat().st_size
    except OSError as exc:
        return False, f"output not written: {exc}"
    return size > 0, None


def failures_named(failures: list[IcatFailure], names: Iterable[str]) -> list[IcatFailure]:
    """The failures whose file name is one of *names* (case-insensitive).

    Extraction patterns are substrings ("config/SYSTEM" also matches
    ``config/systemprofile/...``): a file the tool would not have used
    anyway must not be reported as a missing piece of the artifact.
    """
    wanted = {n.lower() for n in names}
    return [f for f in failures if f.path.replace("\\", "/").rsplit("/", 1)[-1].lower() in wanted]


def extraction_failure_fields(failures: list[IcatFailure]) -> dict[str, object]:
    """Response fields listing files that exist in the image but could not be read."""
    if not failures:
        return {}
    return {
        "extraction_failures": [f.as_dict() for f in failures[:10]],
        "extraction_failure_count": len(failures),
        "extraction_note": (
            f"{len(failures)} matching file(s) exist in the image but could not be read "
            "(see extraction_failures). Their absence from the results is an extraction "
            "failure, not evidence that they do not exist."
        ),
    }


def nothing_extracted_response(
    tc_id: str,
    tool_name: str,
    params: Mapping[str, object],
    t0: float,
    missing_message: str,
    failures: list[IcatFailure],
) -> dict[str, object]:
    """Error for "no input file": *artifact_missing*, or *extraction_failed* if some were seen."""
    if not failures:
        return error_response(
            tc_id,
            tool_name,
            params,
            missing_message,
            (time.monotonic() - t0) * 1000,
            error_type="artifact_missing",
        )
    listed = "; ".join(f"{f.path}: {f.reason}" for f in failures[:5])
    more = f" (and {len(failures) - 5} more)" if len(failures) > 5 else ""
    return error_response(
        tc_id,
        tool_name,
        params,
        f"The input files exist in the image but could not be read: {listed}{more}",
        (time.monotonic() - t0) * 1000,
        error_type="extraction_failed",
        suggestion=(
            "This is a read failure, not evidence that the artifact is absent. Check the "
            "image (run_mmls, run_fsstat) or read the files another way, and record the gap."
        ),
    )


def add_extraction_failures(
    result: dict[str, object], failures: list[IcatFailure]
) -> dict[str, object]:
    """Add the files that could not be read to a tool response (in place)."""
    fields = extraction_failure_fields(failures)
    if fields:
        result.update(fields)
        if result.get("status") == "success":
            result["status"] = "partial"
    return result


def _tsk_extract_files(
    image_path: str,
    path_patterns: list[str],
    predicate: Callable[[str], bool] | None = None,
    failures: list[IcatFailure] | None = None,
    icat_timeout: int = BULK_ICAT_TIMEOUT,
    include_deleted: bool = True,
) -> list[tuple[str, Path]]:
    """Extract files from a disk image via TSK fls + icat.

    Searches all indexed ``tsk.filelist*`` sources (primary and secondary
    partitions) for entries matching any of the *path_patterns*
    (case-insensitive substring match), then extracts each via ``icat``
    using the correct partition offset.

    When no indexed sources exist (e.g. ``run_fls`` has not completed
    yet), runs fls inline on the primary partition as a fallback.

    Args:
        image_path: Path to the disk image.
        path_patterns: Substring patterns to match against file paths.
        predicate: Optional extra filter on the lower-cased ``/``-separated
            relative path, applied after a pattern matched and before the
            file is extracted.
        failures: When given, receives an :class:`IcatFailure` for every
            matching file that icat could not read.
        icat_timeout: Seconds allowed per file (large databases need more).
        include_deleted: When False, deleted fls entries are skipped: for
            parsers that must not mistake a deleted file for a live one
            (the tuples returned do not say which is which).

    Returns:
        List of ``(relative_path, extracted_path)`` tuples.
    """
    if is_triage_root(image_path):
        return _triage_extract_files(image_path, path_patterns, predicate)

    chunk_groups = _collect_fls_chunks(image_path)
    if not chunk_groups:
        return []

    ctx = get_ctx()
    extract_dir: Path | None = None
    extracted: list[tuple[str, Path]] = []
    seen: set[str] = set()

    for chunks, offset in chunk_groups:
        for chunk in chunks:
            for entry in fls_file_entries(chunk):
                inode_str = entry.base_inode
                rel_path = entry.path
                rel_lower = rel_path.lower().replace("\\", "/")

                if not any(pat.lower() in rel_lower for pat in path_patterns):
                    continue
                if entry.deleted and not include_deleted:
                    continue
                if predicate is not None and not predicate(rel_lower):
                    continue
                dedup_key = f"{offset}:{inode_str}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                if extract_dir is None:
                    extract_dir = Path(tempfile.mkdtemp(prefix="mulder_tsk_extract_"))
                    with _tsk_lock:
                        _tsk_extract_dirs.append(str(extract_dir))
                    ctx.db.set_kv("tsk_extract_dir", str(extract_dir))

                safe_name = rel_path.replace("/", "_").replace("\\", "_")
                out_path = extract_dir / safe_name
                ok, reason = icat_file(
                    image_path, offset, inode_str, out_path, timeout=icat_timeout
                )
                if ok:
                    extracted.append((rel_path, out_path))
                elif reason is not None and entry.deleted:
                    # A deleted entry whose clusters were reused often cannot be
                    # read: that is expected, not a gap in the live artifact.
                    logger.debug(
                        "Cannot extract deleted %s (inode %s): %s", rel_path, inode_str, reason
                    )
                elif reason is not None:
                    logger.warning("Cannot extract %s (inode %s): %s", rel_path, inode_str, reason)
                    if failures is not None:
                        failures.append(IcatFailure(rel_path, inode_str, reason))

    return extracted


def _triage_extract_files(
    root: str,
    path_patterns: list[str],
    predicate: Callable[[str], bool] | None = None,
) -> list[tuple[str, Path]]:
    """``_tsk_extract_files`` for a triage root: copy matching files, no Sleuth Kit.

    Matching is the same case-insensitive substring test applied to the
    same relative path shape as ``fls -r -p``, and the output is the same:
    files copied under their flattened path into a registered
    ``mulder_tsk_extract_*`` directory that the caller removes with
    ``_cleanup_tsk_extract_dir``. Copies (not links) keep the collection
    untouched if a parser opens a hive for writing.

    Args:
        root: Triage root directory.
        path_patterns: Substring patterns to match against file paths.

    Returns:
        List of ``(relative_path, extracted_path)`` tuples.
    """
    patterns = [p.lower().replace("\\", "/") for p in path_patterns]
    extract_dir: Path | None = None
    extracted: list[tuple[str, Path]] = []
    for rel_path, src in iter_tree_files(root):
        rel_lower = rel_path.lower()
        if not any(pat in rel_lower for pat in patterns):
            continue
        if predicate is not None and not predicate(rel_lower):
            continue
        if extract_dir is None:
            extract_dir = Path(tempfile.mkdtemp(prefix="mulder_tsk_extract_"))
            with _tsk_lock:
                _tsk_extract_dirs.append(str(extract_dir))
            get_ctx().db.set_kv("tsk_extract_dir", str(extract_dir))
        out_path = extract_dir / rel_path.replace("/", "_")
        try:
            shutil.copyfile(src, out_path)
        except OSError as exc:
            logger.warning("Could not stage %s from triage root %s: %s", rel_path, root, exc)
            continue
        extracted.append((rel_path, out_path))
    return extracted


def _triage_redirect(
    tc_id: str,
    tool_name: str,
    params: Mapping[str, object],
    image_path: str,
    suggestion: str = "",
) -> dict[str, object] | None:
    """An error response for image-only tools called on a triage collection.

    Partition tables, file listings, carving and volume encryption only
    exist on a raw image. A triage root is a directory of collected files,
    so these tools do not apply; the response names the tools that do.
    """
    if not is_triage_root(image_path):
        return None
    return error_response(
        tc_id,
        tool_name,
        params,
        f"{image_path} is a triage collection (collected files, not a raw disk image); "
        f"{tool_name} does not apply",
        error_type="not_applicable_triage",
        suggestion=suggestion
        or (
            "Use the Windows artifact parsers directly on this path (run_registry_parser, "
            "run_prefetch_parser, run_amcache_parser, run_shimcache_parser, run_mft_parser, "
            "run_usn_parser, run_lnk_parser, run_jumplist_parser, run_shellbags_parser, "
            "run_srum_parser, run_evtx_parser, run_hayabusa); the $MFT parsed by "
            "run_mft_parser is the file inventory and MAC timeline."
        ),
    )


def _optical_redirect(
    tc_id: str, tool_name: str, params: Mapping[str, object], image_path: str
) -> dict[str, object] | None:
    """An error response pointing at run_optical_listing when *image_path* is a disc.

    Sleuth Kit has no UDF/ISO 9660 support: on a burned CD-R ``fls`` and
    ``fsstat`` exit 1 with "Possible encryption detected (High entropy)" and
    ``mmls`` finds no partition table, which sent every model in the NDLC
    benchmark looking for the disc's files on other devices.
    """
    media = probe_optical(image_path)
    if media is None:
        return None
    return error_response(
        tc_id,
        tool_name,
        params,
        f"optical media ({media.upper()}) - Sleuth Kit cannot read CD/DVD filesystems; "
        "use run_optical_listing",
        error_type="optical_media",
        suggestion=(
            f"Call run_optical_listing(image_path={image_path!r}) to list the disc "
            "(deleted files included), then extract_optical_file for individual files."
        ),
    )


def _classify_mmls_failure(returncode: int, stderr: str) -> tuple[str, str, str]:
    """Classify an mmls failure into an error type, message, and suggestion.

    Returns:
        A (error_type, error_message, suggestion) tuple.
    """
    stderr_lower = stderr.strip().lower()

    ewf_indicators = ("ewf", "libewf", "e01", "expert witness")
    if any(kw in stderr_lower for kw in ewf_indicators):
        return (
            "ewf_unsupported",
            f"mmls cannot read this E01 image (exit {returncode}): {stderr[:300]}",
            "The SleuthKit binary may lack libewf support. "
            "Try mounting the E01 with ewfmount first, then pass the "
            "raw device path to run_fls with partition_offset=0.",
        )

    if not stderr_lower:
        return (
            "no_partition_table",
            f"mmls found no partition table (exit {returncode}). "
            "This image is likely a partition dump or single-filesystem "
            "image rather than a full disk.",
            "Skip mmls and call run_fls with partition_offset=0 to "
            "list files directly from the filesystem.",
        )

    return (
        "mmls_failed",
        f"mmls exited {returncode}: {stderr[:300]}",
        "If the image is a partition dump rather than a full disk, "
        "call run_fls with partition_offset=0 directly.",
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_mmls(image_path: str) -> dict[str, object]:
    """List partitions in a disk image using TSK mmls.

    Call first on any disk image to discover partition layout before
    running run_fls or other disk extraction tools.

    Indexes as ``tsk.partitions``; provides the sector offsets needed
    by downstream tools.

    Args:
        image_path: Path to the disk image (E01, dd, img).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    redirect = _triage_redirect(tc_id, "run_mmls", params, image_path)
    if redirect is not None:
        return redirect

    if not require_binary("mmls"):
        return error_response(
            tc_id, "run_mmls", params, "mmls not found on PATH", error_type="binary_missing"
        )

    run = run_tool(["mmls", image_path], timeout=60)
    if run.timed_out or run.launch_error is not None:
        return error_response(
            tc_id,
            "run_mmls",
            params,
            run.describe(),
            (time.monotonic() - t0) * 1000,
            error_type=run.error_type,
        )

    if run.failed:
        redirect = _optical_redirect(tc_id, "run_mmls", params, image_path)
        if redirect is not None:
            return redirect
        stderr_text = run.stderr.strip()
        error_type, error_msg, suggestion = _classify_mmls_failure(
            run.returncode if run.returncode is not None else -1, stderr_text
        )
        logger.info("mmls failed on %s: %s", image_path, error_type)
        return error_response(
            tc_id,
            "run_mmls",
            params,
            error_msg,
            (time.monotonic() - t0) * 1000,
            error_type=error_type,
            suggestion=suggestion,
        )

    summary = extract_and_index(run.stdout.strip(), "tsk.partitions", image_path, "sleuthkit")
    _add_warning(summary, run.warning())
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_mmls", params, summary, "tsk.partitions", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_fls(
    image_path: str,
    partition_offset: int | None = None,
    force: bool = False,
) -> dict[str, object]:
    """List all files and directories (including deleted) from a disk image.

    Call after run_mmls on disk images. Partition offset is auto-detected
    if omitted. Required before run_evtx_parser and run_registry_parser
    which use the file listing to locate artifacts via inode extraction.

    Indexes the primary (largest) partition as ``tsk.filelist`` and any
    additional non-trivial partitions as ``tsk.filelist.p1``,
    ``tsk.filelist.p2``, etc.  Entries marked with ``*`` are deleted
    files.  Searchable via ``search(query, source='tsk.filelist')``.

    Args:
        image_path: Path to the disk image.
        partition_offset: Sector offset of the partition.  Auto-detected
            via mmls if omitted.  When provided explicitly, only that
            single partition is analyzed.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "partition_offset": partition_offset, "force": force}

    redirect = _triage_redirect(tc_id, "run_fls", params, image_path)
    if redirect is not None:
        return redirect
    explicit_offset = partition_offset is not None

    if not force:
        existing = sources_already_indexed(["tsk.filelist"], evidence_path=image_path)
        if existing:
            return tool_response(
                tc_id,
                "run_fls",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "tsk.filelist",
                0.0,
            )

    if not require_binary("fls"):
        return error_response(
            tc_id, "run_fls", params, "fls not found on PATH", error_type="binary_missing"
        )

    if partition_offset is None:
        ctx = get_ctx()
        stored = ctx.db.get_kv(f"{_KV_OFFSET_PREFIX}{image_path}")
        if stored is not None:
            with contextlib.suppress(ValueError):
                partition_offset = int(stored)
        if partition_offset is None:
            partition_offset = 0

    def _try_fls(offset: int) -> ToolRun:
        cmd = ["fls", "-r", "-p"]
        if offset > 0:
            cmd.extend(["-o", str(offset)])
        cmd.append(image_path)
        return run_tool(cmd, timeout=TOOL_TIMEOUT)

    run = _try_fls(partition_offset)
    if run.timed_out:
        return error_response(
            tc_id,
            "run_fls",
            params,
            f"{run.describe()} (partition_offset={partition_offset})",
            (time.monotonic() - t0) * 1000,
            error_type="timeout",
        )

    lookup: list[str] = []
    if not run.ok and partition_offset == 0:
        detected = _detect_partition_offset(image_path, problems=lookup)
        if detected > 0:
            logger.info(
                "run_fls: offset 0 failed, retrying with mmls-detected offset %d",
                detected,
            )
            retry = _try_fls(detected)
            if retry.timed_out:
                return error_response(
                    tc_id,
                    "run_fls",
                    params,
                    f"{retry.describe()} on retry (partition_offset={detected})",
                    (time.monotonic() - t0) * 1000,
                    error_type="timeout",
                )
            if not (retry.failed and run.has_output):
                run = retry
                partition_offset = detected

    if not run.ok or not run.has_output:
        redirect = _optical_redirect(tc_id, "run_fls", params, image_path)
        if redirect is not None:
            return redirect

    if run.failed:
        message = (
            f"{run.describe()} (tried partition_offset={partition_offset}). "
            "Run run_mmls first to find the correct NTFS partition offset, then retry "
            "run_fls with that offset."
        )
        if lookup:
            message += f" Partition lookup: {'; '.join(lookup)}"
        return error_response(
            tc_id,
            "run_fls",
            params,
            message,
            (time.monotonic() - t0) * 1000,
            error_type="extraction_failed" if run.error_type == "tool_failed" else run.error_type,
        )

    ctx = get_ctx()
    ctx.db.set_kv(f"{_KV_OFFSET_PREFIX}{image_path}", str(partition_offset))
    ctx.db.set_kv(
        f"{_KV_SOURCE_OFFSET_PREFIX}tsk.filelist:{image_path}",
        str(partition_offset),
    )

    summary = extract_and_index(run.stdout.strip(), "tsk.filelist", image_path, "sleuthkit")
    _add_warning(summary, run.warning())

    if not explicit_offset:
        failed_parts: list[dict[str, object]] = []
        table_problems: list[str] = []
        secondary = _index_secondary_partitions(
            image_path, partition_offset, failed_parts, table_problems
        )
        if secondary:
            summary["secondary_partitions"] = secondary
        if failed_parts:
            summary["secondary_partition_failures"] = failed_parts
            _add_warning(
                summary,
                f"fls failed or stopped early on {len(failed_parts)} secondary partition(s) "
                "(see secondary_partition_failures): files on those partitions are missing "
                "from the listing, which is not evidence that they do not exist.",
            )
        if table_problems:
            summary["partition_note"] = (
                "Only the primary partition was listed; secondary partitions were not "
                f"scanned: {'; '.join(table_problems)}"
            )

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_fls", params, summary, "tsk.filelist", elapsed)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_mactime(image_path: str, time_range: str | None = None) -> dict[str, object]:
    """Generate a filesystem MAC timeline from a disk image using TSK fls + mactime.

    Call on disk images when you need file modification/access/change
    timestamps. Automatically detects partition offset. Use time_range
    to narrow to an incident window.

    Indexes as ``tsk.timeline``; timestamps are in mactime CSV format,
    queryable via search() and get_timeline().

    Args:
        image_path: Path to the disk image.
        time_range: Optional date range filter for mactime (e.g.
            "2015-08-01..2015-08-05").
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path, "time_range": time_range}

    redirect = _triage_redirect(tc_id, "run_mactime", params, image_path)
    if redirect is not None:
        return redirect

    for binary in ("fls", "mactime"):
        if not require_binary(binary):
            return error_response(
                tc_id,
                "run_mactime",
                params,
                f"{binary} not found on PATH",
                error_type="binary_missing",
            )

    if time_range and not _MACTIME_RANGE_RE.match(time_range.strip()):
        return error_response(
            tc_id,
            "run_mactime",
            params,
            f"Invalid time_range {time_range!r}: mactime takes yyyy-mm-dd or "
            "yyyy-mm-dd..yyyy-mm-dd (each date optionally with Thh:mm:ss)",
            (time.monotonic() - t0) * 1000,
            error_type="invalid_parameter",
            suggestion='For example time_range="2015-08-01..2015-08-05".',
        )

    lookup: list[str] = []
    offset = _resolve_partition_offset(image_path, lookup)
    fls_cmd = ["fls", "-r", "-m", "/"]
    if offset > 0:
        fls_cmd.extend(["-o", str(offset)])
    fls_cmd.append(image_path)

    fls_run = run_tool(fls_cmd, timeout=TOOL_TIMEOUT)
    if not fls_run.has_output:
        if fls_run.ok:
            message = f"fls produced no bodyfile output at partition offset {offset}"
        else:
            message = (
                f"fls could not build the bodyfile at partition offset {offset}: "
                f"{fls_run.describe()}"
            )
        if lookup:
            message += f" ({'; '.join(lookup)})"
        return error_response(
            tc_id,
            "run_mactime",
            params,
            message,
            (time.monotonic() - t0) * 1000,
            error_type=fls_run.error_type,
            suggestion=(
                "Run run_mmls to find the filesystem's partition offset and run_fls with it; "
                "run_mactime reuses the offset run_fls stored."
            ),
        )

    mac_cmd = ["mactime", "-b", "-", "-d"]
    if time_range:
        # One argument: mactime reads only ARGV[0] and splits it on "..".
        # Passing the two dates separately silently dropped the end date.
        mac_cmd.append(time_range.strip())

    mac_run = run_tool(mac_cmd, timeout=TOOL_TIMEOUT, input_text=fls_run.stdout)
    if not mac_run.ok and not _mactime_rows(mac_run.stdout):
        return error_response(
            tc_id,
            "run_mactime",
            params,
            f"mactime failed on the fls bodyfile: {mac_run.describe()}",
            (time.monotonic() - t0) * 1000,
            error_type=mac_run.error_type,
        )

    summary = extract_and_index(mac_run.stdout.strip(), "tsk.timeline", image_path, "sleuthkit")
    if mac_run.ok and not _mactime_rows(mac_run.stdout):
        summary["note"] = "mactime ran and found no filesystem activity" + (
            f" in {time_range}" if time_range else ""
        )
    _add_warning(summary, fls_run.warning())
    _add_warning(summary, mac_run.warning())
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_mactime", params, summary, "tsk.timeline", elapsed)


_MACTIME_DATE = r"\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2})?"
_MACTIME_RANGE_RE = re.compile(rf"^{_MACTIME_DATE}(?:\.\.{_MACTIME_DATE})?$")
"""The date range forms mactime accepts (``parse_isodate`` in mactime.base)."""


def _mactime_rows(stdout: str) -> bool:
    """Whether mactime printed any timeline row (beyond the ``-d`` CSV header)."""
    return any(line.strip() and not line.startswith("Date,") for line in stdout.splitlines())


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_fsstat(image_path: str) -> dict[str, object]:
    """Retrieve filesystem metadata (type, block size, volume label) from a disk image.

    Call on disk images to identify the filesystem type and configuration
    before deeper analysis. Useful for confirming NTFS vs FAT vs ext.

    Indexes as ``tsk.fsstat``; output includes filesystem version, cluster
    size, and volume serial number.

    Args:
        image_path: Path to the disk image.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params = {"image_path": image_path}

    redirect = _triage_redirect(tc_id, "run_fsstat", params, image_path)
    if redirect is not None:
        return redirect

    if not require_binary("fsstat"):
        return error_response(
            tc_id, "run_fsstat", params, "fsstat not found on PATH", error_type="binary_missing"
        )

    lookup: list[str] = []
    offset = _resolve_partition_offset(image_path, lookup)
    cmd = ["fsstat"]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.append(image_path)

    run = run_tool(cmd, timeout=60)
    if not run.ok and not run.timed_out:
        redirect = _optical_redirect(tc_id, "run_fsstat", params, image_path)
        if redirect is not None:
            return redirect

    if run.failed:
        message = f"fsstat failed at partition offset {offset}: {run.describe()}"
        if lookup:
            message += f" ({'; '.join(lookup)})"
        return error_response(
            tc_id,
            "run_fsstat",
            params,
            message,
            (time.monotonic() - t0) * 1000,
            error_type=run.error_type,
            suggestion=(
                "Run run_mmls to list the partitions, then run_fls with the filesystem's "
                "partition_offset (run_fsstat reuses the offset run_fls stored)."
            ),
        )

    summary = extract_and_index(run.stdout.strip(), "tsk.fsstat", image_path, "sleuthkit")
    _add_warning(summary, run.warning())
    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(tc_id, "run_fsstat", params, summary, "tsk.fsstat", elapsed)
