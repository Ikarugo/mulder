"""Windows file-system and user-activity artifacts parsed with EZ Tools.

Five extractors that feed sources the query tools in ``eztools`` and the
composite analyses already read, but that nothing used to populate:

============================  ==============  ================================
Extractor                     EZ tool         Source
============================  ==============  ================================
``run_usn_parser``            MFTECmd         ``ez.usnjrnl`` ($UsnJrnl:$J)
``run_lnk_parser``            LECmd           ``ez.lnkfiles``
``run_jumplist_parser``       JLECmd          ``ez.jumplists``
``run_shellbags_parser``      SBECmd          ``ez.shellbags``
``run_srum_parser``           dissect.esedb   ``ez.srum``
============================  ==============  ================================

Each takes an ``image_path`` that is either a disk image or a triage root
(:mod:`mulder.triage`); files are located with ``_tsk_extract_files``,
which reads an image through Sleuth Kit and a triage root directly.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from mulder.patterns import fls_file_entries
from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    TOOL_TIMEOUT,
    adaptive_timeout,
    error_response,
    make_tool_call_id,
    require_binary,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.misc import _run_ez_tool
from mulder.server.tools.extract.registry import _discover_user_hives_via_tsk
from mulder.server.tools.extract.tsk import (
    IcatFailure,
    _cleanup_tsk_extract_dir,
    _collect_fls_chunks,
    _tsk_extract_files,
    add_extraction_failures,
    icat_file,
    nothing_extracted_response,
)
from mulder.triage import child_ci, is_triage_root, iter_tree_files

__all__ = [
    "run_jumplist_parser",
    "run_lnk_parser",
    "run_shellbags_parser",
    "run_srum_parser",
    "run_usn_parser",
]

SRC_USNJRNL = "ez.usnjrnl"
SRC_LNKFILES = "ez.lnkfiles"
SRC_JUMPLISTS = "ez.jumplists"
SRC_SHELLBAGS = "ez.shellbags"
SRC_SRUM = "ez.srum"

#: A path inside a user profile, modern or XP layout, possibly under
#: ``Windows.old``. Group 1 is the profile (user) name.
_PROFILE_RE = re.compile(r"(?:^|/)(?:users|documents and settings)/([^/]+)/")

#: Names the $J stream is stored under: TSK and Velociraptor keep the
#: ``$UsnJrnl:$J`` stream name, KAPE writes ``$J``.
_USN_NAMES = frozenset({"$usnjrnl:$j", "$j", "$usnjrnl%3a$j"})

_ICAT_TIMEOUT = TOOL_TIMEOUT * 4


def _skipped(tc_id: str, tool: str, params: dict[str, object], source: str) -> dict[str, object]:
    existing = sources_already_indexed([source], evidence_path=str(params["image_path"]))
    if not existing:
        return {}
    return tool_response(
        tc_id,
        tool,
        params,
        {
            "status": "skipped",
            "reason": "Sources already indexed from prior extraction",
            "existing_sources": existing,
        },
        source,
        0.0,
    )


def _in_profile(rel_lower: str) -> bool:
    return _PROFILE_RE.search(rel_lower) is not None


def _run_on_extracted_dir(
    image_path: str,
    patterns: list[str],
    predicate: Callable[[str], bool],
    dll: str,
    extra_args: list[str],
    source: str,
    tool: str,
    tc_id: str,
    params: dict[str, object],
    t0: float,
    missing_message: str,
) -> dict[str, object]:
    """Stage matching files in one directory and run *dll* over it with ``-d``."""
    failures: list[IcatFailure] = []
    extracted = _tsk_extract_files(image_path, patterns, predicate, failures)
    if not extracted:
        return nothing_extracted_response(tc_id, tool, params, t0, missing_message, failures)
    extract_dir = str(extracted[0][1].parent)
    try:
        result = _run_ez_tool(
            dll, ["-d", extract_dir, *extra_args], source, image_path, tc_id, tool, params, t0
        )
    finally:
        _cleanup_tsk_extract_dir(extract_dir)
    return add_extraction_failures(result, failures)


# ---------------------------------------------------------------------------
# $UsnJrnl:$J
# ---------------------------------------------------------------------------


def _icat_to_file(
    image_path: str, offset: int, inode: str, dest: Path, skip_holes: bool = False
) -> bool:
    """Stream ``icat`` output for *inode* to *dest*; True if non-empty."""
    ok, _reason = icat_file(
        image_path, offset, inode, dest, skip_holes=skip_holes, timeout=_ICAT_TIMEOUT
    )
    return ok


def _usn_from_image(
    image_path: str, dest: Path, problems: list[str] | None = None
) -> tuple[Path | None, Path | None]:
    """Extract $J (the named ``$UsnJrnl:$J`` stream) and $MFT from a disk image.

    The stream has to be addressed with its full ``inode-type-id`` from the
    fls listing: the bare inode reads the file's unnamed data attribute,
    which ``$UsnJrnl`` does not have. ``-h`` drops the sparse holes that
    make up most of a $J stream's logical size. Read errors go to
    *problems*, so "not on this volume" and "could not be read" differ.
    """
    if not require_binary("icat"):
        if problems is not None:
            problems.append("icat (Sleuth Kit) is not installed")
        return None, None
    for chunks, offset in _collect_fls_chunks(image_path):
        for chunk in chunks:
            for entry in fls_file_entries(chunk):
                if entry.deleted:
                    continue
                if not entry.path.lower().replace("\\", "/").endswith("$extend/$usnjrnl:$j"):
                    continue
                j_path = dest / "$J"
                ok, reason = icat_file(
                    image_path, offset, entry.inode, j_path, skip_holes=True, timeout=_ICAT_TIMEOUT
                )
                if not ok:
                    if reason is not None and problems is not None:
                        problems.append(f"$J (offset {offset}): {reason}")
                    continue
                mft_path = dest / "$MFT"
                mft_ok, mft_reason = icat_file(
                    image_path, offset, "0", mft_path, timeout=_ICAT_TIMEOUT
                )
                if mft_reason is not None and problems is not None:
                    problems.append(f"$MFT (offset {offset}): {mft_reason}")
                return j_path, (mft_path if mft_ok else None)
    return None, None


def _usn_from_tree(root: str) -> tuple[Path | None, Path | None]:
    """Locate $J and $MFT in a triage root; they are read in place, never copied."""
    base = Path(root)
    mft = child_ci(base, "$MFT")
    extend = child_ci(base, "$Extend")
    j_path: Path | None = None
    if extend is not None and extend.is_dir():
        for child in sorted(extend.iterdir()):
            if child.is_file() and child.name.lower() in _USN_NAMES and child.stat().st_size:
                j_path = child
                break
    return j_path, (mft if mft is not None and mft.is_file() else None)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_usn_parser(image_path: str, force: bool = False) -> dict[str, object]:
    """Parse the NTFS change journal ($UsnJrnl:$J) with MFTECmd (EZ Tools).

    Call on Windows disk images and triage collections to recover file
    creations, deletions, renames and overwrites, including files that no
    longer exist: the journal outlives the $MFT records it describes.
    Pairs $J with the volume's $MFT so every entry gets its full parent
    path. Indexes as ``ez.usnjrnl``; query with
    ``parse_usn_journal(t_start, t_end)`` or ``search(source='ez.usnjrnl')``.

    Args:
        image_path: Disk image, or triage collection directory.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path, "force": force}
    if not force and (skipped := _skipped(tc_id, "run_usn_parser", params, SRC_USNJRNL)):
        return skipped

    with tempfile.TemporaryDirectory(prefix="mulder_usn_") as tmp:
        problems: list[str] = []
        if is_triage_root(image_path):
            j_path, mft_path = _usn_from_tree(image_path)
        else:
            j_path, mft_path = _usn_from_image(image_path, Path(tmp), problems)
        if j_path is None:
            if problems:
                return error_response(
                    tc_id,
                    "run_usn_parser",
                    params,
                    "The $UsnJrnl:$J stream could not be read: " + "; ".join(problems),
                    (time.monotonic() - t0) * 1000,
                    error_type="extraction_failed",
                )
            return error_response(
                tc_id,
                "run_usn_parser",
                params,
                "No $UsnJrnl:$J stream found (not collected, empty, or not an NTFS volume)",
                (time.monotonic() - t0) * 1000,
                error_type="artifact_missing",
            )
        args = ["-f", str(j_path)]
        if mft_path is not None:
            args.extend(["-m", str(mft_path)])
        result = _run_ez_tool(
            "MFTECmd.dll",
            args,
            SRC_USNJRNL,
            image_path,
            tc_id,
            "run_usn_parser",
            params,
            t0,
            timeout=adaptive_timeout(j_path, base=TOOL_TIMEOUT * 2),
        )
        if mft_path is None and result.get("status") != "error":
            result["note"] = (
                "Parsed without the $MFT"
                + (f" ({'; '.join(problems)})" if problems else "")
                + ": entries have file names but not their full parent paths."
            )
        return result


# ---------------------------------------------------------------------------
# LNK files and Jump Lists
# ---------------------------------------------------------------------------


def _is_user_lnk(rel_lower: str) -> bool:
    return rel_lower.endswith(".lnk") and _in_profile(rel_lower)


def _is_jumplist(rel_lower: str) -> bool:
    return rel_lower.endswith(
        (".automaticdestinations-ms", ".customdestinations-ms")
    ) and _in_profile(rel_lower)


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_lnk_parser(image_path: str, force: bool = False) -> dict[str, object]:
    """Parse Windows shortcut (.lnk) files from user profiles with LECmd (EZ Tools).

    Call on Windows disk images and triage collections to show which files,
    folders and removable or network volumes each user opened: Recent
    items, Office recent files and desktop shortcuts record the target path,
    its timestamps, volume serial and the machine it lived on. Indexes as
    ``ez.lnkfiles``; query with ``parse_lnk_files()`` or
    ``search(source='ez.lnkfiles')``.

    Args:
        image_path: Disk image, or triage collection directory.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path, "force": force}
    if not force and (skipped := _skipped(tc_id, "run_lnk_parser", params, SRC_LNKFILES)):
        return skipped
    return _run_on_extracted_dir(
        image_path,
        [".lnk"],
        _is_user_lnk,
        "LECmd.dll",
        ["-q"],
        SRC_LNKFILES,
        "run_lnk_parser",
        tc_id,
        params,
        t0,
        "No .lnk files found in user profiles",
    )


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_jumplist_parser(image_path: str, force: bool = False) -> dict[str, object]:
    """Parse Jump Lists (Automatic/CustomDestinations) with JLECmd (EZ Tools).

    Call on Windows disk images and triage collections to list, per
    application, the files and locations each user opened and when, often
    long after the files and the LNK entries are gone. Indexes as
    ``ez.jumplists``; query with ``parse_jump_lists()`` or
    ``search(source='ez.jumplists')``.

    Args:
        image_path: Disk image, or triage collection directory.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path, "force": force}
    if not force and (skipped := _skipped(tc_id, "run_jumplist_parser", params, SRC_JUMPLISTS)):
        return skipped
    return _run_on_extracted_dir(
        image_path,
        ["automaticdestinations-ms", "customdestinations-ms"],
        _is_jumplist,
        "JLECmd.dll",
        ["-q"],
        SRC_JUMPLISTS,
        "run_jumplist_parser",
        tc_id,
        params,
        t0,
        "No Jump List files found in user profiles",
    )


# ---------------------------------------------------------------------------
# Shellbags
# ---------------------------------------------------------------------------

_USER_HIVE_BASENAMES = ("ntuser.dat", "usrclass.dat")


def _stage_user_hives(image_path: str, dest: Path) -> int:
    """Copy each user's NTUSER.DAT/UsrClass.dat into ``dest/<user>/`` under their real names.

    SBECmd recognizes hives by file name, so the flattened names used
    elsewhere will not do. From a triage root the hives' transaction logs
    (``.LOG1``/``.LOG2``) come along, so dirty hives are replayed.
    Returns the number of hives staged.
    """
    staged = 0
    if is_triage_root(image_path):
        for rel, src in iter_tree_files(image_path):
            rel_lower = rel.lower()
            name = rel_lower.rsplit("/", 1)[-1]
            if not name.startswith(_USER_HIVE_BASENAMES):
                continue
            base = next(b for b in _USER_HIVE_BASENAMES if name.startswith(b))
            if name != base and not name.startswith(f"{base}.log"):
                continue
            m = _PROFILE_RE.search(rel_lower)
            if m is None:
                continue
            # One folder per profile path ("Users_alice", "Windows.old_Users_alice"):
            # SBECmd reports it as the source, which names the user.
            user_dir = dest / rel[: m.end(1)].replace("/", "_")
            user_dir.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, user_dir / src.name)
            staged += name == base
        return staged

    hives, tmp_dir = _discover_user_hives_via_tsk(image_path)
    try:
        for path, hive_type, username in hives:
            target = "NTUSER.DAT" if hive_type == "ntuser" else "UsrClass.dat"
            # Same user name twice (Windows.old): keep both, in separate folders.
            user_dir = dest / username
            n = 2
            while (user_dir / target).exists():
                user_dir = dest / f"{username}_{n}"
                n += 1
            user_dir.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, user_dir / target)
            staged += 1
    finally:
        if tmp_dir:
            _cleanup_tsk_extract_dir(tmp_dir)
    return staged


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_shellbags_parser(image_path: str, force: bool = False) -> dict[str, object]:
    """Parse Shellbags from user registry hives with SBECmd (EZ Tools).

    Call on Windows disk images and triage collections to reconstruct the
    folders each user browsed in Explorer, including folders on USB drives,
    network shares and ZIP archives that no longer exist, with first and
    last interaction times. Indexes as ``ez.shellbags``; query with
    ``parse_shellbags()`` or ``search(source='ez.shellbags')``.

    Args:
        image_path: Disk image, or triage collection directory.
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path, "force": force}
    if not force and (skipped := _skipped(tc_id, "run_shellbags_parser", params, SRC_SHELLBAGS)):
        return skipped

    with tempfile.TemporaryDirectory(prefix="mulder_shellbags_") as tmp:
        if _stage_user_hives(image_path, Path(tmp)) == 0:
            return error_response(
                tc_id,
                "run_shellbags_parser",
                params,
                "No NTUSER.DAT or UsrClass.dat found in user profiles",
                (time.monotonic() - t0) * 1000,
                error_type="artifact_missing",
            )
        return _run_ez_tool(
            "SBECmd.dll",
            ["-d", tmp],
            SRC_SHELLBAGS,
            image_path,
            tc_id,
            "run_shellbags_parser",
            params,
            t0,
        )


# ---------------------------------------------------------------------------
# SRUM
# ---------------------------------------------------------------------------


def _is_srum_input(rel_lower: str) -> bool:
    return rel_lower.endswith("system32/sru/srudb.dat")


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_srum_parser(image_path: str, force: bool = False) -> dict[str, object]:
    """Parse the System Resource Usage Monitor database (SRUDB.dat).

    Call on Windows disk images and triage collections to get about 30 to
    60 days of per-application network bytes sent and received,
    application resource use and run times (``application_timeline``,
    with ``DurationMS``), and network connections: the main evidence of
    exfiltration volume on a host. The database is read in Python
    (dissect.esedb), which works on Linux and on databases copied from a
    running system; SrumECmd cannot run here (it needs Windows' ESE
    engine). Every record is one line of ``ez.srum`` starting with
    ``srum=<table>``, with application paths and user SIDs resolved; query
    with ``search(query, source='ez.srum')``.

    Args:
        image_path: Disk image, or triage collection directory.
        force: Re-run extraction even if sources already exist.
    """
    from mulder.server.tools.extract.ese import SRUM_TABLE_NOTES, read_srum

    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path, "force": force}
    if not force and (skipped := _skipped(tc_id, "run_srum_parser", params, SRC_SRUM)):
        return skipped

    failures: list[IcatFailure] = []
    extracted = _tsk_extract_files(image_path, ["srudb.dat"], _is_srum_input, failures)
    if not extracted:
        return nothing_extracted_response(
            tc_id,
            "run_srum_parser",
            params,
            t0,
            "SRUDB.dat not found (Windows 8+ keeps it in Windows/System32/sru)",
            failures,
        )
    extract_dir = str(extracted[0][1].parent)
    # The live database first (shortest path: Windows/System32/sru), then any
    # other copy (Windows.old, a second volume) if the live one is unreadable.
    candidates = sorted(extracted, key=lambda item: (len(item[0]), item[0]))
    read = None
    used = ""
    problems: list[str] = []
    try:
        for rel, path in candidates:
            try:
                attempt = read_srum(path)
            except Exception as exc:  # noqa: BLE001 - dissect raises several error types
                problems.append(
                    f"{rel}: not readable as an ESE database: {type(exc).__name__}: {exc}"
                )
                continue
            if attempt.lines:
                read, used = attempt, rel
                break
            detail = "; ".join(f"{e['table']}: {e['error']}" for e in attempt.errors)
            problems.append(f"{rel}: no readable SRUM record" + (f" ({detail})" if detail else ""))
    finally:
        _cleanup_tsk_extract_dir(extract_dir)

    if read is None:
        return error_response(
            tc_id,
            "run_srum_parser",
            params,
            "SRUDB.dat could not be read: " + "; ".join(problems),
            (time.monotonic() - t0) * 1000,
            error_type="tool_failed",
            suggestion=(
                "Check the file with query_ese_database(file_path) (it lists what can be "
                "read), and record the gap if the database is damaged."
            ),
        )
    summary = extract_and_index("\n".join(read.lines), SRC_SRUM, image_path, "dissect.esedb")
    summary["records_per_table"] = read.counts
    summary["database_state"] = read.state
    summary["database"] = used
    summary["tables"] = {
        name: SRUM_TABLE_NOTES[name] for name in read.counts if name in SRUM_TABLE_NOTES
    }
    others = [rel for rel, _ in candidates if rel != used]
    if others:
        summary["other_copies_not_read"] = others
    summary["hint"] = (
        "Per-application traffic is in network_data (BytesSent/BytesRecvd); sdp_* tables "
        "are system-wide counters, not traffic of one application. Network interfaces "
        "(InterfaceLuid, L2ProfileId) are not resolved to names."
    )
    warnings: list[str] = [f"{used}: {p}" for p in read.notes]
    warnings += problems
    if note := read.state_note():
        warnings.append(note)
    if read.errors:
        summary["table_errors"] = read.errors
        warnings.append(
            "Some SRUM tables could not be read to the end: "
            + "; ".join(
                f"{e['table']} ({e['records_read']} records read): {e['error']}"
                for e in read.errors
            )
        )
    if warnings:
        summary["tool_warning"] = "\n".join(warnings)
    result = tool_response(
        tc_id, "run_srum_parser", params, summary, SRC_SRUM, (time.monotonic() - t0) * 1000
    )
    return add_extraction_failures(result, failures)
