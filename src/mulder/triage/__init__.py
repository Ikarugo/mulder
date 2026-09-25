"""Triage collections: filesystem trees collected from a live host.

Remote incident response rarely produces a full disk image. Collectors such
as Velociraptor, KAPE or DFIR-ORC copy a targeted set of artifacts (registry
hives, event logs, Prefetch, $MFT, ...) while preserving their original paths.
Once normalized with ``mulder prepare-triage``, such a collection is a plain
directory that mirrors the root of the source volume::

    <out>/<HOSTNAME>/C/$MFT
    <out>/<HOSTNAME>/C/Windows/System32/config/SYSTEM
    <out>/<HOSTNAME>/C/Windows/Prefetch/*.pf
    <out>/<HOSTNAME>/C/Users/<user>/NTUSER.DAT

The directory holding ``Windows`` (``<HOSTNAME>/C`` above) is a *triage
root*. Mulder treats it as a disk image that is already mounted: tools that
take an ``image_path`` accept it, and every step that would read the image
with Sleuth Kit (``fls``/``icat``) or FUSE-mount it reads the tree directly.

This module holds the detection and tree-walking helpers shared by the
classifier and the extraction tools. It performs no writes.
"""

from __future__ import annotations

import os
import zipfile
from collections.abc import Iterator
from pathlib import Path

__all__ = [
    "TRIAGE_ARTIFACT_TYPE",
    "RAW_COLLECTION_ARTIFACT_TYPE",
    "child_ci",
    "descend_ci",
    "detect_raw_collection",
    "find_triage_roots",
    "find_unprepared_collections",
    "is_triage_root",
    "iter_tree_files",
]

#: Artifact type the classifier assigns to a triage root.
TRIAGE_ARTIFACT_TYPE = "triage_collection"

#: Artifact type for a collector output that has not been normalized yet.
RAW_COLLECTION_ARTIFACT_TYPE = "raw_triage_collection"

_VELOCIRAPTOR_MARKERS = ("client_info.json", "collection_context.json", "uploads.json")


def child_ci(parent: Path, name: str) -> Path | None:
    """Return the child of *parent* named *name*, ignoring case, or None.

    Collections copied from NTFS keep the source casing (``Windows`` vs
    ``WINDOWS``); Linux filesystems are case-sensitive, so a plain join is
    not enough.
    """
    direct = parent / name
    if direct.exists():
        return direct
    target = name.lower()
    try:
        for child in parent.iterdir():
            if child.name.lower() == target:
                return child
    except OSError:
        return None
    return None


def descend_ci(root: Path, parts: tuple[str, ...] | list[str]) -> Path | None:
    """Follow *parts* below *root* case-insensitively; None if any step is missing."""
    current = root
    for part in parts:
        nxt = child_ci(current, part)
        if nxt is None:
            return None
        current = nxt
    return current


def is_triage_root(path: str | os.PathLike[str]) -> bool:
    """Return True if *path* is a directory mirroring the root of a Windows volume.

    A triage root holds ``Windows/System32/config`` (the registry hives) or a
    ``$MFT`` copied from the volume. Disk image files are never triage roots.
    """
    p = Path(path)
    try:
        if not p.is_dir():
            return False
    except OSError:
        return False
    config = descend_ci(p, ("Windows", "System32", "config"))
    if config is not None and config.is_dir():
        return True
    mft = child_ci(p, "$MFT")
    return mft is not None and mft.is_file()


def iter_tree_files(root: str | os.PathLike[str]) -> Iterator[tuple[str, Path]]:
    """Yield ``(relative_posix_path, absolute_path)`` for every file below *root*.

    Relative paths use ``/`` and carry no leading slash, the same shape as
    ``fls -r -p`` output, so path patterns written for Sleuth Kit listings
    match unchanged. Directory symlinks are not followed.
    """
    base = Path(root)
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames.sort()
        current = Path(dirpath)
        for name in sorted(filenames):
            abs_path = current / name
            yield abs_path.relative_to(base).as_posix(), abs_path


def detect_raw_collection(path: str | os.PathLike[str]) -> str | None:
    """Identify collector output that must go through ``mulder prepare-triage``.

    Returns ``"velociraptor"`` for a Velociraptor offline collection (a
    directory or zip holding ``uploads/`` next to ``client_info.json`` or
    ``collection_context.json``), ``"kape"`` for a KAPE target destination
    (drive-letter folders such as ``C/`` that mirror a volume), or None.
    """
    p = Path(path)
    try:
        if p.is_file() and p.suffix.lower() == ".zip":
            return _detect_raw_collection_zip(p)
        if not p.is_dir():
            return None
    except OSError:
        return None

    if child_ci(p, "uploads") is not None and any(
        child_ci(p, marker) is not None for marker in _VELOCIRAPTOR_MARKERS
    ):
        return "velociraptor"

    if not is_triage_root(p) and (
        _has_drive_folder(p) or any(_has_drive_folder(c) for c in _subdirs(p))
    ):
        # KAPE writes drive folders into --tdest, or into a timestamped
        # sub-folder of it.
        return "kape"
    return None


def _subdirs(p: Path) -> list[Path]:
    try:
        return sorted(c for c in p.iterdir() if c.is_dir())
    except OSError:
        return []


def _has_drive_folder(p: Path) -> bool:
    """True if *p* holds a drive-letter folder (``C``) that is a triage root."""
    return any(len(c.name) == 1 and c.name.isalpha() and is_triage_root(c) for c in _subdirs(p))


def find_triage_roots(root: str | os.PathLike[str], max_depth: int = 4) -> list[Path]:
    """Return the triage roots at most *max_depth* levels below *root* (or *root* itself).

    The search stops descending at a triage root, so a collected volume is
    never walked in full.
    """
    base = Path(root)
    found: list[Path] = []

    def _visit(p: Path, depth: int) -> None:
        if is_triage_root(p):
            found.append(p)
            return
        if depth >= max_depth:
            return
        try:
            children = sorted(c for c in p.iterdir() if c.is_dir() and not c.name.startswith("."))
        except OSError:
            return
        for child in children:
            _visit(child, depth + 1)

    _visit(base, 0)
    return found


def find_unprepared_collections(
    evidence_path: str | os.PathLike[str], max_depth: int = 2
) -> list[Path]:
    """Return Velociraptor collections under *evidence_path* not yet normalized.

    Mulder cannot read the percent-encoded ``uploads/`` layout directly, so
    ``mulder investigate`` checks for these before spending any tokens. KAPE
    output is not reported: its drive-letter folders are already triage roots.
    Only the first *max_depth* levels are inspected.
    """
    root = Path(evidence_path)
    found: list[Path] = []

    def _visit(p: Path, depth: int) -> None:
        if detect_raw_collection(p) == "velociraptor":
            found.append(p)
            return
        if depth >= max_depth or not p.is_dir():
            return
        try:
            children = sorted(p.iterdir())
        except OSError:
            return
        for child in children:
            if child.name.startswith("."):
                continue
            if child.is_dir() or child.suffix.lower() == ".zip":
                _visit(child, depth + 1)

    _visit(root, 0)
    return found


def _detect_raw_collection_zip(path: Path) -> str | None:
    """Return ``"velociraptor"`` if the zip at *path* is an offline collection."""
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return None
    top = {n.split("/", 1)[0].lower() for n in names}
    if "uploads" in top and any(m in top for m in _VELOCIRAPTOR_MARKERS):
        return "velociraptor"
    return None
