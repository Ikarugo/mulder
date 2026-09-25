"""Normalize collector output into triage roots (``mulder prepare-triage``).

Supported inputs:

* **Velociraptor offline collection**, as the zip the collector produced or
  that zip extracted. Uploaded files live under ``uploads/<accessor>/`` with
  percent-encoded path components (``C%3A``, ``%5C%5C.%5CC%3A`` for the raw
  NTFS device). The same file may be collected by several accessors; the
  ``ntfs`` copy wins over ``auto`` and ``file`` because it was read from the
  raw volume. ``results/`` and the collection metadata are kept under
  ``_collector/velociraptor/`` for later ingestion.
* **KAPE target destination**: drive-letter folders (``C/``, ``D/``) that
  already mirror each volume, optionally one level down in a timestamped
  folder. Other files (copy logs) go to ``_collector/kape/``.
* **Plain tree**: a directory that is itself the root of a volume (a copy of
  ``C:\\``, as distributed with many training labs).

Output layout, one directory per host::

    <out>/<HOSTNAME>/C/...                 triage root for volume C:
    <out>/<HOSTNAME>/_collector/...        collector metadata and results
    <out>/<HOSTNAME>/TRIAGE_MANIFEST.json  provenance, hashes, coverage

Files are copied (never linked) so the output is self-contained and a tool
that opens a hive for writing cannot alter the original collection. Every
copied file is hashed with SHA-256 while it is written; the manifest maps
each output file back to its entry in the source collection.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import json
import logging
import os
import re
import shutil
import time
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import IO, Any
from urllib.parse import unquote

from mulder.triage import child_ci, descend_ci, detect_raw_collection, is_triage_root

logger = logging.getLogger(__name__)

MANIFEST_NAME = "TRIAGE_MANIFEST.json"
COLLECTOR_DIR = "_collector"

# Accessor precedence when the same file was uploaded more than once.
_ACCESSOR_RANK = {"ntfs": 3, "auto": 2, "file": 1}

_DRIVE_RE = re.compile(r"^(?://[.?]/)?([A-Za-z]):(?:/(.*))?$")
_VSS_RE = re.compile(
    r"^//[.?]/GLOBALROOT/Device/(HarddiskVolumeShadowCopy\d+)(?:/(.*))?$", re.IGNORECASE
)
_COLLECTION_NAME_RE = re.compile(r"^Collection-(.+?)-\d{4}-\d{2}-\d{2}", re.IGNORECASE)
_KAPE_VSS_RE = re.compile(r"^vss(\d+)$", re.IGNORECASE)
_HOST_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")

_COPY_CHUNK = 1024 * 1024


class TriagePrepareError(Exception):
    """Raised when a collection cannot be normalized."""


@dataclass
class _SourceEntry:
    """One file inside the source collection (zip member or file on disk)."""

    name: str
    size: int
    mtime: float | None
    opener: Callable[[], IO[bytes]]


@dataclass
class _Planned:
    """A source entry scheduled to be written at *dest* (relative to the host dir)."""

    dest: str
    entry: _SourceEntry
    rank: int


@dataclass
class PrepareResult:
    """Outcome of a normalization run."""

    host_dir: Path
    hostname: str
    kind: str
    triage_roots: list[Path]
    files_written: int
    bytes_written: int
    coverage: dict[str, dict[str, object]]
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Source access
# ---------------------------------------------------------------------------


class _Source:
    """Uniform read access to a collection stored as a zip or a directory."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._zip: zipfile.ZipFile | None = None
        if path.is_file():
            try:
                self._zip = zipfile.ZipFile(path)
            except zipfile.BadZipFile as exc:
                raise TriagePrepareError(f"Not a zip archive: {path}") from exc

    def close(self) -> None:
        """Release the underlying zip handle, if any."""
        if self._zip is not None:
            self._zip.close()

    def entries(self) -> Iterator[_SourceEntry]:
        """Yield every regular file in the collection."""
        if self._zip is not None:
            zf = self._zip
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.flag_bits & 0x1:
                    raise TriagePrepareError(
                        f"{self.path.name} is encrypted ({info.filename}). Decrypt it first "
                        "(for a password-protected Velociraptor collection: 7z x with the "
                        "password) and pass the extracted directory."
                    )
                mtime = _zip_mtime(info)
                yield _SourceEntry(
                    name=info.filename,
                    size=info.file_size,
                    mtime=mtime,
                    opener=functools.partial(zf.open, info),
                )
            return

        for dirpath, dirnames, filenames in os.walk(self.path, followlinks=False):
            dirnames.sort()
            for fname in sorted(filenames):
                full = Path(dirpath) / fname
                try:
                    st = full.stat()
                except OSError:
                    continue
                if not full.is_file():
                    continue
                yield _SourceEntry(
                    name=full.relative_to(self.path).as_posix(),
                    size=st.st_size,
                    mtime=st.st_mtime,
                    opener=functools.partial(_open_binary, full),
                )

    def read_json(self, name: str) -> dict[str, Any] | None:
        """Return the JSON object stored at *name* (top level), or None."""
        try:
            if self._zip is not None:
                raw = self._zip.read(name)
            else:
                candidate = child_ci(self.path, name)
                if candidate is None:
                    return None
                raw = candidate.read_bytes()
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except (KeyError, OSError, ValueError):
            return None
        if isinstance(data, list) and data and isinstance(data[0], dict):
            data = data[0]
        return data if isinstance(data, dict) else None


def _open_binary(path: Path) -> IO[bytes]:
    return path.open("rb")


def _zip_mtime(info: zipfile.ZipInfo) -> float | None:
    try:
        return time.mktime((*info.date_time, 0, 0, -1))
    except (OverflowError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Path mapping
# ---------------------------------------------------------------------------


def _safe_parts(path: str) -> list[str] | None:
    """Split *path* into components, rejecting traversal and empty names."""
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    return parts


def map_velociraptor_path(name: str, include_vss: bool = False) -> tuple[str, int] | None:
    """Map a Velociraptor upload path to ``(dest_relative_path, accessor_rank)``.

    ``uploads/ntfs/%5C%5C.%5CC%3A/$MFT`` maps to ``C/$MFT``;
    ``uploads/auto/C%3A/Windows/System32/config/SAM`` maps to
    ``C/Windows/System32/config/SAM``. Shadow copies map to
    ``_vss/HarddiskVolumeShadowCopyN/...`` when *include_vss* is set and are
    dropped otherwise. Anything else under ``uploads/`` lands in
    ``_collector/velociraptor/uploads/``. Returns None for entries to skip.
    """
    parts = name.split("/")
    if len(parts) < 3 or parts[0].lower() != "uploads":
        return None
    accessor = parts[1].lower()
    rank = _ACCESSOR_RANK.get(accessor, 0)
    decoded = "/".join(unquote(p) for p in parts[2:]).replace("\\", "/")

    m = _DRIVE_RE.match(decoded)
    if m:
        rest = _safe_parts(m.group(2) or "")
        if not rest:
            return None
        return "/".join([m.group(1).upper(), *rest]), rank

    m = _VSS_RE.match(decoded)
    if m:
        if not include_vss:
            return None
        rest = _safe_parts(m.group(2) or "")
        if not rest:
            return None
        return "/".join(["_vss", m.group(1), *rest]), rank

    raw_rest = _safe_parts("/".join(parts[1:]))
    if not raw_rest:
        return None
    return "/".join([COLLECTOR_DIR, "velociraptor", "uploads", *raw_rest]), 0


def _velociraptor_hostname(src: _Source) -> str | None:
    for fname in ("client_info.json", "collection_context.json"):
        data = src.read_json(fname)
        if not data:
            continue
        for key in ("Hostname", "hostname", "Fqdn", "fqdn"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().split(".")[0]
        info = data.get("client_info") or data.get("ClientInfo")
        if isinstance(info, dict):
            for key in ("Hostname", "hostname", "Fqdn"):
                value = info.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip().split(".")[0]
    m = _COLLECTION_NAME_RE.match(src.path.name)
    if m:
        return m.group(1)
    return None


def _plan_velociraptor(
    src: _Source, include_vss: bool, warnings: list[str]
) -> dict[str, _Planned]:
    plan: dict[str, _Planned] = {}
    duplicates = 0
    for entry in src.entries():
        name = entry.name
        if name.lower().startswith("uploads/"):
            mapped = map_velociraptor_path(name, include_vss=include_vss)
            if mapped is None:
                continue
            dest, rank = mapped
        else:
            parts = _safe_parts(name)
            if not parts:
                continue
            dest, rank = "/".join([COLLECTOR_DIR, "velociraptor", *parts]), 0

        key = dest.lower()
        existing = plan.get(key)
        if existing is not None:
            duplicates += 1
            if existing.rank >= rank:
                continue
        plan[key] = _Planned(dest=dest, entry=entry, rank=rank)

    # Sparse uploads come with a "<file>.idx" range index; the file itself is
    # what the parsers need.
    for key in [k for k in plan if k.endswith(".idx") and k[:-4] in plan]:
        del plan[key]

    if duplicates:
        warnings.append(
            f"{duplicates} files were collected by several accessors; kept the raw NTFS copy."
        )
    return plan


def _find_kape_base(root: Path) -> Path | None:
    """Return the folder holding KAPE's drive-letter directories."""
    candidates = [root]
    try:
        candidates += sorted(c for c in root.iterdir() if c.is_dir())
    except OSError:
        return None
    for cand in candidates:
        try:
            children = list(cand.iterdir())
        except OSError:
            continue
        if any(
            c.is_dir() and len(c.name) == 1 and c.name.isalpha() and is_triage_root(c)
            for c in children
        ):
            return cand
    return None


def _plan_kape(src: _Source, include_vss: bool) -> dict[str, _Planned]:
    base = _find_kape_base(src.path)
    if base is None:
        raise TriagePrepareError(f"No drive-letter folder found in KAPE output {src.path}")
    base_rel = base.relative_to(src.path).as_posix()
    prefix = "" if base_rel == "." else base_rel + "/"

    plan: dict[str, _Planned] = {}
    for entry in src.entries():
        dest_parts: list[str] | None
        if prefix and not entry.name.startswith(prefix):
            outside = _safe_parts(entry.name)
            dest_parts = [COLLECTOR_DIR, "kape", *outside] if outside else None
        else:
            rel = entry.name[len(prefix) :]
            parts = _safe_parts(rel)
            if not parts:
                continue
            head = parts[0]
            if len(head) == 1 and head.isalpha() and len(parts) > 1:
                dest_parts = [head.upper(), *parts[1:]]
            elif _KAPE_VSS_RE.match(head) and len(parts) > 2:
                dest_parts = ["_vss", head.lower(), *parts[1:]] if include_vss else None
            else:
                dest_parts = [COLLECTOR_DIR, "kape", *parts]
        if not dest_parts or len(dest_parts) < 2:
            continue
        dest = "/".join(dest_parts)
        plan[dest.lower()] = _Planned(dest=dest, entry=entry, rank=0)
    return plan


def _plan_tree(src: _Source, drive: str) -> dict[str, _Planned]:
    plan: dict[str, _Planned] = {}
    for entry in src.entries():
        parts = _safe_parts(entry.name)
        if not parts:
            continue
        dest = "/".join([drive.upper(), *parts])
        plan[dest.lower()] = _Planned(dest=dest, entry=entry, rank=0)
    return plan


# ---------------------------------------------------------------------------
# Coverage report
# ---------------------------------------------------------------------------


def _count_files(directory: Path | None, suffix: str) -> int:
    if directory is None or not directory.is_dir():
        return 0
    return sum(1 for p in directory.iterdir() if p.is_file() and p.name.lower().endswith(suffix))


def _file_present(root: Path, parts: tuple[str, ...]) -> bool:
    found = descend_ci(root, parts)
    return found is not None and found.is_file()


def artifact_coverage(root: Path) -> dict[str, object]:
    """Summarize which key Windows artifacts a triage root contains.

    Used for the manifest and the command's summary so the analyst knows
    up front which questions the collection can answer.
    """
    config = ("Windows", "System32", "config")
    hives = {
        h: _file_present(root, (*config, h)) for h in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY")
    }
    users_dir = child_ci(root, "Users")
    ntuser: list[str] = []
    usrclass: list[str] = []
    ps_history: list[str] = []
    if users_dir is not None and users_dir.is_dir():
        for profile in sorted(p for p in users_dir.iterdir() if p.is_dir()):
            if _file_present(profile, ("NTUSER.DAT",)):
                ntuser.append(profile.name)
            if _file_present(
                profile, ("AppData", "Local", "Microsoft", "Windows", "UsrClass.dat")
            ):
                usrclass.append(profile.name)
            if _file_present(
                profile,
                (
                    "AppData",
                    "Roaming",
                    "Microsoft",
                    "Windows",
                    "PowerShell",
                    "PSReadLine",
                    "ConsoleHost_history.txt",
                ),
            ):
                ps_history.append(profile.name)

    extend = child_ci(root, "$Extend")
    usn = False
    if extend is not None and extend.is_dir():
        usn = any(
            p.is_file() and p.name.lower() in ("$j", "$usnjrnl:$j", "$usnjrnl%3a$j")
            for p in extend.iterdir()
        )

    return {
        "registry_hives": hives,
        "ntuser_dat": ntuser,
        "usrclass_dat": usrclass,
        "amcache": _file_present(root, ("Windows", "appcompat", "Programs", "Amcache.hve")),
        "prefetch_files": _count_files(descend_ci(root, ("Windows", "Prefetch")), ".pf"),
        "evtx_files": _count_files(
            descend_ci(root, ("Windows", "System32", "winevt", "Logs")), ".evtx"
        ),
        "mft": _file_present(root, ("$MFT",)),
        "usn_journal": usn,
        "srum": _file_present(root, ("Windows", "System32", "sru", "SRUDB.dat")),
        "scheduled_tasks": (descend_ci(root, ("Windows", "System32", "Tasks")) is not None),
        "powershell_history": ps_history,
    }


def missing_artifacts(coverage: dict[str, object]) -> list[str]:
    """Human-readable list of key artifacts absent from *coverage*."""
    missing: list[str] = []
    hives = coverage.get("registry_hives")
    if isinstance(hives, dict):
        missing += [f"registry hive {h}" for h, ok in hives.items() if not ok]
    labels = {
        "ntuser_dat": "NTUSER.DAT (any user)",
        "amcache": "Amcache.hve",
        "prefetch_files": "Prefetch",
        "evtx_files": "event logs (EVTX)",
        "mft": "$MFT",
        "usn_journal": "USN journal ($J)",
        "srum": "SRUM database",
    }
    for key, label in labels.items():
        if not coverage.get(key):
            missing.append(label)
    return missing


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _sanitize_hostname(name: str) -> str:
    cleaned = _HOST_SAFE_RE.sub("_", name).strip("._-")
    return cleaned or "HOST"


def _copy_entry(entry: _SourceEntry, dest: Path) -> tuple[str, int]:
    """Stream *entry* to *dest*, returning ``(sha256, size)``."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    with entry.opener() as fin, open(dest, "wb") as fout:
        while True:
            chunk = fin.read(_COPY_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            fout.write(chunk)
            size += len(chunk)
    if entry.mtime is not None:
        with contextlib.suppress(OSError):
            os.utime(dest, (entry.mtime, entry.mtime))
    return digest.hexdigest(), size


def detect_kind(path: Path) -> str:
    """Return the collection kind of *path*: velociraptor, kape or tree."""
    kind = detect_raw_collection(path)
    if kind:
        return kind
    if path.is_dir() and is_triage_root(path):
        return "tree"
    raise TriagePrepareError(
        f"Unrecognized collection: {path}. Expected a Velociraptor offline collection "
        "(zip or extracted), a KAPE target destination (C/, D/ folders), or a copy of a "
        "Windows volume root (holding Windows/System32/config or $MFT)."
    )


def prepare_triage(
    source: str | os.PathLike[str],
    out_dir: str | os.PathLike[str],
    hostname: str | None = None,
    kind: str | None = None,
    drive: str = "C",
    include_vss: bool = False,
    force: bool = False,
    progress: Callable[[int, int], None] | None = None,
) -> PrepareResult:
    """Normalize the collection at *source* into ``<out_dir>/<hostname>/``.

    Args:
        source: Velociraptor zip or directory, KAPE destination, or volume copy.
        out_dir: Directory receiving one sub-directory per host.
        hostname: Host name to use; detected from the collection when omitted.
        kind: Force the collection kind (``velociraptor``, ``kape``, ``tree``).
        drive: Drive letter for a plain ``tree`` source.
        include_vss: Keep files collected from volume shadow copies.
        force: Replace an existing output directory for the same host.
        progress: Optional ``callback(files_done, files_total)``.

    Raises:
        TriagePrepareError: The source is not a supported collection, or the
            output directory already exists and *force* is not set.
    """
    src_path = Path(source).expanduser().resolve()
    if not src_path.exists():
        raise TriagePrepareError(f"Source does not exist: {src_path}")
    if len(drive) != 1 or not drive.isalpha():
        raise TriagePrepareError(f"Invalid drive letter: {drive!r}")

    kind = kind or detect_kind(src_path)
    if kind not in ("velociraptor", "kape", "tree"):
        raise TriagePrepareError(f"Unknown collection kind: {kind}")
    if kind in ("kape", "tree") and not src_path.is_dir():
        raise TriagePrepareError(f"A {kind} collection must be a directory: {src_path}")

    src = _Source(src_path)
    warnings: list[str] = []
    try:
        if kind == "velociraptor":
            plan = _plan_velociraptor(src, include_vss, warnings)
            detected = _velociraptor_hostname(src)
        elif kind == "kape":
            plan = _plan_kape(src, include_vss)
            detected = None
        else:
            plan = _plan_tree(src, drive)
            detected = None

        if not plan:
            raise TriagePrepareError(f"No files to normalize in {src_path}")

        host = _sanitize_hostname(hostname or detected or src_path.stem)
        if not hostname and not detected:
            warnings.append(
                f"Host name not found in the collection; using '{host}'. "
                "Pass --hostname to set it."
            )

        out_root = Path(out_dir).expanduser().resolve()
        if out_root == src_path or out_root.is_relative_to(src_path):
            raise TriagePrepareError("The output directory must be outside the source.")
        host_dir = out_root / host
        if host_dir.exists():
            if not force:
                raise TriagePrepareError(f"{host_dir} already exists. Use --force to replace it.")
            shutil.rmtree(host_dir)
        host_dir.mkdir(parents=True)

        records: list[dict[str, object]] = []
        total_bytes = 0
        items = sorted(plan.values(), key=lambda p: p.dest.lower())
        for i, planned in enumerate(items, 1):
            dest = host_dir / PurePosixPath(planned.dest)
            try:
                sha, size = _copy_entry(planned.entry, dest)
            except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
                warnings.append(f"Could not copy {planned.entry.name}: {exc}")
                continue
            total_bytes += size
            records.append(
                {
                    "path": planned.dest,
                    "source": planned.entry.name,
                    "sha256": sha,
                    "size": size,
                }
            )
            if progress is not None:
                progress(i, len(items))
    finally:
        src.close()

    roots = sorted(
        c for c in host_dir.iterdir() if c.is_dir() and len(c.name) == 1 and is_triage_root(c)
    )
    coverage: dict[str, dict[str, object]] = {}
    for root in roots:
        cov = artifact_coverage(root)
        cov["missing"] = missing_artifacts(cov)
        coverage[root.name] = cov
    if not roots:
        warnings.append(
            "No Windows volume root found after normalization (no Windows/System32/config "
            "and no $MFT). Mulder will not run the Windows artifact parsers on this host."
        )

    source_hash = None
    if src_path.is_file():
        digest = hashlib.sha256()
        with open(src_path, "rb") as f:
            for chunk in iter(lambda: f.read(_COPY_CHUNK), b""):
                digest.update(chunk)
        source_hash = digest.hexdigest()

    manifest = {
        "generator": "mulder prepare-triage",
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": {"path": str(src_path), "kind": kind, "sha256": source_hash},
        "hostname": host,
        "triage_roots": [r.name for r in roots],
        "coverage": coverage,
        "warnings": warnings,
        "files": records,
    }
    (host_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return PrepareResult(
        host_dir=host_dir,
        hostname=host,
        kind=kind,
        triage_roots=roots,
        files_written=len(records),
        bytes_written=total_bytes,
        coverage=coverage,
        warnings=warnings,
    )
