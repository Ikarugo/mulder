"""ESE (JET Blue) databases read in Python: SRUM, Windows Search, and any ``.edb``.

Windows keeps several key artifacts in ESE databases: ``SRUDB.dat``
(per-application resource and network usage), ``Windows.edb`` (the search
index: paths, dates, owners, e-mail headers, content summaries, Timeline
activity) and ``WebCacheV01.dat`` (legacy Edge / Internet Explorer
history). The usual parsers (SrumECmd, ESEDatabaseView) call Windows' own
``esent.dll`` and cannot run in the Linux container. ``dissect.esedb``
reads the file format directly. Windows 11 moved the search index to a
SQLite ``Windows.db``, which is read too.

The ESE reader reads the pages of a database, not its transaction logs:
when a database was copied from a running system ("dirty shutdown"),
changes that were only in the ``.log`` files are missing. Every result
says which state the database was in.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
import shutil
import sqlite3
import tempfile
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    TOOL_TIMEOUT,
    error_response,
    make_tool_call_id,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.tsk import (
    IcatFailure,
    _cleanup_tsk_extract_dir,
    _tsk_extract_files,
    add_extraction_failures,
    nothing_extracted_response,
)
from mulder.triage import is_triage_root, iter_tree_files

__all__ = [
    "ESE_MAGIC",
    "EseReadResult",
    "format_value",
    "is_ese_file",
    "parse_windows_search",
    "query_ese_database",
    "read_srum",
    "read_windows_search",
]

#: Signature at offset 4 of every ESE database header.
ESE_MAGIC = b"\xef\xcd\xab\x89"
SRC_WINDOWS_SEARCH = "windows.search"

_DB_STATES = {
    1: "just created",
    2: "dirty shutdown",
    3: "clean shutdown",
    4: "being converted",
    5: "force detach",
}
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
#: FILETIME values between 1990 and 2100: anything else under a date-like name
#: is a duration, a counter or garbage, and is shown as it is.
_FT_MIN = int((datetime(1990, 1, 1, tzinfo=timezone.utc) - _FILETIME_EPOCH).total_seconds() * 1e7)
_FT_MAX = int((datetime(2100, 1, 1, tzinfo=timezone.utc) - _FILETIME_EPOCH).total_seconds() * 1e7)
_HEX_CAP = 64
_TEXT_CAP = 1000
_LINE_CAP = 6000
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
#: Column names that hold identifiers or hashes: never decoded as text.
_ID_NAME_RE = re.compile(r"(Id|ID|Hash|MD5|Guid|GUID|Luid|LUID|Sid|SID)$")
#: SRUM's application-timeline null marker (dissect handles it after converting).
_SRUM_NULLS = (0x2A2A2A2A2A2A2A2A, 0x2A2A2A2A)


def is_ese_file(path: Path) -> bool:
    """Whether *path* starts with an ESE database header."""
    try:
        with path.open("rb") as fh:
            return fh.read(8)[4:8] == ESE_MAGIC
    except OSError:
        return False


@dataclass
class EseReadResult:
    """Lines read from one database, and what could not be read."""

    lines: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    errors: list[dict[str, object]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    state: str = "unknown"
    truncated: str = ""

    def state_note(self) -> str | None:
        """What the database state means for completeness, when it matters."""
        if self.state in ("clean shutdown", "unknown", "sqlite"):
            return None
        return (
            f"The database is in state '{self.state}' (copied from a running system). Its "
            "pages were read directly; changes still only in its transaction logs (.log "
            "files) are not included, so the most recent records may be missing."
        )


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------


def _iso(dt: datetime, local: bool = False) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    text = dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return text[:-1] + " (local time)" if local and text.endswith("Z") else text


def _filetime(value: int, local: bool = False) -> str | None:
    if not _FT_MIN <= value <= _FT_MAX:
        return None
    return _iso(_FILETIME_EPOCH + timedelta(microseconds=value // 10), local)


def _printable(text: str) -> bool:
    return all(ch.isprintable() or ch in "\t\r\n" for ch in text)


#: Unicode ranges of real text: Latin, Greek, Cyrillic, Hebrew, Arabic,
#: punctuation, CJK, kana, Hangul. Random binary decoded as UTF-16 lands
#: mostly elsewhere (private use, surrogates, rare blocks).
_TEXT_RANGES = (
    (0x20, 0x7E),
    (0xA0, 0x24F),
    (0x370, 0x6FF),
    (0x2000, 0x206F),
    (0x3000, 0x30FF),
    (0x4E00, 0x9FFF),
    (0xAC00, 0xD7AF),
    (0xFF00, 0xFFEF),
)


def _plausible_text(text: str) -> bool:
    if not text or (len(text) < 2 and not text.isascii()):
        return False
    common = sum(
        any(lo <= ord(ch) <= hi for lo, hi in _TEXT_RANGES) or ch in "\t\r\n" for ch in text
    )
    return common >= 0.9 * len(text)


def _bytes_text(value: bytes) -> str | None:
    """*value* as text when it is UTF-16LE or UTF-8 text (NUL-separated lists too)."""
    if not value:
        return None
    candidates: list[str] = []
    if len(value) >= 2 and len(value) % 2 == 0:
        with contextlib.suppress(UnicodeDecodeError):
            candidates.append(value.decode("utf-16-le"))
    with contextlib.suppress(UnicodeDecodeError):
        candidates.append(value.decode("utf-8"))
    for text in candidates:
        parts = [p.strip() for p in text.split("\x00") if p.strip()]
        if parts and all(_printable(p) for p in parts) and _plausible_text("".join(parts)):
            return "; ".join(parts)
    return None


def _hex(value: bytes, cap: int = _HEX_CAP) -> str:
    more = f"...(+{len(value) - cap} bytes)" if len(value) > cap else ""
    return f"hex:{value[:cap].hex()}{more}"


def format_value(
    value: object, *, date_hint: bool = False, local: bool = False, as_text: bool = True
) -> str | None:
    """A cell value as one line of text; None when empty.

    Under a date-like column name, an 8-byte value or an integer in the
    FILETIME range becomes an ISO date (UTC, or marked local time).
    Other bytes are decoded when they are text (UTF-16LE or UTF-8, with
    NUL-separated lists joined by ``;``); anything else binary is capped
    hex, marked as such. *as_text* False keeps identifiers as hex.
    """
    if value is None or value == "" or value == b"":
        return None
    if isinstance(value, datetime):
        return _iso(value, local)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, bytes):
        if date_hint and len(value) == 8:
            stamp = _filetime(int.from_bytes(value, "little"), local)
            if stamp:
                return stamp
        text = _bytes_text(value) if as_text else None
        return _cap(text) if text is not None else _hex(value)
    if isinstance(value, int):
        if date_hint:
            stamp = _filetime(int(value), local)
            if stamp:
                return stamp
        return str(int(value))
    if isinstance(value, str):
        text = value.replace("\x00", " ").strip()
        return _cap(text) if text else None
    return str(value)


def _cap(text: str) -> str:
    text = " ".join(text.split())
    if len(text) <= _TEXT_CAP:
        return text
    return text[:_TEXT_CAP] + f" [...{len(text) - _TEXT_CAP} more chars]"


def _is_date_name(name: str) -> bool:
    return any(k in name for k in ("Time", "Date", "Stamp"))


def _db_state(db: Any) -> str:
    try:
        return _DB_STATES.get(int(db.header.dbstate), f"state {int(db.header.dbstate)}")
    except Exception:  # noqa: BLE001 - informational only
        return "unknown"


# ---------------------------------------------------------------------------
# SRUM
# ---------------------------------------------------------------------------

#: What the provider tables hold, for the agent reading the lines.
SRUM_TABLE_NOTES = {
    "network_data": "per-application bytes sent/received (BytesSent, BytesRecvd)",
    "application": "per-application CPU, I/O and foreground time",
    "application_timeline": "per-application run timeline (EndTime, DurationMS)",
    "network_connectivity": "network connections (ConnectStartTime, ConnectedTime in s)",
    "sdp_network_provider": (
        "cumulative counters per network interface, not per-application traffic"
    ),
    "sdp_volume_provider": "volume usage counters",
}


def read_srum(path: Path) -> EseReadResult:
    """Every record of every SRUM provider table, one line each.

    Application and user IDs are resolved through ``SruDbIdMapTable`` into
    executable paths, service names and SIDs; timestamps are UTC. A value
    that cannot be decoded is kept raw instead of losing the record, and
    a table that breaks part-way keeps the records read before. Raises
    ``dissect.esedb`` errors when the file is not a readable ESE database.
    """
    from dissect.esedb import EseDB
    from dissect.esedb.tools.sru import NAME_TO_GUID_MAP, SKIP_TABLES
    from dissect.util.sid import read_sid
    from dissect.util.ts import oatimestamp

    friendly = {guid: name for name, guid in NAME_TO_GUID_MAP.items()}
    result = EseReadResult()

    with path.open("rb") as fh:
        db = EseDB(fh)
        result.state = _db_state(db)
        id_map: dict[object, Any] = {}
        try:
            id_map = {r.get("IdIndex"): r for r in db.table("SruDbIdMapTable").records()}
        except Exception as exc:  # noqa: BLE001 - ids stay numeric, records are kept
            result.errors.append(
                {"table": "SruDbIdMapTable", "records_read": 0, "error": f"{exc!r}"}
            )

        def resolve(raw: object) -> str:
            record = id_map.get(raw)
            if record is None:
                return f"{raw} (id not in SruDbIdMapTable)"
            blob = record.get("IdBlob")
            if not blob:
                return f"{raw} (empty id)"
            if record.get("IdType") == 3:
                try:
                    return str(read_sid(blob))
                except Exception:  # noqa: BLE001
                    return _hex(bytes(blob))
            text = bytes(blob).decode("utf-16-le", errors="replace").rstrip("\x00")
            return text.replace("\t", " ").strip() or _hex(bytes(blob))

        for table in db.tables():
            if table.name in SKIP_TABLES:
                continue
            name = friendly.get(table.name, table.name)
            columns = [c.name for c in table.columns if c.name != "AutoIncId"]
            count = bad_values = 0
            try:
                for record in table.records():
                    parts = [f"srum={name}"]
                    for column in columns:
                        try:
                            raw = record.get(column)
                            if raw is None or raw in _SRUM_NULLS:
                                continue
                            value: object = raw
                            if column in ("AppId", "UserId"):
                                value = resolve(raw)
                            elif column == "TimeStamp":
                                value = oatimestamp(raw)
                            text = format_value(value, date_hint=_is_date_name(column))
                        except Exception:  # noqa: BLE001 - keep the raw value, not the loss
                            bad_values += 1
                            text = f"{record.get(column)!r} (undecoded)"
                        if text is not None:
                            parts.append(f"{column}={text}")
                    result.lines.append(" | ".join(parts))
                    count += 1
            except Exception as exc:  # noqa: BLE001 - a damaged table must not hide the others
                result.errors.append(
                    {"table": name, "records_read": count, "error": f"{type(exc).__name__}: {exc}"}
                )
            if bad_values:
                result.notes.append(f"{name}: {bad_values} value(s) kept raw (undecodable)")
            result.counts[name] = count
    return result


# ---------------------------------------------------------------------------
# Windows Search
# ---------------------------------------------------------------------------

#: Labelled first, in this order (property names without the "System_" prefix).
_WS_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("path", ("ItemPathDisplay", "ItemUrl")),
    ("modified", ("DateModified",)),
    ("created", ("DateCreated",)),
    ("accessed", ("DateAccessed",)),
    ("size", ("Size",)),
    ("type", ("ItemTypeText", "KindText")),
    ("owner", ("FileOwner",)),
    ("title", ("Title",)),
    ("subject", ("Subject",)),
    ("author", ("Author",)),
    ("from_name", ("Message_FromName",)),
    ("from", ("Message_FromAddress",)),
    ("to_name", ("Message_ToName",)),
    ("to", ("Message_ToAddress",)),
    ("cc", ("Message_CcAddress",)),
    ("sent", ("Message_DateSent",)),
    ("received", ("Message_DateReceived",)),
    ("summary", ("Search_AutoSummary",)),
    ("gathered", ("Search_GatherTime",)),
)
_WS_USED = {name for _, names in _WS_FIELDS for name in names}
#: Properties that repeat the path or carry no evidence; everything else is kept.
_WS_NOISE_RE = re.compile(
    r"^(InvertedOnly.*|ThumbnailCacheId|SFGAOFlags|ParsingName|FileName|ItemName|"
    r"ItemNameDisplay|ItemNameDisplayWithoutExtension|ItemFolderNameDisplay|"
    r"ItemFolderPathDisplay|FolderNameDisplay|.*Narrow|FilePlaceholderStatus|"
    r"Search_AccessCount|Search_LastIndexedTotalTime|Search_Rank|Search_Store|"
    r"Search_HitCount|Search_ReverseFileName|Search_QueryPropertyHits|IsAttachment|"
    r"IsEncrypted|IsFolder|FileAttributes|DateImported|ItemDate|Kind|"
    r"Document_DateCreated|Document_DateSaved|FileExtension|WorkID|"
    r"_ColumnId_\d+)$"
)
_PROPERTY_PREFIX_RE = re.compile(r"^\d+F?-")


def _property_name(column: str) -> str:
    """``4447-System_ItemPathDisplay`` or ``System.ItemPathDisplay`` -> ``ItemPathDisplay``."""
    name = _PROPERTY_PREFIX_RE.sub("", column)
    for prefix in ("System_", "System."):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name.replace(".", "_")


def _ws_value(name: str, value: object) -> str | None:
    if name == "Size" and isinstance(value, bytes) and len(value) == 8:
        return str(int.from_bytes(value, "little"))
    return format_value(
        value,
        date_hint=_is_date_name(name),
        local="Local" in name,
        as_text=not _ID_NAME_RE.search(name),
    )


def _ws_line(work_id: object, props: dict[str, object], prefix: str = "") -> str | None:
    """One indexed item as a line, or None when it holds nothing but noise."""
    parts = [f"{prefix}WorkID={work_id}"]
    for label, names in _WS_FIELDS:
        for name in names:
            text = _ws_value(name, props.get(name))
            if text is not None:
                parts.append(f"{label}={text}")
                break
    for name, value in props.items():
        if name in _WS_USED or _WS_NOISE_RE.match(name):
            continue
        text = _ws_value(name, value)
        if text is not None:
            parts.append(f"{name}={text}")
    if len(parts) == 1:
        return None
    line = " | ".join(parts)
    if len(line) > _LINE_CAP:
        line = line[:_LINE_CAP] + f" [...{len(line) - _LINE_CAP} more chars]"
    return line


def _ese_search_items(
    path: Path, result: EseReadResult
) -> Iterator[tuple[object, dict[str, object]]]:
    from dissect.esedb import EseDB

    with path.open("rb") as fh:
        db = EseDB(fh)
        result.state = _db_state(db)
        names = [t.name for t in db.tables()]
        # Windows 8/10: SystemIndex_PropertyStore; Windows 7: SystemIndex_0A.
        store_name = next(
            (n for n in names if n.endswith("_PropertyStore") or n == "SystemIndex_0A"),
            None,
        )
        if store_name is None:
            raise ValueError(
                f"not a Windows Search index: no *_PropertyStore table "
                f"(tables: {', '.join(names[:15])})"
            )
        table = db.table(store_name)
        columns = [(c.name, _property_name(c.name)) for c in table.columns]
        for record in table.records():
            props: dict[str, object] = {}
            for column, name in columns:
                try:
                    value = record.get(column)
                except Exception:  # noqa: BLE001 - one bad value must not lose the item
                    value = "(undecodable value)"
                if value not in (None, "", b""):
                    props[name] = value
            yield record.get("WorkID"), props


_WAL_NOTE = "present only before the WAL was applied: deleted or changed since"


def _sqlite_search_items(
    path: Path, result: EseReadResult
) -> Iterator[tuple[object, dict[str, object]]]:
    """Items of a Windows 11 ``Windows.db`` (SQLite, one row per item property).

    With a ``-wal`` file next to it, items are read with the WAL applied,
    then the database alone is read for items the WAL removed: Windows
    keeps a deleted file's record in the main database until the WAL is
    checkpointed, so those items are recovered and flagged.
    """
    result.state = "sqlite"
    wal = path.with_name(path.name + "-wal")
    has_wal = wal.is_file() and wal.stat().st_size > 0
    if has_wal:
        result.notes.append(f"{wal.name} applied; items only in the main file are flagged")
    elif wal.is_file():
        result.notes.append(f"{wal.name} is empty: no pending change")
    else:
        result.notes.append(
            f"no {wal.name} next to the database: changes still in the WAL, if the "
            "collector skipped it, are missing"
        )
    with tempfile.TemporaryDirectory(prefix="mulder_winsearch_") as tmpdir:
        main_only = Path(tmpdir) / "main" / "Windows.db"
        main_only.parent.mkdir()
        shutil.copyfile(path, main_only)
        with_wal = main_only
        if has_wal:
            with_wal = Path(tmpdir) / "wal" / "Windows.db"
            with_wal.parent.mkdir()
            shutil.copyfile(path, with_wal)
            shutil.copyfile(wal, with_wal.with_name("Windows.db-wal"))
        seen: set[object] = set()
        for work_id, props in _sqlite_items(with_wal):
            seen.add(work_id)
            yield work_id, props
        if has_wal:
            for work_id, props in _sqlite_items(main_only):
                if work_id not in seen:
                    props["note"] = _WAL_NOTE
                    yield work_id, props


def _sqlite_items(db_path: Path) -> Iterator[tuple[object, dict[str, object]]]:
    conn = sqlite3.connect(str(db_path))
    try:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        store = next((t for t in tables if t.lower().endswith("_propertystore")), None)
        meta = next((t for t in tables if t.lower().endswith("_propertystore_metadata")), None)
        if store is None or meta is None:
            raise ValueError(
                f"not a Windows Search index: no PropertyStore tables "
                f"(tables: {', '.join(tables[:15])})"
            )
        meta_cols = {r[1].lower(): r[1] for r in conn.execute(f'PRAGMA table_info("{meta}")')}
        id_col = meta_cols.get("id")
        name_col = meta_cols.get("uniquekey") or meta_cols.get("name")
        if id_col is None or name_col is None:
            raise ValueError(f"unexpected {meta} columns: {sorted(meta_cols.values())}")
        names = {
            row[0]: _property_name(str(row[1]))
            for row in conn.execute(f'SELECT "{id_col}", "{name_col}" FROM "{meta}"')
        }
        current: object = None
        props: dict[str, object] = {}
        for work_id, column_id, value in conn.execute(
            f'SELECT WorkId, ColumnId, Value FROM "{store}" ORDER BY WorkId'
        ):
            if work_id != current:
                if current is not None:
                    yield current, props
                current, props = work_id, {}
            if value not in (None, "", b""):
                props[names.get(column_id, f"_ColumnId_{column_id}")] = value
        if current is not None:
            yield current, props
    finally:
        conn.close()


def read_windows_search(
    path: Path,
    max_items: int = 200_000,
    time_budget: float = 900.0,
    prefix: str = "",
) -> EseReadResult:
    """Items of a Windows Search index (``Windows.edb`` or ``Windows.db``), one line each.

    Stops at *max_items* items or after *time_budget* seconds and says so
    in ``truncated``. Errors while opening or reading are recorded in
    ``errors`` with the number of items read before them.
    """
    result = EseReadResult()
    with path.open("rb") as fh:
        is_sqlite = fh.read(16).startswith(b"SQLite format 3")
    items = _sqlite_search_items(path, result) if is_sqlite else _ese_search_items(path, result)
    count = 0
    deadline = time.monotonic() + time_budget
    try:
        for work_id, props in items:
            if count >= max_items:
                result.truncated = f"stopped at max_items={max_items}"
                break
            if time.monotonic() > deadline:
                result.truncated = f"stopped after {int(time_budget)}s ({count} items read)"
                break
            line = _ws_line(work_id, props, prefix)
            if line is not None:
                result.lines.append(line)
                count += 1
    except Exception as exc:  # noqa: BLE001 - keep what was read before the damage
        result.errors.append(
            {
                "table": "PropertyStore",
                "records_read": count,
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
    result.counts["items"] = count
    return result


_SEARCH_DIR = "search/data/applications/windows/"
_SEARCH_NAMES = ("windows.edb", "windows.db")
_SEARCH_SIDECARS = ("windows.db-wal", "windows.db-shm")


def _search_databases(
    image_path: str,
) -> tuple[list[tuple[str, Path]], str | None, list[IcatFailure]]:
    """Every Windows Search database: ``(relative path, file)``, a temp dir, failures.

    ``Windows.db`` sidecars (``-wal``, ``-shm``) are staged next to it but
    not returned as databases.
    """
    wanted = tuple(_SEARCH_DIR + n for n in _SEARCH_NAMES)
    staged = tuple(_SEARCH_DIR + n for n in _SEARCH_NAMES + _SEARCH_SIDECARS)
    failures: list[IcatFailure] = []
    if is_triage_root(image_path):
        # Read in place: these files can be several GB and are only opened for reading.
        found = [
            (rel, p) for rel, p in iter_tree_files(image_path) if rel.lower().endswith(wanted)
        ]
        return found, None, failures
    extracted = _tsk_extract_files(
        image_path,
        ["Search/Data/Applications/Windows/"],
        lambda rel: rel.endswith(staged),
        failures,
        icat_timeout=TOOL_TIMEOUT * 4,
    )
    cleanup = str(extracted[0][1].parent) if extracted else None
    databases = [(rel, p) for rel, p in extracted if rel.lower().endswith(wanted)]
    return databases, cleanup, failures


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST)
def parse_windows_search(
    image_path: str, force: bool = False, max_items: int = 200_000
) -> dict[str, object]:
    """Parse the Windows Search index: indexed files, e-mails, contacts, Timeline activity.

    Call on Windows disk images and triage collections. The index
    (``ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb``,
    or ``Windows.db`` on Windows 11) keeps, for each item it indexed, the
    path, dates, size, type and owner, e-mail senders and recipients,
    contact details, Timeline activity (documents opened, by which
    application) and often a summary of the content. Each item is one
    line of ``windows.search``; e-mail addresses found are listed in the
    response. Deleted files: on Windows 10 their records are marked
    deleted and are not read here; on Windows 11 the ones still in the
    main database behind the WAL are recovered and flagged.

    Args:
        image_path: Disk image, or triage collection directory.
        force: Re-run extraction even if the source already exists.
        max_items: Maximum items indexed over all databases (a cut is reported).
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path, "force": force, "max_items": max_items}
    if not force:
        existing = sources_already_indexed([SRC_WINDOWS_SEARCH], evidence_path=image_path)
        if existing:
            return tool_response(
                tc_id,
                "parse_windows_search",
                params,
                {"status": "skipped", "reason": "Already indexed", "existing_sources": existing},
                SRC_WINDOWS_SEARCH,
                0.0,
            )

    databases, cleanup, failures = _search_databases(image_path)
    if not databases:
        return nothing_extracted_response(
            tc_id,
            "parse_windows_search",
            params,
            t0,
            "No Windows Search database found (Search\\Data\\Applications\\Windows\\Windows.edb "
            "or Windows.db): not collected, or indexing was disabled",
            failures,
        )
    lines: list[str] = []
    per_db: list[dict[str, object]] = []
    warnings: list[str] = []
    budget = max(1, int(max_items))
    try:
        for rel, path in databases:
            try:
                read = read_windows_search(
                    path, max_items=max(1, budget - len(lines)), prefix=f"db={Path(rel).name} | "
                )
            except Exception as exc:  # noqa: BLE001 - reported per database
                warnings.append(f"{rel}: could not be opened: {type(exc).__name__}: {exc}")
                per_db.append({"database": rel, "error": f"{type(exc).__name__}: {exc}"})
                continue
            lines.extend(read.lines)
            info: dict[str, object] = {
                "database": rel,
                "items": read.counts.get("items", 0),
                "state": read.state,
            }
            if note := read.state_note():
                info["state_note"] = note
                warnings.append(f"{rel}: {note}")
            if read.notes:
                info["notes"] = read.notes
            if read.truncated:
                info["truncated"] = read.truncated
                warnings.append(
                    f"{rel}: {read.truncated}. Call again with force=True and a higher "
                    "max_items to read everything (the items already read are indexed again)."
                )
            if read.errors:
                info["errors"] = read.errors
                warnings.extend(
                    f"{rel}: {e['error']} ({e['records_read']} items read before it)"
                    for e in read.errors
                )
            per_db.append(info)
    finally:
        if cleanup:
            _cleanup_tsk_extract_dir(cleanup)

    elapsed = (time.monotonic() - t0) * 1000
    if not lines:
        return error_response(
            tc_id,
            "parse_windows_search",
            params,
            "No item could be read from the Windows Search index: "
            + ("; ".join(warnings) or "the index holds no item"),
            elapsed,
            error_type="tool_failed" if warnings else "no_data",
        )

    summary = extract_and_index("\n".join(lines), SRC_WINDOWS_SEARCH, image_path, "dissect.esedb")
    emails = sorted({m.lower() for line in lines for m in _EMAIL_RE.findall(line)})
    summary.update(
        {
            "items_indexed": len(lines),
            "databases": per_db,
            "email_addresses": emails[:100],
            "indexed_as": SRC_WINDOWS_SEARCH,
            "hint": (
                f"Search the items with search(query, source='{SRC_WINDOWS_SEARCH}'): paths, "
                "owners, e-mail addresses, subjects, summaries and Timeline activity are in "
                "the text."
            ),
        }
    )
    if len(emails) > 100:
        summary["email_addresses_not_listed"] = len(emails) - 100
    if warnings:
        summary["tool_warning"] = "\n".join(warnings)
    add_extraction_failures(summary, failures)
    return tool_response(tc_id, "parse_windows_search", params, summary, None, elapsed)


# ---------------------------------------------------------------------------
# Generic ESE query
# ---------------------------------------------------------------------------

_ESE_MAX_ROWS = 1000
_ESE_COUNT_CAP = 100_000
_SOURCE_SAFE_RE = re.compile(r"[^a-z0-9._-]+")


def _count(records: Iterable[object], cap: int) -> str:
    n = 0
    for _ in records:
        n += 1
        if n >= cap:
            return f">={cap}"
    return str(n)


def _column_is_text(column: Any) -> bool:
    return not _ID_NAME_RE.search(str(column.name))


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST)
def query_ese_database(
    file_path: str, table: str = "", offset: int = 0, limit: int = 200
) -> dict[str, object]:
    """Read an ESE (JET Blue) database file: list its tables, or read one table.

    ESE databases hold many Windows artifacts: WebCacheV01.dat (legacy
    Edge / IE history, cookies, downloads), spartan.edb, DataStore.edb,
    Exchange and Active Directory databases. Use run_srum_parser and
    parse_windows_search for SRUDB.dat and Windows.edb. With an empty
    *table*, returns every table with its columns and record count. With
    a table name, reads *limit* records from *offset* and indexes them as
    ``ese.<file>.<table>.<id>``; follow ``next_offset`` to read the rest.

    Args:
        file_path: Absolute path of the database in the evidence (triage collection
            or extracted file).
        table: Table to read; empty to list the tables.
        offset: Number of records to skip.
        limit: Records to read (1 to 1000).
    """
    from dissect.esedb import EseDB
    from dissect.util.ts import oatimestamp

    from mulder.path_policy import PathPolicyError
    from mulder.server.tools.artifacts import _resolve_artifact_path

    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "file_path": file_path,
        "table": table,
        "offset": offset,
        "limit": limit,
    }

    def _fail(message: str, error_type: str = "tool_failed") -> dict[str, object]:
        return error_response(
            tc_id,
            "query_ese_database",
            params,
            message,
            (time.monotonic() - t0) * 1000,
            error_type,
        )

    try:
        target = _resolve_artifact_path(Path(file_path))
    except PathPolicyError as exc:
        return _fail(str(exc), "invalid_path")
    if not target.is_file():
        return _fail(f"File not found: {file_path}", "file_not_found")
    if not is_ese_file(target):
        return _fail(f"Not an ESE database (no ESE header): {file_path}", "invalid_input")
    offset = max(0, int(offset))
    limit = max(1, min(int(limit), _ESE_MAX_ROWS))

    rows: list[str] = []
    skipped: list[str] = []
    stopped = ""
    more = False
    try:
        with target.open("rb") as fh:
            db = EseDB(fh)
            state = _db_state(db)
            state_note = EseReadResult(state=state).state_note()
            if not table:
                tables = []
                for t in db.tables():
                    try:
                        count = _count(t.records(), _ESE_COUNT_CAP)
                    except Exception as exc:  # noqa: BLE001
                        count = f"unreadable ({type(exc).__name__}: {exc})"
                    cols = [f"{c.name}:{getattr(c.type, 'name', c.type)}" for c in t.columns]
                    entry: dict[str, object] = {
                        "table": t.name,
                        "records": count,
                        "columns": cols[:60],
                    }
                    if len(cols) > 60:
                        entry["columns_not_listed"] = len(cols) - 60
                    tables.append(entry)
                result: dict[str, object] = {
                    "file_path": str(target),
                    "state": state,
                    "tables": tables,
                }
                if state_note:
                    result["tool_warning"] = state_note
                return tool_response(
                    tc_id,
                    "query_ese_database",
                    params,
                    result,
                    None,
                    (time.monotonic() - t0) * 1000,
                )
            try:
                t = db.table(table)
            except KeyError:
                names = ", ".join(x.name for x in db.tables())
                return _fail(f"No table {table!r}. Tables: {names}", "invalid_input")
            columns = [
                (c.name, getattr(c.type, "name", "") == "DateTime", _column_is_text(c))
                for c in t.columns
            ]
            index = -1
            try:
                for index, record in enumerate(t.records()):
                    if index < offset:
                        continue
                    if len(rows) + len(skipped) >= limit:
                        more = True
                        break
                    parts = [f"#{index}"]
                    try:
                        for column, is_ole_date, as_text in columns:
                            value = record.get(column)
                            if is_ole_date and isinstance(value, int) and value:
                                value = oatimestamp(value)
                            text = format_value(
                                value,
                                date_hint=_is_date_name(column),
                                local="Local" in column,
                                as_text=as_text,
                            )
                            if text is not None:
                                parts.append(f"{column}={text}")
                    except Exception as exc:  # noqa: BLE001 - skip the record, say which
                        skipped.append(f"#{index}: {type(exc).__name__}: {exc}")
                        continue
                    rows.append(" | ".join(parts))
            except Exception as exc:  # noqa: BLE001 - damaged page: keep what was read
                stopped = f"reading stopped at record #{index + 1}: {type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001 - dissect raises several error types on damage
        return _fail(f"Cannot read {file_path}: {type(exc).__name__}: {exc}")

    elapsed = (time.monotonic() - t0) * 1000
    if not rows:
        if stopped or skipped:
            return _fail(f"No record of {table} could be read: {stopped or skipped[0]}")
        result = {"status": "no_results", "message": f"No record at offset {offset} in {table}"}
        return tool_response(tc_id, "query_ese_database", params, result, None, elapsed)
    label = f"{target.name}.{table}".lower()
    path_id = hashlib.sha1(str(target).encode(), usedforsecurity=False).hexdigest()[:6]
    source = "ese." + (_SOURCE_SAFE_RE.sub("_", label).strip("_") or "table") + f".{path_id}"
    if offset:
        source += f".from{offset}"
    first, last = offset, offset + len(rows) + len(skipped) - 1
    summary = extract_and_index(
        f"=== {target} :: {table} (records #{first}-#{last}) ===\n" + "\n".join(rows),
        source,
        str(target),
        "dissect.esedb",
    )
    summary["records_returned"] = len(rows)
    summary["state"] = state
    warnings: list[str] = []
    if state_note:
        warnings.append(state_note)
    if skipped:
        summary["records_skipped"] = skipped[:20]
        warnings.append(f"{len(skipped)} record(s) could not be decoded and are not in the output")
    if stopped:
        warnings.append(stopped + "; records after it could not be read")
    if more:
        summary["next_offset"] = last + 1
        summary["note"] = (
            f"PARTIAL: records #{first}-#{last} read. Call again with offset={last + 1} "
            "for the rest."
        )
    if warnings:
        summary["tool_warning"] = "\n".join(warnings)
    return tool_response(tc_id, "query_ese_database", params, summary, source, elapsed)
