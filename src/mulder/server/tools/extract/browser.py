"""Browser history and downloads from Chromium, Firefox and Safari databases.

Reads every profile's history database, on a disk image (through Sleuth
Kit) or in a triage collection (the collected files), and indexes each
visit and each download on one timeline as ``browser.history``. Downloads
are what usually matters: a fake installer fetched from a search result is
the initial access of many intrusions, and the download records carry the
source URL, the referrer, the path saved to and the size.
"""

from __future__ import annotations

import re
import shutil
import sqlite3
import tempfile
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    make_tool_call_id,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
from mulder.server.tools.extract.tsk import (
    IcatFailure,
    _cleanup_tsk_extract_dir,
    _tsk_extract_files,
    extraction_failure_fields,
    nothing_extracted_response,
)
from mulder.triage import is_triage_root, iter_tree_files

__all__ = ["browser_database_kind", "parse_browser_history", "read_browser_database"]

SRC_BROWSER = "browser.history"

_SQLITE_MAGIC = b"SQLite format 3\x00"
_SIDECARS = ("-wal", "-journal")
#: Visits read per database; downloads are always read in full.
_MAX_VISITS = 20_000
#: Downloads listed in the tool response (all of them are indexed).
_LISTED_DOWNLOADS = 50

_CHROMIUM_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_SAFARI_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

#: Directories that hold a Chromium-family ``History`` database.
_CHROMIUM_DIRS = (
    "/google/chrome",
    "/chromium/",
    "/microsoft/edge",
    "/bravesoftware/",
    "/opera software/",
    "/vivaldi/",
)
_PROFILE_RE = re.compile(r"(?:^|/)(?:users|documents and settings)/([^/]+)/")
#: Saved files a user would not open from a browser in normal work.
_RISKY_EXT_RE = re.compile(
    r"\.(?:exe|msi|msix|appx|dll|scr|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|iso|img|vhdx?|"
    r"jar|zip|7z|rar)$",
    re.IGNORECASE,
)


def browser_database_kind(rel_path: str) -> str | None:
    """``chromium``, ``firefox`` or ``safari`` for a history database path, else None."""
    rel = "/" + rel_path.lower().replace("\\", "/")
    name = rel.rsplit("/", 1)[-1]
    if name == "history" and any(d in rel for d in _CHROMIUM_DIRS):
        return "chromium"
    if name == "places.sqlite" and "/firefox/" in rel:
        return "firefox"
    if name == "history.db" and "/safari/" in rel:
        return "safari"
    return None


def _browser_name(rel_path: str, kind: str) -> str:
    rel = rel_path.lower()
    for marker, name in (
        ("microsoft/edge", "edge"),
        ("bravesoftware", "brave"),
        ("opera software", "opera"),
        ("vivaldi", "vivaldi"),
        ("chromium", "chromium"),
        ("google/chrome", "chrome"),
    ):
        if marker in rel:
            return name
    return kind


def _profile_of(rel_path: str) -> str:
    m = _PROFILE_RE.search(rel_path.lower().replace("\\", "/"))
    return m.group(1) if m else "unknown"


def _iso(epoch: datetime, value: object, unit_s: float) -> str | None:
    """``epoch + value * unit_s`` as an ISO UTC string; None for empty or absurd values."""
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    try:
        return (epoch + timedelta(seconds=value * unit_s)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OverflowError:
        return None


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')}


def _chromium(conn: sqlite3.Connection) -> Iterator[dict[str, object]]:
    for t, url, title, transition in conn.execute(
        "SELECT v.visit_time, u.url, u.title, v.transition FROM visits v "
        "JOIN urls u ON u.id = v.url ORDER BY v.visit_time DESC LIMIT ?",
        (_MAX_VISITS,),
    ):
        yield {
            "event": "VISIT",
            "time": _iso(_CHROMIUM_EPOCH, t, 1e-6),
            "url": url,
            "title": title,
            # The low byte is the core transition type: 1 typed, 0 link, 8 reload...
            "transition": (transition & 0xFF) if isinstance(transition, int) else None,
        }
    cols = _columns(conn, "downloads")
    if not cols:
        return
    wanted = [
        c
        for c in (
            "start_time",
            "end_time",
            "target_path",
            "current_path",
            "tab_url",
            "referrer",
            "received_bytes",
            "total_bytes",
            "mime_type",
            "state",
            "danger_type",
        )
        if c in cols
    ]
    chain = (
        ", (SELECT c.url FROM downloads_url_chains c WHERE c.id = d.id "
        "ORDER BY c.chain_index DESC LIMIT 1) AS url"
        if _columns(conn, "downloads_url_chains")
        else ", NULL AS url"
    )
    conn.row_factory = sqlite3.Row
    try:
        for row in conn.execute(
            f"SELECT {', '.join('d.' + c for c in wanted)}{chain} FROM downloads d"
        ):
            r = dict(row)
            yield {
                "event": "DOWNLOAD",
                "time": _iso(_CHROMIUM_EPOCH, r.get("start_time"), 1e-6),
                "end_time": _iso(_CHROMIUM_EPOCH, r.get("end_time"), 1e-6),
                "url": r.get("url") or r.get("tab_url"),
                "target": r.get("target_path") or r.get("current_path"),
                "referrer": r.get("referrer") or r.get("tab_url"),
                "size": r.get("total_bytes") or r.get("received_bytes"),
                "mime": r.get("mime_type"),
                "danger_type": r.get("danger_type"),
            }
    finally:
        conn.row_factory = None


def _firefox(conn: sqlite3.Connection) -> Iterator[dict[str, object]]:
    for t, url, title in conn.execute(
        "SELECT v.visit_date, p.url, p.title FROM moz_historyvisits v "
        "JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date DESC LIMIT ?",
        (_MAX_VISITS,),
    ):
        yield {"event": "VISIT", "time": _iso(_UNIX_EPOCH, t, 1e-6), "url": url, "title": title}
    if not _columns(conn, "moz_annos"):
        return
    # Since Firefox 26, downloads live in places.sqlite as page annotations.
    for added, url, dest in conn.execute(
        "SELECT a.dateAdded, p.url, a.content FROM moz_annos a "
        "JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id "
        "JOIN moz_places p ON p.id = a.place_id "
        "WHERE n.name = 'downloads/destinationFileURI'"
    ):
        target = dest
        if isinstance(dest, str) and dest.startswith("file:///"):
            from urllib.parse import unquote

            target = unquote(dest[len("file:///") :])
        yield {
            "event": "DOWNLOAD",
            "time": _iso(_UNIX_EPOCH, added, 1e-6),
            "url": url,
            "target": target,
        }


def _safari(conn: sqlite3.Connection) -> Iterator[dict[str, object]]:
    for t, url, title in conn.execute(
        "SELECT hv.visit_time, hi.url, hv.title FROM history_visits hv "
        "JOIN history_items hi ON hi.id = hv.history_item ORDER BY hv.visit_time DESC LIMIT ?",
        (_MAX_VISITS,),
    ):
        yield {"event": "VISIT", "time": _iso(_SAFARI_EPOCH, t, 1.0), "url": url, "title": title}


_READERS = {"chromium": _chromium, "firefox": _firefox, "safari": _safari}


def read_browser_database(
    path: Path, kind: str, sidecars: dict[str, Path]
) -> list[dict[str, object]]:
    """Visits and downloads of one database, read from a private copy.

    The database and its ``-wal``/``-journal`` files are copied first, so
    pages still in the WAL are read and the evidence is never opened.

    Raises:
        sqlite3.Error, OSError: The database cannot be copied or read.
    """
    with tempfile.TemporaryDirectory(prefix="mulder_browser_") as tmpdir:
        copy = Path(tmpdir) / "db.sqlite"
        shutil.copyfile(path, copy)
        for suffix, side in sidecars.items():
            shutil.copyfile(side, copy.with_name(copy.name + suffix))
        conn = sqlite3.connect(str(copy))
        try:
            conn.execute("PRAGMA trusted_schema=OFF")
            return list(_READERS[kind](conn))
        finally:
            conn.close()


def _record_line(r: dict[str, object]) -> str:
    flag = ""
    if r["event"] == "DOWNLOAD" and _RISKY_EXT_RE.search(
        str(r.get("target") or r.get("url") or "")
    ):
        flag = "[EXECUTABLE OR ARCHIVE] "
    parts = [f"{r.get('time') or 'unknown-time'} {r['event']} {flag}browser={r['browser']}"]
    parts.append(f"user={r['profile']}")
    for key in ("url", "title", "target", "referrer", "size", "mime", "end_time", "danger_type"):
        value = r.get(key)
        if value not in (None, ""):
            parts.append(f"{key}={value}")
    if r.get("transition") == 1:
        parts.append("typed=yes")
    parts.append(f"db={r['db']}")
    return " | ".join(parts)


def _database_files(
    image_path: str, failures: list[IcatFailure]
) -> tuple[dict[str, Path], str | None]:
    """Every history database and sidecar, by lower-cased relative path, plus a dir to clean."""

    def wanted(rel_lower: str) -> bool:
        base = rel_lower
        for suffix in _SIDECARS:
            base = base.removesuffix(suffix)
        return browser_database_kind(base) is not None

    if is_triage_root(image_path):
        files = {
            rel.lower().replace("\\", "/"): path
            for rel, path in iter_tree_files(image_path)
            if wanted(rel.lower().replace("\\", "/"))
        }
        return files, None
    extracted = _tsk_extract_files(
        image_path,
        ["/History", "places.sqlite", "History.db"],
        predicate=wanted,
        failures=failures,
    )
    cleanup = str(extracted[0][1].parent) if extracted else None
    return {rel.lower().replace("\\", "/"): path for rel, path in extracted}, cleanup


@mcp.tool()
@tool_access(
    Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST | Role.CROSS_EXECUTOR | Role.CROSS_ANALYST
)
def parse_browser_history(image_path: str, force: bool = False) -> dict[str, object]:
    """Read every browser profile's history and downloads into one timeline.

    Call on Windows and macOS disk images and on triage collections. Reads
    Chrome, Edge, Brave, Opera, Vivaldi and Chromium (``History``), Firefox
    (``places.sqlite``) and Safari (``History.db``) for every user, with
    their WAL files. Each visit and each download is indexed as
    ``browser.history`` with its UTC time, user and URL; a download also
    carries the saved path, the referrer and the size. Downloads of
    executables, scripts, disk images and archives are flagged
    ``[EXECUTABLE OR ARCHIVE]`` and listed in ``downloads``: this is
    where a fake installer fetched from a search result shows up.

    Args:
        image_path: Disk image, or triage collection directory.
        force: Re-run extraction even if the source already exists.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"image_path": image_path, "force": force}
    if not force:
        existing = sources_already_indexed([SRC_BROWSER], evidence_path=image_path)
        if existing:
            return tool_response(
                tc_id,
                "parse_browser_history",
                params,
                {"status": "skipped", "reason": "Already indexed", "existing_sources": existing},
                SRC_BROWSER,
                0.0,
            )

    failures: list[IcatFailure] = []
    files, cleanup = _database_files(image_path, failures)
    records: list[dict[str, object]] = []
    databases: list[dict[str, object]] = []
    try:
        for rel, path in sorted(files.items()):
            kind = browser_database_kind(rel)
            if kind is None:
                continue
            entry: dict[str, object] = {"db": rel, "browser": _browser_name(rel, kind)}
            databases.append(entry)
            try:
                with path.open("rb") as f:
                    if f.read(len(_SQLITE_MAGIC)) != _SQLITE_MAGIC:
                        entry["error"] = "not a SQLite database"
                        continue
                sidecars = {s: files[rel + s] for s in _SIDECARS if rel + s in files}
                rows = read_browser_database(path, kind, sidecars)
            except (sqlite3.Error, OSError) as exc:
                entry["error"] = str(exc)
                continue
            profile = _profile_of(rel)
            for r in rows:
                r.update(browser=entry["browser"], profile=profile, db=rel)
            records.extend(rows)
            entry["visits"] = sum(1 for r in rows if r["event"] == "VISIT")
            entry["downloads"] = sum(1 for r in rows if r["event"] == "DOWNLOAD")
    finally:
        if cleanup:
            _cleanup_tsk_extract_dir(cleanup)

    if not databases:
        return nothing_extracted_response(
            tc_id,
            "parse_browser_history",
            params,
            t0,
            "No browser history database found (not collected, or no browser used)",
            failures,
        )

    records.sort(key=lambda r: str(r.get("time") or ""))
    summary: dict[str, object] = {"databases": databases}
    if records:
        summary.update(
            extract_and_index(
                "\n".join(_record_line(r) for r in records), SRC_BROWSER, image_path, "browser"
            )
        )
    downloads = [r for r in records if r["event"] == "DOWNLOAD"]
    risky = [
        r for r in downloads if _RISKY_EXT_RE.search(str(r.get("target") or r.get("url") or ""))
    ]
    listed = (risky + [r for r in downloads if r not in risky])[:_LISTED_DOWNLOADS]
    summary["visits"] = len(records) - len(downloads)
    summary["downloads_total"] = len(downloads)
    summary["downloads"] = [
        {k: r.get(k) for k in ("time", "browser", "profile", "url", "target", "referrer", "size")}
        for r in listed
    ]
    if len(downloads) > len(listed):
        summary["downloads_not_listed"] = len(downloads) - len(listed)
    summary["indexed_as"] = SRC_BROWSER
    summary["hint"] = (
        f"All visits and downloads are indexed as '{SRC_BROWSER}'. Executables, scripts and "
        "archives are listed first in 'downloads'; check each one's url and referrer, then "
        "search the source around its time for the page that led to it."
    )
    unreadable = [d for d in databases if "error" in d]
    if unreadable:
        summary["tool_warning"] = (
            f"{len(unreadable)} of {len(databases)} browser databases could not be read; "
            "see 'databases' for the reason. Their history is NOT in this result."
        )
    if failures:
        summary.update(extraction_failure_fields(failures))
    # Returned in full (source=None): the downloads list is the finding.
    return tool_response(
        tc_id, "parse_browser_history", params, summary, None, (time.monotonic() - t0) * 1000
    )
