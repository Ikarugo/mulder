"""parse_browser_history on a triage collection: visits and downloads, every browser."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from mulder.server.tools.extract.browser import browser_database_kind

# 2025-03-14T09:41:27Z in each browser's clock.
_CHROMIUM_T = 13_386_418_887_000_000  # microseconds since 1601
_FIREFOX_T = 1_741_945_287_000_000  # microseconds since 1970
_INSTALLER_URL = "https://files.example.net/dl/7c1e/SetupTool.exe"
_SEARCH_URL = "https://search.example.org/?q=setup+tool+download"


def _chromium_history(path: Path, with_downloads: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                           visit_count INTEGER, last_visit_time INTEGER);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,
                             transition INTEGER);
        """
    )
    conn.execute("INSERT INTO urls VALUES (1, ?, 'Search', 1, ?)", (_SEARCH_URL, _CHROMIUM_T))
    conn.execute("INSERT INTO visits VALUES (1, 1, ?, ?)", (_CHROMIUM_T, 0x30000001))
    if with_downloads:
        conn.executescript(
            """
            CREATE TABLE downloads (id INTEGER PRIMARY KEY, start_time INTEGER,
                end_time INTEGER, target_path TEXT, tab_url TEXT, referrer TEXT,
                received_bytes INTEGER, total_bytes INTEGER, mime_type TEXT);
            CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
            """
        )
        conn.execute(
            "INSERT INTO downloads VALUES (1, ?, ?, ?, ?, ?, 102912, 102912, "
            "'application/octet-stream')",
            (
                _CHROMIUM_T + 5_000_000,
                _CHROMIUM_T + 6_000_000,
                r"C:\Users\alice\Downloads\SetupTool.exe",
                _SEARCH_URL,
                _SEARCH_URL,
            ),
        )
        conn.execute("INSERT INTO downloads_url_chains VALUES (1, 0, ?)", (_INSTALLER_URL,))
    conn.commit()
    conn.close()


def _firefox_places(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT);
        CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER,
                                        visit_date INTEGER);
        CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER,
            anno_attribute_id INTEGER, content TEXT, dateAdded INTEGER);
        """
    )
    conn.execute("INSERT INTO moz_places VALUES (1, 'https://docs.example.com/guide', 'Guide')")
    conn.execute("INSERT INTO moz_places VALUES (2, 'https://cdn.example.com/report.pdf', NULL)")
    conn.execute("INSERT INTO moz_historyvisits VALUES (1, 1, ?)", (_FIREFOX_T,))
    conn.execute("INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI')")
    conn.execute(
        "INSERT INTO moz_annos VALUES (1, 2, 1, "
        "'file:///C:/Users/bob/Downloads/report%20Q1.pdf', ?)",
        (_FIREFOX_T + 60_000_000,),
    )
    conn.commit()
    conn.close()


@pytest.fixture()
def volume(tmp_path: Path) -> Path:
    root = tmp_path / "evidence" / "WS01" / "C"
    (root / "Windows/System32/config").mkdir(parents=True)
    (root / "Windows/System32/config/SYSTEM").write_bytes(b"regf")
    _chromium_history(root / "Users/alice/AppData/Local/Google/Chrome/User Data/Default/History")
    _chromium_history(
        root / "Users/alice/AppData/Local/Microsoft/Edge/User Data/Default/History",
        with_downloads=False,
    )
    _firefox_places(
        root / "Users/bob/AppData/Roaming/Mozilla/Firefox/Profiles/ab12cd.default/places.sqlite"
    )
    # Not a browser database, despite the name.
    (root / "Users/alice/Documents/History").parent.mkdir(parents=True)
    (root / "Users/alice/Documents/History").write_bytes(b"notes")
    return root


@pytest.fixture()
def case(volume: Path, tmp_path: Path) -> Path:
    from mulder.server.app import _tool_dispatch_sync, init_server

    init_server(db_dir=tmp_path / "cases")
    result = _tool_dispatch_sync["scan_evidence"](
        evidence_path=str(tmp_path / "evidence"), case_id="browser"
    )
    assert result["status"] == "success", result
    return volume


def _call(name: str, **kwargs: Any) -> dict[str, Any]:
    from mulder.server.app import _tool_dispatch_sync

    return _tool_dispatch_sync[name](**kwargs)  # type: ignore[no-any-return]


@pytest.mark.parametrize(
    ("rel", "kind"),
    [
        ("Users/a/AppData/Local/Google/Chrome/User Data/Default/History", "chromium"),
        ("Users/a/AppData/Local/Microsoft/Edge/User Data/Profile 1/History", "chromium"),
        (
            "Users/a/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/History",
            "chromium",
        ),
        ("Users/a/AppData/Roaming/Opera Software/Opera Stable/History", "chromium"),
        ("Users/a/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/places.sqlite", "firefox"),
        ("Users/a/Library/Safari/History.db", "safari"),
        ("Users/a/Documents/History", None),
        ("Users/a/AppData/Local/Google/Chrome/User Data/Default/History-journal", None),
    ],
)
def test_database_kind(rel: str, kind: str | None) -> None:
    assert browser_database_kind(rel) == kind


def test_downloads_and_visits_of_every_browser(case: Path) -> None:
    result = _call("parse_browser_history", image_path=str(case))
    assert result["status"] == "success", result
    payload = result["results"]

    browsers = {d["browser"] for d in payload["databases"]}
    assert browsers == {"chrome", "edge", "firefox"}
    assert all("error" not in d for d in payload["databases"])
    assert payload["visits"] == 3
    assert payload["downloads_total"] == 2

    first = payload["downloads"][0]  # executables are listed first
    assert first["url"] == _INSTALLER_URL
    assert first["referrer"] == _SEARCH_URL
    assert first["profile"] == "alice"
    assert first["browser"] == "chrome"
    assert first["time"] == "2025-03-14T09:41:32Z"
    assert first["size"] == 102912
    pdf = payload["downloads"][1]
    assert pdf["target"] == "C:/Users/bob/Downloads/report Q1.pdf"
    assert pdf["time"] == "2025-03-14T09:42:27Z"

    hits = _call("search", query="SetupTool.exe", source="browser.history")
    text = " ".join(str(h.get("window", h).get("raw_text", "")) for h in hits["results"])
    assert "[EXECUTABLE OR ARCHIVE]" in text


def test_second_run_is_skipped_unless_forced(case: Path) -> None:
    assert _call("parse_browser_history", image_path=str(case))["status"] == "success"
    again = _call("parse_browser_history", image_path=str(case))
    assert "already indexed" in again["hint"]
    forced = _call("parse_browser_history", image_path=str(case), force=True)
    assert forced["results"]["downloads_total"] == 2


def test_unreadable_database_is_reported_not_hidden(case: Path) -> None:
    edge = case / "Users/alice/AppData/Local/Microsoft/Edge/User Data/Default/History"
    edge.write_bytes(b"SQLite format 3\x00" + b"\x00" * 200)
    result = _call("parse_browser_history", image_path=str(case))
    payload = result["results"]
    broken = [d for d in payload["databases"] if d["browser"] == "edge"]
    assert broken and "error" in broken[0]
    assert "NOT in this result" in payload["tool_warning"]
    assert payload["downloads_total"] == 2  # the other databases are still read


def test_no_browser_at_all(tmp_path: Path) -> None:
    from mulder.server.app import _tool_dispatch_sync, init_server

    root = tmp_path / "evidence" / "WS02" / "C"
    (root / "Windows/System32/config").mkdir(parents=True)
    (root / "Windows/System32/config/SYSTEM").write_bytes(b"regf")
    init_server(db_dir=tmp_path / "cases")
    _tool_dispatch_sync["scan_evidence"](evidence_path=str(tmp_path / "evidence"), case_id="nob")
    result = _call("parse_browser_history", image_path=str(root))
    assert result["status"] != "success" or result["results"].get("status") != "success"
    assert "No browser history database" in str(result)
