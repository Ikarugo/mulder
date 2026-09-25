"""Searching for a date or a time must find ISO timestamps.

FTS5's unicode61 tokenizer splits on punctuation only, so
``2024-11-06T02:52:01Z`` is indexed as ``2024 / 11 / 06t02 / 52 / 01z``. The
phrase ``"2024-11-06"`` ends on the token ``06``, which is not ``06t02``, and
``"02:52:01"`` ends on ``01``, which is not ``01z``: on a real run, every
search with a date in it returned zero results and said nothing about why.
The index now receives the text with the ``T`` between date and time
replaced by a space (the stored window is unchanged), dates and times in
queries are prefix phrases (``01z``, fractions of seconds, and databases
indexed before the change), and an empty search explains how multi-word
queries match.

These tests use a real FTS5 case database, not a mock.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from mulder.db import CaseDB, _fts5_any_query, _sanitize_fts5_query
from mulder.models import WindowRow

LINES = [
    "srum=network_data | TimeStamp=2024-11-06T02:00:00Z | AppId=powershell.exe | BytesSent=13",
    "2024-11-06T02:52:01Z task=\\Updater | last_run_utc=2024-11-06T02:52:01.1234567Z",
    "2024-11-07 10:00:00 unrelated line for 10.0.0.12",
]


@pytest.fixture
def case_db(tmp_path: Path) -> Iterator[CaseDB]:
    db = CaseDB.create(case_id="dates", evidence_root="/ev", db_dir=tmp_path)
    source_id = db.register_source(
        source_name="ez.srum",
        source_path="/evidence/SRUDB.dat",
        source_hash="h",
        extractor="test",
        line_count=len(LINES),
    )
    db.insert_windows(
        source_id,
        [
            WindowRow(
                window_id=None,
                source_id=source_id,
                line_start=i + 1,
                line_end=i + 1,
                event_time=None,
                raw_text=line,
            )
            for i, line in enumerate(LINES)
        ],
    )
    yield db
    db.close()


def _texts(db: CaseDB, query: str, match: Any = "all") -> list[str]:
    return [w.raw_text for w, _ in db.search_windows(query, match=match)]


class TestQueryConstruction:
    @pytest.mark.parametrize(
        ("query", "expected"),
        [
            ("2024-11-06", '"2024-11-06"*'),
            ('"2024-11-06"', '"2024-11-06"*'),
            ("02:52:01", '"02:52:01"*'),
            ("2024-11-06T02:52", '"2024-11-06 02:52"*'),
            ("2024-11-06T02:52:01Z", '"2024-11-06 02:52:01"*'),
            ("2024-11-06T02:52:01+02:00", '"2024-11-06 02:52:01"*'),
            ("10.0.0.1", '"10.0.0.1"'),  # not a date: an IP must not become a prefix
            ('"brute force"', '"brute force"'),
            ('"mimi"*', '"mimi"*'),
        ],
    )
    def test_sanitizer(self, query: str, expected: str) -> None:
        assert _sanitize_fts5_query(query) == expected

    def test_any_query_keeps_the_prefix_on_its_phrase(self) -> None:
        assert _fts5_any_query("powershell 2024-11-06") == 'powershell OR "2024-11-06"*'


class TestAgainstARealDatabase:
    def test_date_finds_iso_timestamps(self, case_db: CaseDB) -> None:
        hits = _texts(case_db, "2024-11-06")
        assert len(hits) == 2
        assert all("2024-11-06T" in h for h in hits)

    def test_time_finds_timestamps_with_a_zone_or_fraction(self, case_db: CaseDB) -> None:
        assert len(_texts(case_db, "02:52:01")) == 1

    def test_the_query_from_the_failed_run(self, case_db: CaseDB) -> None:
        hits = _texts(case_db, "powershell.exe 2024-11-06 BytesSent")
        assert hits == [LINES[0]]

    def test_a_date_does_not_match_another_day(self, case_db: CaseDB) -> None:
        assert _texts(case_db, "2024-11-0") == []
        assert all("2024-11-07" in h for h in _texts(case_db, "2024-11-07"))

    def test_ip_addresses_stay_exact(self, case_db: CaseDB) -> None:
        assert _texts(case_db, "10.0.0.1") == []
        assert len(_texts(case_db, "10.0.0.12")) == 1

    def test_hour_after_the_t_is_searchable(self, case_db: CaseDB) -> None:
        assert _texts(case_db, "2024-11-06T02:52") == [LINES[1]]

    def test_stored_text_keeps_its_t(self, case_db: CaseDB) -> None:
        (text,) = _texts(case_db, "powershell.exe")
        assert "2024-11-06T02:00:00Z" in text

    def test_a_utc_timestamp_finds_the_same_instant_written_without_zone(
        self, case_db: CaseDB
    ) -> None:
        assert _texts(case_db, "2024-11-06T02:52:01Z") == [LINES[1]]

    def test_count_agrees_with_results(self, case_db: CaseDB) -> None:
        assert case_db.count_search_windows("2024-11-06") == 2


def test_a_case_indexed_before_the_change_is_reindexed_once(tmp_path: Path) -> None:
    from sqlalchemy import text

    db = CaseDB.create(case_id="old", evidence_root="/ev", db_dir=tmp_path)
    sid = db.register_source("ez.srum", "/e", "h", "test", len(LINES))
    db.insert_windows(
        sid,
        [
            WindowRow(
                window_id=None,
                source_id=sid,
                line_start=1,
                line_end=1,
                event_time=None,
                raw_text=LINES[1],
            )
        ],
    )
    # Rebuild the index the old way (raw text, "06t02" tokens) and forget the version.
    with db._engine.begin() as conn:
        conn.execute(text("INSERT INTO windows_fts(windows_fts) VALUES('delete-all')"))
        conn.execute(
            text(
                "INSERT INTO windows_fts(rowid, raw_text) SELECT window_id, raw_text FROM windows"
            )
        )
        conn.execute(text("DELETE FROM kv_store WHERE key = 'fts_text_version'"))
    assert _texts(db, "2024-11-06T02:52") == []
    db.close()

    reopened = CaseDB.open("old", tmp_path)
    assert _texts(reopened, "2024-11-06T02:52") == [LINES[1]]
    assert reopened.get_kv("fts_text_version") == "1"
    reopened.close()


@pytest.fixture()
def case(tmp_path: Path) -> Path:
    """An open case with one indexed source."""
    from mulder.server.app import init_server
    from mulder.server.extract_helpers import extract_and_index

    root = tmp_path / "evidence" / "WS01" / "C"
    (root / "Windows" / "System32" / "config").mkdir(parents=True)
    (root / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"regf")
    init_server(db_dir=tmp_path / "cases")
    _call("scan_evidence", evidence_path=str(tmp_path / "evidence"), case_id="dates")
    extract_and_index("\n".join(LINES), "ez.srum", str(root), "test")
    return root


def _call(name: str, **kwargs: Any) -> dict[str, Any]:
    from mulder.server.app import _tool_dispatch_sync

    return _tool_dispatch_sync[name](**kwargs)  # type: ignore[no-any-return]


class TestSearchTool:
    def test_date_query_through_the_tool(self, case: Path) -> None:
        result = _call("search", query="powershell.exe 2024-11-06 BytesSent", source="ez.srum")
        assert result["result_count"] == 1

    def test_empty_multi_word_search_explains_itself(self, case: Path) -> None:
        result = _call("search", query="srum AnyDesk.exe BytesSent BytesRecvd")
        assert result["result_count"] == 0
        hint = str(result["hint"])
        assert "had to be in the same window" in hint
        assert "queries=[...]" in hint
        assert "not proof of absence" in hint

    def test_excerpt_is_centred_on_the_timestamp(self, case: Path) -> None:
        result = _call("search", query="2024-11-06T02:52:01", source="ez.srum")
        (hit,) = result["results"]
        assert hit["window"]["match_count"] == 2  # both timestamps, not every "11" or "06"
        assert "02:52:01" in str(hit["window"])

    def test_explicit_or_gets_no_same_window_advice(self, case: Path) -> None:
        result = _call("search", query="mimikatz OR rubeus")
        assert "same window" not in str(result["hint"])
        lower = _call("search", query="mimikatz or rubeus")
        assert "write AND, OR, NOT in capitals" in str(lower["hint"])

    def test_empty_single_word_search_has_no_and_advice(self, case: Path) -> None:
        result = _call("search", query="mimikatz")
        assert "same window" not in str(result["hint"])
        assert "whole words" in str(result["hint"])
