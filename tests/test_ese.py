"""ESE databases read in Python: SRUM, Windows Search and any ``.edb``.

SrumECmd needs Windows' ESE engine and failed on every Linux run ("Platform
not supported"), so SRUM (exfiltration volume, application run times) and
the Windows Search index (e-mail addresses, deleted files) were never read.
These tests pin the dissect.esedb-based readers that replace it, using the
SRUM database from dissect.esedb's own test suite (``fixtures/ese``).
"""

from __future__ import annotations

import gzip
import os
import sqlite3
import struct
from pathlib import Path
from typing import Any

import pytest

from mulder.server.tools.extract import ese

_FIXTURES = Path(__file__).parent / "fixtures" / "ese"
_FT = 133753318940000000  # 2024-11-06T01:58:14Z


def _srudb(dest: Path, dbstate: int | None = None) -> Path:
    data = bytearray(gzip.decompress((_FIXTURES / "SRUDB.dat.gz").read_bytes()))
    if dbstate is not None:
        struct.pack_into("<I", data, 0x34, dbstate)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(bytes(data))
    return dest


@pytest.fixture()
def case(tmp_path: Path) -> Path:
    """An open case over a triage collection; returns the volume root."""
    from mulder.server.app import _tool_dispatch_sync, init_server

    root = tmp_path / "evidence" / "WS01" / "C"
    (root / "Windows" / "System32" / "config").mkdir(parents=True)
    (root / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"regf")
    init_server(db_dir=tmp_path / "cases")
    result = _tool_dispatch_sync["scan_evidence"](
        evidence_path=str(tmp_path / "evidence"), case_id="ese"
    )
    assert result["status"] == "success", result
    return root


def _call(name: str, **kwargs: Any) -> dict[str, Any]:
    from mulder.server.app import _tool_dispatch_sync

    return _tool_dispatch_sync[name](**kwargs)  # type: ignore[no-any-return]


def _windows(result: dict[str, Any]) -> list[str]:
    return [str(r.get("window", r).get("raw_text", "")) for r in result["results"]]


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------


class TestValues:
    def test_utf16_bytes_are_text(self) -> None:
        assert ese.format_value("metushelah@example.com".encode("utf-16-le")) == (
            "metushelah@example.com"
        )

    def test_short_binary_ids_stay_hex(self) -> None:
        assert ese.format_value(b"\xc3/W\xed@\xbf\xafP") == "hex:c32f57ed40bfaf50"

    def test_filetime_bytes_under_a_date_name(self) -> None:
        raw = _FT.to_bytes(8, "little")
        assert ese.format_value(raw, date_hint=True) == "2024-11-06T01:58:14Z"
        assert ese.format_value(raw).startswith("hex:")

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Bob".encode("utf-16-le"), "Bob"),
            ("Иван".encode("utf-16-le"), "Иван"),
            ("张伟".encode("utf-16-le"), "张伟"),
            ("Eli\x00Metushelah\x00".encode("utf-16-le"), "Eli; Metushelah"),
            (b"plain ascii", "plain ascii"),
        ],
    )
    def test_text_bytes(self, raw: bytes, expected: str) -> None:
        assert ese.format_value(raw) == expected

    @pytest.mark.parametrize("raw", [b"*u\x15", b"\x01\x02", b"\x00\x00\x00\x01"])
    def test_small_binaries_are_hex(self, raw: bytes) -> None:
        assert str(ese.format_value(raw)).startswith("hex:")

    def test_identifier_columns_stay_hex(self) -> None:
        assert ese.format_value("Bob".encode("utf-16-le"), as_text=False).startswith("hex:")

    def test_filetime_integers_and_local_times(self) -> None:
        assert ese.format_value(_FT, date_hint=True) == "2024-11-06T01:58:14Z"
        assert ese.format_value(3615, date_hint=True) == "3615"  # a duration, not a date
        assert ese.format_value(_FT, date_hint=True, local=True) == (
            "2024-11-06T01:58:14 (local time)"
        )

    def test_long_text_is_capped_with_a_marker(self) -> None:
        text = ese.format_value("x" * 5000)
        assert text is not None and "more chars]" in text


# ---------------------------------------------------------------------------
# SRUM
# ---------------------------------------------------------------------------


class TestReadSrum:
    def test_every_table_is_read_with_resolved_ids(self, tmp_path: Path) -> None:
        read = ese.read_srum(_srudb(tmp_path / "SRUDB.dat"))
        assert read.state == "clean shutdown"
        assert read.errors == []
        assert sum(read.counts.values()) == 220 == len(read.lines)
        assert read.counts["application"] == 203
        app = next(line for line in read.lines if line.startswith("srum=application |"))
        assert "TimeStamp=2021-11-16T19:18:00Z" in app
        assert "UserId=S-1-5-" in app
        assert "ForegroundCycleTime=" in app
        assert read.state_note() is None

    def test_dirty_database_is_read_and_flagged(self, tmp_path: Path) -> None:
        read = ese.read_srum(_srudb(tmp_path / "SRUDB.dat", dbstate=2))
        assert read.state == "dirty shutdown"
        assert len(read.lines) == 220
        assert "transaction logs" in str(read.state_note())

    def test_not_an_ese_file_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "SRUDB.dat"
        bad.write_bytes(b"\x00" * 8192)
        with pytest.raises(Exception):  # noqa: B017 - dissect raises several types
            ese.read_srum(bad)


class TestRunSrumParser:
    def test_triage_collection(self, case: Path) -> None:
        _srudb(case / "Windows" / "System32" / "sru" / "SRUDB.dat", dbstate=2)
        result = _call("run_srum_parser", image_path=str(case))
        assert result["status"] == "partial", result  # dirty database: flagged, not hidden
        assert "transaction logs" in str(result.get("tool_warning"))
        hits = _call("search", query="srum=application", source="ez.srum")
        assert any("ForegroundCycleTime" in w for w in _windows(hits))

    def test_clean_database_is_a_success(self, case: Path) -> None:
        _srudb(case / "Windows" / "System32" / "sru" / "SRUDB.dat")
        result = _call("run_srum_parser", image_path=str(case))
        assert result["status"] == "success", result

    def test_unreadable_database_is_an_error_not_an_empty_source(self, case: Path) -> None:
        from mulder.server.helpers import sources_already_indexed

        path = case / "Windows" / "System32" / "sru" / "SRUDB.dat"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"\x00" * 8192)
        result = _call("run_srum_parser", image_path=str(case))
        assert result["status"] == "error"
        assert "not readable as an ESE database" in result["error_message"]
        assert sources_already_indexed(["ez.srum"], evidence_path=str(case)) == []

    def test_missing_database(self, case: Path) -> None:
        result = _call("run_srum_parser", image_path=str(case))
        assert result["error_type"] == "artifact_missing"


# ---------------------------------------------------------------------------
# Windows Search
# ---------------------------------------------------------------------------


def _windows_db(path: Path, items: dict[int, dict[str, object]]) -> Path:
    """A Windows 11 style ``Windows.db``: one row per (item, property)."""
    keys = sorted({k for props in items.values() for k in props})
    ids = {k: i + 1 for i, k in enumerate(keys)}
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE SystemIndex_1_PropertyStore_Metadata (Id INTEGER, UniqueKey TEXT)")
    conn.execute(
        "CREATE TABLE SystemIndex_1_PropertyStore (WorkId INTEGER, ColumnId INTEGER, Value)"
    )
    conn.executemany(
        "INSERT INTO SystemIndex_1_PropertyStore_Metadata VALUES (?, ?)",
        [(i, k) for k, i in ids.items()],
    )
    conn.executemany(
        "INSERT INTO SystemIndex_1_PropertyStore VALUES (?, ?, ?)",
        [(wid, ids[k], v) for wid, props in items.items() for k, v in props.items()],
    )
    conn.commit()
    conn.close()
    return path


_SEARCH_DIR = "ProgramData/Microsoft/Search/Data/Applications/Windows"
_ITEMS: dict[int, dict[str, object]] = {
    10: {
        "4447-System_ItemPathDisplay": r"C:\Users\Eli\Documents\Meeting Notes.txt",
        "15F-System_DateModified": _FT.to_bytes(8, "little"),
        "13F-System_Size": (412).to_bytes(8, "little"),
        "4631F-System_Search_GatherTime": _FT.to_bytes(8, "little"),
        "4520-System_Search_AutoSummary": "Send the contact list to balikvar@laffa.com",
    },
    11: {
        "4447-System_ItemPathDisplay": "mapi://{S-1-5-21-1}/Inbox/Re: plan",
        "4522-System_Message_FromAddress": "metushelah@example.org".encode("utf-16-le"),
        "4535-System_Message_ToName": "Eli",
        "4678-System_ThumbnailCacheId": b"\xc3/W\xed@\xbf\xafP",
    },
    12: {"4678-System_ThumbnailCacheId": b"\x01\x02"},
}


class TestWindowsSearch:
    def test_line_has_labelled_fields(self) -> None:
        props = {ese._property_name(k): v for k, v in _ITEMS[11].items()}
        line = ese._ws_line(11, props)
        assert line is not None
        assert "from=metushelah@example.org" in line
        assert "to_name=Eli" in line
        assert "ThumbnailCacheId" not in line

    def test_item_without_identifying_data_is_skipped(self) -> None:
        assert ese._ws_line(12, {"ThumbnailCacheId": b"\x01\x02"}) is None

    def test_windows11_sqlite_index(self, tmp_path: Path) -> None:
        read = ese.read_windows_search(_windows_db(tmp_path / "Windows.db", _ITEMS))
        assert read.state == "sqlite"
        assert read.counts["items"] == 2
        notes = next(line for line in read.lines if "Meeting Notes" in line)
        assert "modified=2024-11-06T01:58:14Z" in notes
        assert "size=412" in notes
        assert "summary=Send the contact list to balikvar@laffa.com" in notes

    def test_max_items_is_reported(self, tmp_path: Path) -> None:
        read = ese.read_windows_search(_windows_db(tmp_path / "Windows.db", _ITEMS), max_items=1)
        assert read.truncated == "stopped at max_items=1"
        assert read.counts["items"] == 1

    def test_tool_lists_email_addresses(self, case: Path) -> None:
        _windows_db(case / _SEARCH_DIR / "Windows.db", _ITEMS)
        result = _call("parse_windows_search", image_path=str(case))
        assert result["status"] == "success", result
        payload = result["results"]
        assert payload["items_indexed"] == 2
        assert payload["email_addresses"] == ["balikvar@laffa.com", "metushelah@example.org"]
        hits = _call("search", query="balikvar", source="windows.search")
        assert any("Meeting Notes" in w for w in _windows(hits))

    def test_other_properties_are_kept(self, tmp_path: Path) -> None:
        items = {
            3: {
                "4447-System_ItemPathDisplay": r"\\{S-1-5-21-1}\LS\Desktop\ActivityHistory\{D339}",
                "4302-System_FileOwner": "ELI-PC\\Eli",
                "9999-System_Activity_ContentUri": "file:///C:/Users/Public/malware/New-beacon.xml",
                "9998-System_ActivityHistory_LocalStartTime": _FT.to_bytes(8, "little"),
                "4448-System_ItemPathDisplayNarrow": "noise",
            }
        }
        read = ese.read_windows_search(_windows_db(tmp_path / "Windows.db", items))
        (line,) = read.lines
        assert "owner=ELI-PC\\Eli" in line
        assert "Activity_ContentUri=file:///C:/Users/Public/malware/New-beacon.xml" in line
        assert "ActivityHistory_LocalStartTime=2024-11-06T01:58:14 (local time)" in line
        assert "Narrow" not in line

    def test_items_deleted_in_the_wal_are_recovered(self, tmp_path: Path) -> None:
        src = _windows_db(tmp_path / "src" / "Windows.db", _ITEMS)
        conn = sqlite3.connect(src)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("DELETE FROM SystemIndex_1_PropertyStore WHERE WorkId = 11")
        conn.commit()
        dest = tmp_path / "collected"
        dest.mkdir()
        for name in ("Windows.db", "Windows.db-wal"):  # copied while the WAL is live
            (dest / name).write_bytes((src.parent / name).read_bytes())
        conn.close()
        read = ese.read_windows_search(dest / "Windows.db")
        by_id = {line.split(" | ")[0]: line for line in read.lines}
        assert "WorkID=10" in by_id
        assert ese._WAL_NOTE in by_id["WorkID=11"]
        assert any("applied" in n for n in read.notes)

    def test_unreadable_index_is_an_error_with_its_cause(self, case: Path) -> None:
        path = case / _SEARCH_DIR / "Windows.edb"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"\x00" * 65536)
        result = _call("parse_windows_search", image_path=str(case))
        assert result["status"] == "error"
        assert result["error_type"] == "tool_failed"
        assert (
            "InvalidDatabase" in result["error_message"] or "signature" in result["error_message"]
        )

    def test_missing_index(self, case: Path) -> None:
        result = _call("parse_windows_search", image_path=str(case))
        assert result["error_type"] == "artifact_missing"

    @pytest.mark.skipif(
        not os.environ.get("MULDER_ESE_SAMPLES"), reason="MULDER_ESE_SAMPLES not set"
    )
    def test_real_windows_edb(self) -> None:
        path = Path(os.environ["MULDER_ESE_SAMPLES"]) / "Windows.edb"
        read = ese.read_windows_search(path)
        assert read.state == "dirty shutdown"
        assert read.counts["items"] == 1183
        assert any(line.startswith("WorkID=3 | path=C:\\Users\\Public") for line in read.lines)
        assert not any("ThumbnailCacheId" in line for line in read.lines)


# ---------------------------------------------------------------------------
# query_ese_database
# ---------------------------------------------------------------------------


class TestQueryEseDatabase:
    def test_lists_tables(self, case: Path) -> None:
        db = _srudb(case / "Users" / "eli" / "AppData" / "Local" / "app.edb")
        result = _call("query_ese_database", file_path=str(db))
        assert result["status"] == "success", result
        tables = {t["table"]: t for t in result["results"]["tables"]}
        assert tables["SruDbIdMapTable"]["records"] == "106"
        assert any(c.startswith("IdBlob:") for c in tables["SruDbIdMapTable"]["columns"])

    def test_reads_a_table_in_pages(self, case: Path) -> None:
        db = _srudb(case / "app.edb")
        table = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
        first = _call("query_ese_database", file_path=str(db), table=table, limit=150)
        assert first["status"] == "success", first
        assert '"next_offset": 150' in first["preview"]
        assert "PARTIAL" in first["preview"]
        second = _call("query_ese_database", file_path=str(db), table=table, offset=150, limit=150)
        assert second["status"] == "success"
        assert '"records_returned": 53' in second["preview"]
        assert "next_offset" not in second["preview"]

    def test_dates_are_decoded(self, case: Path) -> None:
        db = _srudb(case / "app.edb")
        table = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
        _call("query_ese_database", file_path=str(db), table=table, limit=5)
        hits = _call("search", query="ForegroundCycleTime", source="ese")
        assert any("TimeStamp=2021-11-16T19:18:00Z" in w for w in _windows(hits))

    def test_dirty_database_is_partial_and_source_names_differ_by_path(self, case: Path) -> None:
        a = _srudb(case / "Users" / "a" / "WebCacheV01.dat", dbstate=2)
        b = _srudb(case / "Users" / "b" / "WebCacheV01.dat", dbstate=2)
        table = "SruDbIdMapTable"
        ra = _call("query_ese_database", file_path=str(a), table=table, limit=5)
        rb = _call("query_ese_database", file_path=str(b), table=table, limit=5)
        assert ra["status"] == "partial"
        assert "transaction logs" in str(ra["tool_warning"])
        assert ra["source"] != rb["source"]

    def test_errors(self, case: Path) -> None:
        not_ese = case / "notes.edb"
        not_ese.write_bytes(b"hello")
        assert _call("query_ese_database", file_path=str(not_ese))["error_type"] == "invalid_input"
        db = _srudb(case / "app.edb")
        missing = _call("query_ese_database", file_path=str(db), table="Nope")
        assert "SruDbIdMapTable" in missing["error_message"]


def test_catalog_lists_known_ese_databases_wherever_they_are(tmp_path: Path) -> None:
    from mulder.extractors.classifier import EvidenceClassifier

    root = tmp_path / "evidence" / "C"
    for rel in (
        "$MFT",
        "Windows/System32/config/SYSTEM",
        "Windows/System32/sru/SRUDB.dat",
        f"{_SEARCH_DIR}/Windows.edb",
        "Users/eli/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat",
        "Windows/SoftwareDistribution/DataStore/DataStore.edb",
        "Users/eli/Downloads/stolen.edb",
    ):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(b"x")
    found = {
        item.path.relative_to(root).as_posix(): item.artifact_type
        for item in EvidenceClassifier().classify(tmp_path / "evidence")
        if item.artifact_type.endswith(("_database", "_index"))
    }
    assert found == {
        "Windows/System32/sru/SRUDB.dat": "srum_database",
        f"{_SEARCH_DIR}/Windows.edb": "windows_search_index",
        "Users/eli/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat": "ese_database",
        "Users/eli/Downloads/stolen.edb": "ese_database",
    }
