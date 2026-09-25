"""User-activity extractors (USN, LNK, Jump Lists, Shellbags, SRUM) and query_sqlite_file.

The EZ Tools themselves are not run: ``_run_ez_tool`` is replaced by a
recorder that captures the arguments and the files staged for the tool,
which is what these extractors are responsible for.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.helpers import TOOL_TIMEOUT
from mulder.server.tools.extract import user_activity as ua

_FILES: dict[str, bytes] = {
    "$MFT": b"FILE0",
    "$Extend/$UsnJrnl:$J": b"usn-records",
    "Windows/System32/config/SYSTEM": b"regf",
    "Windows/System32/config/SOFTWARE": b"regf-software",
    "Windows/System32/config/SOFTWARE.LOG1": b"log",
    "Windows/System32/sru/SRUDB.dat": b"ese-srum",
    "Users/alice/NTUSER.DAT": b"regf-nt",
    "Users/alice/NTUSER.DAT.LOG1": b"nt-log1",
    "Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat": b"regf-uc",
    "Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2": b"uc-log2",
    "Users/alice/AppData/Roaming/Microsoft/Windows/Recent/report.docx.lnk": b"L-recent",
    "Users/alice/Desktop/tool.lnk": b"L-desktop",
    (
        "Users/alice/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/"
        "5f7b5f1e01b83767.automaticDestinations-ms"
    ): b"JL-auto",
    (
        "Users/alice/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/"
        "28c8b86deab549a1.customDestinations-ms"
    ): b"JL-custom",
    "ProgramData/Microsoft/Windows/Start Menu/Programs/App.lnk": b"L-startmenu",
    "Windows.old/Users/alice/NTUSER.DAT": b"regf-old",
}


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    base = tmp_path / "triage" / "WS01" / "C"
    for rel, data in _FILES.items():
        path = base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return base


class _Recorder:
    """Stands in for ``_run_ez_tool``; snapshots staged files while they exist."""

    def __init__(self, result: dict[str, object] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.result = result or {"status": "success"}

    def __call__(
        self,
        dll: str,
        args: list[str],
        source: str,
        source_path: str,
        tc_id: str,
        tool: str,
        params: object,
        t0: float,
        timeout: int | None = None,
    ) -> dict[str, object]:
        files: dict[str, bytes] = {}
        if args[0] == "-d":
            base = Path(args[1])
            files = {
                p.relative_to(base).as_posix(): p.read_bytes()
                for p in sorted(base.rglob("*"))
                if p.is_file()
            }
        else:
            files = {a: Path(a).read_bytes() for a in args if Path(a).is_file()}
        self.calls.append(
            {"dll": dll, "args": args, "source": source, "files": files, "timeout": timeout}
        )
        return dict(self.result)


@pytest.fixture()
def ez() -> Iterator[_Recorder]:
    rec = _Recorder()
    with (
        patch.object(ua, "_run_ez_tool", rec),
        patch.object(ua, "sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.extract.tsk.get_ctx"),
    ):
        yield rec


def _call(fn: Any, image_path: Path | str) -> dict[str, Any]:
    return fn.__wrapped__(str(image_path))  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# $UsnJrnl:$J
# ---------------------------------------------------------------------------


class TestUsn:
    def test_triage_reads_j_and_mft_in_place(self, root: Path, ez: _Recorder) -> None:
        assert _call(ua.run_usn_parser, root) == {"status": "success"}
        (call,) = ez.calls
        assert call["dll"] == "MFTECmd.dll"
        assert call["source"] == "ez.usnjrnl"
        assert call["args"] == [
            "-f",
            str(root / "$Extend" / "$UsnJrnl:$J"),
            "-m",
            str(root / "$MFT"),
        ]
        assert call["timeout"] >= TOOL_TIMEOUT * 2

    def test_kape_name(self, root: Path, ez: _Recorder) -> None:
        (root / "$Extend" / "$UsnJrnl:$J").rename(root / "$Extend" / "$J")
        _call(ua.run_usn_parser, root)
        assert ez.calls[0]["args"][1] == str(root / "$Extend" / "$J")

    def test_missing_journal(self, root: Path, ez: _Recorder) -> None:
        (root / "$Extend" / "$UsnJrnl:$J").unlink()
        result = _call(ua.run_usn_parser, root)
        assert result["status"] == "error"
        assert result["error_type"] == "artifact_missing"
        assert ez.calls == []

    def test_image_reads_the_named_stream(self, tmp_path: Path, ez: _Recorder) -> None:
        image = tmp_path / "disk.E01"
        image.write_bytes(b"EVF")
        fls = (
            "r/r 11-128-3:\t$Extend/$UsnJrnl:$Max\n"
            "r/r 11-128-4:\t$Extend/$UsnJrnl:$J\n"
            "r/r 64-128-2:\tWindows/notepad.exe\n"
        )
        commands: list[list[str]] = []

        def fake_icat(cmd: list[str], stdout: Any, **_: Any) -> Any:
            commands.append(cmd)
            stdout.write(b"J-bytes" if cmd[-1] == "11-128-4" else b"MFT-bytes")

            class _Done:
                returncode = 0

            return _Done()

        with (
            patch.object(ua, "_collect_fls_chunks", return_value=[([fls], 2048)]),
            patch.object(ua, "require_binary", return_value="/usr/bin/icat"),
            patch(
                "mulder.server.tools.extract.user_activity.subprocess.run", side_effect=fake_icat
            ),
        ):
            _call(ua.run_usn_parser, image)

        assert commands == [
            ["icat", "-h", "-o", "2048", str(image), "11-128-4"],
            ["icat", "-o", "2048", str(image), "0"],
        ]
        (call,) = ez.calls
        assert list(call["files"].values()) == [b"J-bytes", b"MFT-bytes"]
        assert call["args"][0] == "-f" and call["args"][2] == "-m"


# ---------------------------------------------------------------------------
# LNK and Jump Lists
# ---------------------------------------------------------------------------


class TestLnkAndJumpLists:
    def test_lnk_only_from_user_profiles(self, root: Path, ez: _Recorder) -> None:
        _call(ua.run_lnk_parser, root)
        (call,) = ez.calls
        assert call["dll"] == "LECmd.dll"
        assert call["source"] == "ez.lnkfiles"
        assert sorted(call["files"].values()) == [b"L-desktop", b"L-recent"]
        staged_dir = Path(call["args"][1])
        assert not staged_dir.exists(), "staging directory must be cleaned up"

    def test_jump_lists(self, root: Path, ez: _Recorder) -> None:
        _call(ua.run_jumplist_parser, root)
        (call,) = ez.calls
        assert call["dll"] == "JLECmd.dll"
        names = sorted(call["files"])
        assert names[0].endswith(".automaticDestinations-ms")
        assert names[1].endswith(".customDestinations-ms")

    def test_no_lnk(self, tmp_path: Path, ez: _Recorder) -> None:
        bare = tmp_path / "C"
        (bare / "Windows" / "System32" / "config").mkdir(parents=True)
        result = _call(ua.run_lnk_parser, bare)
        assert result["error_type"] == "artifact_missing"

    def test_already_indexed_is_skipped(self, root: Path) -> None:
        rec = _Recorder()
        with (
            patch.object(ua, "_run_ez_tool", rec),
            patch.object(ua, "sources_already_indexed", return_value=["ez.lnkfiles"]),
            patch.object(ua, "tool_response", side_effect=lambda *a, **k: a[3]),
        ):
            result = _call(ua.run_lnk_parser, root)
        assert result["status"] == "skipped"
        assert rec.calls == []


# ---------------------------------------------------------------------------
# Shellbags
# ---------------------------------------------------------------------------


class TestShellbags:
    def test_triage_hives_keep_names_and_logs(self, root: Path, ez: _Recorder) -> None:
        _call(ua.run_shellbags_parser, root)
        (call,) = ez.calls
        assert call["dll"] == "SBECmd.dll"
        assert call["source"] == "ez.shellbags"
        assert call["files"] == {
            "Users_alice/NTUSER.DAT": b"regf-nt",
            "Users_alice/NTUSER.DAT.LOG1": b"nt-log1",
            "Users_alice/UsrClass.dat": b"regf-uc",
            "Users_alice/UsrClass.dat.LOG2": b"uc-log2",
            "Windows.old_Users_alice/NTUSER.DAT": b"regf-old",
        }

    def test_image_hives_one_folder_per_user(self, tmp_path: Path, ez: _Recorder) -> None:
        staged = tmp_path / "staged"
        staged.mkdir()
        hives = []
        for i, (htype, data) in enumerate(
            [("ntuser", b"a-nt"), ("usrclass", b"a-uc"), ("ntuser", b"old-nt")]
        ):
            f = staged / f"hive{i}"
            f.write_bytes(data)
            hives.append((f, htype, "alice"))
        with patch.object(ua, "_discover_user_hives_via_tsk", return_value=(hives, str(staged))):
            _call(ua.run_shellbags_parser, tmp_path / "disk.E01")
        assert ez.calls[0]["files"] == {
            "alice/NTUSER.DAT": b"a-nt",
            "alice/UsrClass.dat": b"a-uc",
            "alice_2/NTUSER.DAT": b"old-nt",
        }
        assert not staged.exists()

    def test_no_user_hives(self, tmp_path: Path, ez: _Recorder) -> None:
        bare = tmp_path / "C"
        (bare / "Windows" / "System32" / "config").mkdir(parents=True)
        assert _call(ua.run_shellbags_parser, bare)["error_type"] == "artifact_missing"


# ---------------------------------------------------------------------------
# SRUM
# ---------------------------------------------------------------------------


class TestSrum:
    def test_srudb_with_software_hive(self, root: Path, ez: _Recorder) -> None:
        _call(ua.run_srum_parser, root)
        (call,) = ez.calls
        assert call["dll"] == "SrumECmd.dll"
        assert call["args"][0] == "-f" and call["args"][2] == "-r"
        assert call["files"] == {
            call["args"][1]: b"ese-srum",
            call["args"][3]: b"regf-software",
        }

    def test_dirty_database_hint(self, root: Path) -> None:
        rec = _Recorder({"status": "error", "error_message": "SrumECmd.dll produced no CSV"})
        with (
            patch.object(ua, "_run_ez_tool", rec),
            patch.object(ua, "sources_already_indexed", return_value=[]),
            patch("mulder.server.tools.extract.tsk.get_ctx"),
        ):
            result = _call(ua.run_srum_parser, root)
        assert "esentutl" in result["suggestion"]

    def test_missing_binary_keeps_its_own_message(self, root: Path) -> None:
        rec = _Recorder({"status": "error", "error_type": "binary_missing"})
        with (
            patch.object(ua, "_run_ez_tool", rec),
            patch.object(ua, "sources_already_indexed", return_value=[]),
            patch("mulder.server.tools.extract.tsk.get_ctx"),
        ):
            result = _call(ua.run_srum_parser, root)
        assert "suggestion" not in result

    def test_missing_database(self, root: Path, ez: _Recorder) -> None:
        (root / "Windows" / "System32" / "sru" / "SRUDB.dat").unlink()
        assert _call(ua.run_srum_parser, root)["error_type"] == "artifact_missing"
        assert ez.calls == []


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_tools_are_registered_for_executors() -> None:
    from mulder.server.app import _tool_dispatch_sync
    from mulder.server.helpers import TOOL_SOURCE_PREFIXES
    from mulder.server.tool_access import Role, get_tools_for_role

    for tool, source in [
        ("run_usn_parser", "ez.usnjrnl"),
        ("run_lnk_parser", "ez.lnkfiles"),
        ("run_jumplist_parser", "ez.jumplists"),
        ("run_shellbags_parser", "ez.shellbags"),
        ("run_srum_parser", "ez.srum"),
    ]:
        assert tool in _tool_dispatch_sync
        assert TOOL_SOURCE_PREFIXES[tool] == [source]
        assert f"mcp__mulder__{tool}" in get_tools_for_role(Role.EXTRACT_EXECUTOR)
    assert "query_sqlite_file" in _tool_dispatch_sync


# ---------------------------------------------------------------------------
# query_sqlite_file
# ---------------------------------------------------------------------------


@pytest.fixture()
def case(tmp_path: Path) -> Iterator[Path]:
    """An active case whose evidence root is <tmp>/evidence."""
    from mulder.server.app import create_case, init_server

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    init_server(db_dir=tmp_path / "cases")
    create_case("sqlite-case", str(evidence))
    yield evidence


def _history_db(path: Path, keep_open: bool = False) -> sqlite3.Connection | None:
    """A places.sqlite look-alike; *keep_open* leaves the last rows in the WAL only."""
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, visit_count INT)")
    conn.executemany(
        "INSERT INTO moz_places (url, visit_count) VALUES (?, ?)",
        [(f"https://example.org/{i}", i) for i in range(5)],
    )
    conn.commit()
    conn.execute("INSERT INTO moz_places (url, visit_count) VALUES ('https://mega.nz/x', 9)")
    conn.commit()
    if keep_open:
        return conn
    conn.close()
    return None


def _query(**kwargs: Any) -> dict[str, Any]:
    from mulder.server.app import _tool_dispatch_sync

    return _tool_dispatch_sync["query_sqlite_file"](**kwargs)  # type: ignore[no-any-return]


class TestQuerySqliteFile:
    def test_empty_query_lists_schema(self, case: Path) -> None:
        db = case / "places.sqlite"
        _history_db(db)
        result = _query(file_path=str(db))
        assert result["status"] == "success"
        (table,) = result["tables"]
        assert table["name"] == "moz_places"
        assert table["columns"] == ["id", "url", "visit_count"]
        assert table["rows"] == 6

    def test_select_sees_wal_pages_and_leaves_evidence_alone(self, case: Path) -> None:
        db = case / "places.sqlite"
        writer = _history_db(db, keep_open=True)
        assert (case / "places.sqlite-wal").exists()
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in case.iterdir()}
        try:
            result = _query(
                file_path=str(db),
                query="SELECT url FROM moz_places WHERE url LIKE '%mega%'",
                description="firefox alice",
            )
        finally:
            assert writer is not None
            writer.close()
        assert result["status"] == "success"
        assert result["result_count"] == 1
        assert result["source"] == "sqlite.firefox_alice"
        after_names = {p.name for p in case.iterdir()}
        assert "places.sqlite-shm" not in after_names - set(before)

    def test_rows_are_capped(self, case: Path) -> None:
        db = case / "places.sqlite"
        _history_db(db)
        result = _query(file_path=str(db), query="SELECT * FROM moz_places", max_rows=2)
        assert result["result_count"] == 2
        assert result["truncated"] is True

    @pytest.mark.parametrize(
        "query",
        [
            "DELETE FROM moz_places",
            "SELECT 1; DROP TABLE moz_places",
            "ATTACH DATABASE '/etc/passwd' AS x",
            "PRAGMA writable_schema=ON",
        ],
    )
    def test_writes_are_refused(self, case: Path, query: str) -> None:
        db = case / "places.sqlite"
        _history_db(db)
        result = _query(file_path=str(db), query=query)
        assert result["status"] == "error"

    def test_path_outside_evidence_is_refused(self, case: Path, tmp_path: Path) -> None:
        outside = tmp_path / "outside.sqlite"
        _history_db(outside)
        result = _query(file_path=str(outside), query="SELECT 1")
        assert result["status"] == "error"
        assert "outside" in result["error_message"]

    def test_non_sqlite_file(self, case: Path) -> None:
        f = case / "notes.db"
        f.write_text("plain text")
        result = _query(file_path=str(f))
        assert "Not a SQLite database" in result["error_message"]
