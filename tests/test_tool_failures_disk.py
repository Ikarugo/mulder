"""Failed Sleuth Kit and EVTX runs must be errors or warnings, not empty successes.

The TSK wrappers ignored exit codes: ``fsstat`` that found no filesystem
indexed an empty ``tsk.fsstat``, ``mactime`` rejecting a date range indexed an
empty ``tsk.timeline``, fls failing on a secondary partition was only logged,
and a failed ``mmls`` silently turned into partition offset 0. The EVTX
indexer fell back from EvtxECmd to python-evtx and then said only "No events
parsed". These tests drive the tools through ``run_tool`` with a faked
``subprocess.run``: a failed run is an error with the tool's reason and
nothing indexed; a non-zero exit after real output is ``partial`` with a
``tool_warning``; a clean run that found nothing stays a success.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.tools.extract import evtx, tsk

Proc = subprocess.CompletedProcess[str]
Result = Proc | Callable[[list[str], dict[str, Any]], Proc]

IMAGE = "/evidence/disk.dd"
MMLS_NO_TABLE = "Cannot determine partition type\n"


def _proc(rc: int, stdout: str = "", stderr: str = "") -> Proc:
    return subprocess.CompletedProcess(args=["tool"], returncode=rc, stdout=stdout, stderr=stderr)


class Harness:
    """Fakes one result per program name and records runs and indexing."""

    def __init__(self) -> None:
        self.indexed: list[tuple[str, str]] = []
        self.argv: list[list[str]] = []
        self.inputs: list[str | None] = []
        self.results: dict[str, Result] = {}
        self.kv: dict[str, str] = {}
        self.ctx = MagicMock()
        self.ctx.db.get_kv.side_effect = self.kv.get
        self.ctx.db.set_kv.side_effect = self.kv.__setitem__
        self.ctx.db.get_sources.return_value = []

    def index(self, raw: str, source_name: str, *_: object, **__: object) -> dict[str, object]:
        self.indexed.append((source_name, raw))
        return {"source_name": source_name, "windows_indexed": 1}

    def _run(self, argv: list[str], **kwargs: Any) -> Proc:
        self.argv.append(list(argv))
        self.inputs.append(kwargs.get("input"))
        name = Path(argv[0]).name
        if name == "dotnet":
            name = "EvtxECmd"
        result = self.results.get(name, _proc(0))
        if isinstance(result, subprocess.CompletedProcess):
            return result
        return result(argv, kwargs)

    def ran(self, name: str) -> list[list[str]]:
        return [a for a in self.argv if Path(a[0]).name == name]

    def patches(self, module: Any) -> list[Any]:
        return [
            patch("mulder.server.helpers.subprocess.run", side_effect=self._run),
            patch("mulder.server.helpers.has_ctx", return_value=True),
            patch("mulder.server.helpers.get_ctx", return_value=self.ctx),
            patch.object(module, "get_ctx", return_value=self.ctx),
            patch.object(module, "extract_and_index", side_effect=self.index),
            patch.object(module, "require_binary", side_effect=lambda b: f"/usr/bin/{b}"),
        ]

    def call(self, fn: Any, *args: Any, module: Any = tsk, **kwargs: Any) -> Any:
        with (
            patch.object(tsk, "probe_optical", return_value=None),
            patch.object(tsk, "get_ctx", return_value=self.ctx),
            patch.object(tsk, "require_binary", side_effect=lambda b: f"/usr/bin/{b}"),
        ):
            ps = self.patches(module)
            for p in ps:
                p.start()
            try:
                return getattr(fn, "__wrapped__", fn)(*args, **kwargs)
            finally:
                for p in reversed(ps):
                    p.stop()


@pytest.fixture
def h() -> Harness:
    return Harness()


def _assert_failed(result: dict[str, Any], h: Harness) -> None:
    assert result["status"] == "error", result
    assert h.indexed == [], "a failed run must not register a source"


# ---------------------------------------------------------------------------
# Partition helpers: the reason offset 0 was used is available to callers
# ---------------------------------------------------------------------------


class TestPartitionHelpers:
    def test_partition_table_text_reports_mmls_failure(self, h: Harness) -> None:
        h.results["mmls"] = _proc(1, stderr=MMLS_NO_TABLE)
        problems: list[str] = []
        assert h.call(tsk._partition_table_text, IMAGE, problems) == ""
        assert len(problems) == 1
        assert "mmls exited 1" in problems[0]
        assert "Cannot determine partition type" in problems[0]

    def test_partition_table_text_without_problems_list_still_works(self, h: Harness) -> None:
        h.results["mmls"] = _proc(1, stderr=MMLS_NO_TABLE)
        assert h.call(tsk._partition_table_text, IMAGE) == ""

    def test_detect_partition_offset_reports_timeout(self, h: Harness) -> None:
        def timeout(argv: list[str], kwargs: dict[str, Any]) -> Proc:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        h.results["mmls"] = timeout
        problems: list[str] = []
        assert h.call(tsk._detect_partition_offset, IMAGE, problems) == 0
        assert "mmls timed out after 30s" in problems[0]

    def test_run_fls_inline_failure_has_a_reason(self, h: Harness) -> None:
        h.results["mmls"] = _proc(1, stderr=MMLS_NO_TABLE)
        h.results["fls"] = _proc(1, stderr="Cannot determine file system type\n")
        problems: list[str] = []
        assert h.call(tsk._run_fls_inline, IMAGE, problems) == ""
        assert len(problems) == 1
        assert "fls exited 1" in problems[0]
        assert "Cannot determine file system type" in problems[0]
        assert "partition table not read" in problems[0], "offset 0 fallback is explained"
        assert h.kv == {}, "no offset is stored for a failed listing"

    def test_run_fls_inline_success_drops_the_mmls_note(self, h: Harness) -> None:
        h.results["mmls"] = _proc(1, stderr=MMLS_NO_TABLE)
        h.results["fls"] = _proc(0, "r/r 5-128-1:\tfile.txt\n")
        problems: list[str] = []
        assert h.call(tsk._run_fls_inline, IMAGE, problems).startswith("r/r 5")
        assert problems == []
        assert h.kv == {f"tsk_partition_offset:{IMAGE}": "0"}

    def test_collect_fls_chunks_passes_problems_through(self, h: Harness) -> None:
        h.results["fls"] = _proc(1, stderr="Invalid magic value\n")
        h.kv[f"tsk_partition_offset:{IMAGE}"] = "2048"
        problems: list[str] = []
        assert h.call(tsk._collect_fls_chunks, IMAGE, problems) == []
        assert "Invalid magic value" in problems[0]
        assert "partition offset 2048" in problems[0]


# ---------------------------------------------------------------------------
# run_mmls
# ---------------------------------------------------------------------------


class TestMmls:
    def test_launch_failure_is_an_error(self, h: Harness) -> None:
        def missing(argv: list[str], kwargs: dict[str, Any]) -> Proc:
            raise FileNotFoundError(2, "No such file or directory", "mmls")

        h.results["mmls"] = missing
        result = h.call(tsk.run_mmls, IMAGE)
        _assert_failed(result, h)
        assert result["error_type"] == "binary_missing"

    def test_output_then_exit_nonzero_is_partial(self, h: Harness) -> None:
        table = (
            "DOS Partition Table\n002:  000:000   0000002048   0041943039   0041940992   NTFS\n"
        )
        h.results["mmls"] = _proc(1, table, "Error reading extended partition\n")
        result = h.call(tsk.run_mmls, IMAGE)
        assert result["status"] == "partial"
        assert "Error reading extended partition" in result["tool_warning"]
        assert h.indexed[0][0] == "tsk.partitions"


# ---------------------------------------------------------------------------
# run_fsstat
# ---------------------------------------------------------------------------


class TestFsstat:
    def test_failure_is_an_error_with_reasons(self, h: Harness) -> None:
        h.results["mmls"] = _proc(1, stderr=MMLS_NO_TABLE)
        h.results["fsstat"] = _proc(1, stderr="Cannot determine file system type\n")
        result = h.call(tsk.run_fsstat, IMAGE)
        _assert_failed(result, h)
        assert result["error_type"] == "tool_failed"
        assert "fsstat exited 1" in result["error_message"]
        assert "Cannot determine file system type" in result["error_message"]
        assert "partition offset 0" in result["error_message"]
        assert "mmls exited 1" in result["error_message"]

    def test_output_then_exit_nonzero_is_partial(self, h: Harness) -> None:
        h.kv[f"tsk_partition_offset:{IMAGE}"] = "2048"
        h.results["fsstat"] = _proc(1, "FILE SYSTEM INFORMATION\nFile System Type: NTFS\n", "x")
        result = h.call(tsk.run_fsstat, IMAGE)
        assert result["status"] == "partial"
        assert "fsstat exited 1" in result["tool_warning"]
        assert h.indexed[0][0] == "tsk.fsstat"
        assert h.ran("fsstat")[0][:3] == ["fsstat", "-o", "2048"]

    def test_success(self, h: Harness) -> None:
        h.kv[f"tsk_partition_offset:{IMAGE}"] = "0"
        h.results["fsstat"] = _proc(0, "File System Type: NTFS\n")
        result = h.call(tsk.run_fsstat, IMAGE)
        assert result["status"] == "success"
        assert "tool_warning" not in result
        assert h.ran("mmls") == []


# ---------------------------------------------------------------------------
# run_mactime
# ---------------------------------------------------------------------------

BODY = "0|/Windows/notepad.exe|123-128-1|r/rrwxrwxrwx|0|0|100|1|2|3|4\n"
TIMELINE_HEADER = "Date,Size,Type,Mode,UID,GID,Meta,File Name\n"


class TestMactime:
    def test_fls_failure_is_an_error_with_reasons(self, h: Harness) -> None:
        h.results["mmls"] = _proc(1, stderr=MMLS_NO_TABLE)
        h.results["fls"] = _proc(1, stderr="Cannot determine file system type\n")
        result = h.call(tsk.run_mactime, IMAGE)
        _assert_failed(result, h)
        assert "fls exited 1" in result["error_message"]
        assert "Cannot determine file system type" in result["error_message"]
        assert "mmls exited 1" in result["error_message"]
        assert h.ran("mactime") == []

    def test_mactime_failure_is_an_error(self, h: Harness) -> None:
        h.kv[f"tsk_partition_offset:{IMAGE}"] = "0"
        h.results["fls"] = _proc(0, BODY)
        h.results["mactime"] = _proc(255, stderr="Invalid Date: 2015-13-45\n")
        result = h.call(tsk.run_mactime, IMAGE, time_range="2015-13-45..2015-14-01")
        _assert_failed(result, h)
        assert "mactime exited 255" in result["error_message"]
        assert "Invalid Date" in result["error_message"]

    def test_header_only_failure_is_an_error(self, h: Harness) -> None:
        h.kv[f"tsk_partition_offset:{IMAGE}"] = "0"
        h.results["fls"] = _proc(0, BODY)
        h.results["mactime"] = _proc(1, TIMELINE_HEADER, "died")
        result = h.call(tsk.run_mactime, IMAGE)
        _assert_failed(result, h)

    def test_malformed_time_range_is_rejected_before_running(self, h: Harness) -> None:
        result = h.call(tsk.run_mactime, IMAGE, time_range="last week")
        assert result["error_type"] == "invalid_parameter"
        assert h.argv == []

    def test_time_range_is_one_argument(self, h: Harness) -> None:
        """mactime reads only its first date argument: the end date was dropped."""
        h.kv[f"tsk_partition_offset:{IMAGE}"] = "0"
        h.results["fls"] = _proc(0, BODY)
        h.results["mactime"] = _proc(0, TIMELINE_HEADER + "Mon Aug 03 2015,100,m...,x\n")
        result = h.call(tsk.run_mactime, IMAGE, time_range="2015-08-01..2015-08-05")
        assert result["status"] == "success"
        assert h.ran("mactime")[0][-1] == "2015-08-01..2015-08-05"
        assert h.inputs[-1] == BODY

    def test_nothing_in_range_stays_success(self, h: Harness) -> None:
        h.kv[f"tsk_partition_offset:{IMAGE}"] = "0"
        h.results["fls"] = _proc(0, BODY)
        h.results["mactime"] = _proc(0, TIMELINE_HEADER)
        result = h.call(tsk.run_mactime, IMAGE, time_range="2001-01-01")
        assert result["status"] == "success"
        assert "no filesystem activity" in result["preview"]

    def test_partial_bodyfile_is_partial(self, h: Harness) -> None:
        h.kv[f"tsk_partition_offset:{IMAGE}"] = "0"
        h.results["fls"] = _proc(1, BODY, "Error reading inode 99\n")
        h.results["mactime"] = _proc(0, TIMELINE_HEADER + "row\n")
        result = h.call(tsk.run_mactime, IMAGE)
        assert result["status"] == "partial"
        assert "Error reading inode 99" in result["tool_warning"]


# ---------------------------------------------------------------------------
# run_fls
# ---------------------------------------------------------------------------

LISTING = "r/r 66-128-3:\tWindows/System32/config/SYSTEM\n"
MMLS_TWO = (
    "DOS Partition Table\n"
    "002:  000:000   0000002048   0041943039   0041940992   NTFS / exFAT (0x07)\n"
    "003:  000:001   0041943040   0062914559   0020971520   NTFS / exFAT (0x07)\n"
)


class TestFls:
    def _fls(self, failing_offset: str) -> Callable[[list[str], dict[str, Any]], Proc]:
        def run(argv: list[str], kwargs: dict[str, Any]) -> Proc:
            if failing_offset in argv:
                return _proc(1, stderr="Invalid magic value in superblock\n")
            return _proc(0, LISTING)

        return run

    def test_secondary_partition_failure_is_reported(self, h: Harness) -> None:
        h.results["mmls"] = _proc(0, MMLS_TWO)
        h.kv[f"tsk_partition_offset:{IMAGE}"] = "2048"
        h.results["fls"] = self._fls("41943040")
        with patch.object(tsk, "sources_already_indexed", return_value=[]):
            result = h.call(tsk.run_fls, IMAGE)
        assert result["status"] == "partial"
        assert "secondary partition" in result["tool_warning"]
        assert "Invalid magic value" in result["preview"]
        assert [s for s, _ in h.indexed] == ["tsk.filelist"]

    def test_all_partitions_listed_is_success(self, h: Harness) -> None:
        h.results["mmls"] = _proc(0, MMLS_TWO)
        h.kv[f"tsk_partition_offset:{IMAGE}"] = "2048"
        h.results["fls"] = _proc(0, LISTING)
        with patch.object(tsk, "sources_already_indexed", return_value=[]):
            result = h.call(tsk.run_fls, IMAGE)
        assert result["status"] == "success"
        assert [s for s, _ in h.indexed] == ["tsk.filelist", "tsk.filelist.p1"]

    def test_failure_includes_partition_lookup_reason(self, h: Harness) -> None:
        h.results["mmls"] = _proc(1, stderr=MMLS_NO_TABLE)
        h.results["fls"] = _proc(1, stderr="Cannot determine file system type\n")
        with patch.object(tsk, "sources_already_indexed", return_value=[]):
            result = h.call(tsk.run_fls, IMAGE)
        _assert_failed(result, h)
        assert result["error_type"] == "extraction_failed"
        assert "Cannot determine file system type" in result["error_message"]
        assert "Partition lookup: partition table not read" in result["error_message"]

    def test_output_then_exit_nonzero_is_partial(self, h: Harness) -> None:
        h.results["fls"] = _proc(1, LISTING, "Error reading directory 42\n")
        with patch.object(tsk, "sources_already_indexed", return_value=[]):
            result = h.call(tsk.run_fls, IMAGE, partition_offset=2048)
        assert result["status"] == "partial"
        assert "Error reading directory 42" in result["tool_warning"]
        assert h.indexed == [("tsk.filelist", LISTING.strip())]


# ---------------------------------------------------------------------------
# EVTX
# ---------------------------------------------------------------------------

EVTX_FAIL = _proc(1, stderr="Unhandled exception: EVTX header checksum mismatch\n")
CSV = "RecordNumber,EventId\n1,4624\n"


def _evtxecmd_writes(text: str, rc: int = 0) -> Callable[[list[str], dict[str, Any]], Proc]:
    def run(argv: list[str], kwargs: dict[str, Any]) -> Proc:
        out = Path(argv[argv.index("--csv") + 1])
        (out / "out.csv").write_text(text)
        return _proc(rc, "Processed 1 file\n")

    return run


#: An EVTX file that holds one event record (its signature after the chunk header).
_EVTX_WITH_RECORD = b"ElfFile\x00" + b"\x00" * (0x1200 - 8) + b"**\x00\x00" + b"\x00" * 64
#: An EVTX file with a header and an empty chunk: an unused channel.
_EVTX_EMPTY = b"ElfFile\x00" + b"\x00" * (0x1000 - 8) + b"ElfChnk\x00" + b"\x00" * 0x10000


@pytest.fixture
def extract_dir(tmp_path: Path) -> Iterator[Path]:
    d = tmp_path / "evtx_extract"
    d.mkdir()
    for name in ("Security.evtx", "System.evtx"):
        (d / name).write_bytes(_EVTX_WITH_RECORD)
    with evtx._evtx_lock:
        saved = dict(evtx._evtx_extract_dirs)
        evtx._evtx_extract_dirs.clear()
        evtx._evtx_extract_dirs[IMAGE] = str(d)
    yield d
    with evtx._evtx_lock:
        evtx._evtx_extract_dirs.clear()
        evtx._evtx_extract_dirs.update(saved)


@pytest.fixture
def ez() -> Iterator[None]:
    with (
        patch.object(evtx, "_find_ez_tool", return_value="/opt/ez/EvtxECmd.dll"),
        patch.object(evtx, "_python_evtx_missing", return_value=None),
    ):
        yield


def _python_evtx(texts: dict[str, str]) -> Any:
    def parse(path: Path, event_ids: object = None) -> tuple[str, str]:
        return path.stem.lower(), texts.get(path.name, "")

    return patch("mulder.extractors.disk._parse_evtx_file", side_effect=parse)


@pytest.mark.usefixtures("ez")
class TestIndexEvtxFile:
    def test_both_parsers_failing_is_an_error_naming_both(
        self, h: Harness, extract_dir: Path
    ) -> None:
        h.results["EvtxECmd"] = EVTX_FAIL
        with _python_evtx({}):
            result = h.call(evtx.index_evtx_file, "System.evtx", module=evtx)
        _assert_failed(result, h)
        message = result["error_message"]
        assert "EvtxECmd produced no CSV" in message
        assert "dotnet exited 1" in message
        assert "checksum mismatch" in message
        assert "python-evtx also parsed no events" in message

    def test_failure_is_remembered_and_not_rerun(self, h: Harness, extract_dir: Path) -> None:
        h.results["EvtxECmd"] = EVTX_FAIL
        with _python_evtx({}):
            first = h.call(evtx.index_evtx_file, "System.evtx", module=evtx)
            runs = len(h.argv)
            second = h.call(evtx.index_evtx_file, "System.evtx", module=evtx)
            assert len(h.argv) == runs, "the identical call must not run EvtxECmd again"
            other_ids = h.call(evtx.index_evtx_file, "System.evtx", [7045], module=evtx)
            forced = h.call(evtx.index_evtx_file, "System.evtx", force=True, module=evtx)
        assert first["status"] == "error"
        assert second["status"] == "error"
        assert "Not run again" in second["error_message"]
        assert "checksum mismatch" in second["error_message"]
        assert "Not run again" not in other_ids["error_message"]
        assert "Not run again" not in forced["error_message"]

    def test_python_evtx_fallback_success_notes_the_ez_failure(
        self, h: Harness, extract_dir: Path
    ) -> None:
        h.results["EvtxECmd"] = EVTX_FAIL
        with _python_evtx({"System.evtx": "2024-01-01 | 7045 | system | <Event/>"}):
            result = h.call(evtx.index_evtx_file, "System.evtx", module=evtx)
        assert result["status"] == "success"
        assert h.indexed[0][0] == "evtx.system"
        assert "checksum mismatch" in result["preview"]

    def test_evtxecmd_nonzero_with_csv_is_partial(self, h: Harness, extract_dir: Path) -> None:
        h.results["EvtxECmd"] = _evtxecmd_writes(CSV, rc=1)
        result = h.call(evtx.index_evtx_file, "System.evtx", module=evtx)
        assert result["status"] == "partial"
        assert h.indexed == [("evtx.system", CSV)]

    def test_companion_failures_are_reported(self, h: Harness, extract_dir: Path) -> None:
        def ez_run(argv: list[str], kwargs: dict[str, Any]) -> Proc:
            if argv[argv.index("-f") + 1].endswith("Security.evtx"):
                return _evtxecmd_writes(CSV)(argv, kwargs)
            return EVTX_FAIL

        h.results["EvtxECmd"] = ez_run
        with _python_evtx({}):
            result = h.call(evtx.index_evtx_file, "Security.evtx", module=evtx)
        assert result["status"] == "partial"
        assert result["companion_failures"][0]["file"] == "System.evtx"
        assert "checksum mismatch" in result["companion_failures"][0]["error"]
        assert "python-evtx parsed no events" in result["companion_failures"][0]["error"]
        assert "companion log" in result["tool_warning"]
        assert [s for s, _ in h.indexed] == ["evtx.security"]

    def test_companion_timeout_is_reported(self, h: Harness, extract_dir: Path) -> None:
        def timeout(argv: list[str], kwargs: dict[str, Any]) -> Proc:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        h.results["EvtxECmd"] = timeout
        failures: list[dict[str, object]] = []
        with patch.object(evtx, "get_ctx", return_value=h.ctx):
            indexed = h.call(
                evtx._auto_index_companion_logs, str(extract_dir), IMAGE, failures, module=evtx
            )
        assert indexed == []
        assert failures[0]["file"] == "System.evtx"
        assert "timed out" in str(failures[0]["error"])

    def test_clean_run_stays_success(self, h: Harness, extract_dir: Path) -> None:
        h.results["EvtxECmd"] = _evtxecmd_writes(CSV)
        result = h.call(evtx.index_evtx_file, "System.evtx", module=evtx)
        assert result["status"] == "success"
        assert "tool_warning" not in result


@pytest.mark.usefixtures("ez")
class TestRunEvtxParserDirectory:
    def test_both_parsers_failing_is_an_error(self, h: Harness, extract_dir: Path) -> None:
        h.results["EvtxECmd"] = EVTX_FAIL
        with (
            _python_evtx({}),
            patch.object(evtx, "sources_already_indexed", return_value=[]),
        ):
            result = h.call(evtx.run_evtx_parser, str(extract_dir), module=evtx)
        _assert_failed(result, h)
        message = result["error_message"]
        assert "checksum mismatch" in message
        assert "python-evtx also parsed no events from 2 EVTX file(s)" in message

    def test_evtxecmd_missing_is_named_in_the_error(self, h: Harness, extract_dir: Path) -> None:
        with (
            _python_evtx({}),
            patch.object(evtx, "sources_already_indexed", return_value=[]),
            patch.object(evtx, "_find_ez_tool", return_value=None),
        ):
            result = h.call(evtx.run_evtx_parser, str(extract_dir), module=evtx)
        _assert_failed(result, h)
        assert "EvtxECmd.dll not found" in result["error_message"]

    def test_directory_without_evtx_is_artifact_missing(self, h: Harness, tmp_path: Path) -> None:
        with patch.object(evtx, "sources_already_indexed", return_value=[]):
            result = h.call(evtx.run_evtx_parser, str(tmp_path), module=evtx)
        assert result["error_type"] == "artifact_missing"

    def test_python_evtx_success_without_evtxecmd_is_success(
        self, h: Harness, extract_dir: Path
    ) -> None:
        texts = {"Security.evtx": "a | 4624 | security | x", "System.evtx": "b | 7045 | system"}
        with (
            _python_evtx(texts),
            patch.object(evtx, "sources_already_indexed", return_value=[]),
            patch.object(evtx, "_find_ez_tool", return_value=None),
        ):
            result = h.call(evtx.run_evtx_parser, str(extract_dir), module=evtx)
        assert result["status"] == "success"
        assert sorted(s for s, _ in h.indexed) == ["evtx.security", "evtx.system"]


def test_image_mode_names_the_listing_failure(h: Harness, tmp_path: Path) -> None:
    image = tmp_path / "disk.dd"
    image.write_bytes(b"\x00" * 512)
    h.results["mmls"] = _proc(1, stderr=MMLS_NO_TABLE)
    h.results["fls"] = _proc(1, stderr="Cannot determine file system type\n")
    with (
        patch.object(evtx, "sources_already_indexed", return_value=[]),
        patch.object(evtx, "_find_carved_evtx", return_value=[]),
    ):
        result = h.call(evtx.run_evtx_parser, str(image), module=evtx)
    assert result["status"] == "error"
    assert result["error_type"] == "extraction_failed"
    assert "Cannot determine file system type" in result["error_message"]
    with evtx._evtx_lock:
        evtx._evtx_extract_dirs.pop(str(image), None)


class TestEmptyEventLogs:
    """Most channels are empty: that is a fact about the host, not a parser failure."""

    def test_record_detection(self, tmp_path: Path) -> None:
        full, empty = tmp_path / "a.evtx", tmp_path / "b.evtx"
        full.write_bytes(_EVTX_WITH_RECORD)
        empty.write_bytes(_EVTX_EMPTY)
        assert evtx._evtx_has_records(full) is True
        assert evtx._evtx_has_records(empty) is False
        assert evtx._evtx_has_records(tmp_path / "missing.evtx") is True  # unsure: say yes

    def test_directory_of_empty_logs_is_not_an_error(self, h: Harness, tmp_path: Path) -> None:
        d = tmp_path / "logs"
        d.mkdir()
        for name in ("Microsoft-Windows-A.evtx", "Microsoft-Windows-B.evtx"):
            (d / name).write_bytes(_EVTX_EMPTY)
        with (
            _python_evtx({}),
            patch.object(evtx, "sources_already_indexed", return_value=[]),
            patch.object(evtx, "_find_ez_tool", return_value=None),
        ):
            result = h.call(evtx.run_evtx_parser, str(d), module=evtx)
        assert result["status"] == "success"
        assert result["results"]["logs_without_records_count"] == 2

    def test_empty_companion_is_not_a_failure(self, h: Harness, extract_dir: Path) -> None:
        (extract_dir / "System.evtx").write_bytes(_EVTX_EMPTY)
        with _python_evtx({"Security.evtx": "2024-01-01 | 4624 | security | <Event/>"}):
            result = h.call(evtx.index_evtx_file, "Security.evtx", module=evtx)
        assert "companion_failures" not in result
        assert result["status"] == "success"

    def test_index_of_an_empty_log_says_so(self, h: Harness, extract_dir: Path) -> None:
        (extract_dir / "System.evtx").write_bytes(_EVTX_EMPTY)
        with _python_evtx({}):
            result = h.call(evtx.index_evtx_file, "System.evtx", module=evtx)
        assert result["status"] == "success"
        assert "holds no event record" in str(result["results"]["message"])
