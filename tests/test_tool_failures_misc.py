"""Failed runs of the misc extraction tools must be errors, not empty sources.

Each wrapper used to index ``proc.stdout.strip()`` whatever the exit code, so
a tool that could not open its input registered an empty (or placeholder, or
stderr) source and answered ``status: success`` -- which the agent reads as
"ran, found nothing". These tests drive each wrapper through ``run_tool``
with a faked ``subprocess.run`` and check three shapes: a failed run is an
error and nothing is indexed; a non-zero exit after real output is indexed as
``partial`` with a ``tool_warning``; a clean run that found nothing stays a
success.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.server.tools.extract import misc

Proc = subprocess.CompletedProcess[str]
Runner = Callable[..., Proc]


def _proc(rc: int, stdout: str = "", stderr: str = "") -> Proc:
    return subprocess.CompletedProcess(args=["tool"], returncode=rc, stdout=stdout, stderr=stderr)


class Harness:
    """Records what was indexed and what was run."""

    def __init__(self) -> None:
        self.indexed: list[tuple[str, str]] = []
        self.summaries: list[dict[str, object]] = []
        self.argv: list[list[str]] = []

    def index(self, raw: str, source_name: str, *_: object, **__: object) -> dict[str, object]:
        self.indexed.append((source_name, raw))
        summary: dict[str, object] = {"source_name": source_name, "windows_indexed": 1}
        self.summaries.append(summary)
        return summary

    def call(self, tool: Any, *args: Any, result: Proc | Runner, **kwargs: Any) -> Any:
        def _run(argv: list[str], **_: object) -> Proc:
            self.argv.append(list(argv))
            if isinstance(result, subprocess.CompletedProcess):
                return result
            return result(argv)

        with (
            patch.object(misc, "require_binary", return_value="/usr/bin/tool"),
            patch("mulder.server.helpers.subprocess.run", side_effect=_run),
            patch.object(misc, "extract_and_index", side_effect=self.index),
        ):
            return tool.__wrapped__(*args, **kwargs)


@pytest.fixture
def h() -> Harness:
    return Harness()


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    path = tmp_path / "evidence.bin"
    path.write_bytes(b"\x00" * 64)
    return path


@pytest.fixture
def triage_root(tmp_path: Path) -> Iterator[Path]:
    root = tmp_path / "triage" / "WS01" / "C"
    (root / "Windows" / "System32" / "config").mkdir(parents=True)
    (root / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"regf")
    (root.parent / "manifest.json").write_text(json.dumps({"hostname": "WS01"}))
    yield root


def _assert_failed(result: dict[str, Any], h: Harness) -> None:
    assert result["status"] == "error", result
    assert result["error_type"] in {"tool_failed", "timeout"}, result
    assert h.indexed == [], "a failed run must not register a source"


# ---------------------------------------------------------------------------
# run_clamav
# ---------------------------------------------------------------------------


class TestClamav:
    def test_scan_error_is_an_error(self, h: Harness, evidence: Path) -> None:
        proc = _proc(
            2,
            stdout=f"{evidence}: Can't open file or directory ERROR\n",
            stderr="LibClamAV Error: cli_loaddbdir(): No supported database files found\n",
        )
        result = h.call(misc.run_clamav, str(evidence), result=proc)
        _assert_failed(result, h)
        assert "exited 2" in result["error_message"]
        assert "No supported database" in result["error_message"]

    def test_detection_exit_1_is_a_success(self, h: Harness, evidence: Path) -> None:
        proc = _proc(1, stdout=f"{evidence}: Win.Test.EICAR_HDB-1 FOUND\n")
        result = h.call(misc.run_clamav, str(evidence), result=proc)
        assert result["status"] == "success"
        assert "tool_warning" not in result
        assert h.summaries[0]["detections"] == 1
        assert h.indexed[0][1].endswith("FOUND")

    def test_clean_scan_stays_success(self, h: Harness, evidence: Path) -> None:
        result = h.call(misc.run_clamav, str(evidence), result=_proc(0, f"{evidence}: OK\n"))
        assert result["status"] == "success"
        assert h.summaries[0]["detections"] == 0

    def test_errors_after_a_partial_scan_are_partial(self, h: Harness, tmp_path: Path) -> None:
        stdout = f"{tmp_path}/a.exe: OK\n{tmp_path}/b.exe: Access denied ERROR\n"
        result = h.call(misc.run_clamav, str(tmp_path), result=_proc(2, stdout))
        assert result["status"] == "partial"
        assert "exited 2" in result["tool_warning"]
        assert h.summaries[0]["scan_errors"] == 1

    def test_missing_target(self, h: Harness, tmp_path: Path) -> None:
        result = h.call(misc.run_clamav, str(tmp_path / "nope"), result=_proc(0))
        assert result["error_type"] == "file_not_found"
        assert h.argv == []


# ---------------------------------------------------------------------------
# run_regripper
# ---------------------------------------------------------------------------


class TestRegripper:
    def test_failed_run_is_an_error(self, h: Harness, evidence: Path) -> None:
        proc = _proc(255, stderr="Not a valid registry hive file\n")
        result = h.call(misc.run_regripper, str(evidence), result=proc)
        _assert_failed(result, h)
        assert "Not a valid registry hive" in result["error_message"]

    def test_output_then_exit_nonzero_is_partial(self, h: Harness, evidence: Path) -> None:
        result = h.call(misc.run_regripper, str(evidence), result=_proc(1, "compname v.1\nWS01"))
        assert result["status"] == "partial"
        assert h.indexed == [("regripper.evidence", "compname v.1\nWS01")]

    def test_success(self, h: Harness, evidence: Path) -> None:
        result = h.call(misc.run_regripper, str(evidence), result=_proc(0, "compname v.1"))
        assert result["status"] == "success"
        assert h.argv[0][-1] == "-a"


# ---------------------------------------------------------------------------
# libyal tools: vshadowinfo, bdeinfo, fvdeinfo
# ---------------------------------------------------------------------------


class TestLibyal:
    @pytest.mark.parametrize(
        ("tool", "banner"),
        [
            (misc.run_vshadow_info, "vshadowinfo 20210425"),
            (misc.run_bdeinfo, "bdeinfo 20231220"),
            (misc.run_fvdeinfo, "fvdeinfo 20231220"),
        ],
    )
    def test_banner_only_failure_is_an_error(
        self, h: Harness, evidence: Path, tool: Any, banner: str
    ) -> None:
        proc = _proc(1, stdout=f"{banner}\n\n", stderr="Unable to open: evidence.bin.\n")
        result = h.call(tool, str(evidence), result=proc)
        _assert_failed(result, h)
        assert "Unable to open" in result["error_message"]

    def test_vshadow_stderr_is_never_indexed(self, h: Harness, evidence: Path) -> None:
        result = h.call(misc.run_vshadow_info, str(evidence), result=_proc(1, stderr="bad"))
        _assert_failed(result, h)

    @pytest.mark.parametrize(
        ("tool", "source"),
        [
            (misc.run_vshadow_info, "vshadow.info"),
            (misc.run_bdeinfo, "bde.info"),
            (misc.run_fvdeinfo, "fvde.info"),
        ],
    )
    def test_success_is_indexed(self, h: Harness, evidence: Path, tool: Any, source: str) -> None:
        stdout = "tool 20231220\n\nVolume information:\n\tNumber of stores: 0\n"
        result = h.call(tool, str(evidence), result=_proc(0, stdout))
        assert result["status"] == "success"
        assert h.indexed[0][0] == source


# ---------------------------------------------------------------------------
# run_dislocker
# ---------------------------------------------------------------------------


class TestDislocker:
    def test_metadata_failure_is_an_error(self, h: Harness, evidence: Path) -> None:
        proc = _proc(1, stderr="[ERROR] The signature of the volume doesn't match\n")
        result = h.call(misc.run_dislocker, str(evidence), result=proc)
        _assert_failed(result, h)
        assert "signature" in result["error_message"]

    def test_metadata_success(self, h: Harness, evidence: Path) -> None:
        result = h.call(misc.run_dislocker, str(evidence), result=_proc(0, "Signature: -FVE-FS-"))
        assert result["status"] == "success"
        assert h.indexed[0][0] == "dislocker.metadata"

    def test_fuse_failure_is_an_error_and_cleans_up(self, h: Harness, evidence: Path) -> None:
        proc = _proc(1, stderr="[CRITICAL] Unable to grab VMK or FVEK. Abort.\n")
        result = h.call(misc.run_dislocker, str(evidence), result=proc, password="secret")
        _assert_failed(result, h)
        assert "dislocker-fuse failed" in result["error_message"]
        assert "Unable to grab VMK" in result["error_message"]
        assert "secret" not in json.dumps(result)
        assert not Path(h.argv[0][-1]).exists(), "the unused mount point was left behind"
        assert str(evidence) not in misc._dislocker_mounts


# ---------------------------------------------------------------------------
# run_radare2
# ---------------------------------------------------------------------------


class TestRadare2:
    def test_directory_is_rejected(self, h: Harness, tmp_path: Path) -> None:
        result = h.call(misc.run_radare2, str(tmp_path), result=_proc(0))
        assert result["status"] == "error"
        assert result["error_type"] == "invalid_input"
        assert h.argv == [] and h.indexed == []

    def test_cannot_open_with_exit_0_is_an_error(self, h: Harness, evidence: Path) -> None:
        proc = _proc(0, stderr="ERROR: Cannot open 'evidence.bin'\n")
        result = h.call(misc.run_radare2, str(evidence), result=proc)
        _assert_failed(result, h)
        assert "Cannot open" in result["error_message"]

    def test_nonzero_exit_without_output_is_an_error(self, h: Harness, evidence: Path) -> None:
        _assert_failed(h.call(misc.run_radare2, str(evidence), result=_proc(1)), h)

    def test_success_with_warnings_on_stderr(self, h: Harness, evidence: Path) -> None:
        proc = _proc(0, "arch x86\nbits 64\n", stderr="WARN: Relocs has not been applied\n")
        result = h.call(misc.run_radare2, str(evidence), result=proc)
        assert result["status"] == "success"
        assert h.indexed[0] == ("radare2.analysis", "arch x86\nbits 64")


# ---------------------------------------------------------------------------
# run_tcpflow / run_tcpxtract
# ---------------------------------------------------------------------------


def _writes(files: dict[str, bytes], rc: int, stdout: str = "", stderr: str = "") -> Runner:
    """A fake run that writes *files* into the ``-o`` directory, then exits *rc*."""

    def _run(argv: list[str]) -> Proc:
        out = Path(argv[argv.index("-o") + 1])
        for name, data in files.items():
            (out / name).write_bytes(data)
        return _proc(rc, stdout, stderr)

    return _run


class TestTcpflow:
    def test_failure_does_not_index_the_placeholder(self, h: Harness, evidence: Path) -> None:
        run = _writes({"report.xml": b"<dfxml/>"}, 1, stderr="tcpflow: unknown file format\n")
        result = h.call(misc.run_tcpflow, str(evidence), result=run)
        _assert_failed(result, h)
        assert "unknown file format" in result["error_message"]

    def test_streams_then_nonzero_exit_is_partial(self, h: Harness, evidence: Path) -> None:
        run = _writes({"010.000.000.001.00080-010.000.000.002.51000": b"GET / HTTP/1.1"}, 1)
        result = h.call(misc.run_tcpflow, str(evidence), result=run)
        assert result["status"] == "partial"
        assert "exited 1" in result["tool_warning"]
        assert h.summaries[0]["stream_count"] == 1

    def test_streams_success(self, h: Harness, evidence: Path) -> None:
        run = _writes({"a-b": b"GET / HTTP/1.1", "report.xml": b"<dfxml/>"}, 0)
        result = h.call(misc.run_tcpflow, str(evidence), result=run)
        assert result["status"] == "success"
        assert h.summaries[0]["stream_count"] == 1
        assert "report.xml" not in h.indexed[0][1]

    def test_clean_run_without_streams_stays_success(self, h: Harness, evidence: Path) -> None:
        result = h.call(misc.run_tcpflow, str(evidence), result=_writes({}, 0))
        assert result["status"] == "success"
        assert h.summaries[0]["stream_count"] == 0


class TestTcpxtract:
    def test_usage_text_is_an_error(self, h: Harness, evidence: Path) -> None:
        proc = _proc(0, stdout="Usage: tcpxtract [OPTIONS] [[-d <device>] [-f <file>]]\n")
        result = h.call(misc.run_tcpxtract, str(evidence), result=proc)
        _assert_failed(result, h)
        assert "usage" in result["error_message"]

    def test_nonzero_exit_without_files_is_an_error(self, h: Harness, evidence: Path) -> None:
        proc = _proc(1, stderr="Could not open config file\n")
        _assert_failed(h.call(misc.run_tcpxtract, str(evidence), result=proc), h)

    def test_carved_files_success(self, h: Harness, evidence: Path) -> None:
        run = _writes({"00000000.jpg": b"\xff\xd8\xff"}, 0)
        result = h.call(misc.run_tcpxtract, str(evidence), result=run)
        assert result["status"] == "success"
        assert h.summaries[0]["files_carved"] == 1

    def test_carved_files_then_nonzero_exit_is_partial(self, h: Harness, evidence: Path) -> None:
        run = _writes({"00000000.jpg": b"\xff\xd8\xff"}, 1)
        result = h.call(misc.run_tcpxtract, str(evidence), result=run)
        assert result["status"] == "partial"


# ---------------------------------------------------------------------------
# run_chkrootkit
# ---------------------------------------------------------------------------


class TestChkrootkit:
    def test_windows_triage_root_is_not_applicable(self, h: Harness, triage_root: Path) -> None:
        result = h.call(misc.run_chkrootkit, str(triage_root), result=_proc(0, "not infected"))
        assert result["status"] == "error"
        assert result["error_type"] == "not_applicable_triage"
        assert h.argv == [] and h.indexed == []

    def test_failure_is_an_error(self, h: Harness, tmp_path: Path) -> None:
        proc = _proc(1, stderr="chkrootkit: need root privileges\n")
        result = h.call(misc.run_chkrootkit, str(tmp_path), result=proc)
        _assert_failed(result, h)
        assert "need root" in result["error_message"]

    def test_output_then_nonzero_exit_is_partial(self, h: Harness, tmp_path: Path) -> None:
        proc = _proc(1, "Checking `amd'... not found\n")
        result = h.call(misc.run_chkrootkit, str(tmp_path), result=proc)
        assert result["status"] == "partial"

    def test_success(self, h: Harness, tmp_path: Path) -> None:
        proc = _proc(0, "Checking `amd'... not found\n")
        result = h.call(misc.run_chkrootkit, str(tmp_path), result=proc)
        assert result["status"] == "success"
        assert h.argv[0] == ["chkrootkit", "-r", str(tmp_path)]


def test_timeout_without_output_is_a_timeout_error(h: Harness, evidence: Path) -> None:
    def _slow(argv: list[str]) -> Proc:
        raise subprocess.TimeoutExpired(argv, 600)

    result = h.call(misc.run_bdeinfo, str(evidence), result=_slow)
    assert result["status"] == "error"
    assert result["error_type"] == "timeout"
    assert h.indexed == []
