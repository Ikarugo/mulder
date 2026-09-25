"""The shared rules for external tools: a failure is never reported as "found nothing".

These pin the central helpers every wrapper relies on:

- ``run_tool`` / ``ToolRun``: exit code, the program's own last lines,
  timeouts with partial output, a missing binary, closed stdin;
- failure memory: an identical run that already failed is refused unless
  ``force`` is set;
- ``tool_response``: an error or partial status inside the result reaches
  the top level, and a large result is cut with a marker, not silently;
- "already indexed" skips ignore empty sources and are per parameter;
- composite tools do not count an empty source as evidence checked;
- mount failures carry their reason;
- batch results (``get_completed_results``) and ``run_parallel`` keep
  statuses, warnings and say what they cut.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.helpers import (
    TOOL_SOURCE_PREFIXES,
    failure_key,
    remember_failure,
    repeated_failure_response,
    run_failure_response,
    run_tool,
    sources_already_indexed,
    tool_response,
)


@pytest.fixture()
def case(tmp_path: Path) -> Path:
    """An open, empty case; returns its evidence directory."""
    from mulder.server.app import _tool_dispatch_sync, init_server

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "notes.txt").write_text("case notes")
    init_server(db_dir=tmp_path / "cases")
    result = _tool_dispatch_sync["scan_evidence"](evidence_path=str(evidence), case_id="core")
    assert result["status"] == "success", result
    return evidence


def _register(name: str, path: str, text: str) -> None:
    from mulder.server.extract_helpers import extract_and_index

    extract_and_index(text, name, path, "test")


class TestRunTool:
    def _py(self, code: str, **kwargs: Any) -> Any:
        return run_tool([sys.executable, "-c", code], **kwargs)

    def test_clean_run(self) -> None:
        run = self._py("print('rows')")
        assert run.ok and run.has_output and not run.failed
        assert run.warning() is None

    def test_failure_carries_exit_code_and_output(self) -> None:
        run = self._py(
            "import sys; print('opening image'); sys.stderr.write('bad sector\\n'); sys.exit(3)"
        )
        assert run.failed is False  # it printed something on stdout
        run = self._py("import sys; sys.stderr.write('cannot open E01\\n'); sys.exit(2)")
        assert run.failed
        assert run.error_type == "tool_failed"
        message = run.describe()
        assert "exited 2" in message and "cannot open E01" in message

    def test_partial_output_gives_a_warning(self) -> None:
        run = self._py("import sys; print('row 1'); sys.exit(1)")
        assert not run.ok and not run.failed
        assert "may be incomplete" in str(run.warning())

    def test_timeout_keeps_partial_output(self) -> None:
        run = self._py("import time; print('row', flush=True); time.sleep(5)", timeout=1)
        assert run.timed_out and run.error_type == "timeout"
        assert "row" in run.stdout
        assert "timed out after 1s" in run.describe()

    def test_missing_binary(self) -> None:
        run = run_tool(["/nonexistent/tool-xyz"])
        assert run.failed and run.error_type == "binary_missing"
        assert "could not be started" in run.describe()

    def test_stdin_is_closed(self) -> None:
        run = self._py("import sys; print(repr(sys.stdin.read()))", timeout=5)
        assert run.ok and run.stdout.strip() == "''"

    def test_undecodable_output_does_not_crash(self) -> None:
        run = self._py("import sys; sys.stdout.buffer.write(b'C:\\\\Users\\\\Andr\\xe9')")
        assert run.ok and "Andr" in run.stdout


class TestFailureMemory:
    def test_identical_run_is_refused_until_forced(self, case: Path) -> None:
        run = run_tool([sys.executable, "-c", "import sys; sys.exit(4)"])
        key = failure_key("run_x", "/evidence/disk.E01", "SYSTEM")
        first = run_failure_response("tc_1", "run_x", {}, run, time.monotonic(), memory_key=key)
        assert first["status"] == "error"

        again = repeated_failure_response("tc_2", "run_x", {}, key, time.monotonic())
        assert again is not None and "already failed" in str(again["error_message"])
        assert "force=True" in str(again["suggestion"])
        assert repeated_failure_response("tc_3", "run_x", {"force": True}, key) is None

    def test_key_depends_on_parameters(self, case: Path) -> None:
        remember_failure(failure_key("run_x", "/e", "hunt"), "boom")
        assert (
            repeated_failure_response("t", "run_x", {}, failure_key("run_x", "/e", "srum")) is None
        )

    def test_missing_binary_is_not_remembered(self, case: Path) -> None:
        run = run_tool(["/nonexistent/tool-xyz"])
        key = failure_key("run_x", "/e")
        run_failure_response("t", "run_x", {}, run, memory_key=key)
        assert repeated_failure_response("t", "run_x", {}, key) is None


class TestToolResponse:
    def test_error_inside_the_result_reaches_the_top(self) -> None:
        resp = tool_response(
            "tc", "run_volatility", {}, {"status": "error", "error_message": "Unsatisfied"}, "v"
        )
        assert resp["status"] == "error" and resp["error_message"] == "Unsatisfied"

    def test_warning_makes_it_partial(self) -> None:
        resp = tool_response(
            "tc", "t", {}, {"windows_indexed": 3, "tool_warning": "exited 1 after 3 rows"}, "s"
        )
        assert resp["status"] == "partial"

    def test_inline_results_are_lifted_too(self) -> None:
        resp = tool_response("tc", "t", {}, {"status": "partial", "tool_warning": "w"}, None)
        assert resp["status"] == "partial"

    def test_large_preview_is_cut_with_a_marker(self) -> None:
        alerts = [{"signature": f"ET RULE {i}", "src": "10.0.0.1"} for i in range(500)]
        resp = tool_response(
            "tc", "run_suricata", {}, {"alerts": alerts, "windows_indexed": 1}, "s"
        )
        assert resp["preview_truncated"] is True
        assert "not shown" in str(resp["preview"])
        assert "preview above is cut" in str(resp["hint"])

    def test_nothing_indexed_is_not_called_indexed(self) -> None:
        resp = tool_response("tc", "t", {}, {"windows_indexed": 0, "line_count": 0}, "s")
        assert "Nothing was indexed" in str(resp["hint"])

    def test_skip_mentions_force(self) -> None:
        resp = tool_response(
            "tc", "t", {"force": False}, {"status": "skipped", "existing_sources": ["x"]}, "x"
        )
        assert "force=True" in str(resp["hint"])


class TestSkips:
    def test_empty_source_does_not_block_a_run(self, case: Path) -> None:
        _register("regripper.system", "/e/disk.E01", "")
        assert sources_already_indexed(["regripper."], evidence_path="/e/disk.E01") == []
        _register("regripper.software", "/e/disk.E01", "key\nvalue")
        assert sources_already_indexed(["regripper."], evidence_path="/e/disk.E01") == [
            "regripper.software"
        ]

    @pytest.mark.parametrize(
        "tool",
        [
            "run_volatility",
            "run_volatility_batch",
            "run_registry_parser",
            "run_chainsaw",
            "run_zircolite",
            "run_evtx_parser",
            "run_bulk_extractor",
        ],
    )
    def test_parameter_dependent_tools_decide_themselves(self, tool: str) -> None:
        assert tool not in TOOL_SOURCE_PREFIXES

    def test_registry_skip_is_per_hive(self, case: Path) -> None:
        from mulder.server.tools.extract.registry import run_registry_parser

        image = str(case / "disk.E01")
        Path(image).write_bytes(b"x")
        _register("registry.software", image, "Microsoft\\Windows")
        fn = run_registry_parser.__wrapped__
        skipped = fn(image_path=image, hive="SOFTWARE")
        assert skipped["hint"] and "already indexed" in str(skipped["hint"])
        with patch(
            "mulder.server.tools.extract.registry._tsk_extract_files", return_value=[]
        ) as extract:
            fn(image_path=image, hive="SYSTEM")
        assert extract.called  # SYSTEM was not skipped because SOFTWARE exists

    def test_chainsaw_skip_is_per_mode(self, case: Path) -> None:
        from mulder.server.tools import chainsaw

        evtx = case / "logs"
        evtx.mkdir()
        _register("chainsaw.hunt", str(evtx), "detection")
        fn = chainsaw.run_chainsaw.__wrapped__
        assert "already indexed" in str(fn(evidence_path=str(evtx), mode="hunt").get("hint"))
        with patch.object(chainsaw, "_chainsaw_binary", return_value=None):
            other = fn(evidence_path=str(evtx), mode="srum")
        assert other["status"] == "error" and other["error_type"] == "binary_missing"


class TestCompositeEmptySources:
    def test_empty_source_is_reported_not_counted(self, case: Path) -> None:
        from mulder.server.tools.composite import core

        _register("hayabusa.alerts", "/e", "")
        core._invalidate_sources_cache()
        assert core._source_exists("hayabusa.alerts") is False
        (missing,) = core._check_missing_sources([("hayabusa.alerts", "run_hayabusa")])
        assert "indexed nothing" in missing["reason"]
        meta = core._build_coverage_metadata(["hayabusa.alerts"])
        assert meta["sources_empty"] == ["hayabusa.alerts"]
        assert "hayabusa.alerts" not in meta["sources_queried_names"]

    def test_real_source_is_counted(self, case: Path) -> None:
        from mulder.server.tools.composite import core

        _register("hayabusa.alerts", "/e", "rule hit")
        core._invalidate_sources_cache()
        assert core._source_exists("hayabusa.alerts") is True
        assert core._check_missing_sources([("hayabusa.alerts", "run_hayabusa")]) == []


class TestMountErrors:
    def test_reason_is_kept(self, tmp_path: Path) -> None:
        from mulder.server.extract_helpers import MountError, _MountCache

        def fail(image: Path, mount_point: Path, problems: list[str]) -> bool:
            problems.append("xmount: cannot open segment disk.E02")
            return False

        cache = _MountCache()
        with (
            patch("mulder.server.extract_helpers._mount_image", side_effect=fail),
            pytest.raises(MountError) as exc,
            cache.acquire(str(tmp_path / "disk.E01")),
        ):
            pass
        assert "cannot open segment disk.E02" in str(exc.value)


class TestIcat:
    def test_failure_reason_and_no_leftover_file(self, tmp_path: Path) -> None:
        from mulder.server.tools.extract.tsk import icat_file

        dest = tmp_path / "SYSTEM"
        proc = subprocess.CompletedProcess([], 1, stdout=None, stderr=b"Error reading image\n")
        with patch("mulder.server.tools.extract.tsk.subprocess.run", return_value=proc):
            ok, reason = icat_file("/e/disk.E01", 2048, "1234", dest)
        assert ok is False
        assert reason is not None and "Error reading image" in reason
        assert not dest.exists()


class TestBatchResults:
    def test_job_summary_keeps_status_warning_and_details(self) -> None:
        from mulder.server.tools.jobs import _job_summary

        details = {"non_pki_downloads": [{"url": "http://x/kape.zip"}], "entries": 2}
        summary = _job_summary(
            {
                "job_id": "j1",
                "tool": "parse_cryptnet_url_cache",
                "status": "completed",
                "result": {
                    "tool_call_id": "tc_9",
                    "status": "partial",
                    "tool_warning": "icat failed on 1 file",
                    "results": details,
                    "source": None,
                },
            }
        )
        assert summary["result_status"] == "partial"
        assert summary["tool_warning"] == "icat failed on 1 file"
        assert "kape.zip" in str(summary["details"])
        assert summary["job_id"] == "j1"

    def test_long_details_are_marked(self) -> None:
        from mulder.server.tools.jobs import _JOB_DETAILS_BUDGET, _job_summary

        summary = _job_summary(
            {"tool": "t", "status": "completed", "result": {"preview": "x" * 5000}}
        )
        assert summary["details_truncated"] is True
        assert len(str(summary["details"])) < _JOB_DETAILS_BUDGET + 200
        assert "wait(job_id=...)" in str(summary["details"])

    def test_get_completed_results_flags_unclean_tools(self, case: Path) -> None:
        from mulder.server.tools import jobs

        store = MagicMock()
        store.get_completed_results.return_value = [
            {"job_id": "a", "tool": "run_hayabusa", "result": {"status": "partial"}},
            {"job_id": "b", "tool": "run_prefetch_parser", "result": {"status": "success"}},
        ]
        with patch.object(jobs, "_get_job_store", return_value=store):
            resp = jobs.get_completed_results.__wrapped__("bg_1")
        assert resp["results_not_clean"] == ["run_hayabusa (partial)"]
        assert "gap" in str(resp["hint"])


class TestRunParallelSlim:
    def test_cut_is_marked_and_explained(self) -> None:
        from mulder.server.app import _slim_result

        slim = _slim_result(
            {"status": "success", "results": [{"name": f"f{i}"} for i in range(40)]},
            "list_directory",
        )
        assert slim["results_total"] == 40
        assert "Call list_directory directly" in slim["truncation_note"]
        assert "case DB" not in slim["truncation_note"]

    def test_uncut_result_has_no_note(self) -> None:
        from mulder.server.app import _slim_result

        assert "truncation_note" not in _slim_result({"results": [1, 2]}, "t")

    def test_long_strings_are_marked(self) -> None:
        from mulder.server.app import _slim_result

        slim = _slim_result({"results": {"text": "y" * 2000}}, "t")
        assert "more chars not shown" in json.dumps(slim)


class TestReviewFixes:
    """False alarms and misreports found by reviewing the first version of these changes."""

    _VOL_ERROR = (
        "Volatility 3 Framework 2.7.0\n"
        "Unsatisfied requirement plugins.PsList.kernel.layer_name: \n"
        "\n"
        "A translation layer requirement was not fulfilled.  Please verify that:\n"
        "\tA file was provided to create this layer (by -f, --single-location or by config)\n"
        "\tThe file is a valid memory image and was acquired cleanly\n"
    )

    def _vol(self, plugin: str, rc: int, stdout: str) -> tuple[dict[str, object], list[str]]:
        from mulder.server.tools.extract import volatility

        indexed: list[str] = []

        def _index(raw_output: str, **_: object) -> dict[str, object]:
            indexed.append(raw_output)
            return {"windows_indexed": 1, "line_count": 2}

        proc = subprocess.CompletedProcess([], rc, stdout=stdout, stderr="")
        with (
            patch.object(volatility.subprocess, "run", return_value=proc),
            patch.object(volatility, "extract_and_index", side_effect=_index),
        ):
            return volatility._run_single_vol_plugin(["vol"], "/e/mem.raw", plugin), indexed

    def test_volatility_error_text_is_not_indexed(self) -> None:
        result, indexed = self._vol("windows.pslist.PsList", 1, self._VOL_ERROR)
        assert result["status"] == "error"
        assert "Unsatisfied requirement" in str(result["error_message"])
        assert indexed == []

    def test_header_only_detection_plugin_is_a_clean_empty_result(self) -> None:
        header = "Volatility 3 Framework 2.7.0\nPID\tProcess\tStart VPN\tEnd VPN\tTag\n"
        result, indexed = self._vol("windows.malfind.Malfind", 0, header)
        assert result["status"] == "no_results"
        result, _ = self._vol("windows.pslist.PsList", 0, "PID\tPPID\tImageFileName\n")
        assert result["status"] == "header_only"
        assert indexed == []

    def test_timeouts_are_not_remembered(self, case: Path) -> None:
        run = run_tool([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
        key = failure_key("run_x", "/e/disk.E01")
        run_failure_response("t", "run_x", {}, run, memory_key=key)
        assert repeated_failure_response("t", "run_x", {}, key) is None

    def test_not_applicable_skip_is_not_called_already_indexed(self) -> None:
        resp = tool_response(
            "tc",
            "run_mft_parser",
            {"force": False},
            {"status": "skipped", "reason": "Not applicable: ext4 has no $MFT"},
            "ez.mft",
        )
        assert "already indexed" not in str(resp["hint"])
        assert "ext4 has no $MFT" in str(resp["hint"])

    def test_yara_defines_signature_base_externals(self) -> None:
        from mulder.server.tools import yara

        assert yara._YARA_EXTERNALS[:2] == ("-d", "filename=")
        assert "filepath=" in yara._YARA_EXTERNALS

    def test_failures_named_keeps_only_the_artifact(self) -> None:
        from mulder.server.tools.extract.tsk import IcatFailure, failures_named

        failures = [
            IcatFailure("Windows/System32/config/SYSTEM", "10", "bad"),
            IcatFailure("Windows/System32/config/systemprofile/x.dat", "11", "bad"),
        ]
        assert [f.inode for f in failures_named(failures, ("SYSTEM",))] == ["10"]

    def test_deleted_entries_that_cannot_be_read_are_not_gaps(self, case: Path) -> None:
        from mulder.server.tools.extract import tsk

        fls = (
            "r/r 10-128-1:\tWindows/Prefetch/A.EXE-1.pf\n"
            "r/r * 11-128-1:\tWindows/Prefetch/OLD.EXE-2.pf\n"
        )
        failures: list[Any] = []
        with (
            patch.object(tsk, "_collect_fls_chunks", return_value=[([fls], 0)]),
            patch.object(tsk, "icat_file", return_value=(False, "icat exited 1")),
        ):
            tsk._tsk_extract_files("/e/disk.E01", [".pf"], failures=failures)
        assert [f.path for f in failures] == ["Windows/Prefetch/A.EXE-1.pf"]

    def test_batch_not_clean_lists_only_errors_and_partials(self) -> None:
        from mulder.server.tools import jobs

        store = MagicMock()
        store.get_completed_results.return_value = [
            {"tool": "extract_archive", "result": {"status": "already_extracted"}},
            {"tool": "run_fls", "result": {"status": "partial"}},
        ]
        with patch.object(jobs, "_get_job_store", return_value=store):
            resp = jobs.get_completed_results.__wrapped__("bg_1")
        assert resp["results_not_clean"] == ["run_fls (partial)"]
