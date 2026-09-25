"""Failed carving and network tools must not be reported as "ran, found nothing".

Each wrapper here used to ignore the exit code of its external tool and index
whatever was left (an empty audit, "No files carved", "Total alerts: 0",
"[tshark error ...]") as a successful result. The rules now:

* nothing usable + tool did not complete -> error, nothing indexed;
* tool did not complete but left output -> indexed, ``partial`` + ``tool_warning``;
* tool completed and found nothing -> success, as before.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder.server.tools.extract import carving, pcap
from mulder.server.tools.extract.carving import (
    run_binwalk,
    run_bulk_extractor,
    run_foremost,
    run_scalpel,
)
from mulder.server.tools.extract.pcap import (
    run_pcap_analysis,
    run_suricata,
    run_zeek_analysis,
)

_RUN = "mulder.server.helpers.subprocess.run"
Proc = subprocess.CompletedProcess


def _proc(cmd: list[str], rc: int, stdout: str = "", stderr: str = "") -> Proc[str]:
    return subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr=stderr)


@pytest.fixture
def image(tmp_path: Path) -> Path:
    path = tmp_path / "evidence.dd"
    path.write_bytes(b"\x00" * 4096)
    return path


@pytest.fixture
def capture(tmp_path: Path) -> Path:
    path = tmp_path / "traffic.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
    return path


class _Indexed:
    """Records what ``extract_and_index`` was asked to index."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def __call__(self, raw: str, source_name: str, *args: object) -> dict[str, object]:
        self.calls.append((source_name, raw))
        return {
            "source_name": source_name,
            "windows_indexed": 1 if raw.strip() else 0,
            "line_count": raw.count("\n") + 1,
            "status": "indexed",
        }

    def sources(self) -> list[str]:
        return [name for name, _ in self.calls]


# ---------------------------------------------------------------------------
# Carving
# ---------------------------------------------------------------------------


@pytest.fixture
def carve_env() -> Iterator[_Indexed]:
    indexed = _Indexed()
    with (
        patch.object(carving, "require_binary", return_value="/usr/bin/tool"),
        patch.object(carving, "sources_already_indexed", return_value=[]),
        patch.object(carving, "_check_disk_space", return_value=None),
        patch.object(carving, "extract_and_index", side_effect=indexed),
    ):
        yield indexed


def _out_dir(cmd: list[str]) -> Path:
    return Path(cmd[cmd.index("-o") + 1])


class TestForemost:
    def test_failed_run_without_audit_is_an_error(self, image: Path, carve_env: _Indexed) -> None:
        proc = _proc(["foremost"], 1, "", "foremost: cannot open evidence.dd: Permission denied")
        with patch(_RUN, return_value=proc):
            result = run_foremost.__wrapped__(str(image))  # type: ignore[attr-defined]

        assert result["status"] == "error"
        assert "Permission denied" in result["error_message"]
        assert carve_env.calls == []

    def test_non_zero_after_audit_is_partial(self, image: Path, carve_env: _Indexed) -> None:
        def run(cmd: list[str], **kwargs: Any) -> Proc[str]:
            out = _out_dir(cmd)
            out.mkdir(parents=True)
            (out / "audit.txt").write_text("Foremost version 1.5.7\n3 FILES EXTRACTED\n")
            return _proc(cmd, 1, "", "foremost: read error at sector 4096")

        with patch(_RUN, side_effect=run):
            result = run_foremost.__wrapped__(str(image))  # type: ignore[attr-defined]

        assert result["status"] == "partial"
        assert "read error" in str(result["tool_warning"])
        assert carve_env.sources() == ["foremost.audit"]
        assert "3 FILES EXTRACTED" in carve_env.calls[0][1]

    def test_clean_run_stays_success(self, image: Path, carve_env: _Indexed) -> None:
        def run(cmd: list[str], **kwargs: Any) -> Proc[str]:
            out = _out_dir(cmd)
            out.mkdir(parents=True)
            (out / "audit.txt").write_text("0 FILES EXTRACTED\n")
            return _proc(cmd, 0)

        with patch(_RUN, side_effect=run):
            result = run_foremost.__wrapped__(str(image))  # type: ignore[attr-defined]

        assert result["status"] == "success"
        assert "tool_warning" not in result


class TestScalpel:
    def test_failed_run_does_not_index_its_stdout(self, image: Path, carve_env: _Indexed) -> None:
        proc = _proc(["scalpel"], 255, "Scalpel version 1.60\nOpening target\n", "ERROR: read")
        with patch(_RUN, return_value=proc):
            result = run_scalpel.__wrapped__(str(image))  # type: ignore[attr-defined]

        assert result["status"] == "error"
        assert "exited 255" in result["error_message"]
        assert carve_env.calls == []

    def test_no_file_type_configured_is_an_error(self, image: Path, carve_env: _Indexed) -> None:
        proc = _proc(
            ["scalpel"],
            0,
            "ERROR: The configuration file didn't specify any file types to carve.\n",
        )
        with patch(_RUN, return_value=proc):
            result = run_scalpel.__wrapped__(str(image))  # type: ignore[attr-defined]

        assert result["status"] == "error"
        assert "scalpel.conf" in result["suggestion"]
        assert carve_env.calls == []

    def test_clean_run_stays_success(self, image: Path, carve_env: _Indexed) -> None:
        def run(cmd: list[str], **kwargs: Any) -> Proc[str]:
            out = _out_dir(cmd)
            out.mkdir(parents=True)
            (out / "audit.txt").write_text("Scalpel audit\njpg: 2 files\n")
            return _proc(cmd, 0, "done\n")

        with patch(_RUN, side_effect=run):
            result = run_scalpel.__wrapped__(str(image))  # type: ignore[attr-defined]

        assert result["status"] == "success"
        assert carve_env.calls == [("scalpel.audit", "Scalpel audit\njpg: 2 files\n")]


class TestBinwalk:
    def test_failed_run_is_an_error(self, image: Path, carve_env: _Indexed) -> None:
        proc = _proc(["binwalk"], 1, "", "binwalk: Permission denied")
        with patch(_RUN, return_value=proc):
            result = run_binwalk.__wrapped__(str(image))  # type: ignore[attr-defined]

        assert result["status"] == "error"
        assert carve_env.calls == []

    def test_non_zero_with_output_is_partial(self, image: Path, carve_env: _Indexed) -> None:
        proc = _proc(["binwalk"], 3, "DECIMAL  HEX  DESCRIPTION\n0  0x0  gzip\n", "boom")
        with patch(_RUN, return_value=proc):
            result = run_binwalk.__wrapped__(str(image))  # type: ignore[attr-defined]

        assert result["status"] == "partial"
        assert "exited 3" in str(result["tool_warning"])
        assert carve_env.sources() == ["binwalk.scan"]

    def test_clean_run_stays_success(self, image: Path, carve_env: _Indexed) -> None:
        proc = _proc(["binwalk"], 0, "DECIMAL  HEX  DESCRIPTION\n")
        with patch(_RUN, return_value=proc):
            result = run_binwalk.__wrapped__(str(image))  # type: ignore[attr-defined]

        assert result["status"] == "success"


class TestBulkExtractor:
    def test_failure_message_carries_the_end_of_stderr(
        self, image: Path, carve_env: _Indexed
    ) -> None:
        stderr = "x" * 2000 + "\nbulk_extractor: fatal: cannot open image: Permission denied\n"
        with patch(_RUN, return_value=_proc(["bulk_extractor"], 1, "", stderr)):
            result = run_bulk_extractor.__wrapped__(str(image))  # type: ignore[attr-defined]

        assert result["status"] == "error"
        assert "cannot open image" in result["error_message"]
        assert carve_env.calls == []

    def test_timeout_after_features_is_partial_and_marked(
        self, image: Path, carve_env: _Indexed
    ) -> None:
        def run(cmd: list[str], **kwargs: Any) -> Proc[str]:
            (_out_dir(cmd) / "email.txt").write_text("0\tuser@example.com\tctx\n")
            raise subprocess.TimeoutExpired(cmd, 5)

        with (
            patch(_RUN, side_effect=run),
            patch.object(carving, "remember_failure") as remember,
        ):
            result = run_bulk_extractor.__wrapped__(str(image))  # type: ignore[attr-defined]

        assert result["status"] == "partial"
        assert "timed out" in str(result["tool_warning"])
        assert carve_env.sources() == ["bulk.email"]
        key, message = remember.call_args[0]
        assert key.endswith(":partial") and message

    def test_sources_of_a_partial_run_do_not_skip_the_next_run(
        self, image: Path, carve_env: _Indexed
    ) -> None:
        with (
            patch.object(carving, "sources_already_indexed", return_value=["bulk.email"]),
            patch.object(carving, "previous_failure", return_value="timed out earlier"),
            patch(_RUN, return_value=_proc(["bulk_extractor"], 0)) as run,
        ):
            result = run_bulk_extractor.__wrapped__(str(image))  # type: ignore[attr-defined]

        assert run.called
        assert result["status"] == "success"

    def test_timeout_without_features_is_an_error(self, image: Path, carve_env: _Indexed) -> None:
        with patch(_RUN, side_effect=subprocess.TimeoutExpired(["bulk_extractor"], 5)):
            result = run_bulk_extractor.__wrapped__(str(image))  # type: ignore[attr-defined]

        assert result["status"] == "error"
        assert result["error_type"] == "timeout"
        assert carve_env.calls == []

    def test_cut_feature_files_are_reported(self, image: Path, carve_env: _Indexed) -> None:
        def run(cmd: list[str], **kwargs: Any) -> Proc[str]:
            lines = "".join(f"{i}\tuser{i}@example.com\tctx\n" for i in range(100))
            (_out_dir(cmd) / "email.txt").write_text(lines)
            return _proc(cmd, 0)

        with (
            patch(_RUN, side_effect=run),
            patch.object(carving, "_MAX_FEATURE_FILE_SIZE", 200),
        ):
            result = run_bulk_extractor.__wrapped__(str(image))  # type: ignore[attr-defined]

        assert result["status"] == "partial"
        assert "bulk.email" in str(result["tool_warning"])
        assert "truncated_features" in str(result["preview"])
        indexed = carve_env.calls[0][1]
        assert len(indexed) <= 200 and indexed.endswith("ctx")


# ---------------------------------------------------------------------------
# tshark (run_pcap_analysis)
# ---------------------------------------------------------------------------


def _binaries(*present: str) -> Callable[[str], str | None]:
    def which(name: str) -> str | None:
        base = Path(name).name
        return f"/usr/bin/{base}" if base in present else None

    return which


@pytest.fixture
def pcap_env() -> Iterator[_Indexed]:
    indexed = _Indexed()
    with (
        patch.object(pcap, "require_binary", side_effect=_binaries("tshark")),
        patch.object(pcap, "extract_and_index", side_effect=indexed),
    ):
        yield indexed


def _preview(result: dict[str, Any]) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(str(result["preview"]))
    return parsed


class TestPcapAnalysis:
    def test_unreadable_capture_is_an_error_not_indexed(
        self, capture: Path, pcap_env: _Indexed
    ) -> None:
        proc = _proc(["tshark"], 2, "", "tshark: The file isn't a capture file in a known format")
        with patch(_RUN, return_value=proc):
            result = run_pcap_analysis.__wrapped__(str(capture), mode="dns")  # type: ignore[attr-defined]

        assert result["status"] == "error"
        assert "isn't a capture file" in result["error_message"]
        assert pcap_env.calls == []

    def test_capture_cut_mid_packet_is_a_note_not_a_warning(
        self, capture: Path, pcap_env: _Indexed
    ) -> None:
        # Carved and live-copied captures often end mid-packet: tshark reads
        # everything before it and exits 2. Flagging it would make most real
        # captures "partial".
        proc = _proc(
            ["tshark"],
            2,
            "frame.time\tip.src\nJan 1\t10.0.0.1\n",
            "tshark: The file appears to have been cut short in the middle of a packet.",
        )
        with patch(_RUN, return_value=proc):
            result = run_pcap_analysis.__wrapped__(str(capture), mode="dns")  # type: ignore[attr-defined]

        assert result["status"] == "success"
        assert pcap_env.sources() == ["pcap.dns"]
        assert "ends in the middle of a packet" in pcap_env.calls[0][1]
        assert "[tshark" not in pcap_env.calls[0][1]

    def test_other_non_zero_exit_with_output_is_partial(
        self, capture: Path, pcap_env: _Indexed
    ) -> None:
        proc = _proc(["tshark"], 2, "frame.time\tip.src\nJan 1\t10.0.0.1\n", "tshark: bad record")
        with patch(_RUN, return_value=proc):
            result = run_pcap_analysis.__wrapped__(str(capture), mode="dns")  # type: ignore[attr-defined]

        assert result["status"] == "partial"
        assert "bad record" in str(result["tool_warning"])

    def test_all_modes_report_per_mode_errors(self, capture: Path, pcap_env: _Indexed) -> None:
        def run(cmd: list[str], **kwargs: Any) -> Proc[str]:
            if "http" in cmd or "smtp" in cmd:
                return _proc(cmd, 2, "", "tshark: dissector bug")
            return _proc(cmd, 0, "header\nrow\n")

        with patch(_RUN, side_effect=run):
            result = run_pcap_analysis.__wrapped__(str(capture), mode="all")  # type: ignore[attr-defined]

        assert result["status"] == "partial"
        body = _preview(result)
        failed = {e["mode"] for e in body["mode_errors"]}
        assert failed == {"http", "smtp"}
        assert "pcap.http" not in pcap_env.sources()
        assert all("tshark error" not in raw for _, raw in pcap_env.calls)

    def test_empty_success_stays_success(self, capture: Path, pcap_env: _Indexed) -> None:
        with patch(_RUN, return_value=_proc(["tshark"], 0, "")):
            result = run_pcap_analysis.__wrapped__(str(capture), mode="dns")  # type: ignore[attr-defined]

        assert result["status"] == "success"
        assert _preview(result)["modes"][0]["status"] == "no_output"

    def test_packet_limit_is_reported(self, capture: Path, pcap_env: _Indexed) -> None:
        def run(cmd: list[str], **kwargs: Any) -> Proc[str]:
            if cmd[0].endswith("capinfos"):
                return _proc(cmd, 0, f"File name: {capture}\nNumber of packets:   50000\n")
            return _proc(cmd, 0, "header\nrow\n")

        with (
            patch.object(pcap, "require_binary", side_effect=_binaries("tshark", "capinfos")),
            patch(_RUN, side_effect=run),
        ):
            result = run_pcap_analysis.__wrapped__(str(capture), mode="dns", max_packets=100)  # type: ignore[attr-defined]

        body = _preview(result)
        assert body["packets_in_capture"] == 50000
        assert body["packets_limited_to"] == 100
        assert result["status"] == "success"


# ---------------------------------------------------------------------------
# Zeek
# ---------------------------------------------------------------------------


@pytest.fixture
def zeek_env() -> Iterator[_Indexed]:
    indexed = _Indexed()
    with (
        patch.object(pcap, "require_binary", side_effect=_binaries("zeek")),
        patch.object(pcap, "extract_and_index", side_effect=indexed),
    ):
        yield indexed


def _conn_log(records: int) -> str:
    return "".join(
        json.dumps({"uid": f"C{i}", "id.resp_h": "8.8.8.8", "duration": 1.0}) + "\n"
        for i in range(records)
    )


class TestZeek:
    def test_failed_run_without_logs_is_an_error(self, capture: Path, zeek_env: _Indexed) -> None:
        proc = _proc(["zeek"], 1, "", "fatal error: problem with trace file (bad dump file)")
        with patch(_RUN, return_value=proc):
            result = run_zeek_analysis.__wrapped__(str(capture))  # type: ignore[attr-defined]

        assert result["status"] == "error"
        assert "problem with trace file" in result["error_message"]
        assert zeek_env.calls == []

    def test_non_zero_with_logs_is_partial(self, capture: Path, zeek_env: _Indexed) -> None:
        def run(cmd: list[str], **kwargs: Any) -> Proc[str]:
            (Path(kwargs["cwd"]) / "conn.log").write_text(_conn_log(3))
            return _proc(cmd, 1, "", "error: truncated packet")

        with patch(_RUN, side_effect=run):
            result = run_zeek_analysis.__wrapped__(str(capture))  # type: ignore[attr-defined]

        assert result["status"] == "partial"
        assert "truncated packet" in str(result["tool_warning"])
        assert "zeek.conn" in zeek_env.sources()

    def test_cut_logs_are_reported(
        self, capture: Path, zeek_env: _Indexed, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(pcap, "_ZEEK_LOG_INDEX_CHARS", 50_000)

        def run(cmd: list[str], **kwargs: Any) -> Proc[str]:
            (Path(kwargs["cwd"]) / "conn.log").write_text(_conn_log(2000))
            return _proc(cmd, 0)

        with patch(_RUN, side_effect=run):
            result = run_zeek_analysis.__wrapped__(str(capture))  # type: ignore[attr-defined]

        assert result["status"] == "partial"
        assert "zeek.conn" in str(result["tool_warning"])
        indexed = dict(zeek_env.calls)
        assert len(indexed["zeek.conn"]) <= pcap._ZEEK_LOG_INDEX_CHARS
        assert "2000 records" in indexed["zeek.summary"]
        assert "only the first" in indexed["zeek.summary"]

    def test_clean_run_stays_success(self, capture: Path, zeek_env: _Indexed) -> None:
        def run(cmd: list[str], **kwargs: Any) -> Proc[str]:
            (Path(kwargs["cwd"]) / "conn.log").write_text(_conn_log(3))
            return _proc(cmd, 0)

        with patch(_RUN, side_effect=run):
            result = run_zeek_analysis.__wrapped__(str(capture))  # type: ignore[attr-defined]

        assert result["status"] == "success"


# ---------------------------------------------------------------------------
# Suricata
# ---------------------------------------------------------------------------


_ALERT = json.dumps(
    {
        "event_type": "alert",
        "src_ip": "10.0.0.5",
        "dest_ip": "1.2.3.4",
        "alert": {"signature": "ET TROJAN test", "severity": 1, "category": "c"},
    }
)


def _suricata(rc: int, eve: str | None, stdout: str = "") -> Callable[..., Proc[str]]:
    def run(cmd: list[str], **kwargs: Any) -> Proc[str]:
        if eve is not None:
            (Path(cmd[cmd.index("-l") + 1]) / "eve.json").write_text(eve)
        return _proc(cmd, rc, stdout, "" if rc == 0 else "E: suricata: engine failed")

    return run


@pytest.fixture
def suricata_env() -> Iterator[_Indexed]:
    indexed = _Indexed()
    with (
        patch.object(pcap, "_suricata_binary", return_value="/usr/bin/suricata"),
        patch.object(pcap, "extract_and_index", side_effect=indexed),
    ):
        yield indexed


class TestSuricata:
    def test_failed_run_without_eve_is_an_error(
        self, capture: Path, suricata_env: _Indexed
    ) -> None:
        with patch(_RUN, side_effect=_suricata(1, None)):
            result = run_suricata.__wrapped__(str(capture))  # type: ignore[attr-defined]

        assert result["status"] == "error"
        assert "engine failed" in result["error_message"]
        assert suricata_env.calls == []

    def test_failed_run_with_empty_eve_is_an_error(
        self, capture: Path, suricata_env: _Indexed
    ) -> None:
        with patch(_RUN, side_effect=_suricata(1, "")):
            result = run_suricata.__wrapped__(str(capture))  # type: ignore[attr-defined]

        assert result["status"] == "error"
        assert suricata_env.calls == []

    def test_non_zero_with_alerts_is_partial(self, capture: Path, suricata_env: _Indexed) -> None:
        with patch(_RUN, side_effect=_suricata(1, _ALERT + "\n")):
            result = run_suricata.__wrapped__(str(capture))  # type: ignore[attr-defined]

        assert result["status"] == "partial"
        assert "Total alerts: 1" in suricata_env.calls[0][1]

    def test_no_rules_loaded_is_a_warning(self, capture: Path, suricata_env: _Indexed) -> None:
        stdout = "Info: detect: 1 rule files processed. 0 rules successfully loaded, 0 failed\n"
        with patch(_RUN, side_effect=_suricata(0, "", stdout)):
            result = run_suricata.__wrapped__(str(capture))  # type: ignore[attr-defined]

        assert result["status"] == "partial"
        assert "no detection rules" in str(result["tool_warning"])

    def test_clean_run_stays_success(self, capture: Path, suricata_env: _Indexed) -> None:
        stdout = "Info: detect: 45000 rules successfully loaded, 0 rules failed\n"
        with patch(_RUN, side_effect=_suricata(0, _ALERT + "\n", stdout)):
            result = run_suricata.__wrapped__(str(capture))  # type: ignore[attr-defined]

        assert result["status"] == "success"
        assert "Total alerts: 1" in suricata_env.calls[0][1]


# ---------------------------------------------------------------------------
# analyze_disk_pcaps
# ---------------------------------------------------------------------------


def _disk_pcaps(**kwargs: Any) -> dict[str, Any]:
    from mulder.server.app import _tool_dispatch_sync

    def fake_icat(image_path: str, inode: str, offset: int, dest: Path) -> bool:
        dest.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
        return True

    ctx = MagicMock()
    ctx.case_id = "case"
    fls = "r/r 6001:\tCaptures/network.pcap\n"
    with (
        patch("mulder.server.tools.extract.disk_pcap.get_ctx", return_value=ctx),
        patch("mulder.server.tools.extract.disk_pcap.require_binary", return_value=True),
        patch(
            "mulder.server.tools.extract.disk_pcap._collect_fls_chunks",
            return_value=[([fls], 63)],
        ),
        patch(
            "mulder.server.tools.extract.disk_pcap._extract_pcap_via_icat",
            side_effect=fake_icat,
        ),
    ):
        result: dict[str, Any] = _tool_dispatch_sync["analyze_disk_pcaps"](
            case_id="case", image_path="/images/disk.dd", **kwargs
        )
    return result


class TestAnalyzeDiskPcaps:
    def test_credential_search_failures_are_reported(self) -> None:
        indexed = _Indexed()

        def run(cmd: list[str], **kwargs: Any) -> Proc[str]:
            if "-Y" in cmd:
                return _proc(cmd, 2, "", "tshark: cut short in the middle of a packet")
            return _proc(cmd, 0, "stats\n")

        with (
            patch(_RUN, side_effect=run),
            patch("mulder.server.tools.extract.disk_pcap.extract_and_index", side_effect=indexed),
        ):
            result = _disk_pcaps(run_ids=False, extract_credentials=True)

        assert result["status"] == "partial"
        body = result["results"]
        assert body["total_credentials_found"] == 0
        assert body["credential_searches_failed"] == 6
        assert "credentials:ftp_credentials" in str(result["tool_warning"])

    def test_unreadable_captures_are_an_error_and_not_indexed(self) -> None:
        indexed = _Indexed()
        proc = _proc(["tshark"], 2, "", "tshark: The file isn't a capture file")
        with (
            patch(_RUN, return_value=proc),
            patch("mulder.server.tools.extract.disk_pcap.extract_and_index", side_effect=indexed),
        ):
            result = _disk_pcaps(run_ids=False, extract_credentials=False)

        assert result["status"] == "error"
        assert indexed.calls == []

    def test_suricata_failure_is_not_zero_alerts(self) -> None:
        indexed = _Indexed()

        def run(cmd: list[str], **kwargs: Any) -> Proc[str]:
            if cmd[0].endswith("suricata"):
                return _proc(cmd, 1, "", "E: suricata: rule path missing")
            return _proc(cmd, 0, "stats\n")

        with (
            patch(_RUN, side_effect=run),
            patch("mulder.server.tools.extract.disk_pcap.extract_and_index", side_effect=indexed),
            patch.object(pcap, "_suricata_binary", return_value="/usr/bin/suricata"),
        ):
            result = _disk_pcaps(run_ids=True, extract_credentials=False)

        assert result["status"] == "partial"
        ids = result["results"]["analyses"][0]["ids_alerts"]
        assert "total_alerts" not in ids
        assert "rule path missing" in ids["error"]

    def test_clean_run_stays_success(self) -> None:
        indexed = _Indexed()
        with (
            patch(_RUN, return_value=_proc(["tshark"], 0, "stats\n")),
            patch("mulder.server.tools.extract.disk_pcap.extract_and_index", side_effect=indexed),
        ):
            result = _disk_pcaps(run_ids=False, extract_credentials=True)

        assert result["status"] == "success"
        assert "tool_warning" not in result
