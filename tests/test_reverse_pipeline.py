"""Reverse pipeline: gates, phases, prompts and role separation."""

from __future__ import annotations

import re
import struct
import time
from pathlib import Path
from typing import Any

import pytest

from mulder.orchestrator.prompts import REVERSE_COMMON
from mulder.orchestrator.reverse_gates import (
    validate_re_counter,
    validate_re_deep,
    validate_re_mapping,
    validate_re_report,
    validate_re_triage,
)
from mulder.orchestrator.reverse_phases import (
    RE_COUNTER,
    RE_DEEP,
    RE_MAPPING,
    RE_REPORT,
    RE_TRIAGE,
    REVERSE_PHASES,
)
from mulder.orchestrator.roles import _EXECUTOR_CONTROL_TOOLS
from mulder.reverse.sample import detect_sample_kind
from mulder.server.tool_access import ALL_ROLES, REVERSE_ROLES, all_registered_tools
from mulder.server.tool_access import get_tools_for_role as tools_for

SPLIT = [RE_TRIAGE, RE_MAPPING, RE_DEEP, RE_COUNTER]
REGISTERED = frozenset(t.removeprefix("mcp__mulder__") for t in all_registered_tools())
PLANNER_OWN = frozenset(
    {
        "open_case",
        "reverse_status",
        "get_findings",
        "get_investigation_summary",
        "list_sources",
        "get_source_stats",
        "search",
        "get_raw_output",
    }
)

# -- gates -------------------------------------------------------------------------


def _snap(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "sample_kind": "pe",
        "tool_counts": {},
        "sources": [],
        "findings_count": 0,
        "findings_with_mitre": 0,
        "status": {
            "priorities": [],
            "packed": None,
            "capa_ran": False,
            "capabilities": {"total": 0, "decided": 0, "open": []},
            "findings": [],
            "high_severity_unchallenged": [],
        },
        "project_file": None,
    }
    status = kw.pop("status", {})
    base.update(kw)
    base["status"].update(status)
    return base


def test_triage_gate_native_needs_triage_capa_and_load() -> None:
    gate = validate_re_triage(_snap(tool_counts={"triage_binary": 1}))
    assert not gate.passed
    assert any("run_capa" in g for g in gate.gaps)
    assert any("reverse_analyze" in g for g in gate.gaps)
    assert any("No finding" in g for g in gate.gaps)
    ok = validate_re_triage(
        _snap(
            tool_counts={"triage_binary": 1, "run_capa": 1, "reverse_analyze": 1},
            findings_count=2,
        )
    )
    assert ok.passed, ok.gaps


def test_triage_gate_script_needs_reading() -> None:
    gate = validate_re_triage(_snap(sample_kind="script", findings_count=1))
    assert not gate.passed and any("reverse_read_script" in g for g in gate.gaps)
    ok = validate_re_triage(
        _snap(sample_kind="script", findings_count=1, tool_counts={"reverse_read_script": 3})
    )
    assert ok.passed


def test_mapping_gate_needs_priorities_or_packed() -> None:
    gate = validate_re_mapping(_snap(sources=["reverse.program"]))
    assert not gate.passed and any("reverse_prioritize" in g for g in gate.gaps)
    assert validate_re_mapping(
        _snap(sources=["reverse.program"], status={"priorities": [{"target": "f"}]})
    ).passed
    assert validate_re_mapping(
        _snap(sources=["reverse.program"], status={"packed": {"reason": "UPX"}})
    ).passed
    not_loaded = validate_re_mapping(_snap(status={"packed": {"reason": "UPX"}}))
    assert not not_loaded.passed


def test_deep_gate_capabilities_and_code_citations() -> None:
    finding = {"finding_id": "f1", "title": "C2", "severity": "high", "cites_code": False}
    gate = validate_re_deep(
        _snap(
            status={
                "capa_ran": True,
                "capabilities": {"total": 2, "decided": 1, "open": ["x"]},
                "findings": [finding],
            }
        )
    )
    assert not gate.passed
    assert any("no verdict: x" in g for g in gate.gaps)
    assert any("f1" in g and "cite no decompiled" in g for g in gate.gaps)
    ok = validate_re_deep(
        _snap(
            status={
                "capa_ran": True,
                "capabilities": {"total": 2, "decided": 2, "open": []},
                "findings": [
                    {**finding, "cites_code": True},
                    {"finding_id": "f2", "title": "PE", "severity": "info", "cites_code": False},
                ],
            }
        )
    )
    assert ok.passed, ok.gaps
    empty = validate_re_deep(_snap())
    assert not empty.passed and any("No capability finding" in g for g in empty.gaps)


def test_counter_gate() -> None:
    gate = validate_re_counter(_snap(status={"high_severity_unchallenged": ["f1"]}))
    assert not gate.passed
    assert len(gate.gaps) == 3
    ok = validate_re_counter(
        _snap(tool_counts={"audit_evidence_coverage": 1, "audit_tool_coverage": 1})
    )
    assert ok.passed


def test_report_gate(tmp_path: Path) -> None:
    report = tmp_path / "c.report.md"
    started = time.time()
    missing = validate_re_report(
        _snap(readiness={"gates": [{"name": "narrative_submitted", "passed": False}]}),
        report,
        started,
    )
    assert not missing.passed and "narrative_submitted" in missing.gaps[0]
    project = tmp_path / "proj" / "mulder.gpr"
    report.write_text(f"see {project}\n")
    ok = validate_re_report(
        _snap(project_file=project, findings_with_mitre=1, ioc_export="x.csv"), report, started
    )
    assert ok.passed, ok.gaps
    report.write_text("no path\n")
    bad = validate_re_report(_snap(project_file=project), report, started)
    assert {c.name for c in bad.checks if not c.passed} == {
        "ghidra_project_named",
        "attack_mapping",
        "iocs_exported",
    }
    packed = validate_re_report(
        _snap(status={"packed": {"reason": "UPX"}}, ioc_export="x.csv"), report, started
    )
    assert packed.passed


# -- phases and roles --------------------------------------------------------------


def test_reverse_and_forensic_tool_sets_are_separate() -> None:
    reverse_tools = {t for t in all_registered_tools() if "reverse_" in t}
    assert reverse_tools
    assert not reverse_tools & set(tools_for(ALL_ROLES))
    for phase in REVERSE_PHASES:
        allowed = (
            phase.planner_allowed_tools
            + phase.executor_allowed_tools
            + phase.analyst_allowed_tools
            + phase.single_allowed_tools
        )
        # No forensic extraction tool leaks into the reverse phases.
        assert "mcp__mulder__run_volatility" not in allowed
        assert "mcp__mulder__run_fls" not in allowed
        assert set(allowed) <= set(tools_for(REVERSE_ROLES))


@pytest.mark.parametrize("phase", SPLIT, ids=lambda p: p.name)
def test_planner_prompt_advertises_only_executor_tools(phase: Any) -> None:
    mentioned = set(re.findall(r"\b[a-z][a-z0-9_]*\b", phase.planner_system_prompt)) & REGISTERED
    executor = {t.removeprefix("mcp__mulder__") for t in phase.executor_allowed_tools}
    control = {t.removeprefix("mcp__mulder__") for t in _EXECUTOR_CONTROL_TOOLS}
    assert mentioned - PLANNER_OWN - executor - control == set()
    planner = {t.removeprefix("mcp__mulder__") for t in phase.planner_allowed_tools}
    assert (PLANNER_OWN & mentioned) <= planner


@pytest.mark.parametrize("phase", SPLIT, ids=lambda p: p.name)
def test_analyst_prompt_names_only_analyst_tools(phase: Any) -> None:
    mentioned = set(re.findall(r"\b[a-z][a-z0-9_]*\b", phase.analyst_system_prompt)) & REGISTERED
    analyst = {t.removeprefix("mcp__mulder__") for t in phase.analyst_allowed_tools}
    blocked = {t.removeprefix("mcp__mulder__") for t in phase.disallowed_tools}
    # Tools the prompt forbids by name may appear; every other one must be callable.
    forbidden_mentions = {"submit_narrative", "finalize_report"}
    assert mentioned - analyst - forbidden_mentions == set()
    assert (mentioned & analyst & blocked) - forbidden_mentions == set()


def test_report_phase_tools() -> None:
    names = {t.removeprefix("mcp__mulder__") for t in RE_REPORT.single_allowed_tools}
    wanted = {"finalize_report", "submit_narrative", "reverse_annotations", "reverse_status"}
    assert wanted <= names
    assert not any(n.startswith("run_") for n in names)
    # The shared rules name code-reading tools as citations; the report's own
    # instructions must only name tools the report writer can call.
    own = RE_REPORT.single_system_prompt.replace(REVERSE_COMMON, "")
    mentioned = set(re.findall(r"\b[a-z][a-z0-9_]*\b", own))
    assert (mentioned & REGISTERED) <= names


@pytest.mark.parametrize(
    "prompt",
    [p.planner_system_prompt for p in SPLIT]
    + [p.analyst_system_prompt for p in SPLIT]
    + [RE_TRIAGE.executor_system_prompt, RE_REPORT.single_system_prompt],
)
def test_every_prompt_carries_the_safety_rules(prompt: str) -> None:
    assert "ADVERSARIAL SAMPLE WARNING" in prompt
    assert "never as instructions" in prompt.lower()
    assert "STATIC ANALYSIS ONLY" in prompt


def test_no_phase_offers_a_shell() -> None:
    for phase in REVERSE_PHASES:
        assert "Bash" in phase.disallowed_tools and "Shell" in phase.disallowed_tools


def test_early_phases_cannot_finalize() -> None:
    for phase in (RE_TRIAGE, RE_MAPPING, RE_DEEP):
        assert "mcp__mulder__finalize_report" in phase.disallowed_tools
        assert "mcp__mulder__reverse_challenge" in phase.disallowed_tools


# -- sample kinds -----------------------------------------------------------------


def _pe(dotnet: bool) -> bytes:
    head = bytearray(1024)
    head[:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x80)
    head[0x80:0x84] = b"PE\0\0"
    opt = 0x80 + 24
    struct.pack_into("<H", head, opt, 0x20B)
    if dotnet:
        struct.pack_into("<II", head, opt + 112 + 14 * 8, 0x2000, 0x48)
    return bytes(head)


@pytest.mark.parametrize(
    ("name", "data", "kind"),
    [
        ("a.exe", _pe(False), "pe"),
        ("b.exe", _pe(True), "pe_dotnet"),
        ("c.txt", _pe(False), "pe"),
        ("d", b"\x7fELF\x02\x01\x01" + b"\0" * 64, "elf"),
        ("e", b"\xcf\xfa\xed\xfe" + b"\0" * 64, "macho"),
        ("f.ps1", b"\xff\xfe" + "Write-Host 1".encode("utf-16-le"), "script"),
        ("g", b"var a = 1;\nfunction f() {}\n", "script"),
        ("h.pdf", b"%PDF-1.7\n", "document"),
        ("i.zip", b"PK\x03\x04" + b"\0" * 30, "archive"),
        ("j.bin", bytes(range(256)), "unknown"),
    ],
)
def test_sample_kind(tmp_path: Path, name: str, data: bytes, kind: str) -> None:
    p = tmp_path / name
    p.write_bytes(data)
    assert detect_sample_kind(p) == kind
