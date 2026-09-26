"""Record-keeping tools, reverse-mode finalize gates and the report section."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mulder.reverse.state import CASE_KIND_KEY, REVERSE_KIND, SAMPLE_KEY


def _call(name: str, **kwargs: Any) -> dict[str, Any]:
    from mulder.server.app import _tool_dispatch_sync

    return _tool_dispatch_sync[name](**kwargs)  # type: ignore[no-any-return]


CAPA = {
    "rules": {
        "persist via Run registry key": {
            "meta": {"namespace": "persistence/registry/run", "attack": [{"id": "T1547.001"}]},
            "matches": [[{"type": "absolute", "value": 0x1400014E6}, {}]],
        },
        "encode data using XOR": {
            "meta": {"namespace": "data-manipulation/encoding/xor", "attack": []},
            "matches": {"0x1400014c2": {}},
        },
        "contain loop": {"meta": {"lib": True, "namespace": "lib"}, "matches": []},
    }
}


@pytest.fixture()
def case(tmp_path: Path) -> Path:
    """A reverse case over one sample, with capa results recorded."""
    import mulder.server.tools  # noqa: F401
    from mulder.server.app import get_ctx, init_server
    from mulder.server.tools.binary import _remember_capa_capabilities

    sample = tmp_path / "evidence" / "toy.exe"
    sample.parent.mkdir()
    sample.write_bytes(b"MZ" + b"\0" * 256)
    init_server(db_dir=tmp_path / "cases")
    r = _call("scan_evidence", evidence_path=str(sample), case_id="rev")
    assert r["status"] == "success", r
    db = get_ctx().db
    db.set_kv(CASE_KIND_KEY, REVERSE_KIND)
    db.set_kv(SAMPLE_KEY, str(sample))
    _remember_capa_capabilities(CAPA, str(sample))
    return sample


def _tc(tool: str = "reverse_decompile") -> str:
    """Log a tool call as if an agent had made it; return its ID."""
    from mulder.server.app import get_ctx
    from mulder.server.helpers import make_tool_call_id

    tc = make_tool_call_id()
    get_ctx().audit.log_tool_call(tool_call_id=tc, tool_name=tool, params={}, output_hash="x")
    return tc


def _finding(title: str, severity: str, refs: list[str], mitre: list[str] | None = None) -> str:
    r = _call(
        "submit_finding",
        title=title,
        description=title,
        severity=severity,
        confidence="inference",
        evidence_refs=refs,
        sources=["reverse.decompile"],
        mitre_attack_ids=mitre or [],
    )
    assert r["status"] == "accepted", r
    return str(r["finding_id"])


def test_capa_capabilities_are_kept_for_the_gates(case: Path) -> None:
    from mulder.reverse.state import capa_capabilities
    from mulder.server.app import get_ctx

    caps = capa_capabilities(get_ctx().db.get_kv, str(case))
    assert caps is not None
    by_name = {c["name"]: c for c in caps}
    assert set(by_name) == {"persist via Run registry key", "encode data using XOR"}
    assert by_name["persist via Run registry key"]["addresses"] == ["0x1400014e6"]
    assert by_name["encode data using XOR"]["addresses"] == ["0x1400014c2"]
    assert by_name["persist via Run registry key"]["attack"] == ["T1547.001"]


def test_status_lists_what_is_open(case: Path) -> None:
    status = _call("reverse_status")["results"]
    assert status["sample"] == str(case)
    assert status["capa_ran"] is True
    assert status["capabilities"]["open"] == [
        "encode data using XOR",
        "persist via Run registry key",
    ]
    assert status["priorities"] == [] and status["packed"] is None


def test_prioritize_merges_by_target_and_validates(case: Path) -> None:
    tc = _tc("reverse_xrefs")
    r = _call(
        "reverse_prioritize",
        functions=[
            {
                "target": "FUN_1",
                "reason": "calls RegSetValueExW",
                "evidence_refs": [tc],
                "rank": 2,
            },
            {"target": "FUN_2", "reason": "XOR loop", "evidence_refs": [tc], "rank": 1},
        ],
    )
    assert r["status"] == "success", r
    assert [p["target"] for p in r["results"]["priorities"]] == ["FUN_2", "FUN_1"]
    r = _call(
        "reverse_prioritize",
        functions=[{"target": "FUN_1", "reason": "updated", "evidence_refs": [tc], "rank": 3}],
    )
    assert len(r["results"]["priorities"]) == 2
    bad = _call(
        "reverse_prioritize", functions=[{"target": "X", "reason": "r", "evidence_refs": ["tc_x"]}]
    )
    assert bad["error_type"] == "invalid_evidence_refs"
    assert _call("reverse_prioritize")["error_type"] == "invalid_parameter"
    assert (
        _call("reverse_prioritize", functions=[{"target": "Y", "evidence_refs": [tc]}])[
            "error_type"
        ]
        == "invalid_parameter"
    )


def test_packed_verdict_needs_a_reason(case: Path) -> None:
    tc = _tc("triage_binary")
    assert _call("reverse_prioritize", packed=True, evidence_refs=[tc])["status"] == "error"
    r = _call(
        "reverse_prioritize",
        packed=True,
        packed_reason="UPX sections, entropy 7.9",
        evidence_refs=[tc],
    )
    assert r["results"]["packed"]["reason"].startswith("UPX")


def test_capability_verdicts_close_the_open_list(case: Path) -> None:
    tc = _tc()
    r = _call(
        "reverse_capability_verdict",
        capability="encode data using XOR",
        verdict="confirmed",
        basis="code",
        note="xor_decode XORs the URL with 0x5A",
        evidence_refs=[tc],
    )
    assert r["status"] == "success", r
    assert r["results"]["open"] == ["persist via Run registry key"]
    wrong = _call(
        "reverse_capability_verdict",
        capability="persist via Run",
        verdict="refuted",
        basis="code",
        note="n",
        evidence_refs=[tc],
    )
    assert wrong["error_type"] == "not_found"
    assert "persist via Run registry key" in wrong["error_message"]
    bad = _call(
        "reverse_capability_verdict",
        capability="persist via Run registry key",
        verdict="maybe",
        basis="code",
        note="n",
        evidence_refs=[tc],
    )
    assert bad["error_type"] == "invalid_parameter"


def test_challenges_and_code_citations(case: Path) -> None:
    code = _tc("reverse_decompile")
    triage = _tc("triage_binary")
    high = _finding("Persists through the Run key", "high", [code], ["T1547.001"])
    _finding("Only a triage claim", "medium", [triage])
    status = _call("reverse_status")["results"]
    assert status["high_severity_unchallenged"] == [high]
    uncited = status["findings_without_code_citation"]
    assert len(uncited) == 1 and uncited[0] != high
    r = _call(
        "reverse_challenge",
        finding_id=high,
        outcome="upheld",
        reasoning="reachable from main via install_persistence",
        evidence_refs=[_tc("reverse_call_path")],
    )
    assert r["results"]["high_unchallenged"] == []
    assert (
        _call(
            "reverse_challenge",
            finding_id=high,
            outcome="maybe",
            reasoning="r",
            evidence_refs=[code],
        )["error_type"]
        == "invalid_parameter"
    )


def test_yara_rule_is_stored_as_a_candidate(case: Path) -> None:
    tc = _tc("reverse_read_bytes")
    bad = _call("reverse_submit_yara", rule="not a rule", evidence_refs=[tc])
    assert bad["error_type"] == "invalid_parameter"
    rule = 'rule toy { strings: $a = "ToyBeacon" condition: $a }'
    r = _call("reverse_submit_yara", rule=rule, evidence_refs=[tc])
    assert r["status"] == "success", r
    assert "validated by a human" in r["results"]["status"]
    assert _call("reverse_status")["results"]["yara"]["rule"] == rule


def test_finalize_gates_in_reverse_mode(case: Path) -> None:
    from mulder.server.app import get_ctx
    from mulder.server.tools.findings import _evaluate_finalize_gates

    _finding("Decodes its C2 URL with XOR 0x5A", "high", [_tc()], ["T1140"])
    ctx = get_ctx()
    args = (
        ctx.db.get_findings(),
        ctx.db.get_case_metadata(),
        ctx.db.get_sources(),
        ctx.audit.summary(),
    )
    forensic = {g["name"]: g["passed"] for g in _evaluate_finalize_gates(*args)}
    reverse = {g["name"]: g["passed"] for g in _evaluate_finalize_gates(*args, reverse=True)}
    assert forensic["minimum_findings"] is False and forensic["timestamp_coverage"] is False
    assert reverse["minimum_findings"] is True and reverse["timestamp_coverage"] is True
    readiness = _call("check_finalize_readiness")
    names = {g["name"]: g["passed"] for g in readiness["gates"]}
    assert names["timestamp_coverage"] is True


def test_report_section(case: Path, tmp_path: Path) -> None:
    from mulder.reverse.report import add_reverse_section, build_reverse_section
    from mulder.server.app import get_cfg, get_ctx

    tc = _tc()
    _call(
        "reverse_capability_verdict",
        capability="encode data using XOR",
        verdict="confirmed",
        basis="code",
        note="xor | with 0x5A",
        evidence_refs=[tc],
    )
    _call(
        "reverse_submit_yara",
        rule='rule toy { strings: $a = "ToyBeacon" condition: $a }',
        evidence_refs=[tc],
    )
    text = build_reverse_section(get_cfg().db_dir, "rev", get_ctx().db.get_kv)
    assert "## Reverse engineering (static analysis)" in text
    assert "1/2 decided" in text and "**not verified**" in text
    assert "xor \\| with 0x5A" in text
    assert "TO BE VALIDATED BY A HUMAN ANALYST" in text
    assert "No disassembler project was created" in text

    md, html = add_reverse_section("# Report\n", "<html><body><p>x</p></body></html>")
    assert md.startswith("# Report") and "Candidate YARA rule" in md
    assert html.index("reverse-engineering") < html.index("</body>")
    assert "<script" not in html


def test_report_section_names_the_ghidra_project(case: Path) -> None:
    from mulder.reverse.backend import project_dir_for, sample_sha256
    from mulder.reverse.ghidra_backend import append_annotation
    from mulder.reverse.report import build_reverse_section
    from mulder.server.app import get_cfg, get_ctx

    pdir = project_dir_for(get_cfg().db_dir, "rev", "ghidra", case, sample_sha256(case))
    pdir.mkdir(parents=True)
    (pdir / "mulder.gpr").write_text("")
    append_annotation(
        pdir,
        "ghidra",
        {"address": "0x1400014c2", "old_name": "FUN_1400014c2", "new_name": "decode_url"},
    )
    text = build_reverse_section(get_cfg().db_dir, "rev", get_ctx().db.get_kv)
    assert str(pdir / "mulder.gpr") in text
    assert "decode_url" in text and "FUN_1400014c2" in text


def test_reverse_state_survives_a_damaged_record(case: Path) -> None:
    from mulder.reverse.state import STATE_KEY, load_state
    from mulder.server.app import get_ctx

    get_ctx().db.set_kv(STATE_KEY, "{not json")
    state = load_state(get_ctx().db.get_kv)
    assert state["priorities"] == [] and state["verdicts"] == {}
    get_ctx().db.set_kv(STATE_KEY, json.dumps([1, 2]))
    assert load_state(get_ctx().db.get_kv)["challenges"] == {}
