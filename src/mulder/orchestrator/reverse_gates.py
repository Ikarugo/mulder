"""Quality gates of the static malware analysis pipeline (``mulder reverse``).

Each gate reads a snapshot of the case (built by the orchestrator from the
database and the audit log, no LLM involved) and says whether the phase
produced what the next one needs. A failed gate retries the phase with the
gaps as instructions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mulder.orchestrator.gates import GateCheck, GateResult

__all__ = [
    "NATIVE_KINDS",
    "validate_re_counter",
    "validate_re_deep",
    "validate_re_mapping",
    "validate_re_report",
    "validate_re_triage",
]

NATIVE_KINDS = frozenset({"pe", "elf", "macho"})
#: Findings of these severities must cite code; "info" facts (format,
#: compiler) come from triage tools.
_CODE_CITATION_SEVERITIES = frozenset({"critical", "high", "medium", "low"})


def _result(phase: str, checks: list[GateCheck], gaps: list[str]) -> GateResult:
    return GateResult(
        passed=all(c.passed for c in checks), phase_name=phase, checks=checks, gaps=gaps
    )


def _called(snap: dict[str, Any], tool: str) -> bool:
    return int(snap.get("tool_counts", {}).get(tool, 0)) > 0


def _has_source(snap: dict[str, Any], prefix: str) -> bool:
    return any(str(s).startswith(prefix) for s in snap.get("sources", []))


def validate_re_triage(snap: dict[str, Any]) -> GateResult:
    """Triage ran the tools for the sample's type and stated what the file is."""
    checks: list[GateCheck] = []
    gaps: list[str] = []
    kind = str(snap.get("sample_kind", "unknown"))

    determined = kind != "unknown" or _has_source(snap, "binary.triage")
    checks.append(GateCheck("file_type_determined", determined, f"sample kind: {kind}"))
    if not determined:
        gaps.append("File type not determined: run triage_binary on the sample.")

    required = ["triage_binary"]
    if kind in NATIVE_KINDS:
        required += ["run_capa", "reverse_analyze"]
    elif kind == "script":
        required = ["reverse_read_script"]
    for tool in required:
        ok = _called(snap, tool)
        checks.append(GateCheck(f"{tool}_run", ok, "called" if ok else "never called"))
        if not ok:
            gaps.append(f"{tool} was not run on the sample.")

    findings = int(snap.get("findings_count", 0))
    checks.append(GateCheck("triage_findings", findings > 0, f"{findings} finding(s)"))
    if findings == 0:
        gaps.append(
            "No finding describes the sample yet: submit what triage established "
            "(format, compiler, packing, notable capabilities and strings)."
        )
    return _result("re_triage", checks, gaps)


def validate_re_mapping(snap: dict[str, Any]) -> GateResult:
    """The sample is loaded and the functions to study are chosen (or it is packed)."""
    checks: list[GateCheck] = []
    gaps: list[str] = []
    status = snap.get("status", {})
    analysed = _has_source(snap, "reverse.program")
    checks.append(
        GateCheck(
            "disassembler_loaded", analysed, "program analysed" if analysed else "not analysed"
        )
    )
    if not analysed:
        gaps.append("reverse_analyze has not succeeded on the sample.")
    priorities = status.get("priorities") or []
    packed = bool(status.get("packed"))
    ok = bool(priorities) or packed
    detail = "sample declared packed" if packed else f"{len(priorities)} function(s) prioritised"
    checks.append(GateCheck("functions_prioritised", ok, detail))
    if not ok:
        gaps.append(
            "No function was prioritised: call reverse_prioritize with the functions to "
            "study, or reverse_prioritize(packed=True, packed_reason=...) if the sample "
            "is packed."
        )
    return _result("re_mapping", checks, gaps)


def validate_re_deep(snap: dict[str, Any]) -> GateResult:
    """Every capa capability decided in code; every finding backed by code."""
    checks: list[GateCheck] = []
    gaps: list[str] = []
    status = snap.get("status", {})
    caps = status.get("capabilities") or {}
    open_caps = list(caps.get("open") or [])
    if status.get("capa_ran"):
        ok = not open_caps
        checks.append(
            GateCheck(
                "capabilities_decided",
                ok,
                f"{caps.get('decided', 0)}/{caps.get('total', 0)} capa capabilities decided",
            )
        )
        if not ok:
            shown = ", ".join(open_caps[:15]) + (" ..." if len(open_caps) > 15 else "")
            gaps.append(
                f"{len(open_caps)} capa capabilities have no verdict: {shown}. Read the code "
                "at their matches and call reverse_capability_verdict for each."
            )
    else:
        checks.append(GateCheck("capabilities_decided", True, "capa did not run on the sample"))

    findings = [
        f
        for f in status.get("findings") or []
        if not str(f.get("title", "")).startswith("[NEGATIVE]")
    ]
    serious = [f for f in findings if f.get("severity") in _CODE_CITATION_SEVERITIES]
    uncited = [f for f in serious if not f.get("cites_code")]
    ok = bool(serious) and not uncited
    checks.append(
        GateCheck(
            "findings_cite_code",
            ok,
            f"{len(serious) - len(uncited)}/{len(serious)} findings cite decompiled "
            "or disassembled code",
        )
    )
    if not serious:
        gaps.append(
            "No capability finding yet: submit one finding per capability, citing the "
            "reverse_decompile or reverse_disassemble calls that show it."
        )
    elif uncited:
        ids = ", ".join(f"{f['finding_id']} ({f['title'][:60]})" for f in uncited[:10])
        gaps.append(
            f"These findings cite no decompiled or disassembled code: {ids}. Read the code "
            "and add the reverse_decompile/reverse_disassemble tool_call_ids with "
            "update_finding, or downgrade them to info."
        )
    return _result("re_deep", checks, gaps)


def validate_re_counter(snap: dict[str, Any]) -> GateResult:
    """Audits ran and every high-severity finding was challenged."""
    checks: list[GateCheck] = []
    gaps: list[str] = []
    for tool in ("audit_evidence_coverage", "audit_tool_coverage"):
        ok = _called(snap, tool)
        checks.append(GateCheck(f"{tool}_called", ok, "called" if ok else "never called"))
        if not ok:
            gaps.append(f"Call {tool}.")
    unchallenged = list(snap.get("status", {}).get("high_severity_unchallenged") or [])
    ok = not unchallenged
    checks.append(
        GateCheck(
            "high_severity_challenged",
            ok,
            "all challenged" if ok else f"{len(unchallenged)} not challenged",
        )
    )
    if not ok:
        gaps.append(
            f"High or critical findings not challenged: {', '.join(unchallenged)}. Check "
            "reachability (reverse_call_path), library code and benign use, then call "
            "reverse_challenge for each."
        )
    return _result("re_counter", checks, gaps)


def validate_re_report(snap: dict[str, Any], report_path: Path, started_at: float) -> GateResult:
    """Report written, IOCs exported, ATT&CK present, Ghidra project named."""
    checks: list[GateCheck] = []
    gaps: list[str] = []
    written = report_path.is_file() and report_path.stat().st_mtime >= started_at - 1.0
    checks.append(GateCheck("report_written", written, str(report_path)))
    if not written:
        failing = [
            f"{g.get('name')}: {g.get('detail')}"
            for g in (snap.get("readiness") or {}).get("gates", [])
            if not g.get("passed")
        ]
        gaps.append(
            "finalize_report did not write the report. "
            + ("Fix: " + "; ".join(failing) if failing else "Call finalize_report.")
        )
        return _result("re_report", checks, gaps)

    text = report_path.read_text(encoding="utf-8", errors="replace")
    project = snap.get("project_file")
    if project:
        ok = str(project) in text
        checks.append(GateCheck("ghidra_project_named", ok, str(project)))
        if not ok:
            gaps.append(f"The report does not give the Ghidra project path {project}.")

    packed = bool(snap.get("status", {}).get("packed"))
    mitre = int(snap.get("findings_with_mitre", 0))
    ok = mitre > 0 or packed
    checks.append(GateCheck("attack_mapping", ok, f"{mitre} finding(s) with ATT&CK IDs"))
    if not ok:
        gaps.append(
            "No finding carries a MITRE ATT&CK technique ID: add them with update_finding."
        )

    exported = bool(snap.get("ioc_export"))
    checks.append(GateCheck("iocs_exported", exported, str(snap.get("ioc_export") or "no export")))
    if not exported:
        gaps.append("The IOC export could not be written.")
    return _result("re_report", checks, gaps)
