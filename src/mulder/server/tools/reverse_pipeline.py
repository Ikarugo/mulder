"""Record-keeping tools of the reverse-engineering pipeline (``mulder reverse``).

The analyst agents use them to write down what each phase established, in
a form the orchestrator's quality gates can check:

* :func:`reverse_prioritize`: the functions worth studying, or the
  statement that the sample is packed (the pipeline then stops);
* :func:`reverse_capability_verdict`: for each capability capa reported,
  whether the code confirms or refutes it;
* :func:`reverse_challenge`: the counter-analysis outcome for a finding;
* :func:`reverse_submit_yara`: a candidate YARA rule, for a human to validate;
* :func:`reverse_status`: everything above plus what is still open.

Every entry cites tool calls from the audit log, like a finding does.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from mulder.reverse.state import (
    CHALLENGE_OUTCOMES,
    SAMPLE_KEY,
    VERDICT_BASES,
    VERDICTS,
    capa_capabilities,
    capability_coverage,
    load_state,
    save_state,
)
from mulder.server.app import get_ctx, mcp
from mulder.server.helpers import error_response, make_tool_call_id, tool_response
from mulder.server.tool_access import Role, tool_access

__all__ = [
    "CODE_READING_TOOLS",
    "reverse_capability_verdict",
    "reverse_challenge",
    "reverse_prioritize",
    "reverse_status",
    "reverse_submit_yara",
]

#: Tool calls that show code. A reverse finding must cite at least one.
CODE_READING_TOOLS = frozenset(
    {"reverse_decompile", "reverse_disassemble", "reverse_read_script", "reverse_decode_layer"}
)
_MAX_PRIORITIES = 60
_MAX_TEXT = 2000


class _Invalid(Exception):
    def __init__(self, message: str, error_type: str = "invalid_parameter") -> None:
        super().__init__(message)
        self.error_type = error_type


def _check_refs(refs: list[str] | None, required: bool = True) -> list[str]:
    refs = [str(r) for r in (refs or []) if str(r).strip()]
    if required and not refs:
        raise _Invalid("evidence_refs must cite at least one tool_call_id")
    audit = get_ctx().audit
    unknown = [r for r in refs if not audit.has_tool_call(r)]
    if unknown:
        raise _Invalid(
            f"Unknown tool_call_id(s) {unknown}: cite IDs returned by earlier tool calls "
            "in this case.",
            "invalid_evidence_refs",
        )
    return refs


def _sample(file_path: str) -> str:
    sample = file_path or get_ctx().db.get_kv(SAMPLE_KEY) or ""
    if not sample:
        raise _Invalid("file_path is required (no sample is recorded for this case)")
    return sample


def _get(key: str) -> str | None:
    return get_ctx().db.get_kv(key)


def _set(key: str, value: str) -> None:
    get_ctx().db.set_kv(key, value)


def _run(
    tool: str, params: dict[str, object], body: Callable[[], dict[str, object]]
) -> dict[str, object]:
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    try:
        result = body()
    except _Invalid as exc:
        return error_response(
            tc_id,
            tool,
            params,
            str(exc),
            (time.monotonic() - t0) * 1000,
            error_type=exc.error_type,
        )
    return tool_response(tc_id, tool, params, result, None, (time.monotonic() - t0) * 1000)


def _findings_code_citations() -> list[dict[str, Any]]:
    """Per finding: does it cite a call that shows code?"""
    ctx = get_ctx()
    rows = []
    for f in ctx.db.get_findings():
        cited = sorted({ctx.audit.tool_name_of(r) or "?" for r in f.evidence_refs})
        rows.append(
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "cites_code": any(t in CODE_READING_TOOLS for t in cited),
                "cited_tools": cited,
            }
        )
    return rows


def status_snapshot(sample: str) -> dict[str, Any]:
    """The reverse state of the open case, with what the gates will check."""
    state = load_state(_get)
    caps = capa_capabilities(_get, sample)
    findings = _findings_code_citations()
    high = [f for f in findings if f["severity"] in ("critical", "high")]
    return {
        "sample": sample,
        "packed": state["packed"],
        "priorities": state["priorities"],
        "capa_ran": caps is not None,
        "capabilities": capability_coverage(caps or [], state["verdicts"]),
        "verdicts": state["verdicts"],
        "findings": findings,
        "findings_without_code_citation": [
            f["finding_id"] for f in findings if not f["cites_code"]
        ],
        "high_severity_unchallenged": [
            f["finding_id"] for f in high if f["finding_id"] not in state["challenges"]
        ],
        "challenges": state["challenges"],
        "yara": state["yara"],
    }


@mcp.tool()
@tool_access(Role.RE_PLANNER | Role.RE_ANALYST | Role.RE_REPORT, unthrottled=True)
def reverse_status(file_path: str = "") -> dict[str, object]:
    """Show what the reverse-engineering pipeline has established for the sample.

    Call at the start of every planner or analyst session of a
    'mulder reverse' case, and before finishing a phase, to see what is
    still open.

    Returns the prioritised functions (or the packed verdict), capa
    capabilities with their verdicts and those still open, findings with
    whether they cite decompiled or disassembled code, high-severity
    findings not yet challenged, and the candidate YARA rule.

    Args:
        file_path: Sample path; defaults to the case's sample.
    """
    params: dict[str, object] = {"file_path": file_path}
    return _run("reverse_status", params, lambda: status_snapshot(_sample(file_path)))


@mcp.tool()
@tool_access(Role.RE_ANALYST)
def reverse_prioritize(
    functions: list[dict[str, Any]] | None = None,
    packed: bool = False,
    packed_reason: str = "",
    evidence_refs: list[str] | None = None,
    file_path: str = "",
) -> dict[str, object]:
    """Record the functions to study in depth, or that the sample is packed.

    Call at the end of the mapping phase. Each entry says which function,
    why (the import, string or capa match that points to it) and which tool
    calls show it. Entries are merged by target. With packed=True the
    pipeline stops after the report: unpacking is out of scope.

    Returns the full prioritised list.

    Args:
        functions: [{"target": "FUN_140001550" or "0x140001550", "reason": "...",
            "evidence_refs": ["tc_..."], "rank": 1}], most important first.
        packed: True when the sample is packed or encrypted so its code cannot
            be studied statically.
        packed_reason: The indicators (entropy, section names, import count).
        evidence_refs: Tool calls supporting the packed verdict.
        file_path: Sample path; defaults to the case's sample.
    """
    params: dict[str, object] = {
        "functions": functions,
        "packed": packed,
        "packed_reason": packed_reason,
        "evidence_refs": evidence_refs,
        "file_path": file_path,
    }

    def body() -> dict[str, object]:
        _sample(file_path)
        state = load_state(_get)
        if packed:
            if not packed_reason.strip():
                raise _Invalid("packed_reason is required when packed=True")
            state["packed"] = {
                "reason": packed_reason[:_MAX_TEXT],
                "evidence_refs": _check_refs(evidence_refs),
            }
        entries = list(functions or [])
        if not entries and not packed:
            raise _Invalid("Give at least one function, or packed=True with its reason")
        by_target = {str(p["target"]): p for p in state["priorities"]}
        for n, entry in enumerate(entries):
            if not isinstance(entry, dict) or not str(entry.get("target", "")).strip():
                raise _Invalid(f"functions[{n}] needs a target (name or address)")
            reason = str(entry.get("reason", "")).strip()
            if not reason:
                raise _Invalid(f"functions[{n}] needs a reason")
            target = str(entry["target"]).strip()
            by_target[target] = {
                "target": target,
                "reason": reason[:_MAX_TEXT],
                "evidence_refs": _check_refs(entry.get("evidence_refs")),
                "rank": int(entry.get("rank") or len(by_target) + 1),
            }
        if len(by_target) > _MAX_PRIORITIES:
            raise _Invalid(
                f"At most {_MAX_PRIORITIES} priorities: keep the functions that matter most"
            )
        state["priorities"] = sorted(by_target.values(), key=lambda p: int(p["rank"]))
        save_state(_set, state)
        return {"priorities": state["priorities"], "packed": state["packed"]}

    return _run("reverse_prioritize", params, body)


@mcp.tool()
@tool_access(Role.RE_ANALYST)
def reverse_capability_verdict(
    capability: str,
    verdict: str,
    basis: str,
    note: str,
    evidence_refs: list[str],
    finding_id: str = "",
    file_path: str = "",
) -> dict[str, object]:
    """Confirm or refute, from the code, one capability capa reported.

    Call once per capa capability during deep analysis, after reading the
    code at its match addresses. A refuted capability needs a basis:
    unreachable, library_code, dead_code, benign_use or other. Cite the
    decompile or disassembly calls that show it.

    Returns the verdict and how many capabilities are still open.

    Args:
        capability: capa rule name exactly as reported.
        verdict: confirmed or refuted.
        basis: code, unreachable, library_code, dead_code, benign_use or other.
        note: What the code does (or does not do), in one or two sentences.
        evidence_refs: Tool calls showing it (reverse_decompile, reverse_disassemble...).
        finding_id: The finding that reports this capability, if any.
        file_path: Sample path; defaults to the case's sample.
    """
    params: dict[str, object] = {
        "capability": capability,
        "verdict": verdict,
        "basis": basis,
        "note": note,
        "evidence_refs": evidence_refs,
        "finding_id": finding_id,
        "file_path": file_path,
    }

    def body() -> dict[str, object]:
        sample = _sample(file_path)
        if verdict not in VERDICTS:
            raise _Invalid(f"verdict must be one of {', '.join(VERDICTS)}")
        if basis not in VERDICT_BASES:
            raise _Invalid(f"basis must be one of {', '.join(VERDICT_BASES)}")
        if not note.strip():
            raise _Invalid("note is required")
        caps = capa_capabilities(_get, sample) or []
        names = {str(c["name"]) for c in caps}
        if names and capability not in names:
            close = sorted(n for n in names if capability.lower() in n.lower())[:5]
            raise _Invalid(
                f"capa did not report {capability!r}. "
                + (f"Did you mean: {close}?" if close else "Use reverse_status to list them."),
                "not_found",
            )
        refs = _check_refs(evidence_refs)
        if finding_id and finding_id not in {f.finding_id for f in get_ctx().db.get_findings()}:
            raise _Invalid(f"Unknown finding_id {finding_id!r}", "not_found")
        state = load_state(_get)
        state["verdicts"][capability] = {
            "verdict": verdict,
            "basis": basis,
            "note": note[:_MAX_TEXT],
            "evidence_refs": refs,
            "finding_id": finding_id or None,
        }
        save_state(_set, state)
        coverage = capability_coverage(caps, state["verdicts"])
        return {"capability": capability, "verdict": verdict, "open": coverage["open"]}

    return _run("reverse_capability_verdict", params, body)


@mcp.tool()
@tool_access(Role.RE_ANALYST)
def reverse_challenge(
    finding_id: str,
    outcome: str,
    reasoning: str,
    evidence_refs: list[str],
) -> dict[str, object]:
    """Record the counter-analysis of one finding.

    Call during counter-analysis for every high or critical finding (and
    any other you checked): is the code really malicious or library code,
    is it reachable from an entry point, is there a benign explanation? If
    the outcome is downgraded or withdrawn, also update or delete the
    finding.

    Returns the recorded challenge and the high-severity findings still
    unchallenged.

    Args:
        finding_id: The finding challenged.
        outcome: upheld, downgraded or withdrawn.
        reasoning: What was checked and what it showed.
        evidence_refs: Tool calls behind the reasoning (e.g. reverse_call_path).
    """
    params: dict[str, object] = {
        "finding_id": finding_id,
        "outcome": outcome,
        "reasoning": reasoning,
        "evidence_refs": evidence_refs,
    }

    def body() -> dict[str, object]:
        if outcome not in CHALLENGE_OUTCOMES:
            raise _Invalid(f"outcome must be one of {', '.join(CHALLENGE_OUTCOMES)}")
        if not reasoning.strip():
            raise _Invalid("reasoning is required")
        findings = {f.finding_id: f for f in get_ctx().db.get_findings()}
        if finding_id not in findings and outcome != "withdrawn":
            raise _Invalid(f"Unknown finding_id {finding_id!r}", "not_found")
        refs = _check_refs(evidence_refs)
        state = load_state(_get)
        state["challenges"][finding_id] = {
            "outcome": outcome,
            "reasoning": reasoning[:_MAX_TEXT],
            "evidence_refs": refs,
        }
        save_state(_set, state)
        open_high = [
            fid
            for fid, f in findings.items()
            if f.severity in ("critical", "high") and fid not in state["challenges"]
        ]
        return {"finding_id": finding_id, "outcome": outcome, "high_unchallenged": open_high}

    return _run("reverse_challenge", params, body)


def _compile_yara(rule: str) -> str | None:
    """Syntax error message, or None when the rule compiles (or yara is absent)."""
    try:
        import yara  # type: ignore[import-not-found,unused-ignore]
    except ImportError:
        return None
    try:
        yara.compile(source=rule)
    except Exception as exc:  # noqa: BLE001 - yara.SyntaxError and friends
        return str(exc)
    return None


@mcp.tool()
@tool_access(Role.RE_ANALYST | Role.RE_REPORT)
def reverse_submit_yara(
    rule: str, evidence_refs: list[str], file_path: str = ""
) -> dict[str, object]:
    """Store a candidate YARA rule for the sample, to be validated by a human.

    Call at the end of deep analysis with a rule built on what the code
    showed: decoded strings, configuration, distinctive byte sequences
    from reverse_read_bytes or reverse_disassemble. Avoid strings any
    program has. The rule is checked for syntax when yara-python is
    installed. It is shown in the report marked for human validation.

    Returns whether the rule compiled.

    Args:
        rule: The complete YARA rule text.
        evidence_refs: Tool calls the rule's strings come from.
        file_path: Sample path; defaults to the case's sample.
    """
    params: dict[str, object] = {"rule": rule, "evidence_refs": evidence_refs}

    def body() -> dict[str, object]:
        _sample(file_path)
        if "rule " not in rule or "condition" not in rule:
            raise _Invalid("rule must be a complete YARA rule (rule name, strings, condition)")
        if len(rule) > 20_000:
            raise _Invalid("rule is too long (max 20000 characters)")
        refs = _check_refs(evidence_refs)
        error = _compile_yara(rule)
        if error:
            raise _Invalid(f"The rule does not compile: {error}", "yara_syntax_error")
        state = load_state(_get)
        state["yara"] = {
            "rule": rule,
            "evidence_refs": refs,
            "status": "candidate: to be validated by a human analyst before any use",
        }
        save_state(_set, state)
        return {"stored": True, "status": state["yara"]["status"]}

    return _run("reverse_submit_yara", params, body)
