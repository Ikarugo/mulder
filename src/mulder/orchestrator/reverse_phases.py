"""Phase definitions for the static malware analysis pipeline (``mulder reverse``).

Five phases on one sample, built on the same planner/executor/analyst
machinery as the forensic pipeline, with their own roles (RE_*) so that
neither pipeline sees the other's tools:

1. triage: file type, packing, capa/FLOSS/DIE/YARA, disassembler load;
2. mapping: leads (imports, strings, capa matches) to a prioritised list
   of functions, or the statement that the sample is packed;
3. deep: decompile, annotate, extract configuration and IOCs, confirm or
   refute every capa capability, propose a YARA rule;
4. counter: challenge every serious finding (reachability, library code,
   benign use) and run the audits;
5. report: narrative and final report with the Ghidra project section.
"""

from __future__ import annotations

from mulder.orchestrator.phases import PhaseConfig
from mulder.orchestrator.prompts import (
    REVERSE_COUNTER_ANALYST_PROMPT,
    REVERSE_COUNTER_PLANNER_PROMPT,
    REVERSE_DEEP_ANALYST_PROMPT,
    REVERSE_DEEP_PLANNER_PROMPT,
    REVERSE_EXECUTOR_PROMPT,
    REVERSE_MAPPING_ANALYST_PROMPT,
    REVERSE_MAPPING_PLANNER_PROMPT,
    REVERSE_REPORT_PROMPT,
    REVERSE_TRIAGE_ANALYST_PROMPT,
    REVERSE_TRIAGE_PLANNER_PROMPT,
)
from mulder.server.tool_access import Role, get_tools_for_role

__all__ = [
    "RE_COUNTER",
    "RE_DEEP",
    "RE_MAPPING",
    "RE_REPORT",
    "RE_TRIAGE",
    "REVERSE_PHASES",
]

_SAMPLE_BLOCK = (
    "Case ID: {case_id}\n"
    "Call open_case(case_id='{case_id}') as your FIRST action.\n\n"
    "SAMPLE:\n"
    "  path: {sample_path}\n"
    "  sha256: {sample_sha256}\n"
    "  detected type: {sample_kind}\n"
    "{sample_note}\n"
    "{case_briefing}"
)

_EXECUTOR_TEMPLATE = (
    "The case_id is '{case_id}'. Call open_case(case_id='{case_id}') "
    "as your FIRST action before executing any other tools.\n\n{plan}"
)

_ANALYST_TEMPLATE = (
    _SAMPLE_BLOCK + "\nExecution results:\n{execution_results}\n\n"
    "Investigation questions:\n{investigation_questions}"
)

#: No phase may run a shell or write outside the MCP tools.
_BLOCKED = ["Bash", "Shell"]
#: Report-only tools stay out of the analysis phases.
_ANALYSIS_BLOCKED = [
    *_BLOCKED,
    "mcp__mulder__submit_narrative",
    "mcp__mulder__finalize_report",
]
#: Audit and cleanup tools belong to counter-analysis.
_EARLY_BLOCKED = [
    *_ANALYSIS_BLOCKED,
    "mcp__mulder__audit_evidence_coverage",
    "mcp__mulder__audit_tool_coverage",
    "mcp__mulder__check_finalize_readiness",
    "mcp__mulder__deduplicate_findings",
    "mcp__mulder__delete_finding",
    "mcp__mulder__reverse_challenge",
]

_PLANNER_TOOLS = get_tools_for_role(Role.RE_PLANNER)
_EXECUTOR_TOOLS = get_tools_for_role(Role.RE_EXECUTOR)
_ANALYST_TOOLS = get_tools_for_role(Role.RE_ANALYST)


def _split(
    name: str,
    planner_prompt: str,
    analyst_prompt: str,
    planner_task: str,
    disallowed: list[str],
    executor_max_turns: int = 40,
    analyst_max_turns: int = 60,
    max_follow_ups: int = 2,
) -> PhaseConfig:
    return PhaseConfig(
        name=name,
        mode="split",
        disallowed_tools=disallowed,
        planner_system_prompt=planner_prompt,
        planner_prompt_template=_SAMPLE_BLOCK + "\n" + planner_task,
        planner_allowed_tools=_PLANNER_TOOLS,
        planner_max_turns=12,
        executor_system_prompt=REVERSE_EXECUTOR_PROMPT,
        executor_prompt_template=_EXECUTOR_TEMPLATE,
        executor_allowed_tools=_EXECUTOR_TOOLS,
        executor_max_turns=executor_max_turns,
        analyst_system_prompt=analyst_prompt,
        analyst_prompt_template=_ANALYST_TEMPLATE,
        analyst_allowed_tools=_ANALYST_TOOLS,
        analyst_max_turns=analyst_max_turns,
        max_follow_ups=max_follow_ups,
    )


RE_TRIAGE = _split(
    "re_triage",
    REVERSE_TRIAGE_PLANNER_PROMPT,
    REVERSE_TRIAGE_ANALYST_PROMPT,
    "Plan the triage of this sample.",
    _EARLY_BLOCKED + ["mcp__mulder__reverse_prioritize"],
    analyst_max_turns=50,
    max_follow_ups=1,
)

RE_MAPPING = _split(
    "re_mapping",
    REVERSE_MAPPING_PLANNER_PROMPT,
    REVERSE_MAPPING_ANALYST_PROMPT,
    "Plan the mapping of this sample: the leads that will decide which functions to study.",
    _EARLY_BLOCKED,
    analyst_max_turns=60,
    max_follow_ups=1,
)

RE_DEEP = _split(
    "re_deep",
    REVERSE_DEEP_PLANNER_PROMPT,
    REVERSE_DEEP_ANALYST_PROMPT,
    "Plan the decompilation of the prioritised functions and of the functions "
    "holding capa capabilities that have no verdict yet.",
    _EARLY_BLOCKED,
    executor_max_turns=80,
    analyst_max_turns=120,
    max_follow_ups=3,
)

RE_COUNTER = _split(
    "re_counter",
    REVERSE_COUNTER_PLANNER_PROMPT,
    REVERSE_COUNTER_ANALYST_PROMPT,
    "Plan the checks that could prove the current findings wrong.",
    _ANALYSIS_BLOCKED,
    analyst_max_turns=70,
    max_follow_ups=1,
)

RE_REPORT = PhaseConfig(
    name="re_report",
    mode="single",
    single_role="analyst",
    single_system_prompt=REVERSE_REPORT_PROMPT,
    single_prompt_template=_SAMPLE_BLOCK
    + "\nWrite the analysis narrative and finalize the report.",
    single_allowed_tools=get_tools_for_role(Role.RE_REPORT),
    single_max_turns=30,
    disallowed_tools=_BLOCKED,
)

REVERSE_PHASES = (RE_TRIAGE, RE_MAPPING, RE_DEEP, RE_COUNTER, RE_REPORT)
