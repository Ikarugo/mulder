"""Planner prompts only advertise tools the phase's executor may run, and a
plan that names an off-role tool is trimmed and logged (issue #175)."""

from __future__ import annotations

import logging
import re
from unittest.mock import patch

import pytest

from mulder.orchestrator.phases import ALTERNATIVE_NARRATIVE, CROSS_SYSTEM, EXTRACTION, PhaseConfig
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import PhaseResult, Plan
from mulder.server.tool_access import ALL_ROLES, get_tools_for_role

SPLIT_PHASES = [EXTRACTION, CROSS_SYSTEM, ALTERNATIVE_NARRATIVE]

REGISTERED = frozenset(t.removeprefix("mcp__mulder__") for t in get_tools_for_role(ALL_ROLES))

#: Tools the planner prompts tell the planner to call (or not call) itself
#: while reading the case, as opposed to tools it puts in the plan.
PLANNER_OWN_TOOLS = frozenset(
    {
        "open_case",
        "list_directory",
        "get_tool_guide",
        "get_findings",
        "get_investigation_summary",
        "list_sources",
        "get_source_stats",
        "get_timeline",
        "get_bookmarks",
    }
)


def _advertised(phase: PhaseConfig) -> set[str]:
    mentioned = set(re.findall(r"\b[a-z][a-z0-9_]*\b", phase.planner_system_prompt)) & REGISTERED
    return mentioned - PLANNER_OWN_TOOLS


@pytest.mark.parametrize("phase", SPLIT_PHASES, ids=lambda p: p.name)
def test_planner_prompt_only_advertises_executor_tools(phase: PhaseConfig) -> None:
    executor = {t.removeprefix("mcp__mulder__") for t in phase.executor_allowed_tools}
    advertised = _advertised(phase)
    assert advertised, f"{phase.name}: prompt names no plannable tools; extractor broke?"
    assert advertised <= executor, (
        f"{phase.name} planner prompt advertises tools its executor cannot run: "
        f"{sorted(advertised - executor)}"
    )


@pytest.mark.asyncio()
async def test_run_executor_drops_off_role_tasks_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator("/evidence")
    orch._case_id = "case"
    plan = Plan(
        plan_id="p",
        tasks=[
            {"tool": "search", "args": {"query": "x"}, "purpose": "ok"},
            {"tool": "check_finalize_readiness", "args": {}, "purpose": "analyst-only"},
            {"tool": "run_mmls", "args": {}, "purpose": "extraction-only"},
        ],
        investigation_questions=[],
        expected_sources=[],
        raw_text="plan",
        turns_used=1,
    )
    seen: dict[str, object] = {}

    async def mock_execute(**kwargs: object) -> PhaseResult:
        seen.update(kwargs)
        return PhaseResult(phase_name="x", success=True, messages=[], turns_used=1)

    with (
        patch.object(orch._session, "execute", side_effect=mock_execute),
        caplog.at_level(logging.WARNING, logger="mulder.orchestrator.roles"),
    ):
        await orch._roles.run_executor(ALTERNATIVE_NARRATIVE, plan)

    prompt = str(seen["prompt"])
    assert '"search"' in prompt
    assert "check_finalize_readiness" not in prompt
    assert "run_mmls" not in prompt
    allowed = seen["allowed_tools"]
    assert isinstance(allowed, list)
    assert "mcp__mulder__search" in allowed
    assert "mcp__mulder__check_finalize_readiness" not in allowed
    assert any(
        "check_finalize_readiness, run_mmls" in r.getMessage()
        and "alternative_narrative" in r.getMessage()
        for r in caplog.records
    ), caplog.text
