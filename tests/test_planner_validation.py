"""Malformed planner tasks are repaired or rejected before execution."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from claude_agent_sdk.types import AssistantMessage, TextBlock

from mulder.orchestrator.phases import CROSS_SYSTEM
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import PhaseResult, extract_json_plan

BAD = json.dumps(
    {
        "tasks": [
            "Open the case using open_case(case_id='case')",
            "Review findings and sources",
            "Plan cross-system correlation",
        ]
    }
)
GOOD = json.dumps(
    {"tasks": [{"tool": "correlate_across_sources", "args": {}, "purpose": "find shared IOCs"}]}
)
VARS = {"case_id": "case", "case_briefing": ""}


def _make_orchestrator(tmp_path: Path) -> Orchestrator:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        return Orchestrator(evidence_path="/evidence", case_id="case", db_dir=str(tmp_path))


@pytest.mark.parametrize("tasks", [["text"], [{"tool": "search"}, "text"], [None], [1], []])
def test_rejects_invalid_tasks(tasks: list[object]) -> None:
    assert extract_json_plan([json.dumps({"tasks": tasks})]) is None


@pytest.mark.asyncio
async def test_invalid_plan_runs_utility_repair_and_accepts_corrected_plan(tmp_path: Path) -> None:
    orch = _make_orchestrator(tmp_path)
    responses = [
        PhaseResult(phase_name="query", messages=[BAD]),
        PhaseResult(phase_name="query", messages=[GOOD]),
    ]
    with patch.object(orch._session, "execute", new=AsyncMock(side_effect=responses)) as execute:
        plan = await orch._roles.run_planner(CROSS_SYSTEM, VARS)
    assert execute.await_count == 2
    assert plan is not None
    assert plan.tasks[0]["tool"] == "correlate_across_sources"
    assert execute.call_args.kwargs["allowed_tools"] == []


@pytest.mark.asyncio
async def test_invalid_repair_fails_phase_cleanly_without_executor(tmp_path: Path) -> None:
    orch = _make_orchestrator(tmp_path)
    with patch.object(
        orch._session,
        "execute",
        new=AsyncMock(return_value=PhaseResult(phase_name="query", messages=[BAD])),
    ) as execute:
        result = await orch._run_split_phase(CROSS_SYSTEM, VARS)
    assert not result.success
    assert execute.await_count == 2


def test_display_retains_malformed_message_without_raising(tmp_path: Path) -> None:
    orch = _make_orchestrator(tmp_path)
    messages: list[str] = []
    message = AssistantMessage(content=[TextBlock(text=BAD)], model="test-model")
    orch._session._process_assistant_message(message, "", set(), messages)
    assert messages == [BAD]
