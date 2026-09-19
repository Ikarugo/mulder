"""Split-phase gate failures are retried with the gate's gap list: an
analyst-only remediation session first, a full re-plan only if that fails,
all bounded by ``max_retries`` (issue #195)."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest

from mulder.orchestrator.gates import GateResult
from mulder.orchestrator.phases import ALTERNATIVE_NARRATIVE
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import ExecutionResults, PhaseResult, Plan

GAP = "timestamp_coverage: 3 non-negative finding(s) missing event_time_start: ['A', 'B', 'C']"


class _Harness:
    """Mock roles around a real ``run_remediation`` and capture every prompt."""

    def __init__(self, gate_outcomes: list[bool]) -> None:
        with patch("mulder.orchestrator.runner.InvestigationDashboard"):
            self.orch = Orchestrator("/evidence", case_id="test-case")
        self.gate_outcomes = iter(gate_outcomes)
        self.planner_contexts: list[str] = []
        self.session_prompts: list[str] = []

    async def planner(
        self,
        phase: Any,
        prompt_vars: Any = None,
        follow_up_context: str = "",
        log_prefix: str = "",
    ) -> Plan:
        self.planner_contexts.append(follow_up_context)
        return Plan("p", [{"tool": "t", "args": {}, "purpose": "p"}], [], [], "plan", 1)

    async def executor(self, phase: Any, plan: Plan, *a: Any, **kw: Any) -> ExecutionResults:
        return ExecutionResults(plan.plan_id, [], 1, False, tool_calls=1)

    async def session_execute(self, **kwargs: Any) -> PhaseResult:
        # Only the analyst (and remediation) reach the real session here.
        self.session_prompts.append(kwargs["prompt"])
        return PhaseResult(phase_name="query", messages=["done"], turns_used=1)

    async def validate(self, phase: Any, result: PhaseResult) -> GateResult:
        passed = next(self.gate_outcomes)
        return GateResult(passed, phase.name, gaps=[] if passed else [GAP])

    async def run(self) -> PhaseResult:
        with (
            patch.object(self.orch._roles, "run_planner", side_effect=self.planner),
            patch.object(self.orch._roles, "run_executor", side_effect=self.executor),
            patch.object(self.orch._session, "execute", side_effect=self.session_execute),
            patch.object(self.orch, "_validate_phase", side_effect=self.validate),
        ):
            return await self.orch._run_split_phase(
                ALTERNATIVE_NARRATIVE, prompt_vars={"case_id": "test-case"}
            )


@pytest.mark.asyncio()
async def test_gap_text_reaches_remediation_prompt_before_any_replan() -> None:
    h = _Harness(gate_outcomes=[False, True])
    result = await h.run()

    assert result.success
    assert len(h.planner_contexts) == 1  # the remediation fixed it; no second plan
    remediation_prompt = h.session_prompts[1]
    assert "GATE FAILED" in remediation_prompt
    assert GAP in remediation_prompt
    assert "open_case(case_id='test-case')" in remediation_prompt
    assert "do not re-run extraction" in remediation_prompt.lower()
    assert result.turns_used == 4  # plan + exec + analyst + remediation


@pytest.mark.asyncio()
async def test_failed_remediation_falls_back_to_full_cycle_with_gaps() -> None:
    h = _Harness(gate_outcomes=[False, False, True])
    result = await h.run()

    assert result.success
    assert len(h.planner_contexts) == 2
    assert h.planner_contexts[0] == ""
    assert json.loads(h.planner_contexts[1]) == {"gate_failure": [GAP]}
    assert sum("GATE FAILED" in p for p in h.session_prompts) == 1


@pytest.mark.asyncio()
async def test_remediation_attempts_count_against_max_retries() -> None:
    assert ALTERNATIVE_NARRATIVE.max_retries == 2
    h = _Harness(gate_outcomes=[False, False, False, False])
    result = await h.run()

    assert not result.success
    # full, remediation, full: three attempts, no more
    assert len(h.planner_contexts) == 2
    assert sum("GATE FAILED" in p for p in h.session_prompts) == 1
    assert len(h.session_prompts) == 3
