"""Structured-output parsing survives tool-call markup leaked by proxied models.

Non-Anthropic models behind the LiteLLM proxy can emit their native tool-call
markup as a stray text block beside the real ToolUseBlock. The patterns below
are real-world leak formats; the DeepSeek one is copied byte-for-byte from a
``bedrock/deepseek.v3.2`` orchestrator log.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from claude_agent_sdk.types import AssistantMessage, TextBlock

from mulder.orchestrator.roles import _REPAIR_MAX_CHARS
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.session import _is_bare_markup_token
from mulder.orchestrator.types import (
    PhaseResult,
    extract_catalog_result,
    extract_json_from_text,
    extract_json_plan,
)

DEEPSEEK_LEAK = "<｜DSML｜function_calls"

PLAN = json.dumps(
    {
        "tasks": [{"tool": "search", "args": {"query": "x"}, "purpose": "p"}],
        "investigation_questions": [],
        "expected_sources": [],
    }
)

LEAKS = {
    "deepseek_full_markup": (
        '<｜DSML｜function_calls>\n<｜DSML｜invoke name="search">\n'
        '<｜DSML｜parameter name="query">{"q": "x"}</｜DSML｜parameter>\n'
        "</｜DSML｜invoke>\n</｜DSML｜function_calls>\n" + PLAN
    ),
    "deepseek_bare_marker": DEEPSEEK_LEAK + "\n" + PLAN,
    "llama_python_tag_trailing": (
        PLAN + '\n<|python_tag|>{"name": "search", "parameters": {"q": 1}}<|eom_id|>'
    ),
    "hermes_tool_call": (
        '<tool_call>\n{"name": "search", "arguments": {"query": "x"}}\n</tool_call>\n'
        "Here is the plan:\n" + PLAN
    ),
    "think_block_with_braces": (
        "<think>\nI should return {tasks: [...]} with one task. "
        "Let me build the object {\n</think>\n" + PLAN
    ),
    "mistral_tool_calls": (
        '[TOOL_CALLS][{"name": "search", "arguments": {"query": "x"}}]\n'
        + PLAN
        + "\n[/TOOL_CALLS]"
    ),
    "llama_function_tag": '<function=search>{"query": "x"}</function>\n' + PLAN,
    "chatml": "<|im_start|>assistant\n" + PLAN + "\n<|im_end|>",
    "fenced_after_markup": "<tool_call>{}</tool_call>\n```json\n" + PLAN + "\n```",
}


@pytest.mark.parametrize("text", LEAKS.values(), ids=LEAKS.keys())
def test_plan_extracted_through_leaked_markup(text: str) -> None:
    plan = extract_json_plan([text])
    assert plan is not None
    assert plan["tasks"][0]["tool"] == "search"
    assert extract_json_from_text(text)["tasks"] == plan["tasks"]


def test_required_keys_skip_leaked_tool_call_object() -> None:
    """The leaked ``{"name": ...}`` object is not mistaken for the catalog."""
    text = '<tool_call>{"name": "x"}</tool_call>\n{"systems": [{"name": "host-a"}]}'
    assert extract_catalog_result([text]) == {"systems": [{"name": "host-a"}]}


def test_braces_inside_strings_do_not_confuse_scan() -> None:
    text = 'noise {\n{"tasks": [{"tool": "t", "args": {"s": "}{"}, "purpose": "p"}]}'
    plan = extract_json_plan([text])
    assert plan is not None
    assert plan["tasks"][0]["args"] == {"s": "}{"}


def test_no_json_still_returns_none_and_empty() -> None:
    assert extract_json_plan([DEEPSEEK_LEAK, "Now I'll examine the sources."]) is None
    assert extract_json_from_text(DEEPSEEK_LEAK) == {}
    assert extract_json_from_text('{"broken": }') == {}


@pytest.mark.parametrize(
    "text",
    [DEEPSEEK_LEAK, "<|python_tag|>", "<tool_call>", "[TOOL_CALLS]", "<|im_start|>", " <think>\n"],
)
def test_bare_marker_detected(text: str) -> None:
    assert _is_bare_markup_token(text)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "Now I'll examine the sources.",
        "<think> reasoning </think>",
        "<tool_call>\n{}\n</tool_call>",
        PLAN,
        "[1] first finding",
        "Done.",
    ],
)
def test_prose_and_json_never_dropped(text: str) -> None:
    assert not _is_bare_markup_token(text)


def _make_orchestrator(tmp_path: Path) -> Orchestrator:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        return Orchestrator(evidence_path="/evidence", case_id="case", db_dir=str(tmp_path))


def test_session_drops_bare_marker_but_keeps_prose_and_plan(tmp_path: Path) -> None:
    orch = _make_orchestrator(tmp_path)
    messages: list[str] = []
    message = AssistantMessage(
        content=[
            TextBlock(text="Now I'll examine the sources."),
            TextBlock(text=DEEPSEEK_LEAK),
            TextBlock(text=PLAN),
        ],
        model="test-model",
    )
    orch._session._process_assistant_message(message, "", set(), messages)
    assert messages == ["Now I'll examine the sources.", PLAN]


@pytest.mark.asyncio
async def test_repair_skips_utility_model_when_no_json_present(tmp_path: Path) -> None:
    """The log case: planner ran out of turns, transcript is prose plus markers."""
    orch = _make_orchestrator(tmp_path)
    with patch.object(orch._session, "execute", new=AsyncMock()) as execute:
        result = await orch._roles._repair_json(
            ["I'll start by opening the case.", DEEPSEEK_LEAK, "Now let me search."],
            "alternative_narrative",
        )
    assert result is None
    execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_repair_prompt_is_bounded_and_starts_at_first_brace(tmp_path: Path) -> None:
    orch = _make_orchestrator(tmp_path)
    huge = "x" * 5000 + '{"tasks": ' + "y" * (3 * _REPAIR_MAX_CHARS)
    with patch.object(
        orch._session,
        "execute",
        new=AsyncMock(return_value=PhaseResult(phase_name="query", messages=[PLAN])),
    ) as execute:
        result = await orch._roles._repair_json([huge], "phase")
    assert result is not None
    sent = execute.call_args.kwargs["prompt"]
    body = sent.split("TEXT:\n", 1)[1]
    assert body.startswith('{"tasks": ')
    assert len(body) == _REPAIR_MAX_CHARS
    assert "ignore" in sent and '{"tasks": []}' in sent
