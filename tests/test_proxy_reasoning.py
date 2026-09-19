"""Reasoning-capable proxy models get LiteLLM's raw ``reasoning_effort``
passthrough and a larger output cap; ``--no-thinking`` and unsupported models
do not (issue #193)."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from mulder.orchestrator.models import ModelConfig
from mulder.orchestrator.proxy import (
    PROXY_MAX_OUTPUT_TOKENS,
    PROXY_REASONING_MAX_OUTPUT_TOKENS,
    ProxyManager,
    _build_proxy_config,
    reasoning_models,
)
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.session import SessionExecutor

DEEPSEEK = "bedrock/deepseek.v3.2"
LLAMA = "bedrock/meta.llama3-3-70b-instruct-v1:0"
_OUT = "CLAUDE_CODE_MAX_OUTPUT_TOKENS"


def _params(config: dict[str, object], name: str) -> dict[str, object]:
    entries = config["model_list"]
    assert isinstance(entries, list)
    return next(e["litellm_params"] for e in entries if e["model_name"] == name)


class TestBuildProxyConfig:
    def test_reasoning_model_gets_passthrough_and_cap(self) -> None:
        params = _params(_build_proxy_config([DEEPSEEK], 4000, {DEEPSEEK}), DEEPSEEK)
        assert params["allowed_openai_params"] == ["reasoning_effort"]
        assert params["max_tokens"] == PROXY_REASONING_MAX_OUTPUT_TOKENS

    def test_other_models_untouched(self) -> None:
        config = _build_proxy_config([DEEPSEEK, LLAMA], 4000, {DEEPSEEK})
        params = _params(config, LLAMA)
        assert "allowed_openai_params" not in params
        assert params["max_tokens"] == PROXY_MAX_OUTPUT_TOKENS

    def test_default_is_no_reasoning(self) -> None:
        params = _params(_build_proxy_config([DEEPSEEK], 4000), DEEPSEEK)
        assert "allowed_openai_params" not in params
        assert params["max_tokens"] == PROXY_MAX_OUTPUT_TOKENS


class TestReasoningModels:
    def _venv(self, tmp_path: Path) -> str:
        (tmp_path / "python").touch()
        (tmp_path / "litellm").touch()
        return str(tmp_path / "litellm")

    def test_queries_litellm_venv_with_routed_names(self, tmp_path: Path) -> None:
        answer = {"bedrock/deepseek.v3.2": True, "ollama_chat/qwen3": False}
        with patch("subprocess.run") as run:
            run.return_value = MagicMock(stdout=json.dumps(answer))
            found = reasoning_models(self._venv(tmp_path), [DEEPSEEK, "ollama/qwen3"])
        assert found == {DEEPSEEK}
        cmd = run.call_args.args[0]
        assert cmd[0] == str(tmp_path / "python")
        assert cmd[-2:] == [DEEPSEEK, "ollama_chat/qwen3"]

    def test_failure_serves_without_reasoning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        err = subprocess.CalledProcessError(1, "python")
        with patch("subprocess.run", side_effect=err), caplog.at_level(logging.WARNING):
            assert reasoning_models(self._venv(tmp_path), [DEEPSEEK]) == set()
        assert "Could not query LiteLLM" in caplog.text

    def test_missing_interpreter(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            assert reasoning_models(str(tmp_path / "litellm"), [DEEPSEEK]) == set()
        assert "No interpreter" in caplog.text


class TestProxyManagerStart:
    def _start(self, thinking: bool, caplog: pytest.LogCaptureFixture) -> dict[str, object]:
        written: dict[str, object] = {}

        def capture_config(self: Path, text: str, encoding: str = "") -> int:
            written.update(yaml.safe_load(text))
            return len(text)

        with (
            patch("shutil.which", return_value="/usr/local/bin/litellm"),
            patch("mulder.orchestrator.proxy._wait_for_health", return_value=True),
            patch("subprocess.Popen"),
            patch("mulder.orchestrator.proxy.reasoning_models", return_value={DEEPSEEK}) as rm,
            patch.object(Path, "write_text", capture_config),
            caplog.at_level(logging.WARNING),
        ):
            pm = ProxyManager(models=[DEEPSEEK, LLAMA], port=4000, thinking=thinking)
            pm.start()
            pm.stop()
        written["_queried"] = rm.called
        written["_reasoning"] = pm.reasoning_models
        return written

    def test_thinking_enables_reasoning_and_warns_for_the_rest(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        written = self._start(True, caplog)
        assert written["_reasoning"] == {DEEPSEEK}
        assert "allowed_openai_params" in _params(written, DEEPSEEK)
        assert "allowed_openai_params" not in _params(written, LLAMA)
        assert f"no reasoning support for {LLAMA}" in caplog.text
        assert DEEPSEEK not in caplog.text

    def test_no_thinking_skips_the_lookup(self, caplog: pytest.LogCaptureFixture) -> None:
        written = self._start(False, caplog)
        assert written["_queried"] is False
        assert written["_reasoning"] == set()
        assert "allowed_openai_params" not in _params(written, DEEPSEEK)
        assert "no reasoning support" not in caplog.text


class TestSessionOutputCap:
    def test_reasoning_model_gets_larger_cap(self) -> None:
        session = SessionExecutor(
            dashboard=MagicMock(), model_config=ModelConfig(), cwd="/tmp", env={}, effort="max"
        )
        session._proxy_reasoning = {DEEPSEEK}
        assert session._gateway_env(DEEPSEEK)[_OUT] == str(PROXY_REASONING_MAX_OUTPUT_TOKENS)
        assert session._gateway_env(LLAMA)[_OUT] == str(PROXY_MAX_OUTPUT_TOKENS)


class TestOrchestratorPlumbing:
    @pytest.mark.parametrize("no_thinking", [False, True])
    def test_hands_thinking_and_reasoning_set_to_proxy_and_session(
        self, no_thinking: bool
    ) -> None:
        with patch("mulder.orchestrator.runner.InvestigationDashboard"):
            orch = Orchestrator(
                "/evidence", model_config=ModelConfig(planner=DEEPSEEK), no_thinking=no_thinking
            )
        with patch("mulder.orchestrator.runner.ProxyManager") as pm_cls:
            pm_cls.return_value.model_windows.return_value = {}
            pm_cls.return_value.env_overrides = {}
            pm_cls.return_value.reasoning_models = set() if no_thinking else {DEEPSEEK}
            orch._start_proxy_if_needed()
        assert pm_cls.call_args.kwargs["thinking"] is not no_thinking
        assert orch._session._proxy_reasoning == (set() if no_thinking else {DEEPSEEK})
