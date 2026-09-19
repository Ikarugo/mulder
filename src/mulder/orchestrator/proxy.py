"""LiteLLM proxy management for non-Claude model routing.

Provides automatic proxy lifecycle management so the Claude Agent SDK
can communicate with any LiteLLM-supported model provider (Bedrock
non-Claude models, OpenAI, Vertex AI, Ollama). The proxy is started
as a subprocess and stopped when the orchestrator completes.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_LITELLM_PREFIXES: tuple[str, ...] = (
    "bedrock/",
    "openai/",
    "vertex_ai/",
    "azure/",
    "ollama/",
)

_DEFAULT_PORT: int = 4000
_HEALTH_CHECK_TIMEOUT: float = 30.0
_HEALTH_CHECK_INTERVAL: float = 0.5
_MASTER_KEY: str = "sk-mulder-proxy"

#: Output tokens reserved per request for proxy-routed models. Doubles as
#: the LiteLLM ``max_tokens`` default and as ``CLAUDE_CODE_MAX_OUTPUT_TOKENS``
#: for the session, because the CLI's explicit value (32000 for model IDs
#: it does not recognise) would otherwise override the proxy default.
PROXY_MAX_OUTPUT_TOKENS: int = 8192


def is_proxy_model(model_id: str) -> bool:
    """Determine whether a model ID requires routing through a LiteLLM proxy.

    Model IDs using a provider prefix (e.g., ``bedrock/meta.llama3-1-70b``)
    are not natively understood by the Claude Agent SDK and must be routed
    through a LiteLLM proxy that translates the Anthropic API format.

    Args:
        model_id: The model identifier to check.

    Returns:
        True if the model needs proxy routing.
    """
    return any(model_id.startswith(prefix) for prefix in _LITELLM_PREFIXES)


def _build_proxy_config(models: list[str], port: int) -> dict[str, Any]:
    """Build a LiteLLM proxy configuration for the given models.

    Preserves each public model name while routing Ollama models through
    the native chat API so streamed tool calls retain their structure.

    Args:
        models: Unique litellm model IDs to serve.
        port: Port number for the proxy server.

    Returns:
        LiteLLM config dict suitable for YAML serialization.
    """
    model_list = []
    for model_id in models:
        model_list.append(
            {
                "model_name": model_id,
                "litellm_params": {
                    "model": (
                        "ollama_chat/" + model_id.removeprefix("ollama/")
                        if model_id.startswith("ollama/")
                        else model_id
                    ),
                    "max_tokens": PROXY_MAX_OUTPUT_TOKENS,
                },
            }
        )

    return {
        "model_list": model_list,
        "litellm_settings": {
            "drop_params": True,
            "num_retries": 2,
            "set_verbose": False,
            "modify_params": True,
        },
        "general_settings": {
            "master_key": _MASTER_KEY,
        },
    }


def _wait_for_health(port: int, timeout: float = _HEALTH_CHECK_TIMEOUT) -> bool:
    """Wait for the LiteLLM proxy to become healthy.

    Polls the proxy health endpoint until it responds or the timeout
    expires.

    Args:
        port: Port the proxy is listening on.
        timeout: Maximum seconds to wait.

    Returns:
        True if the proxy became healthy within the timeout.
    """
    import urllib.error
    import urllib.request

    urls = [
        f"http://localhost:{port}/health/liveliness",
        f"http://localhost:{port}/health",
        f"http://localhost:{port}/",
    ]
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        for url in urls:
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=2) as resp:
                    if resp.status < 400:
                        return True
            except (urllib.error.URLError, OSError, TimeoutError):
                pass
        time.sleep(_HEALTH_CHECK_INTERVAL)

    return False


def fetch_model_windows(port: int, timeout: float = 5.0) -> dict[str, int]:
    """Read each served model's context window from the running proxy.

    LiteLLM's ``/model_group/info`` reports ``max_input_tokens`` per public
    model name from its ``model_prices_and_context_window`` map. Claude Code
    assumes a 200K window for model IDs it does not recognise, so the real
    window is handed to each session as ``CLAUDE_CODE_MAX_CONTEXT_TOKENS``
    (see :mod:`mulder.orchestrator.session`). Reading it over HTTP keeps
    litellm out of mulder's venv.

    Args:
        port: Port the proxy is listening on.
        timeout: Seconds to wait for the endpoint.

    Returns:
        Mapping of model name to context window in tokens. Models the map
        does not know are omitted; any failure yields an empty mapping.
    """
    import json
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        f"http://localhost:{port}/model_group/info",
        headers={"Authorization": f"Bearer {_MASTER_KEY}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.load(resp)
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        logger.warning("Could not read model windows from proxy: %s", exc)
        return {}

    windows: dict[str, int] = {}
    entries = payload.get("data") if isinstance(payload, dict) else None
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        name, window = entry.get("model_group"), entry.get("max_input_tokens")
        if isinstance(name, str) and isinstance(window, (int, float)) and window > 0:
            windows[name] = int(window)
    return windows


class ProxyManager:
    """Manages the lifecycle of a local LiteLLM proxy subprocess.

    Intended for use as a context manager. Starts the proxy on enter,
    stops it on exit.

    Example::

        async with ProxyManager(models=["bedrock/meta.llama3-1-70b"]) as pm:
            env_overrides = pm.env_overrides
            # ... run orchestrator with env_overrides applied
    """

    def __init__(
        self,
        models: list[str],
        port: int | None = None,
        config_path: str | None = None,
    ) -> None:
        """Initialize the proxy manager.

        Args:
            models: LiteLLM model IDs that need proxy routing.
            port: Port for the proxy server. Defaults to 4000 or the
                value of MULDER_PROXY_PORT env var.
            config_path: Optional path to a user-provided LiteLLM config
                YAML. When provided, the auto-generated config is skipped
                and this file is used instead.
        """
        import os

        self._models = models
        self._port = port or int(os.environ.get("MULDER_PROXY_PORT", _DEFAULT_PORT))
        self._config_path = config_path
        self._process: subprocess.Popen[bytes] | None = None
        self._temp_config: Path | None = None

    @property
    def port(self) -> int:
        """The port the proxy is running on."""
        return self._port

    @property
    def env_overrides(self) -> dict[str, str]:
        """Environment variables to route the SDK through the proxy.

        These must be merged into the orchestrator's env dict so that
        agent SDK sessions route API calls through the local proxy
        instead of directly to Anthropic. Bedrock/Vertex flags are
        explicitly disabled so the SDK uses standard API routing (the
        proxy handles provider translation).
        """
        return {
            "ANTHROPIC_BASE_URL": f"http://localhost:{self._port}",
            "ANTHROPIC_AUTH_TOKEN": _MASTER_KEY,
            "CLAUDE_CODE_USE_BEDROCK": "0",
            "CLAUDE_CODE_USE_VERTEX": "0",
            "CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY": "1",
        }

    def start(self) -> None:
        """Start the LiteLLM proxy subprocess.

        LiteLLM is installed in an isolated venv (/opt/litellm) due to
        dependency conflicts with mulder's mcp and rich versions. The
        ``litellm`` binary is symlinked to /usr/local/bin.

        Raises:
            RuntimeError: If litellm is not installed or the proxy fails
                to start within the health check timeout.
        """
        import os
        import shutil

        litellm_bin = shutil.which("litellm")
        if litellm_bin is None:
            raise RuntimeError(
                "LiteLLM is not installed. Install with: "
                "pip install 'litellm[proxy]' or rebuild the Docker image."
            )

        if self._config_path:
            config_file = self._config_path
        else:
            config = _build_proxy_config(self._models, self._port)
            fd, tmp_path = tempfile.mkstemp(suffix=".yaml", prefix="mulder_litellm_")
            self._temp_config = Path(tmp_path)
            os.close(fd)
            self._temp_config.write_text(
                yaml.dump(config, default_flow_style=False), encoding="utf-8"
            )
            config_file = str(self._temp_config)

        cmd = [
            litellm_bin,
            "--config",
            config_file,
            "--port",
            str(self._port),
            "--num_workers",
            "1",
        ]

        logger.info(
            "Starting LiteLLM proxy on port %d for models: %s",
            self._port,
            self._models,
        )

        proxy_env = os.environ.copy()

        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=proxy_env,
        )

        if not _wait_for_health(self._port):
            self.stop()
            raise RuntimeError(
                f"LiteLLM proxy failed to start within {_HEALTH_CHECK_TIMEOUT}s. "
                f"Models: {self._models}"
            )

        logger.info("LiteLLM proxy is healthy on port %d", self._port)

    def model_windows(self) -> dict[str, int]:
        """Context window per served model, empty when the proxy cannot say."""
        return fetch_model_windows(self._port)

    def stop(self) -> None:
        """Stop the proxy subprocess and clean up temporary files."""
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=3)
            self._process = None
            logger.info("LiteLLM proxy stopped")

        if self._temp_config and self._temp_config.exists():
            self._temp_config.unlink()
            self._temp_config = None

    def __enter__(self) -> ProxyManager:
        """Start the proxy on context entry."""
        self.start()
        return self

    def __exit__(self, *_: Any) -> None:
        """Stop the proxy on context exit."""
        self.stop()
