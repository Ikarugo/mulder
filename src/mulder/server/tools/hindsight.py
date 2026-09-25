"""Hindsight MCP tools for Chrome/Chromium browser forensics.

Runs Hindsight against a browser profile directory and indexes the
parsed artifacts (history, downloads, cookies, autofill, bookmarks,
local storage, preferences, etc.) into the case database.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    error_response,
    interpreter_candidates,
    make_tool_call_id,
    run_failure_response,
    run_tool,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access

logger = logging.getLogger(__name__)

_HINDSIGHT_TIMEOUT = 300
_VALID_BROWSERS = ("chrome", "brave", "edge", "opera")


def _find_hindsight_cmd() -> list[str] | None:
    """Locate the Hindsight CLI, trying multiple install conventions."""
    for name in ("hindsight.py", "hindsight"):
        if shutil.which(name):
            return [name]
    for py in interpreter_candidates():
        try:
            subprocess.run(
                [py, "-m", "pyhindsight.hindsight", "--help"],
                capture_output=True,
                timeout=10,
                check=True,
            )
            return [py, "-m", "pyhindsight.hindsight"]
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            continue
    return None


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR | Role.EXTRACT_ANALYST)
def run_hindsight(
    profile_path: str,
    browser: str = "chrome",
) -> dict[str, object]:
    """Analyze Chrome/Chromium browser artifacts using Hindsight.

    Parses browser history, downloads, cookies, autofill, bookmarks,
    preferences, cache, local storage, sessions, and extensions from
    a Chrome/Chromium profile directory.

    Run this after extracting browser profile directories from a disk
    image (typically under ``AppData/Local/Google/Chrome/User Data/Default``
    on Windows or ``~/.config/google-chrome/Default`` on Linux).

    Args:
        profile_path: Path to the browser profile directory
            (e.g. Default/ under Chrome user data).
        browser: Browser type, one of "chrome" (default), "brave", "edge", "opera".
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {"profile_path": profile_path, "browser": browser}
    tool_name = "run_hindsight"

    hs_cmd = _find_hindsight_cmd()
    if not hs_cmd:
        return error_response(
            tc_id,
            tool_name,
            params,
            "Hindsight not found. Install with: pip install pyhindsight",
            error_type="binary_missing",
        )

    if not Path(profile_path).is_dir():
        return error_response(
            tc_id,
            tool_name,
            params,
            f"Profile directory not found: {profile_path}",
            error_type="file_not_found",
        )

    browser_type = browser.lower() if browser.lower() in _VALID_BROWSERS else "chrome"

    with tempfile.TemporaryDirectory(prefix="mulder_hindsight_") as tmpdir:
        output_base = str(Path(tmpdir) / "results")

        cmd = [
            *hs_cmd,
            "-i",
            profile_path,
            "-o",
            output_base,
            "-b",
            browser_type,
            "-f",
            "jsonl",
        ]

        run = run_tool(cmd, timeout=_HINDSIGHT_TIMEOUT)

        raw_output = ""
        artifact_counts: dict[str, int] = {}

        for out_file in sorted(Path(tmpdir).rglob("*")):
            if not out_file.is_file() or out_file.stat().st_size == 0:
                continue
            try:
                text = out_file.read_text(encoding="utf-8", errors="replace")
                raw_output += f"=== {out_file.name} ===\n{text}\n\n"

                if out_file.suffix == ".jsonl":
                    count = sum(1 for line in text.splitlines() if line.strip())
                    artifact_counts[out_file.stem] = count
            except OSError:
                continue

        tool_warning: str | None = None
        if not raw_output.strip():
            if not run.ok:
                # Hindsight did not complete and wrote no result file: what it
                # printed is a traceback or usage text, not browser artifacts.
                return run_failure_response(
                    tc_id,
                    tool_name,
                    params,
                    run,
                    t0,
                    context=f"Hindsight wrote no output for {profile_path}",
                    suggestion=(
                        "Check that profile_path is a Chromium profile directory (it holds "
                        "History, Cookies, Preferences...) and that browser matches it."
                    ),
                )
            raw_output = run.stdout.strip() or run.stderr.strip()
            tool_warning = (
                "Hindsight exited 0 but wrote no result file; its console output was indexed "
                "instead. No browser artifacts were parsed: this is not evidence of absence."
            )
        elif not run.ok:
            tool_warning = (
                f"{run.describe()}\nThe result files written before that were indexed; "
                "they may be incomplete."
            )

    index_result = extract_and_index(
        raw_output,
        "hindsight.browser",
        profile_path,
        "hindsight",
    )

    elapsed = (time.monotonic() - t0) * 1000
    result: dict[str, object] = {
        "browser": browser_type,
        "profile_path": profile_path,
        "artifact_counts": artifact_counts,
        "total_artifacts": sum(artifact_counts.values()),
        "index": index_result,
    }
    if tool_warning:
        result["tool_warning"] = tool_warning

    return tool_response(tc_id, tool_name, params, result, "hindsight.browser", elapsed)
