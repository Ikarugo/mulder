"""Prompt templates for each investigation phase and role.

Each prompt is stored as a separate markdown file in this directory
and loaded at import time. Single-mode phases (catalog, report) have
one prompt. Split-mode phases have three: planner, executor, analyst.
"""

from __future__ import annotations

from pathlib import Path

_DIR = Path(__file__).resolve().parent


def _load(name: str) -> str:
    """Read a prompt file from this package directory.

    Args:
        name: Filename (e.g., ``catalog.md``) relative to this directory.

    Returns:
        The file contents with leading/trailing whitespace stripped.
    """
    return (_DIR / name).read_text(encoding="utf-8").strip()


# Single-mode phases
CATALOG_PROMPT: str = _load("catalog.md")
REPORT_PROMPT: str = _load("report.md")

# Extract phase (split: planner / executor / analyst)
EXTRACT_PLANNER_PROMPT: str = _load("extract_planner.md")
EXTRACT_EXECUTOR_PROMPT: str = _load("extract_executor.md")
EXTRACT_ANALYST_PROMPT: str = _load("extract_analyst.md")

# Cross-system phase (split: planner / executor / analyst)
CROSS_SYSTEM_PLANNER_PROMPT: str = _load("cross_system_planner.md")
CROSS_SYSTEM_EXECUTOR_PROMPT: str = _load("cross_system_executor.md")
CROSS_SYSTEM_ANALYST_PROMPT: str = _load("cross_system_analyst.md")

# Alternative narrative phase (split: planner / executor / analyst)
NARRATIVE_PLANNER_PROMPT: str = _load("narrative_planner.md")
NARRATIVE_EXECUTOR_PROMPT: str = _load("narrative_executor.md")
NARRATIVE_ANALYST_PROMPT: str = _load("narrative_analyst.md")

# Reverse-engineering pipeline (``mulder reverse``). Every role gets the
# shared static-analysis and adversarial-sample rules.
REVERSE_COMMON: str = _load("reverse_common.md")


def _reverse(name: str) -> str:
    return _load(name) + "\n\n" + REVERSE_COMMON


REVERSE_EXECUTOR_PROMPT: str = _reverse("reverse_executor.md")
REVERSE_TRIAGE_PLANNER_PROMPT: str = _reverse("reverse_triage_planner.md")
REVERSE_TRIAGE_ANALYST_PROMPT: str = _reverse("reverse_triage_analyst.md")
REVERSE_MAPPING_PLANNER_PROMPT: str = _reverse("reverse_mapping_planner.md")
REVERSE_MAPPING_ANALYST_PROMPT: str = _reverse("reverse_mapping_analyst.md")
REVERSE_DEEP_PLANNER_PROMPT: str = _reverse("reverse_deep_planner.md")
REVERSE_DEEP_ANALYST_PROMPT: str = _reverse("reverse_deep_analyst.md")
REVERSE_COUNTER_PLANNER_PROMPT: str = _reverse("reverse_counter_planner.md")
REVERSE_COUNTER_ANALYST_PROMPT: str = _reverse("reverse_counter_analyst.md")
REVERSE_REPORT_PROMPT: str = _reverse("reverse_report.md")
