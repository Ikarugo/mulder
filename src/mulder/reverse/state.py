"""State of a reverse-engineering case: what the pipeline has established so far.

Stored as JSON in the case database's key/value table, so every agent
session (each runs its own MCP server) and the orchestrator's gates read
the same record:

* ``priorities``: functions the mapping phase chose to study, each with
  why and the tool calls that justify it;
* ``packed``: set instead when the sample is packed (analysis stops there);
* ``verdicts``: for each capability capa reported, whether the code
  confirms or refutes it, with the calls that show it;
* ``challenges``: the counter-analysis outcome for each finding;
* ``yara``: the candidate YARA rule, always to be validated by a human.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable
from typing import Any

__all__ = [
    "CASE_KIND_KEY",
    "CHALLENGE_OUTCOMES",
    "REVERSE_KIND",
    "SAMPLE_KEY",
    "STATE_KEY",
    "VERDICTS",
    "capability_coverage",
    "capa_capabilities",
    "is_reverse_case",
    "load_state",
    "save_state",
]

CASE_KIND_KEY = "case_kind"
REVERSE_KIND = "reverse"
STATE_KEY = "reverse:state"
SAMPLE_KEY = "reverse:sample"
CAPA_KEY_PREFIX = "capa:capabilities:"

VERDICTS = ("confirmed", "refuted")
VERDICT_BASES = ("code", "unreachable", "library_code", "dead_code", "benign_use", "other")
CHALLENGE_OUTCOMES = ("upheld", "downgraded", "withdrawn")

Getter = Callable[[str], "str | None"]
Setter = Callable[[str, str], None]


def is_reverse_case(get: Getter) -> bool:
    """True when the open case was created by ``mulder reverse``."""
    return get(CASE_KIND_KEY) == REVERSE_KIND


def load_state(get: Getter) -> dict[str, Any]:
    """The case's reverse state, with every section present."""
    raw = get(STATE_KEY)
    try:
        state = json.loads(raw) if raw else {}
    except ValueError:
        state = {}
    if not isinstance(state, dict):
        state = {}
    state.setdefault("priorities", [])
    state.setdefault("packed", None)
    state.setdefault("verdicts", {})
    state.setdefault("challenges", {})
    state.setdefault("yara", None)
    return state


def save_state(set_: Setter, state: dict[str, Any]) -> None:
    state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    set_(STATE_KEY, json.dumps(state))


def capa_capabilities(get: Getter, sample: str) -> list[dict[str, Any]] | None:
    """Capabilities capa reported for *sample*, or None if capa never ran on it."""
    raw = get(CAPA_KEY_PREFIX + sample)
    if raw is None:
        return None
    try:
        rows = json.loads(raw)
    except ValueError:
        return None
    return [r for r in rows if isinstance(r, dict) and r.get("name")]


def capability_coverage(
    capabilities: Iterable[dict[str, Any]], verdicts: dict[str, Any]
) -> dict[str, Any]:
    """Which capa capabilities have a verdict, and which are still open."""
    names = [str(c["name"]) for c in capabilities]
    decided = [n for n in names if n in verdicts]
    return {
        "total": len(names),
        "decided": len(decided),
        "confirmed": sorted(n for n in decided if verdicts[n].get("verdict") == "confirmed"),
        "refuted": sorted(n for n in decided if verdicts[n].get("verdict") == "refuted"),
        "open": sorted(n for n in names if n not in verdicts),
    }
