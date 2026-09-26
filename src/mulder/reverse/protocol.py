"""Helpers shared by the server-side backends and the engine workers.

Kept free of any engine import so both sides (and the unit tests) can use
them without Ghidra or radare2 installed.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from mulder.reverse.backend import BackendError

__all__ = [
    "NAME_RE",
    "clamp",
    "hex_addr",
    "page",
    "parse_hex",
    "validate_name",
]

#: A name the agent may give a function or a label: an identifier, with the
#: few extra characters C++ and Ghidra namespaces use. Anything else (spaces,
#: quotes, control characters, markup) is refused rather than stored in a
#: project the analyst will open.
NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.:$@?<>~]{0,199}")

_HEX_RE = re.compile(r"(?:0x)?([0-9a-fA-F]{1,16})")


def hex_addr(value: int) -> str:
    """Render an address the way every backend returns it."""
    return f"0x{value:x}"


def parse_hex(target: str) -> int | None:
    """Return the integer value of a hex address string, else None.

    ``0x`` is optional, so a bare ``401000`` is an address. A bare word made
    only of hex letters (``add``, ``cafe``) is ambiguous; callers try it as a
    name first.
    """
    m = _HEX_RE.fullmatch(target.strip())
    return int(m.group(1), 16) if m else None


def validate_name(name: str) -> str:
    """Return *name* if it is an acceptable identifier, else raise."""
    if not NAME_RE.fullmatch(name):
        raise BackendError(
            f"Invalid name {name!r}: use an identifier (letters, digits, _ . : $ @ ? < > ~), "
            "starting with a letter or _, at most 200 characters.",
            "invalid_parameter",
        )
    return name


def clamp(value: Any, default: int, lo: int, hi: int, field: str) -> int:
    """Coerce an integer paging parameter into ``[lo, hi]``."""
    if value is None:
        return default
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise BackendError(
            f"{field} must be an integer, got {value!r}", "invalid_parameter"
        ) from None
    if n < lo:
        raise BackendError(f"{field} must be >= {lo}, got {n}", "invalid_parameter")
    return min(n, hi)


def page(items: Sequence[Any], offset: int, limit: int) -> dict[str, Any]:
    """One page of *items*, with what the caller needs to fetch the next one."""
    total = len(items)
    chunk = list(items[offset : offset + limit])
    end = offset + len(chunk)
    return {
        "total": total,
        "offset": offset,
        "returned": len(chunk),
        "next_offset": end if end < total else None,
        "items": chunk,
    }
