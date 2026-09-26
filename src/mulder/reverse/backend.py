"""Backend-neutral interface for the reverse-engineering tools.

Every backend answers the operations below with plain JSON-able dicts of
the same shape. The MCP layer only ever sees this interface, so adding
radare2 next to Ghidra is a matter of implementing it once more.

Addressing convention shared by every operation that takes a ``target``:
a function or symbol name (``main``, ``CreateRemoteThread``), or a hex
address with or without ``0x`` (``0x140001550``). Addresses in results are
always ``0x``-prefixed lowercase hex strings.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "BackendError",
    "BackendTimeout",
    "BackendUnavailable",
    "MAX_BYTES",
    "MAX_DECOMPILE_LINES",
    "MAX_DISASM_INSTRUCTIONS",
    "MAX_PAGE",
    "ReverseBackend",
    "available_backends",
    "get_backend",
    "project_dir_for",
    "register_backend",
    "sample_sha256",
]

# Hard ceilings on a single page of output. The agent pages with
# ``offset`` rather than receiving a whole binary in one response: a
# decompiled function can run to thousands of lines, and every line that
# reaches the model is paid for in tokens.
MAX_PAGE = 200
MAX_DECOMPILE_LINES = 400
MAX_DISASM_INSTRUCTIONS = 400
MAX_BYTES = 4096


class BackendError(Exception):
    """An operation failed inside the backend (bad target, engine error)."""

    def __init__(self, message: str, error_type: str = "backend_error") -> None:
        super().__init__(message)
        self.error_type = error_type


class BackendUnavailable(BackendError):
    """The engine is not installed or cannot start."""

    def __init__(self, message: str) -> None:
        super().__init__(message, "binary_missing")


class BackendTimeout(BackendError):
    """The engine did not answer in time; its session was torn down."""

    def __init__(self, message: str) -> None:
        super().__init__(message, "timeout")


@runtime_checkable
class ReverseBackend(Protocol):
    """Operations every reverse-engineering backend implements."""

    name: str

    def check(self) -> str | None:
        """Return ``None`` when usable, else a human-readable reason."""

    def analyze(self, sample: Path, project_dir: Path, timeout_s: float) -> dict[str, Any]:
        """Load and auto-analyse *sample*; reuse an existing project if present."""

    def is_open(self, project_dir: Path) -> bool:
        """Return True when a live session exists for *project_dir*."""

    def call(
        self, project_dir: Path, op: str, params: dict[str, Any], timeout_s: float
    ) -> dict[str, Any]:
        """Run one read or annotate operation against an analysed sample."""

    def close(self, project_dir: Path | None = None) -> None:
        """Close one session, or every session when *project_dir* is None."""


#: Operations a backend's ``call`` must accept, with the parameters the MCP
#: layer sends. Kept here so a second backend has one list to implement.
OPERATIONS: dict[str, tuple[str, ...]] = {
    "info": (),
    "list_functions": (
        "query",
        "origin",
        "include_library",
        "include_thunks",
        "sort",
        "offset",
        "limit",
    ),
    "decompile": ("target", "offset", "limit"),
    "disassemble": ("target", "offset", "limit"),
    "xrefs": ("target", "direction", "offset", "limit"),
    "strings": ("query", "min_length", "offset", "limit"),
    "imports": ("query", "offset", "limit"),
    "read_bytes": ("target", "length"),
    "annotate": ("target", "new_name", "comment"),
    "annotations": (),
}

_registry: dict[str, type] = {}
_instances: dict[str, ReverseBackend] = {}


def register_backend(name: str, cls: type) -> None:
    """Register a backend class under *name* (``ghidra``, ``radare2``)."""
    _registry[name] = cls


def available_backends() -> list[str]:
    """Names of every registered backend, installed or not."""
    _ensure_builtin()
    return sorted(_registry)


def get_backend(name: str) -> ReverseBackend:
    """Return the process-wide instance of backend *name*."""
    _ensure_builtin()
    if name not in _registry:
        raise BackendError(
            f"Unknown reverse-engineering backend {name!r}; "
            f"available: {', '.join(sorted(_registry))}",
            "invalid_parameter",
        )
    if name not in _instances:
        _instances[name] = _registry[name]()
    return _instances[name]


def _ensure_builtin() -> None:
    if "ghidra" not in _registry:
        from mulder.reverse.ghidra_backend import GhidraBackend

        register_backend("ghidra", GhidraBackend)


def sample_sha256(path: Path) -> str:
    """SHA-256 of *path*, streamed."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def project_dir_for(root: Path, case_id: str, backend: str, sample: Path, sha256: str) -> Path:
    """Directory holding the backend project for one sample of one case.

    Keyed by content hash, so the same sample copied to two paths shares a
    project, and two different samples with the same file name do not.
    """
    safe_case = _SAFE_RE.sub("_", case_id) or "case"
    safe_name = (_SAFE_RE.sub("_", sample.name) or "sample")[:48]
    return root / "reverse" / safe_case / f"{sha256[:16]}_{safe_name}" / backend
