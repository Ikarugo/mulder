"""Reverse-engineering backends for static analysis of a single sample.

The MCP tools in :mod:`mulder.server.tools.reverse` talk to a
:class:`~mulder.reverse.backend.ReverseBackend`. The backend owns the
disassembler/decompiler (Ghidra today, radare2 later) and every backend
answers the same operations with the same JSON shapes, so the tools, the
prompts and the phases never depend on which engine produced the answer.
"""

from mulder.reverse.backend import (
    BackendError,
    BackendUnavailable,
    ReverseBackend,
    available_backends,
    get_backend,
    project_dir_for,
    sample_sha256,
)

__all__ = [
    "BackendError",
    "BackendUnavailable",
    "ReverseBackend",
    "available_backends",
    "get_backend",
    "project_dir_for",
    "sample_sha256",
]
