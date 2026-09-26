"""radare2 backend: the same operations as Ghidra, through r2pipe.

Runs :mod:`mulder.reverse.radare2_worker` in a child process, with the
session management, timeouts, LRU eviction and protocol of
:class:`~mulder.reverse.ghidra_backend.GhidraBackend`. Decompilation needs
the r2ghidra plugin; without it ``decompile`` returns ``binary_missing``
instead of quietly falling back to assembly.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from pathlib import Path

from mulder.reverse.ghidra_backend import GhidraBackend

__all__ = ["Radare2Backend", "find_radare2"]


def find_radare2() -> str | None:
    """``MULDER_RADARE2`` or ``radare2``/``r2`` on PATH."""
    configured = os.environ.get("MULDER_RADARE2")
    if configured:
        return configured if Path(configured).exists() else None
    return shutil.which("radare2") or shutil.which("r2")


class Radare2Backend(GhidraBackend):
    """:class:`~mulder.reverse.backend.ReverseBackend` backed by radare2."""

    name = "radare2"
    project_marker = "mulder"  # radare2 project directory (dir.projects)
    engine_label = "radare2"
    worker_log = "radare2-worker.log"

    def __init__(self, max_sessions: int | None = None) -> None:
        super().__init__(ghidra_dir=Path("/nonexistent"), max_sessions=max_sessions)

    def check(self) -> str | None:
        if importlib.util.find_spec("r2pipe") is None:
            return "r2pipe is not installed: pip install r2pipe (or 'mulder[reverse]')."
        r2 = find_radare2()
        if r2 is None:
            return "radare2 was not found on PATH (or set MULDER_RADARE2)."
        # r2pipe starts "radare2"/"r2" from PATH: make sure the one found is first.
        os.environ["PATH"] = str(Path(r2).parent) + os.pathsep + os.environ.get("PATH", "")
        return None

    def _worker_argv(self, sample: Path, project_dir: Path, analysis_timeout: int) -> list[str]:
        return [
            sys.executable,
            "-m",
            "mulder.reverse.radare2_worker",
            "--sample",
            str(sample),
            "--project-dir",
            str(project_dir),
            "--analysis-timeout",
            str(analysis_timeout),
        ]
