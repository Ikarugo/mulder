"""Server-side half of the Ghidra backend: one worker process per sample.

The MCP server never loads Ghidra itself. Each analysed sample gets a child
process (:mod:`mulder.reverse.ghidra_worker`) that owns a JVM and the
program, and answers JSON requests on its stdin/stdout. If the JVM crashes,
runs out of memory or hangs, the child is killed and the tool returns an
error; the server keeps running.

Sessions are keyed by project directory. At most ``MULDER_REVERSE_MAX_SESSIONS``
(default 2) live at once: opening another closes the least recently used
idle one, which only costs a JVM start the next time it is needed, since
the analysed project stays on disk.
"""

from __future__ import annotations

import atexit
import contextlib
import importlib.util
import json
import logging
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import IO, Any

from mulder.reverse.backend import (
    OPERATIONS,
    BackendError,
    BackendTimeout,
    BackendUnavailable,
)
from mulder.reverse.protocol import validate_name

__all__ = ["GhidraBackend", "find_ghidra_dir"]

logger = logging.getLogger(__name__)

WORKER_LOG = "ghidra-worker.log"
SESSION_FILE = "session.json"
ANNOTATIONS_FILE = "annotations.jsonl"
ANALYSIS_STATE_FILE = "analysis.json"
PROJECT_FILE = "mulder.gpr"

_DEFAULT_MAX_SESSIONS = 2
_DEFAULT_MAXMEM = "4G"
_MAXMEM_RE = re.compile(r"[1-9][0-9]{0,5}[mMgG]")
#: JVM start plus project open, on top of the auto-analysis budget.
_STARTUP_MARGIN_S = 90
_REOPEN_TIMEOUT_S = 180
_SHUTDOWN_GRACE_S = 5.0
_LOG_TAIL_LINES = 15
_ANNOTATIONS_SHOWN = 200
_EOF = object()


def find_ghidra_dir(search_root: Path = Path("/opt")) -> Path | None:
    """Ghidra install: ``MULDER_GHIDRA_DIR``, ``GHIDRA_INSTALL_DIR``, ``/opt/ghidra``
    (the Docker image), then the newest ``/opt/ghidra_<version>_PUBLIC``."""
    for var in ("MULDER_GHIDRA_DIR", "GHIDRA_INSTALL_DIR"):
        value = os.environ.get(var)
        if value:
            return Path(value)
    if (search_root / "ghidra" / "support" / "launch.properties").is_file():
        return search_root / "ghidra"
    candidates = [p for p in search_root.glob("ghidra_*_PUBLIC") if p.is_dir()]

    def version_key(p: Path) -> tuple[int, ...]:
        m = re.match(r"ghidra_([\d.]+)_PUBLIC", p.name)
        return tuple(int(x) for x in m.group(1).split(".") if x) if m else ()

    return max(candidates, key=version_key) if candidates else None


def _log_tail(path: Path, lines: int = _LOG_TAIL_LINES) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    kept = [ln for ln in text.splitlines() if ln.strip()][-lines:]
    return "\n".join(kept)


class _Session:
    """One live worker process and the plumbing to talk to it."""

    def __init__(self, proc: subprocess.Popen[str], project_dir: Path, log_path: Path) -> None:
        self.proc = proc
        self.project_dir = project_dir
        self.log_path = log_path
        self.lock = threading.Lock()
        self.next_id = 1
        self.info: dict[str, Any] = {}
        self._queue: queue.Queue[object] = queue.Queue()
        self._reader = threading.Thread(
            target=self._read, name=f"ghidra-reader-{project_dir.name}", daemon=True
        )
        self._reader.start()

    def _read(self) -> None:
        stream = self.proc.stdout
        assert stream is not None
        for line in stream:
            line = line.strip()
            if not line:
                continue
            try:
                self._queue.put(json.loads(line))
            except ValueError:
                logger.debug("ghidra worker: ignored non-JSON line %r", line[:200])
        self._queue.put(_EOF)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def wait_for(self, rid: int, timeout_s: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_s
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            try:
                msg = self._queue.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError from None
            if msg is _EOF:
                code = self.proc.wait(timeout=5)
                tail = _log_tail(self.log_path)
                raise BackendError(
                    f"The engine worker stopped (exit code {code}). "
                    f"Last log lines ({self.log_path}):\n{tail}",
                    "backend_error",
                )
            if isinstance(msg, dict) and msg.get("id") == rid:
                return msg

    def send(self, msg: dict[str, Any]) -> None:
        stream = self.proc.stdin
        assert stream is not None
        try:
            stream.write(json.dumps(msg) + "\n")
            stream.flush()
        except (BrokenPipeError, OSError) as exc:
            raise BackendError(
                f"The engine worker is gone ({exc}). Last log lines:\n{_log_tail(self.log_path)}",
                "backend_error",
            ) from exc

    def kill(self) -> None:
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                self.proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.proc.wait(timeout=5)
        for stream in (self.proc.stdin, self.proc.stdout):
            with contextlib.suppress(OSError):
                if stream is not None:
                    stream.close()

    def shutdown(self) -> None:
        if self.proc.poll() is None:
            with contextlib.suppress(BackendError, OSError):
                self.send({"id": -1, "op": "shutdown"})
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.proc.wait(timeout=_SHUTDOWN_GRACE_S)
        self.kill()


def _unwrap(msg: dict[str, Any]) -> dict[str, Any]:
    if msg.get("ok"):
        result = msg.get("result")
        return result if isinstance(result, dict) else {"value": result}
    err = msg.get("error") or {}
    raise BackendError(
        str(err.get("message") or "unknown worker error"),
        str(err.get("type") or "backend_error"),
    )


class GhidraBackend:
    """:class:`~mulder.reverse.backend.ReverseBackend` backed by headless Ghidra."""

    name = "ghidra"
    #: File or directory whose presence means the analysed project is on disk.
    project_marker = PROJECT_FILE
    #: What engine the log messages name.
    engine_label = "Ghidra"
    worker_log = WORKER_LOG

    def __init__(
        self,
        ghidra_dir: Path | None = None,
        max_sessions: int | None = None,
        maxmem: str | None = None,
    ) -> None:
        self.ghidra_dir = ghidra_dir if ghidra_dir is not None else find_ghidra_dir()
        env_max = os.environ.get("MULDER_REVERSE_MAX_SESSIONS", "")
        self.max_sessions = max(
            1,
            max_sessions
            if max_sessions is not None
            else int(env_max)
            if env_max.isdigit()
            else _DEFAULT_MAX_SESSIONS,
        )
        mem = maxmem or os.environ.get("MULDER_GHIDRA_MAXMEM") or _DEFAULT_MAXMEM
        self.maxmem = mem if _MAXMEM_RE.fullmatch(mem) else _DEFAULT_MAXMEM
        self._sessions: OrderedDict[Path, _Session] = OrderedDict()
        self._lock = threading.Lock()
        self._starting: dict[Path, threading.Lock] = {}
        atexit.register(self.close)

    # -- availability ------------------------------------------------------

    def check(self) -> str | None:
        if importlib.util.find_spec("pyghidra") is None:
            return (
                "pyghidra is not installed. Install it from the wheel shipped with "
                "Ghidra (<ghidra>/Ghidra/Features/PyGhidra/pypkg/dist/) or with "
                "pip install 'mulder[reverse]'."
            )
        if self.ghidra_dir is None:
            return (
                "Ghidra was not found: set MULDER_GHIDRA_DIR (or GHIDRA_INSTALL_DIR) "
                "or install it under /opt/ghidra_<version>_PUBLIC."
            )
        if not (self.ghidra_dir / "support" / "launch.properties").is_file():
            return f"{self.ghidra_dir} does not look like a Ghidra install (no support/)."
        java_home = os.environ.get("JAVA_HOME")
        if not shutil.which("java") and not (
            java_home and (Path(java_home) / "bin" / "java").exists()
        ):
            return "Java was not found (Ghidra 12 needs a JDK 21 on PATH or in JAVA_HOME)."
        return None

    def _worker_argv(self, sample: Path, project_dir: Path, analysis_timeout: int) -> list[str]:
        assert self.ghidra_dir is not None
        return [
            sys.executable,
            "-m",
            "mulder.reverse.ghidra_worker",
            "--sample",
            str(sample),
            "--project-dir",
            str(project_dir),
            "--ghidra-dir",
            str(self.ghidra_dir),
            "--analysis-timeout",
            str(analysis_timeout),
            "--maxmem",
            self.maxmem,
        ]

    # -- sessions -----------------------------------------------------------

    def is_open(self, project_dir: Path) -> bool:
        with self._lock:
            sess = self._sessions.get(project_dir)
            return sess is not None and sess.alive()

    def has_project(self, project_dir: Path) -> bool:
        """True when a finished analysis for this project is on disk."""
        return (project_dir / SESSION_FILE).is_file() and (
            project_dir / self.project_marker
        ).exists()

    def _evict_for_new(self) -> None:
        """Close idle least-recently-used sessions until one slot is free."""
        victims: list[_Session] = []
        with self._lock:
            for key in list(self._sessions):
                if len(self._sessions) - len(victims) < self.max_sessions:
                    break
                sess = self._sessions[key]
                if sess.lock.acquire(blocking=False):
                    victims.append(sess)
                    del self._sessions[key]
        for sess in victims:
            logger.info("Closing idle Ghidra session %s (session limit)", sess.project_dir)
            try:
                sess.shutdown()
            finally:
                sess.lock.release()

    def _start_lock(self, project_dir: Path) -> threading.Lock:
        with self._lock:
            return self._starting.setdefault(project_dir, threading.Lock())

    def analyze(self, sample: Path, project_dir: Path, timeout_s: float) -> dict[str, Any]:
        reason = self.check()
        if reason:
            raise BackendUnavailable(reason)
        with self._start_lock(project_dir):
            with self._lock:
                existing = self._sessions.get(project_dir)
            if existing is not None and existing.alive():
                info = self._request(existing, "info", {}, max(30.0, timeout_s))
                info["session_reused"] = True
                return info
            if existing is not None:
                self._drop(project_dir)
            return self._spawn(sample, project_dir, timeout_s)

    def _spawn(self, sample: Path, project_dir: Path, timeout_s: float) -> dict[str, Any]:
        self._evict_for_new()
        project_dir.mkdir(parents=True, exist_ok=True)
        analysis_timeout = max(30, int(timeout_s) - _STARTUP_MARGIN_S)
        log_path = project_dir / self.worker_log
        log: IO[str] = log_path.open("a", encoding="utf-8")
        log.write(f"\n=== worker start {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
        log.flush()
        env = dict(os.environ)
        env.setdefault("PYTHONUNBUFFERED", "1")
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                self._worker_argv(sample, project_dir, analysis_timeout),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=log,
                text=True,
                encoding="utf-8",
                bufsize=1,
                start_new_session=True,
                env=env,
                cwd=str(project_dir),
            )
        except OSError as exc:
            log.close()
            raise BackendUnavailable(f"Cannot start the Ghidra worker: {exc}") from exc
        log.close()
        sess = _Session(proc, project_dir, log_path)
        try:
            first = sess.wait_for(0, timeout_s)
        except TimeoutError:
            sess.kill()
            raise BackendTimeout(
                f"{self.engine_label} did not finish loading and analysing {sample.name} within "
                f"{int(timeout_s)} s; the worker was stopped. Last log lines:\n"
                f"{_log_tail(log_path)}"
            ) from None
        except BackendError:
            sess.kill()
            raise
        try:
            info = _unwrap(first)
        except BackendError:
            sess.kill()
            raise
        sess.info = info
        with self._lock:
            self._sessions[project_dir] = sess
            self._sessions.move_to_end(project_dir)
        state = {
            "sample": str(sample),
            "sha256": info.get("sha256"),
            "program_name": info.get("program_name"),
            "backend": self.name,
        }
        (project_dir / SESSION_FILE).write_text(json.dumps(state, indent=2), encoding="utf-8")
        info["session_reused"] = False
        return info

    def _drop(self, project_dir: Path) -> None:
        with self._lock:
            sess = self._sessions.pop(project_dir, None)
        if sess is not None:
            sess.kill()

    def _request(
        self, sess: _Session, op: str, params: dict[str, Any], timeout_s: float
    ) -> dict[str, Any]:
        with sess.lock:
            if not sess.alive():
                self._drop(sess.project_dir)
                raise BackendError(
                    f"The {self.engine_label} worker for this sample has stopped; call "
                    f"reverse_analyze again. Last log lines:\n{_log_tail(sess.log_path)}",
                    "backend_error",
                )
            rid = sess.next_id
            sess.next_id += 1
            sess.send({"id": rid, "op": op, "params": params})
            try:
                msg = sess.wait_for(rid, timeout_s)
            except TimeoutError:
                with self._lock:
                    if self._sessions.get(sess.project_dir) is sess:
                        del self._sessions[sess.project_dir]
                sess.kill()
                raise BackendTimeout(
                    f"{self.engine_label} did not answer '{op}' within {int(timeout_s)} s; "
                    "its session was stopped (the analysed project is kept and reopens on "
                    "the next call)."
                ) from None
            except BackendError:
                self._drop(sess.project_dir)
                raise
        with self._lock:
            if self._sessions.get(sess.project_dir) is sess:
                self._sessions.move_to_end(sess.project_dir)
        return _unwrap(msg)

    def _session_for(self, project_dir: Path) -> _Session:
        with self._lock:
            sess = self._sessions.get(project_dir)
        if sess is not None and sess.alive():
            return sess
        if sess is not None:
            self._drop(project_dir)
        if not self.has_project(project_dir):
            raise BackendError(
                "This sample has not been analysed yet: call reverse_analyze first.",
                "not_analyzed",
            )
        # Analysed earlier (server restart, or the session was evicted):
        # reopen the saved project. The worker does not analyse it again.
        try:
            state = json.loads((project_dir / SESSION_FILE).read_text(encoding="utf-8"))
            sample = Path(str(state["sample"]))
        except (OSError, ValueError, KeyError) as exc:
            raise BackendError(
                f"Cannot reopen the project in {project_dir}: {exc}. Call reverse_analyze again.",
                "not_analyzed",
            ) from exc
        self.analyze(sample, project_dir, _REOPEN_TIMEOUT_S)
        with self._lock:
            reopened = self._sessions.get(project_dir)
        if reopened is None:
            raise BackendError("The Ghidra session could not be reopened", "backend_error")
        return reopened

    # -- operations ---------------------------------------------------------

    def call(
        self, project_dir: Path, op: str, params: dict[str, Any], timeout_s: float
    ) -> dict[str, Any]:
        if op not in OPERATIONS:
            raise BackendError(f"Unknown operation {op!r}", "invalid_parameter")
        unknown = set(params) - set(OPERATIONS[op])
        if unknown:
            raise BackendError(
                f"Unexpected parameter(s) for {op}: {', '.join(sorted(unknown))}",
                "invalid_parameter",
            )
        clean = {k: v for k, v in params.items() if v is not None}
        if op == "annotations":
            return read_annotations(project_dir)
        if op == "annotate" and clean.get("new_name"):
            validate_name(str(clean["new_name"]))
        sess = self._session_for(project_dir)
        result = self._request(sess, op, clean, timeout_s)
        if op == "annotate":
            append_annotation(project_dir, self.name, result)
        return result

    def close(self, project_dir: Path | None = None) -> None:
        with self._lock:
            if project_dir is None:
                sessions = list(self._sessions.values())
                self._sessions.clear()
            else:
                one = self._sessions.pop(project_dir, None)
                sessions = [one] if one is not None else []
        for sess in sessions:
            sess.shutdown()


def append_annotation(project_dir: Path, backend: str, result: dict[str, Any]) -> None:
    """Record one annotation in ``annotations.jsonl`` beside the project.

    The file is engine-neutral so the annotations can later be replayed in
    another tool (radare2 today, the Ghidra GUI from a radare2 run).
    """
    row = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "backend": backend,
        "address": result.get("address"),
        "function": result.get("function"),
        "old_name": result.get("old_name"),
        "new_name": result.get("new_name"),
        "comment": result.get("comment"),
    }
    path = project_dir / ANNOTATIONS_FILE
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


def read_annotations(project_dir: Path) -> dict[str, Any]:
    """Every annotation recorded for this project, oldest first."""
    path = project_dir / ANNOTATIONS_FILE
    rows: list[dict[str, Any]] = []
    unreadable = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        lines = []
    for line in lines:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            unreadable += 1
            continue
        if isinstance(row, dict):
            rows.append(row)
    result: dict[str, Any] = {
        "total": len(rows),
        "annotations": rows[-_ANNOTATIONS_SHOWN:],
        "file": str(path),
    }
    if len(rows) > _ANNOTATIONS_SHOWN:
        result["shown"] = _ANNOTATIONS_SHOWN
        result["note"] = (
            f"Only the {_ANNOTATIONS_SHOWN} most recent annotations are shown; "
            f"the full history is in {path}."
        )
    if unreadable:
        result["unreadable_lines"] = unreadable
    return result
