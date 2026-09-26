"""GhidraBackend process management, tested against a fake worker.

The fake (``tests/fixtures/reverse/fake_ghidra_worker.py``) speaks the real
protocol, so these tests cover pagination pass-through, errors, timeouts
(the child must really be killed), LRU eviction, project reuse and
parameter validation without Ghidra or a JVM.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from mulder.reverse.backend import BackendError, BackendTimeout, BackendUnavailable
from mulder.reverse.ghidra_backend import (
    ANNOTATIONS_FILE,
    GhidraBackend,
    find_ghidra_dir,
    read_annotations,
)

FAKE = Path(__file__).parent / "fixtures" / "reverse" / "fake_ghidra_worker.py"


class FakeBackend(GhidraBackend):
    def check(self) -> str | None:
        return None

    def _worker_argv(self, sample: Path, project_dir: Path, analysis_timeout: int) -> list[str]:
        return [
            sys.executable,
            str(FAKE),
            "--sample",
            str(sample),
            "--project-dir",
            str(project_dir),
            "--analysis-timeout",
            str(analysis_timeout),
        ]


@pytest.fixture()
def backend() -> Iterator[FakeBackend]:
    b = FakeBackend(ghidra_dir=Path("/nonexistent"), max_sessions=2)
    yield b
    b.close()


def _sample(tmp_path: Path, name: str = "sample.exe") -> Path:
    p = tmp_path / name
    p.write_bytes(b"MZ" + b"\0" * 64)
    return p


def _open(b: GhidraBackend, tmp_path: Path, name: str = "sample.exe") -> Path:
    sample = _sample(tmp_path, name)
    pdir = tmp_path / "proj" / name
    b.analyze(sample, pdir, 30)
    return pdir


# -- discovery and availability ---------------------------------------------


def test_find_ghidra_dir_prefers_mulder_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MULDER_GHIDRA_DIR", str(tmp_path / "a"))
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path / "b"))
    assert find_ghidra_dir(tmp_path) == tmp_path / "a"


def test_find_ghidra_dir_falls_back_to_newest_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MULDER_GHIDRA_DIR", raising=False)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    for v in ("11.4.2", "12.1.4", "12.0"):
        (tmp_path / f"ghidra_{v}_PUBLIC").mkdir()
    assert find_ghidra_dir(tmp_path) == tmp_path / "ghidra_12.1.4_PUBLIC"
    assert find_ghidra_dir(tmp_path / "empty") is None
    (tmp_path / "ghidra" / "support").mkdir(parents=True)
    (tmp_path / "ghidra" / "support" / "launch.properties").write_text("")
    assert find_ghidra_dir(tmp_path) == tmp_path / "ghidra", "the Docker image layout wins"


def test_check_reports_missing_pyghidra(monkeypatch: pytest.MonkeyPatch) -> None:
    import mulder.reverse.ghidra_backend as gb

    monkeypatch.setattr(gb.importlib.util, "find_spec", lambda name: None)
    b = GhidraBackend(ghidra_dir=Path("/x"))
    reason = b.check()
    assert reason is not None and "pyghidra" in reason
    with pytest.raises(BackendUnavailable) as exc:
        b.analyze(Path("/x/s.exe"), Path("/x/p"), 10)
    assert exc.value.error_type == "binary_missing"


def test_check_reports_missing_install_and_java(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mulder.reverse.ghidra_backend as gb

    monkeypatch.setattr(gb.importlib.util, "find_spec", lambda name: object())
    assert "does not look like a Ghidra install" in (GhidraBackend(tmp_path).check() or "")
    (tmp_path / "support").mkdir()
    (tmp_path / "support" / "launch.properties").write_text("")
    monkeypatch.setattr(gb.shutil, "which", lambda name: None)
    monkeypatch.delenv("JAVA_HOME", raising=False)
    assert "Java" in (GhidraBackend(tmp_path).check() or "")


def test_maxmem_is_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MULDER_GHIDRA_MAXMEM", "8G")
    assert GhidraBackend(Path("/x")).maxmem == "8G"
    monkeypatch.setenv("MULDER_GHIDRA_MAXMEM", "8G -XX:+Evil")
    assert GhidraBackend(Path("/x")).maxmem == "4G"


# -- protocol --------------------------------------------------------------


def test_analyze_returns_startup_info_and_ignores_jvm_noise(
    backend: FakeBackend, tmp_path: Path
) -> None:
    sample = _sample(tmp_path)
    pdir = tmp_path / "proj"
    info = backend.analyze(sample, pdir, 30)
    assert info["program_name"] == "sample.exe"
    assert info["session_reused"] is False
    assert backend.is_open(pdir)
    # The noise went to the log, not into the protocol.
    assert "Picked up JAVA_TOOL_OPTIONS" in (pdir / "ghidra-worker.log").read_text()
    state = json.loads((pdir / "session.json").read_text())
    assert state["sample"] == str(sample)
    # A second analyze on a live session does not restart anything.
    again = backend.analyze(sample, pdir, 30)
    assert again["session_reused"] is True


def test_pagination_passes_through(backend: FakeBackend, tmp_path: Path) -> None:
    pdir = _open(backend, tmp_path)
    first = backend.call(pdir, "list_functions", {"offset": 0, "limit": 100}, 10)
    assert first["total"] == 250 and first["returned"] == 100 and first["next_offset"] == 100
    last = backend.call(pdir, "list_functions", {"offset": 200, "limit": 100}, 10)
    assert last["returned"] == 50 and last["next_offset"] is None
    dec = backend.call(pdir, "decompile", {"target": "main", "offset": 900, "limit": 400}, 10)
    assert dec["start_line"] == 900 and dec["next_offset"] is None
    assert dec["code"].count("\n") == 99


def test_worker_errors_keep_their_type(backend: FakeBackend, tmp_path: Path) -> None:
    pdir = _open(backend, tmp_path)
    with pytest.raises(BackendError) as exc:
        backend.call(pdir, "decompile", {"target": "missing"}, 10)
    assert exc.value.error_type == "not_found"
    # The session survives an ordinary error.
    assert backend.is_open(pdir)


def test_unknown_operation_and_parameters_are_refused(
    backend: FakeBackend, tmp_path: Path
) -> None:
    pdir = tmp_path / "never-opened"
    with pytest.raises(BackendError) as exc:
        backend.call(pdir, "run_script", {}, 10)
    assert exc.value.error_type == "invalid_parameter"
    with pytest.raises(BackendError) as exc:
        backend.call(pdir, "decompile", {"target": "main", "command": "x"}, 10)
    assert exc.value.error_type == "invalid_parameter"
    assert "command" in str(exc.value)


@pytest.mark.parametrize(
    "name", ["has space", "1starts_with_digit", "quote'", "a" * 201, "new\nline", ""]
)
def test_annotate_refuses_bad_names_before_reaching_the_engine(
    backend: FakeBackend, tmp_path: Path, name: str
) -> None:
    pdir = _open(backend, tmp_path)
    if not name:
        # An empty name means "no rename": the fake accepts a comment-only call.
        backend.call(pdir, "annotate", {"target": "0x401000", "comment": "c"}, 10)
        return
    with pytest.raises(BackendError) as exc:
        backend.call(pdir, "annotate", {"target": "main", "new_name": name}, 10)
    assert exc.value.error_type == "invalid_parameter"


def test_not_analyzed_without_a_project(backend: FakeBackend, tmp_path: Path) -> None:
    with pytest.raises(BackendError) as exc:
        backend.call(tmp_path / "nothing", "list_functions", {}, 10)
    assert exc.value.error_type == "not_analyzed"


# -- failure handling ----------------------------------------------------------


def test_timeout_kills_the_worker(backend: FakeBackend, tmp_path: Path) -> None:
    pdir = _open(backend, tmp_path)
    proc = backend._sessions[pdir].proc
    t0 = time.monotonic()
    with pytest.raises(BackendTimeout) as exc:
        backend.call(pdir, "decompile", {"target": "hang"}, 1)
    assert time.monotonic() - t0 < 10
    assert exc.value.error_type == "timeout"
    assert proc.poll() is not None, "the hung worker must be killed"
    assert not backend.is_open(pdir)
    # The project is on disk: the next call reopens it without re-analysis.
    backend.call(pdir, "list_functions", {"limit": 1}, 10)
    assert (pdir / "fake_analysis_count").read_text() == "1"


def test_crash_is_reported_with_the_log_tail(backend: FakeBackend, tmp_path: Path) -> None:
    pdir = _open(backend, tmp_path)
    with pytest.raises(BackendError) as exc:
        backend.call(pdir, "decompile", {"target": "crash"}, 10)
    assert exc.value.error_type == "backend_error"
    assert "exit code 3" in str(exc.value)
    assert "OutOfMemoryError" in str(exc.value)
    assert not backend.is_open(pdir)


def test_startup_timeout_kills_the_worker(backend: FakeBackend, tmp_path: Path) -> None:
    sample = _sample(tmp_path, "slow_start.exe")
    with pytest.raises(BackendTimeout):
        backend.analyze(sample, tmp_path / "p", 1)
    assert backend._sessions == {}


def test_startup_error_is_returned(backend: FakeBackend, tmp_path: Path) -> None:
    sample = _sample(tmp_path, "bad_start.exe")
    with pytest.raises(BackendError) as exc:
        backend.analyze(sample, tmp_path / "p", 10)
    assert "no loader" in str(exc.value)
    assert backend._sessions == {}


# -- sessions ----------------------------------------------------------------------


def test_lru_eviction_bounds_live_workers(tmp_path: Path) -> None:
    b = FakeBackend(ghidra_dir=Path("/x"), max_sessions=2)
    try:
        a = _open(b, tmp_path, "a.exe")
        c = _open(b, tmp_path, "c.exe")
        proc_a = b._sessions[a].proc
        b.call(c, "info", {}, 10)  # c is now the most recent
        b.call(a, "info", {}, 10)  # ... and now a
        proc_c = b._sessions[c].proc
        d = _open(b, tmp_path, "d.exe")
        assert set(b._sessions) == {a, d}
        assert proc_c.wait(timeout=10) is not None
        assert proc_a.poll() is None
        # The evicted project reopens transparently, without re-analysis.
        b.call(c, "info", {}, 10)
        assert (c / "fake_analysis_count").read_text() == "1"
        assert len(b._sessions) == 2
    finally:
        b.close()


def test_close_all_stops_every_worker(tmp_path: Path) -> None:
    b = FakeBackend(ghidra_dir=Path("/x"), max_sessions=3)
    _open(b, tmp_path, "a.exe")
    _open(b, tmp_path, "b.exe")
    procs = [s.proc for s in b._sessions.values()]
    b.close()
    assert all(p.poll() is not None for p in procs)
    assert b._sessions == {}


def test_concurrent_calls_on_one_session_are_serialised(
    backend: FakeBackend, tmp_path: Path
) -> None:
    pdir = _open(backend, tmp_path)
    results: list[str] = []
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        try:
            r = backend.call(pdir, "decompile", {"target": "slowfn", "offset": i}, 20)
            results.append(r["code"].split("\n")[0])
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert sorted(results) == [f"// line {i}" for i in range(4)]


# -- annotations -------------------------------------------------------------------


def test_annotations_are_recorded_beside_the_project(backend: FakeBackend, tmp_path: Path) -> None:
    pdir = _open(backend, tmp_path)
    r = backend.call(
        pdir, "annotate", {"target": "0x401000", "new_name": "decode_config", "comment": "XOR"}, 10
    )
    assert r["new_name"] == "decode_config"
    rows = [json.loads(x) for x in (pdir / ANNOTATIONS_FILE).read_text().splitlines()]
    assert rows[0]["old_name"] == "FUN_00401000"
    assert rows[0]["new_name"] == "decode_config"
    assert rows[0]["backend"] == "ghidra"
    backend.close()
    # Reading the history needs no worker.
    hist = backend.call(pdir, "annotations", {}, 10)
    assert hist["total"] == 1
    assert not backend.is_open(pdir)


def test_read_annotations_tolerates_a_damaged_line(tmp_path: Path) -> None:
    (tmp_path / ANNOTATIONS_FILE).write_text('{"new_name": "a"}\nnot json\n\n')
    r = read_annotations(tmp_path)
    assert r["total"] == 1 and r["unreadable_lines"] == 1
    assert read_annotations(tmp_path / "none")["total"] == 0
