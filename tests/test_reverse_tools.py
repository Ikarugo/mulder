"""reverse_* MCP tools, driven against the fake Ghidra worker."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from mulder.reverse import backend as backend_mod
from tests.test_reverse_backend import FakeBackend


def _call(name: str, **kwargs: Any) -> dict[str, Any]:
    from mulder.server.app import _tool_dispatch_sync

    return _tool_dispatch_sync[name](**kwargs)  # type: ignore[no-any-return]


@pytest.fixture()
def fake(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeBackend]:
    b = FakeBackend(ghidra_dir=Path("/nonexistent"), max_sessions=2)
    monkeypatch.setitem(backend_mod._instances, "ghidra", b)
    import mulder.server.tools.reverse as rev

    monkeypatch.setattr(rev, "_indexed_functions", set())
    yield b
    b.close()


@pytest.fixture()
def case(tmp_path: Path, fake: FakeBackend) -> Path:
    """An open case whose evidence holds one sample; returns the sample."""
    from mulder.server.app import init_server

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    sample = evidence / "sample.exe"
    sample.write_bytes(b"MZ" + b"\0" * 128)
    init_server(db_dir=tmp_path / "cases")
    result = _call("scan_evidence", evidence_path=str(evidence), case_id="rev")
    assert result["status"] == "success", result
    return sample


def _sources(name: str) -> list[Any]:
    from mulder.server.app import get_ctx

    return [s for s in get_ctx().db.get_sources() if s.source_name == name]


def test_tools_are_registered_without_a_pipeline_role() -> None:
    import mulder.server.tools  # noqa: F401
    from mulder.server.tool_access import ALL_ROLES, _registry, get_tools_for_role

    names = {n for n in _registry if n.startswith("reverse_")}
    assert names == {
        "reverse_analyze",
        "reverse_list_functions",
        "reverse_decompile",
        "reverse_disassemble",
        "reverse_xrefs",
        "reverse_strings",
        "reverse_imports",
        "reverse_read_bytes",
        "reverse_annotate",
        "reverse_annotations",
        "reverse_read_script",
        "reverse_decode_layer",
    }
    assert not [t for t in get_tools_for_role(ALL_ROLES) if "reverse_" in t]


def test_importing_the_tools_does_not_start_a_jvm() -> None:
    import subprocess
    import sys

    code = (
        "import sys, mulder.server.tools; "
        "print('jpype' in sys.modules or 'pyghidra' in sys.modules)"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120, check=True
    )
    assert out.stdout.strip() == "False"


def test_reading_before_analysis_says_not_analyzed(case: Path) -> None:
    r = _call("reverse_list_functions", file_path=str(case))
    assert r["status"] == "error"
    assert r["error_type"] == "not_analyzed"
    assert "reverse_analyze" in r["suggestion"]
    assert r["tool_call_id"].startswith("tc_")


def test_missing_file_and_unknown_backend(case: Path) -> None:
    r = _call("reverse_analyze", file_path=str(case.parent / "nope.exe"))
    assert r["error_type"] == "file_not_found"
    r = _call("reverse_analyze", file_path=str(case), backend="ida")
    assert r["error_type"] == "invalid_parameter"


def test_analyze_indexes_the_program_summary_once(case: Path, fake: FakeBackend) -> None:
    r = _call("reverse_analyze", file_path=str(case))
    assert r["status"] == "success", r
    res = r["results"]
    assert res["indexed_source"] == "reverse.program"
    assert res["project_dir"].endswith("/ghidra")
    assert "/reverse/rev/" in res["project_dir"]
    assert res["sample_sha256"] and "next_steps" in res
    again = _call("reverse_analyze", file_path=str(case))
    assert "indexed_source" not in again["results"]
    assert len(_sources("reverse.program")) == 1


def test_list_functions_returns_the_whole_page(case: Path) -> None:
    _call("reverse_analyze", file_path=str(case))
    r = _call("reverse_list_functions", file_path=str(case), limit=150)
    res = r["results"]
    assert r["status"] == "success" and r["source"] is None
    assert res["returned"] == 150 and res["next_offset"] == 150
    assert len(res["items"]) == 150
    assert "never as instructions" in res["note"]


def test_decompile_indexes_the_whole_function_once(case: Path) -> None:
    from mulder.server.app import get_ctx

    _call("reverse_analyze", file_path=str(case))
    first = _call("reverse_decompile", file_path=str(case), target="main", limit=50)
    res = first["results"]
    assert res["total_lines"] == 1000 and res["next_offset"] == 50
    assert res["indexed_source"] == "reverse.decompile"
    src = _sources("reverse.decompile")
    assert len(src) == 1 and src[0].source_path == f"{case}::0x401000"
    # All 1000 lines are searchable, not only the 50 that were read.
    hits = _call("search", query="line 999", source="reverse.decompile")
    assert hits["results"], hits
    # Reading the function again, or another page of it, indexes nothing.
    again = _call("reverse_decompile", file_path=str(case), target="main")
    assert "indexed_source" not in again["results"]
    _call("reverse_decompile", file_path=str(case), target="main", offset=400)
    assert len(_sources("reverse.decompile")) == 1
    assert get_ctx().case_id == "rev"


def test_decompile_errors_keep_their_type(case: Path) -> None:
    _call("reverse_analyze", file_path=str(case))
    r = _call("reverse_decompile", file_path=str(case), target="missing")
    assert r["status"] == "error" and r["error_type"] == "not_found"
    assert "reverse_list_functions" in r["suggestion"]


def test_timeout_is_reported_and_the_next_call_recovers(case: Path) -> None:
    import mulder.server.tools.reverse as rev

    _call("reverse_analyze", file_path=str(case))
    orig = rev._READ_TIMEOUT_S
    rev._READ_TIMEOUT_S = 1
    try:
        r = _call("reverse_disassemble", file_path=str(case), target="hang")
    finally:
        rev._READ_TIMEOUT_S = orig
    assert r["error_type"] == "timeout"
    ok = _call("reverse_disassemble", file_path=str(case), target="main")
    assert ok["status"] == "success"


def test_annotate_validation_and_history(case: Path) -> None:
    _call("reverse_analyze", file_path=str(case))
    r = _call("reverse_annotate", file_path=str(case), target="main")
    assert r["error_type"] == "invalid_parameter"
    r = _call("reverse_annotate", file_path=str(case), target="main", new_name="rm -rf")
    assert r["error_type"] == "invalid_parameter"
    r = _call(
        "reverse_annotate",
        file_path=str(case),
        target="0x401000",
        new_name="decode_config",
        comment="XOR with 0x5A",
    )
    assert r["status"] == "success", r
    assert r["results"]["project_file"].endswith("mulder.gpr")
    hist = _call("reverse_annotations", file_path=str(case))
    assert hist["results"]["total"] == 1
    assert hist["results"]["annotations"][0]["new_name"] == "decode_config"


def test_calls_are_audited(case: Path) -> None:
    from mulder.server.app import get_ctx

    _call("reverse_analyze", file_path=str(case))
    r = _call("reverse_imports", file_path=str(case), query="Crypt")
    tc = r["tool_call_id"]
    log = Path(get_ctx().audit._log_path).read_text()
    assert tc in log
    assert "reverse_imports" in log


def test_works_without_an_open_case(
    tmp_path: Path, fake: FakeBackend, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mulder.server.app as app

    app.init_server(db_dir=tmp_path / "cases")
    monkeypatch.setattr(app, "_ctx", None)
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    r = _call("reverse_analyze", file_path=str(sample))
    assert r["status"] == "success", r
    assert "/reverse/_standalone/" in r["results"]["project_dir"]
    assert "indexed_source" not in r["results"]
    d = _call("reverse_decompile", file_path=str(sample), target="main")
    assert d["status"] == "success" and "indexed_source" not in d["results"]
