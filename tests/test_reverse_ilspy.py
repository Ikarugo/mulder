"""ILSpy backend (.NET), driven by a fake ilspycmd that copies real-shaped output."""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from mulder.reverse import backend as backend_mod
from mulder.reverse.backend import BackendError
from mulder.reverse.ilspy_backend import IlspyBackend, _parse_file, find_ilspycmd

FAKE = Path(__file__).parent / "fixtures" / "reverse" / "fake_ilspycmd.py"


def _dotnet_pe(path: Path) -> Path:
    head = bytearray(1024)
    head[:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x80)
    head[0x80:0x84] = b"PE\0\0"
    opt = 0x80 + 24
    struct.pack_into("<H", head, opt, 0x10B)
    struct.pack_into("<II", head, opt + 96 + 14 * 8, 0x2008, 0x48)
    path.write_bytes(bytes(head))
    return path


@pytest.fixture()
def opened(tmp_path: Path) -> tuple[IlspyBackend, Path]:
    b = IlspyBackend(str(FAKE))
    pdir = tmp_path / "proj"
    b.analyze(_dotnet_pe(tmp_path / "dropper.exe"), pdir, 60)
    return b, pdir


def test_find_ilspycmd_prefers_the_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MULDER_ILSPYCMD", str(FAKE))
    assert find_ilspycmd() == str(FAKE)
    monkeypatch.setenv("MULDER_ILSPYCMD", str(tmp_path / "missing"))
    assert find_ilspycmd() is None
    assert "ilspycmd was not found" in (IlspyBackend(None).check() or "") or find_ilspycmd()


def test_analyze_indexes_methods_and_references(opened: tuple[IlspyBackend, Path]) -> None:
    b, pdir = opened
    info = b.call(pdir, "info", {}, 10)
    assert info["functions"]["total"] == 6
    assert info["entry_points"][0]["name"] == "ToyDropper.Program::Main"
    assert info["references"] == ["System.Net.WebClient", "Microsoft.Win32.Registry"]
    names = [f["name"] for f in b.call(pdir, "list_functions", {}, 10)["items"]]
    assert "ToyDropper.Program::Decode" in names
    assert not any("Count" in n for n in names), "an expression-bodied property is not a method"


def test_decompile_method_and_type(opened: tuple[IlspyBackend, Path]) -> None:
    b, pdir = opened
    main = b.call(pdir, "decompile", {"target": "Program::Main"}, 10)
    assert main["code"].splitlines()[0].strip() == "private static void Main(string[] args)"
    assert main["code"].rstrip().endswith("}")
    assert main["callees"] == ["Beacon", "Decode", "Persist"]
    assert main["strings"][0]["value"].startswith("aHR0cDov")
    page = b.call(pdir, "decompile", {"target": "ToyDropper.Program", "limit": 10}, 10)
    assert page["total_lines"] > 30 and page["next_offset"] == 10


def test_il_of_a_method(opened: tuple[IlspyBackend, Path]) -> None:
    b, pdir = opened
    il = b.call(pdir, "disassemble", {"target": "Decode"}, 10)
    assert any("FromBase64String" in line for line in il["lines"])
    assert il["lines"][-1].strip().startswith("} // end of method Program::Decode")
    with pytest.raises(BackendError):
        b.call(pdir, "disassemble", {"target": "Persist"}, 10)


def test_xrefs_strings_imports_and_call_path(opened: tuple[IlspyBackend, Path]) -> None:
    b, pdir = opened
    xr = b.call(pdir, "xrefs", {"target": "Persist"}, 10)
    assert [r["from_function"] for r in xr["items"]] == ["ToyDropper.Program::Main"]
    assert "approximate" in xr
    run = b.call(pdir, "strings", {"query": "CurrentVersion"}, 10)["items"]
    assert run[0]["functions"] == ["ToyDropper.Program::Persist"]
    ua = b.call(pdir, "strings", {"query": "ToyAgent"}, 10)["items"]
    assert ua[0]["value"] == "ToyAgent/1.0 {braces}"
    imps = b.call(pdir, "imports", {"query": "kernel32"}, 10)["items"]
    assert imps[0]["name"] == "VirtualAlloc" and imps[0]["callers"] == [
        "ToyDropper.Program::Unused"
    ]
    path = b.call(pdir, "call_path", {"target": "Persist"}, 10)
    assert [p["name"] for p in path["path"]] == [
        "ToyDropper.Program::Main",
        "ToyDropper.Program::Persist",
    ]
    assert b.call(pdir, "call_path", {"target": "Unused"}, 10)["reachable"] is False


def test_annotations_are_recorded_not_applied(opened: tuple[IlspyBackend, Path]) -> None:
    b, pdir = opened
    r = b.call(pdir, "annotate", {"target": "Decode", "new_name": "decode_c2_url"}, 10)
    assert r["saved"] is False and "annotations.jsonl" in r["note"]
    assert b.call(pdir, "annotations", {}, 10)["total"] == 1
    with pytest.raises(BackendError):
        b.call(pdir, "annotate", {"target": "Decode", "new_name": "bad name"}, 10)


def test_ambiguous_and_missing_targets(opened: tuple[IlspyBackend, Path]) -> None:
    b, pdir = opened
    with pytest.raises(BackendError) as exc:
        b.call(pdir, "decompile", {"target": "Nope"}, 10)
    assert exc.value.error_type == "not_found"
    with pytest.raises(BackendError) as exc:
        b.call(pdir, "read_bytes", {"target": "Main"}, 10)
    assert exc.value.error_type == "invalid_parameter"
    raw = b.call(pdir, "read_bytes", {"target": "0x0", "length": 2}, 10)
    assert raw["hex"] == "4d5a"


def test_reopen_after_restart_uses_the_index(opened: tuple[IlspyBackend, Path]) -> None:
    _b, pdir = opened
    fresh = IlspyBackend(str(FAKE))
    assert not fresh.is_open(pdir)
    assert fresh.call(pdir, "list_functions", {"limit": 1}, 10)["total"] == 6
    again = fresh.analyze(Path(fresh._index(pdir).project_dir.parent / "dropper.exe"), pdir, 60)
    assert again["project_reused"] is True


def test_not_a_dotnet_file(tmp_path: Path) -> None:
    b = IlspyBackend(str(FAKE))
    native = tmp_path / "native.exe"
    native.write_bytes(b"MZ")
    with pytest.raises(BackendError) as exc:
        b.analyze(native, tmp_path / "p", 60)
    assert "managed metadata" in str(exc.value)
    with pytest.raises(BackendError) as exc:
        b.call(tmp_path / "p", "info", {}, 10)
    assert exc.value.error_type == "not_analyzed"


def test_parser_handles_nested_types_and_braces_in_strings() -> None:
    src = [
        "namespace A.B",
        "{",
        "\tpublic class Outer",
        "\t{",
        "\t\tprivate class Inner",
        "\t\t{",
        "\t\t\tpublic void Run()",
        "\t\t\t{",
        '\t\t\t\tstring s = "{ not a brace }";',
        "\t\t\t}",
        "\t\t}",
        "\t\tpublic abstract int Size();",
        "\t\tpublic Outer(int x)",
        "\t\t{",
        "\t\t}",
        "\t}",
        "}",
    ]
    methods, types = _parse_file("x.cs", src)
    assert [t["name"] for t in types] == ["A.B.Outer", "A.B.Outer.Inner"]
    assert [(m.full, m.start, m.end) for m in methods] == [
        ("A.B.Outer.Inner::Run", 6, 9),
        ("A.B.Outer::Size", 11, 11),
        ("A.B.Outer::Outer", 12, 14),
    ]


# -- tool routing -------------------------------------------------------------------


@pytest.fixture()
def dotnet_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    from mulder.server.app import _tool_dispatch_sync, init_server

    monkeypatch.setenv("MULDER_ILSPYCMD", str(FAKE))
    monkeypatch.delenv("MULDER_REVERSE_BACKEND", raising=False)
    monkeypatch.setitem(backend_mod._instances, "ilspy", IlspyBackend(str(FAKE)))
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    sample = _dotnet_pe(evidence / "dropper.exe")
    init_server(db_dir=tmp_path / "cases")
    assert (
        _tool_dispatch_sync["scan_evidence"](evidence_path=str(evidence), case_id="net")["status"]
        == "success"
    )
    yield sample


def _call(name: str, **kwargs: Any) -> dict[str, Any]:
    from mulder.server.app import _tool_dispatch_sync

    return _tool_dispatch_sync[name](**kwargs)  # type: ignore[no-any-return]


def test_dotnet_samples_go_to_ilspy_automatically(dotnet_case: Path) -> None:
    r = _call("reverse_analyze", file_path=str(dotnet_case))
    assert r["status"] == "success", r
    assert r["results"]["backend"] == "ilspy"
    assert r["results"]["project_dir"].endswith("/ilspy")
    assert "project_file" not in r["results"]
    d = _call("reverse_decompile", file_path=str(dotnet_case), target="Persist")
    assert "Registry.CurrentUser" in d["results"]["code"]
    assert d["results"]["indexed_source"] == "reverse.decompile"
    m = _call("reverse_map_sample", file_path=str(dotnet_case))
    assert m["status"] == "success", m


def test_orchestrator_routes_dotnet(dotnet_case: Path) -> None:
    from mulder.orchestrator.reverse_runner import choose_route

    route, note = choose_route("pe_dotnet")
    assert route == "disassembler" and "ILSpy" in note


def test_orchestrator_without_ilspy_triages_only(monkeypatch: pytest.MonkeyPatch) -> None:
    from mulder.orchestrator.reverse_runner import choose_route

    monkeypatch.setitem(backend_mod._instances, "ilspy", IlspyBackend(None))
    monkeypatch.setattr(IlspyBackend, "check", lambda self: "ilspycmd was not found")
    route, note = choose_route("pe_dotnet")
    assert route == "triage_only" and "not installed" in note
