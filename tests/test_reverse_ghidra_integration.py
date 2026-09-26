"""End-to-end check of the Ghidra backend on the harmless toy sample.

Skipped unless Ghidra, pyghidra, Java and mingw-w64 are all present. The
sample is compiled from ``tests/fixtures/reverse/toy_beacon.c``; it only
prints text and its "C2" uses the reserved ``.invalid`` TLD.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from mulder.reverse.ghidra_backend import GhidraBackend

SOURCE = Path(__file__).parent / "fixtures" / "reverse" / "toy_beacon.c"
MINGW = "x86_64-w64-mingw32-gcc"

_backend = GhidraBackend()
_reason = _backend.check() or (None if shutil.which(MINGW) else f"{MINGW} not installed")

pytestmark = pytest.mark.skipif(_reason is not None, reason=f"Ghidra integration: {_reason}")


def _compile(out: Path, strip: bool) -> Path:
    cmd = [MINGW, "-O1", "-o", str(out), str(SOURCE)]
    if strip:
        cmd.insert(1, "-s")
    subprocess.run(cmd, check=True, capture_output=True, timeout=120)
    return out


@pytest.fixture(scope="module")
def ghidra(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[GhidraBackend, Path]]:
    root = tmp_path_factory.mktemp("ghidra")
    sample = _compile(root / "toy.exe", strip=False)
    backend = GhidraBackend(max_sessions=2)
    pdir = root / "proj"
    backend.analyze(sample, pdir, 600)
    yield backend, pdir
    backend.close()


def test_info_is_pe_x86_64(ghidra: tuple[GhidraBackend, Path]) -> None:
    backend, pdir = ghidra
    info = backend.call(pdir, "info", {}, 60)
    assert "PE" in info["format"]
    assert info["language"].startswith("x86:LE:64")
    assert info["image_base"].startswith("0x")
    assert info["functions"]["total"] > 20
    assert info["project_reused"] is False


def test_list_functions_finds_the_decoder(ghidra: tuple[GhidraBackend, Path]) -> None:
    backend, pdir = ghidra
    r = backend.call(pdir, "list_functions", {"query": "xor"}, 60)
    assert [f["name"] for f in r["items"]] == ["xor_decode"]
    assert r["items"][0]["origin"] == "symbol"
    assert re.fullmatch(r"0x[0-9a-f]+", r["items"][0]["address"])


def test_decompile_main_shows_the_decode_call_and_key(ghidra: tuple[GhidraBackend, Path]) -> None:
    backend, pdir = ghidra
    r = backend.call(pdir, "decompile", {"target": "main"}, 120)
    assert "xor_decode(" in r["code"]
    assert "0x5a" in r["code"].lower()
    assert "xor_decode" in r["callees"]


def test_strings_find_the_run_key_and_its_user(ghidra: tuple[GhidraBackend, Path]) -> None:
    backend, pdir = ghidra
    r = backend.call(pdir, "strings", {"query": "ToyBeacon"}, 120)
    assert r["total"] == 1
    item = r["items"][0]
    assert item["value"].endswith("CurrentVersion\\Run\\ToyBeacon")
    assert item["functions"], "the function using the Run key must be named"


def test_xrefs_to_printf_has_several_callers(ghidra: tuple[GhidraBackend, Path]) -> None:
    backend, pdir = ghidra
    r = backend.call(pdir, "xrefs", {"target": "printf", "direction": "to"}, 60)
    callers = {row["from_function"] for row in r["items"]}
    assert len(callers) >= 2


def test_read_bytes_decodes_to_the_c2_url(ghidra: tuple[GhidraBackend, Path]) -> None:
    backend, pdir = ghidra
    dec = backend.call(pdir, "decompile", {"target": "main"}, 120)
    m = re.search(r"xor_decode\((0x[0-9a-f]+)", dec["code"])
    assert m, dec["code"]
    r = backend.call(pdir, "read_bytes", {"target": m.group(1), "length": 32}, 60)
    decoded = bytes(b ^ 0x5A for b in bytes.fromhex(r["hex"]))
    assert decoded == b"http://c2.example.invalid/beacon"


def test_disassemble_and_imports_page(ghidra: tuple[GhidraBackend, Path]) -> None:
    backend, pdir = ghidra
    d = backend.call(pdir, "disassemble", {"target": "xor_decode", "limit": 3}, 60)
    assert d["returned"] == 3 and d["next_offset"] == 3
    full = backend.call(pdir, "disassemble", {"target": "xor_decode", "limit": 400}, 60)
    assert full["next_offset"] is None and full["returned"] == full["total"]
    assert "XOR" in " ".join(full["lines"]).upper()
    imp = backend.call(pdir, "imports", {"limit": 5}, 60)
    assert imp["total"] > 5 and imp["next_offset"] == 5


def test_annotate_survives_reopen_without_reanalysis(
    tmp_path: Path,
) -> None:
    sample = _compile(tmp_path / "toy.exe", strip=False)
    backend = GhidraBackend(max_sessions=1)
    pdir = tmp_path / "proj"
    try:
        backend.analyze(sample, pdir, 600)
        analysed = (pdir / "analysis.json").read_text()
        r = backend.call(
            pdir,
            "annotate",
            {"target": "xor_decode", "new_name": "decode_c2_url", "comment": "XOR 0x5A"},
            60,
        )
        assert r["old_name"] == "xor_decode"
        backend.close()
        info = backend.analyze(sample, pdir, 600)
        assert info["project_reused"] is True
        assert (pdir / "analysis.json").read_text() == analysed, "no second analysis"
        found = backend.call(pdir, "list_functions", {"query": "decode_c2"}, 60)
        assert found["items"][0]["origin"] == "user"
        assert backend.call(pdir, "annotations", {}, 60)["total"] == 1
    finally:
        backend.close()


def test_stripped_variant_lists_unnamed_functions(tmp_path: Path) -> None:
    sample = _compile(tmp_path / "toy_s.exe", strip=True)
    backend = GhidraBackend(max_sessions=1)
    pdir = tmp_path / "proj"
    try:
        backend.analyze(sample, pdir, 600)
        r = backend.call(pdir, "list_functions", {"origin": "unnamed", "limit": 5}, 60)
        assert r["total"] > 5
        assert all(f["name"].startswith("FUN_") for f in r["items"])
        s = backend.call(pdir, "strings", {"query": "ToyBeacon"}, 120)
        assert s["items"][0]["functions"]
    finally:
        backend.close()
