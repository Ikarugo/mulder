"""radare2 backend and the Ghidra replay script of annotations."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from mulder.reverse import get_backend
from mulder.reverse.backend import BackendError
from mulder.reverse.export import GHIDRA_SCRIPT_NAME, ghidra_replay_script
from mulder.reverse.ghidra_backend import ANNOTATIONS_FILE
from mulder.reverse.radare2_backend import Radare2Backend
from mulder.reverse.radare2_worker import _short, _unescape

SOURCE = Path(__file__).parent / "fixtures" / "reverse" / "toy_beacon.c"
MINGW = "x86_64-w64-mingw32-gcc"

# -- unit ----------------------------------------------------------------------


def test_registered_and_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    import mulder.reverse.radare2_backend as rb

    assert isinstance(get_backend("radare2"), Radare2Backend)
    monkeypatch.setattr(rb.importlib.util, "find_spec", lambda name: None)
    assert "r2pipe" in (Radare2Backend().check() or "")
    monkeypatch.setattr(rb.importlib.util, "find_spec", lambda name: object())
    monkeypatch.setattr(rb, "find_radare2", lambda: None)
    assert "radare2 was not found" in (Radare2Backend().check() or "")


def test_worker_command_and_project_marker(tmp_path: Path) -> None:
    b = Radare2Backend()
    argv = b._worker_argv(tmp_path / "s.exe", tmp_path / "p", 60)
    assert argv[1:3] == ["-m", "mulder.reverse.radare2_worker"]
    assert "--ghidra-dir" not in argv
    (tmp_path / "p").mkdir()
    assert not b.has_project(tmp_path / "p")
    (tmp_path / "p" / "session.json").write_text("{}")
    (tmp_path / "p" / "mulder").mkdir()
    assert b.has_project(tmp_path / "p")


@pytest.mark.parametrize(
    ("raw", "value"),
    [
        ("Software\\\\Microsoft\\\\Run", "Software\\Microsoft\\Run"),
        ("line\\n", "line\n"),
        ("plain", "plain"),
        ("café \\\\x", "café \\x"),
    ],
)
def test_unescape(raw: str, value: str) -> None:
    assert _unescape(raw) == value


def test_short_names() -> None:
    assert _short("sym.imp.printf") == "printf"
    assert _short("fcn.140001000") == "140001000"
    assert _short("main") == "main"


def test_replay_script_is_valid_python(tmp_path: Path) -> None:
    rows = [
        {"address": "0x1400014c2", "old_name": "fcn.1400014c2", "new_name": "decode_c2_url",
         "comment": 'XOR "0x5A"\nkey'},
        {"address": "0x140009048", "old_name": None, "new_name": None, "comment": "Run key"},
        {"address": "Program.cs:12", "new_name": "decode", "comment": None},
    ]  # fmt: skip
    (tmp_path / ANNOTATIONS_FILE).write_text("\n".join(json.dumps(r) for r in rows) + "\nbad\n")
    text, count = ghidra_replay_script(tmp_path, "/samples/toy.exe")
    assert count == 2, "the ILSpy row (file:line) has no address to replay"
    compile(text, GHIDRA_SCRIPT_NAME, "exec")
    assert "decode_c2_url" in text and "currentProgram" in text


# -- integration (real radare2) ----------------------------------------------------------

_r2 = Radare2Backend()
_reason = _r2.check() or (None if shutil.which(MINGW) else f"{MINGW} not installed")
needs_r2 = pytest.mark.skipif(_reason is not None, reason=f"radare2 integration: {_reason}")


def _compile(out: Path, strip: bool) -> Path:
    cmd = [MINGW, "-O1", "-o", str(out), str(SOURCE)]
    if strip:
        cmd.insert(1, "-s")
    subprocess.run(cmd, check=True, capture_output=True, timeout=120)
    return out


@pytest.fixture(scope="module")
def r2(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Radare2Backend, Path, Path]]:
    root = tmp_path_factory.mktemp("r2")
    sample = _compile(root / "toy.exe", strip=False)
    backend = Radare2Backend(max_sessions=2)
    pdir = root / "proj"
    backend.analyze(sample, pdir, 600)
    yield backend, pdir, sample
    backend.close()


@needs_r2
def test_r2_same_shapes_as_ghidra(r2: tuple[Radare2Backend, Path, Path]) -> None:
    backend, pdir, _ = r2
    info = backend.call(pdir, "info", {}, 60)
    assert info["format"] == "pe" and info["address_size"] == 64
    fns = backend.call(pdir, "list_functions", {"query": "xor"}, 60)["items"]
    assert fns[0]["name"].endswith("xor_decode") and fns[0]["address"].startswith("0x")
    assert set(fns[0]) == {
        "name", "address", "size", "origin", "library", "thunk", "signature", "callers", "callees"
    }  # fmt: skip
    xr = backend.call(pdir, "xrefs", {"target": "printf"}, 60)
    assert len({r["from_function"] for r in xr["items"]}) >= 2
    s = backend.call(pdir, "strings", {"query": "ToyBeacon"}, 60)["items"][0]
    assert s["value"].endswith("CurrentVersion\\Run\\ToyBeacon")
    assert s["functions"]


@needs_r2
def test_r2_bytes_disassembly_and_decompiler(r2: tuple[Radare2Backend, Path, Path]) -> None:
    backend, pdir, _ = r2
    raw = backend.call(pdir, "read_bytes", {"target": "0x1400090a0", "length": 32}, 60)
    decoded = bytes(b ^ 0x5A for b in bytes.fromhex(raw["hex"]))
    assert decoded == b"http://c2.example.invalid/beacon"
    dis = backend.call(pdir, "disassemble", {"target": "xor_decode", "limit": 400}, 60)
    assert "xor" in " ".join(dis["lines"]) and dis["next_offset"] is None
    try:
        dec = backend.call(pdir, "decompile", {"target": "main"}, 120)
    except BackendError as exc:
        assert exc.error_type == "binary_missing" and "r2ghidra" in str(exc)
    else:
        assert "xor_decode" in dec["code"] and "0x5a" in dec["code"].lower()
    path = backend.call(pdir, "call_path", {"target": "xor_decode"}, 60)
    assert path["reachable"] and path["path"][-1]["name"].endswith("xor_decode")


@needs_r2
def test_r2_annotate_survives_reopen_without_reanalysis(tmp_path: Path) -> None:
    sample = _compile(tmp_path / "toy.exe", strip=False)
    backend = Radare2Backend(max_sessions=1)
    pdir = tmp_path / "proj"
    try:
        backend.analyze(sample, pdir, 600)
        analysed = (pdir / "analysis.json").read_text()
        r = backend.call(
            pdir, "annotate", {"target": "xor_decode", "new_name": "decode_c2_url"}, 60
        )
        assert r["old_name"].endswith("xor_decode")
        backend.call(pdir, "annotate", {"target": "decode_c2_url", "comment": "XOR 0x5A"}, 60)
        backend.close()
        info = backend.analyze(sample, pdir, 600)
        assert info["project_reused"] is True
        assert (
            json.loads((pdir / "analysis.json").read_text())["analyzed_at"]
            == json.loads(analysed)["analyzed_at"]
        )
        found = backend.call(pdir, "list_functions", {"query": "decode_c2"}, 60)["items"]
        assert found and found[0]["origin"] == "user"
        assert backend.call(pdir, "annotations", {}, 60)["total"] == 2
    finally:
        backend.close()


@needs_r2
def test_r2_stripped_sample(tmp_path: Path) -> None:
    sample = _compile(tmp_path / "toy_s.exe", strip=True)
    backend = Radare2Backend(max_sessions=1)
    try:
        backend.analyze(sample, tmp_path / "proj", 600)
        r = backend.call(tmp_path / "proj", "list_functions", {"origin": "unnamed"}, 60)
        assert r["total"] > 5
        assert all(f["name"].startswith(("fcn.", "sub.")) for f in r["items"])
    finally:
        backend.close()


# -- replay in real Ghidra ------------------------------------------------------------

_ghidra_reason = get_backend("ghidra").check() or (
    None if shutil.which(MINGW) else f"{MINGW} not installed"
)

_REPLAY = """
import sys
from pathlib import Path
import pyghidra
pyghidra.start(install_dir=Path(sys.argv[3]))
project = pyghidra.open_project(sys.argv[2], "mulder")
program, consumer = pyghidra.consume_program(project, "/toy.exe")
pyghidra.ghidra_script(sys.argv[1], project, program, echo_stdout=True)
program.save("replay", pyghidra.task_monitor())
f = program.getFunctionManager().getFunctionAt(
    program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1400014C2)
)
print("NAME=" + f.getName())
print("COMMENT=" + str(f.getComment()))
program.release(consumer)
project.close()
"""


@pytest.mark.skipif(_ghidra_reason is not None, reason=f"Ghidra replay: {_ghidra_reason}")
def test_replay_script_applies_in_ghidra(tmp_path: Path) -> None:
    from mulder.reverse.ghidra_backend import GhidraBackend

    sample = _compile(tmp_path / "toy.exe", strip=False)
    ghidra = GhidraBackend(max_sessions=1)
    pdir = tmp_path / "gproj"  # not "ghidra": the runner dir is on sys.path
    try:
        ghidra.analyze(sample, pdir, 600)
    finally:
        ghidra.close()
    r2dir = tmp_path / "r2"
    r2dir.mkdir()
    row = {"address": "0x1400014c2", "old_name": "sym.xor_decode", "new_name": "decode_c2_url",
           "comment": "XOR 0x5A"}  # fmt: skip
    (r2dir / ANNOTATIONS_FILE).write_text(json.dumps(row) + "\n")
    text, _ = ghidra_replay_script(r2dir, str(sample))
    script = tmp_path / GHIDRA_SCRIPT_NAME
    script.write_text(text)
    runner = tmp_path / "replay.py"
    runner.write_text(_REPLAY)
    ghidra_dir = str(get_backend("ghidra").ghidra_dir)  # type: ignore[attr-defined]
    out = subprocess.run(
        [sys.executable, str(runner), str(script), str(pdir), ghidra_dir],
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert "NAME=decode_c2_url" in out.stdout, out.stderr[-2000:]
    assert "[mulder] XOR 0x5A" in out.stdout
    assert "1 annotation(s) applied" in out.stdout
