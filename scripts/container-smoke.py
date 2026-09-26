#!/usr/bin/env python3
"""Exercise the built image without credentials or network access.

Run from the checkout (the normal entrypoint drops privileges):
    docker run --rm -i --pull=never --network none IMAGE python3 - \
        < scripts/container-smoke.py

Append ``--reverse-only`` (``python3 - --reverse-only``) to run just the
reverse-engineering checks (Ghidra, radare2 + r2ghidra, ILSpy).

Fixtures and tool outputs live in a temporary container directory. This checks
representative extraction paths, not forensic accuracy across every parser.
"""

import importlib
import json
import os
import plistlib
import shlex
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path


def run(*args: str | Path, cwd: Path | None = None, timeout: int = 180) -> str:
    print("RUN", shlex.join(str(arg) for arg in args), flush=True)
    result = subprocess.run(
        [str(arg) for arg in args], cwd=cwd, capture_output=True, text=True, timeout=timeout
    )
    if result.returncode:
        raise RuntimeError(f"exit {result.returncode}:\n{result.stdout}\n{result.stderr}")
    return result.stdout


def _first_function(backend: object, project: Path) -> str:
    items = backend.call(project, "list_functions", {"limit": 200}, 120)["items"]  # type: ignore[attr-defined]
    assert items, f"no function listed in {project}"
    body = [f for f in items if not f.get("thunk") and not f.get("library")]
    return str((body or items)[0]["address"])


def reverse_checks() -> None:
    """Static reverse engineering: every backend opens a real binary, offline."""
    native_reverse_checks()
    dotnet_reverse_checks()
    run("mulder", "reverse", "--help")


def native_reverse_checks() -> None:
    """Ghidra and radare2 analyse an ELF from the image (read, never executed).

    Both decompilers (Ghidra's native one, r2ghidra) are only shipped upstream
    for x86_64; on arm64 the checks stop at disassembly.
    """
    import platform

    from mulder.reverse import get_backend
    from mulder.reverse.backend import BackendError

    for name in ("pyghidra", "r2pipe"):
        importlib.import_module(name)
    run("java", "-version")
    plugins = Path(run("r2", "-H", "R2_LIBR_PLUGINS").strip())
    has_r2ghidra = (plugins / "core_ghidra.so").exists()
    x86_64 = platform.machine() in ("x86_64", "AMD64")
    if x86_64:
        assert has_r2ghidra, f"r2ghidra plugin missing from {plugins}"
    for name in ("ghidra", "radare2"):
        reason = get_backend(name).check()
        assert reason is None, f"{name} backend unavailable: {reason}"

    with tempfile.TemporaryDirectory(prefix="mulder-reverse-") as directory:
        work = Path(directory)
        elf = work / "sample.elf"
        elf.write_bytes(Path("/usr/bin/true").read_bytes())  # read, never run

        ghidra = get_backend("ghidra")
        info = ghidra.analyze(elf, work / "ghidra-project", 900)
        assert "ELF" in info["format"], info
        target = _first_function(ghidra, work / "ghidra-project")
        if x86_64:  # the Ghidra zip ships its native decompiler for x86_64 only
            code = ghidra.call(work / "ghidra-project", "decompile", {"target": target}, 300)
            assert code["code"].strip(), code
        else:
            ghidra.call(work / "ghidra-project", "disassemble", {"target": target}, 300)
            print("NOTE Ghidra decompiler not checked: no native build for this architecture")
        ghidra.close()
        print(f"PASS Ghidra analysis and decompilation ({info['functions']['total']} functions)")

        r2 = get_backend("radare2")
        info = r2.analyze(elf, work / "r2-project", 900)
        target = _first_function(r2, work / "r2-project")
        try:
            code = r2.call(work / "r2-project", "decompile", {"target": target}, 300)
        except BackendError as exc:
            assert not has_r2ghidra and exc.error_type == "binary_missing", exc
            print("NOTE radare2 without r2ghidra: decompilation unavailable (expected on arm64)")
        else:
            assert code["code"].strip(), code
        r2.close()
        print(f"PASS radare2 analysis ({info['functions']['total']} functions)", flush=True)


def dotnet_reverse_checks() -> None:
    """ILSpy decompiles one of the .NET EZ Tools on the shared .NET 8 runtime."""
    from mulder.reverse import get_backend

    run("ilspycmd", "--version")
    reason = get_backend("ilspy").check()
    assert reason is None, f"ilspy backend unavailable: {reason}"
    with tempfile.TemporaryDirectory(prefix="mulder-reverse-") as directory:
        work = Path(directory)
        assembly = next(Path("/opt/zimmermantools").rglob("PECmd.dll"))
        dotnet = work / "PECmd.dll"
        dotnet.write_bytes(assembly.read_bytes())
        ilspy = get_backend("ilspy")
        info = ilspy.analyze(dotnet, work / "ilspy-project", 900)
        target = _first_function(ilspy, work / "ilspy-project")
        code = ilspy.call(work / "ilspy-project", "decompile", {"target": target}, 300)
        assert code["code"].strip(), code
        print(f"PASS ILSpy decompilation ({info['functions']['total']} methods)", flush=True)


def main() -> None:
    assert os.getuid() != 0, "Run through the image entrypoint as mulder"
    assert Path.home() == Path("/home/mulder"), "Unexpected HOME"
    report = json.loads(run("mulder", "setup", "--verify", "--json", timeout=300))
    assert report["root"] == "/opt", report["root"]
    bad = [
        asset
        for asset in report["assets"]
        if asset["selected"] and asset["status"] not in ("up-to-date", "up-to-date (unmanaged)")
    ]
    assert not bad, bad
    shadowed = [asset for asset in report["assets"] if asset["shadowed_by"]]
    assert not shadowed, shadowed
    assert report["exit"] == 0, report["exit"]
    for name in ("pyewf", "pysqlcipher3.dbapi2", "volatility3", "plaso", "mvt", "oletools"):
        importlib.import_module(name)
    from pysqlcipher3 import dbapi2

    with dbapi2.connect(":memory:") as connection:
        assert connection.execute("PRAGMA cipher_version").fetchone()[0]

    for name in ("aleapp", "ileapp", "zircolite", "signature-base", "didier-stevens"):
        root = Path("/opt") / name
        assert (root / ".git").is_dir(), f"Missing Git metadata: {root}"
        run("git", "-c", f"safe.directory={root}", "-C", root, "cat-file", "-e", "HEAD^{tree}")

    cache = Path.home() / ".cache/volatility3/symbols"
    with tempfile.TemporaryFile(dir=cache) as writable:
        writable.write(b"symbol cache is writable")
    for name in ("linux.zip", "windows.zip"):
        with zipfile.ZipFile(cache / name) as archive:
            entry = next(member for member in archive.infolist() if not member.is_dir())
            assert archive.read(entry), f"Empty symbol member: {name}/{entry.filename}"

    for command in (
        ("ewfinfo", "-V"),
        ("yara", "--version"),
        ("r2", "-v"),
        ("dotnet", "--list-runtimes"),
        ("zeek", "--version"),
        ("suricata", "-V"),
        ("chainsaw", "--version"),
        ("hayabusa", "help"),
        ("capa", "--version"),
        ("floss", "--version"),
        ("guestmount", "--version"),
        ("xmount", "--version"),
        ("ntfs-3g", "--version"),
        ("fuse2fs", "-V"),
        ("clamscan", "--version"),
    ):
        run(*command)
    # The unprivileged mulder user can only mount NTFS through the source-built
    # external-FUSE ntfs-3g; the distro binary (integrated FUSE) refuses.
    ntfs_version = subprocess.run(["ntfs-3g", "--version"], capture_output=True, text=True).stderr
    assert "external FUSE" in ntfs_version, (
        f"ntfs-3g is not the external-FUSE build: {ntfs_version!r}"
    )
    proxy = importlib.import_module("mulder.orchestrator.proxy")
    with proxy.ProxyManager(models=["ollama/smoke"]):
        print("PASS LiteLLM proxy startup and health", flush=True)
    # Exercise the shared .NET runtime and every installed forensic parser.
    for dll in (
        "AmcacheParser",
        "AppCompatCacheParser",
        "EvtxECmd",
        "JLECmd",
        "LECmd",
        "MFTECmd",
        "PECmd",
        "RBCmd",
        "RECmd",
        "SBECmd",
        "SrumECmd",
    ):
        path = next(Path("/opt/zimmermantools").rglob(f"{dll}.dll"))
        run("dotnet", path, "-h")

    with tempfile.TemporaryDirectory(prefix="mulder-smoke-") as directory:
        work = Path(directory)
        # One Ethernet/IPv4/UDP DNS query. Offline decoders explicitly ignore
        # checksums so this tiny fixture needs no packet-generation dependency.
        dns = (
            struct.pack("!6H", 1, 0x0100, 1, 0, 0, 0) + b"\x05smoke\x07example\x00\x00\x01\x00\x01"
        )
        udp = struct.pack("!4H", 54321, 53, 8 + len(dns), 0) + dns
        ip = (
            struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                20 + len(udp),
                1,
                0,
                64,
                17,
                0,
                bytes((192, 0, 2, 1)),
                bytes((192, 0, 2, 53)),
            )
            + udp
        )
        packet = bytes.fromhex("00112233445566778899aabb0800") + ip
        pcap = work / "smoke.pcap"
        pcap.write_bytes(
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1700000000, 0, len(packet), len(packet))
            + packet
        )
        zeek = work / "zeek"
        zeek.mkdir()
        run("zeek", "-C", "-r", pcap, cwd=zeek)
        assert "smoke.example" in (zeek / "dns.log").read_text()

        suricata = work / "suricata"
        suricata.mkdir()
        rules = work / "smoke.rules"
        rules.write_text(
            'alert udp any any -> any 53 (msg:"mulder smoke DNS"; sid:1000001; rev:1;)\n'
        )
        config = work / "suricata.yaml"
        if not os.access("/etc/suricata/suricata.yaml", os.R_OK):
            print(
                "NOTE packaged Suricata config missing or unreadable; using synthetic config",
                flush=True,
            )
        config.write_text(
            "%YAML 1.1\n---\noutputs:\n  - eve-log:\n      enabled: yes\n"
            "      filetype: regular\n      filename: eve.json\n      types:\n        - alert\n"
        )
        if os.access("/etc/suricata/rules", os.R_OK | os.X_OK):
            assert any(Path("/etc/suricata/rules").glob("*.rules")), "ET rules missing"
        else:
            print(
                "NOTE packaged Suricata rules unreadable; verify their inventory as root",
                flush=True,
            )
        run(
            "suricata",
            "--runmode",
            "single",
            "-k",
            "none",
            "-r",
            pcap,
            "-c",
            config,
            "-S",
            rules,
            "-l",
            suricata,
        )
        events = [json.loads(line) for line in (suricata / "eve.json").read_text().splitlines()]
        assert any(event.get("alert", {}).get("signature_id") == 1000001 for event in events)

        evidence = work / "email.raw"
        original = (b"Contact smoke@example.org for the smoke test.\n" * 100).ljust(8192, b"\0")
        evidence.write_bytes(original)
        run("ewfacquire", "-u", "-q", "-t", work / "evidence", evidence)
        pyewf = importlib.import_module("pyewf")
        handle = pyewf.handle()
        try:
            handle.open(pyewf.glob(str(work / "evidence.E01")))
            assert handle.read_buffer(len(original)) == original, "E01 roundtrip differs"
        finally:
            handle.close()
        print("PASS E01 acquisition and pyewf byte-for-byte readback", flush=True)
        bulk = work / "bulk"
        run("bulk_extractor", "-E", "email", "-j", "1", "-o", bulk, evidence)
        assert "smoke@example.org" in (bulk / "email.txt").read_text()

        for name in ("aleapp", "ileapp"):
            source = work / f"{name}-input"
            output = work / f"{name}-output"
            output.mkdir()
            if name == "aleapp":
                fixture = source / "data/misc/adb/adb_keys"
                fixture.parent.mkdir(parents=True)
                fixture.write_text("AAAA smoke@mulder-smoke-host\n")
                expected = "mulder-smoke-host"
            else:
                fixture = source / "Library/Preferences/com.apple.wifi-private-mac-networks.plist"
                fixture.parent.mkdir(parents=True)
                fixture.write_bytes(
                    plistlib.dumps(
                        {
                            "List of scanned networks with private mac": [
                                {"SSID_STR": "mulder-smoke-wifi", "BSSID": "00:11:22:33:44:55"}
                            ]
                        }
                    )
                )
                expected = "mulder-smoke-wifi"
            run(
                "python3",
                f"/opt/{name}/{name}.py",
                "-t",
                "fs",
                "-i",
                source,
                "-o",
                output,
                cwd=work,
                timeout=300,
            )
            assert any(expected in path.read_text() for path in output.rglob("*.tsv")), name
            assert list(output.rglob("tabler-icons.css")), f"{name} report assets missing"
            print(f"PASS {name} synthetic artifact and HTML assets", flush=True)
    reverse_checks()
    print("PASS container smoke checks", flush=True)


if __name__ == "__main__":
    import sys

    if "--reverse-only" in sys.argv[1:]:
        assert os.getuid() != 0, "Run through the image entrypoint as mulder"
        reverse_checks()
        print("PASS reverse-engineering smoke checks", flush=True)
    else:
        main()
