"""Stand-in for mulder.reverse.ghidra_worker, for tests without Ghidra.

Speaks the same line-delimited JSON protocol and mimics the behaviours the
server side has to cope with. Behaviour is driven by the sample's file name
at startup and by the ``target`` parameter afterwards:

* sample ``slow_start*``: never answers the startup request.
* sample ``bad_start*``: answers the startup request with an error.
* target ``hang``: never answers.
* target ``crash``: exits with code 3 after logging to stderr.

Like the real worker it keeps its stdout for the protocol and writes noise
to what the JVM would see as stdout, which must not reach the parent.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from mulder.reverse.ghidra_worker import _protocol_stream
from mulder.reverse.protocol import clamp, page

FUNCTIONS = [
    {
        "name": f"FUN_{0x401000 + i * 0x10:08x}",
        "address": f"0x{0x401000 + i * 0x10:x}",
        "size": 16,
        "origin": "unnamed",
        "library": False,
        "thunk": False,
        "signature": "undefined FUN(void)",
        "callers": i % 7,
        "callees": 1,
    }
    for i in range(250)
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=Path, required=True)
    ap.add_argument("--project-dir", type=Path, required=True)
    ap.add_argument("--analysis-timeout", type=int, default=600)
    args, _ = ap.parse_known_args()

    proto = _protocol_stream()
    # What the JVM prints: must end up in the log, not in the protocol.
    print("Picked up JAVA_TOOL_OPTIONS: -Dnoise=1", flush=True)
    print("INFO  Using log config file", flush=True)

    def send(msg: dict[str, Any]) -> None:
        proto.write(json.dumps(msg) + "\n")
        proto.flush()

    pdir: Path = args.project_dir
    name = args.sample.name
    if name.startswith("slow_start"):
        time.sleep(3600)
    if name.startswith("bad_start"):
        send({"id": 0, "ok": False, "error": {"type": "backend_error", "message": "no loader"}})
        return 1

    counter = pdir / "fake_analysis_count"
    reused = (pdir / "mulder.gpr").exists()
    if not reused:
        (pdir / "mulder.gpr").write_text("fake")
        counter.write_text(str(int(counter.read_text()) + 1 if counter.exists() else 1))
    names: dict[str, str] = {}
    info = {
        "program_name": name,
        "sha256": "0" * 64,
        "format": "Portable Executable (PE)",
        "language": "x86:LE:64:default",
        "functions": {"total": len(FUNCTIONS)},
        "project_reused": reused,
        "project_dir": str(pdir),
    }
    send({"id": 0, "ok": True, "result": info})

    for line in sys.stdin:
        req = json.loads(line)
        rid, op, p = req.get("id"), req.get("op"), req.get("params") or {}
        if op == "shutdown":
            send({"id": rid, "ok": True, "result": {}})
            return 0
        target = p.get("target")
        if target == "hang":
            time.sleep(3600)
        if target == "slowfn":
            time.sleep(0.3)
        if target == "crash":
            print("java.lang.OutOfMemoryError: Java heap space", file=sys.stderr, flush=True)
            sys.exit(3)
        try:
            if op == "info":
                result: dict[str, Any] = info
            elif op == "list_functions":
                rows = [dict(f, name=names.get(f["address"], f["name"])) for f in FUNCTIONS]
                q = str(p.get("query") or "").lower()
                rows = [r for r in rows if q in r["name"].lower()]
                result = page(
                    rows,
                    clamp(p.get("offset"), 0, 0, 10**9, "offset"),
                    clamp(p.get("limit"), 50, 1, 200, "limit"),
                )
            elif op == "decompile":
                if target == "missing":
                    raise LookupError("No function matches 'missing'")
                lines = [f"// line {i}" for i in range(1000)]
                off = clamp(p.get("offset"), 0, 0, 10**9, "offset")
                lim = clamp(p.get("limit"), 200, 1, 400, "limit")
                chunk = lines[off : off + lim]
                end = off + len(chunk)
                result = {
                    "name": "main",
                    "address": "0x401000",
                    "signature": "int main(void)",
                    "total_lines": len(lines),
                    "start_line": off,
                    "next_offset": end if end < len(lines) else None,
                    "code": "\n".join(chunk),
                    "callees": ["decode"],
                    "callers": [],
                    "strings": [{"address": "0x402000", "value": "http://c2.example.invalid"}],
                }
            elif op == "annotate":
                old = "FUN_00401000"
                names["0x401000"] = p.get("new_name") or old
                result = {
                    "address": "0x401000",
                    "function": names["0x401000"],
                    "old_name": old,
                    "new_name": p.get("new_name"),
                    "comment": p.get("comment"),
                    "saved": True,
                }
            else:
                result = {"op": op, "params": p}
            send({"id": rid, "ok": True, "result": result})
        except LookupError as exc:
            send({"id": rid, "ok": False, "error": {"type": "not_found", "message": str(exc)}})
        except Exception as exc:  # noqa: BLE001
            err_type = getattr(exc, "error_type", "backend_error")
            send({"id": rid, "ok": False, "error": {"type": err_type, "message": str(exc)}})
    return 0


if __name__ == "__main__":
    sys.exit(main())
