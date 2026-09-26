"""radare2 engine worker: one child process per analysed sample.

Launched by :class:`mulder.reverse.radare2_backend.Radare2Backend` as
``python -m mulder.reverse.radare2_worker --sample ... --project-dir ...``.
It drives radare2 through r2pipe (radare2 itself runs as a child of this
worker, in the same process group, so killing the worker stops it too),
answers the same operations as the Ghidra worker with the same JSON
shapes, and speaks the same line-delimited JSON protocol.

The first run analyses the sample (``aaa``) and saves a radare2 project in
the project directory; later runs load the project (``Po``) instead of
analysing again. Decompilation needs the r2ghidra plugin (``pdg``); without
it ``decompile`` fails with ``binary_missing`` rather than returning
assembly in its place.

The sample is only ever read: radare2 is opened without debugger or
emulation (no ``-d``, no ESIL execution is requested).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
import time
import traceback
from pathlib import Path
from typing import IO, Any

from mulder.reverse.backend import (
    MAX_BYTES,
    MAX_DECOMPILE_LINES,
    MAX_DISASM_INSTRUCTIONS,
    MAX_PAGE,
    BackendError,
)
from mulder.reverse.ghidra_worker import _error, _protocol_stream, _send
from mulder.reverse.protocol import clamp, hex_addr, page, parse_hex, validate_name

PROJECT_NAME = "mulder"
ANALYSIS_STATE_FILE = "analysis.json"
_STRING_CAP = 300
_COMMENT_PREFIX = "[mulder] "
_ENTRY_NAMES = ("main", "sym.main", "entry0", "sym.WinMain", "sym.wmain", "sym.DllMain")


def _short(name: str) -> str:
    """radare2 flag name without its namespace prefix (``sym.imp.printf`` -> ``printf``)."""
    for prefix in ("sym.imp.", "sym.", "dbg.", "fcn.", "loc.", "sub."):
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


class Radare2Session:
    """One radare2 instance on one sample."""

    def __init__(self, sample: Path, project_dir: Path, analysis_timeout: int) -> None:
        import r2pipe

        self.sample = sample
        self.project_dir = project_dir
        project_dir.mkdir(parents=True, exist_ok=True)
        # -2: no stderr noise on the pipe; -e bin.cache: apply relocations in memory.
        self.r2 = r2pipe.open(str(sample), flags=["-2", "-e", "bin.cache=true"])
        self.cmd("e scr.color=0")
        self.cmd("e scr.interactive=false")
        self.cmd(f"e dir.projects={project_dir}")
        # A project under git writes to the pipe outside the r2pipe framing
        # and desynchronises every later command.
        self.cmd("e prj.vc=false")
        self.state = self._load_state()
        self.reused = (project_dir / PROJECT_NAME).is_dir()
        if self.reused:
            self.cmd(f"Po {PROJECT_NAME}")
            if not self.cmdj("aflj"):
                self.reused = False
        if not self.reused:
            self._analyze(analysis_timeout)
        self._user_names: set[str] = set(self.state.get("user_names", []))
        self._has_decompiler: bool | None = None
        self._strings: list[dict[str, Any]] | None = None

    # -- plumbing ----------------------------------------------------------------

    def cmd(self, command: str) -> str:
        out = self.r2.cmd(command)
        return out if isinstance(out, str) else ""

    def cmdj(self, command: str) -> Any:
        """Run a JSON command, reading its output from a file.

        Large outputs read back through the r2pipe pipe can stall after a
        project has been saved (radare2 5.5); a file redirect avoids the
        pipe for the payload entirely.
        """
        out = self.project_dir / ".r2out.json"
        out.unlink(missing_ok=True)
        self.cmd(f"{command} > {out}")
        try:
            text = out.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            text = ""
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None

    def _state_path(self) -> Path:
        return self.project_dir / ANALYSIS_STATE_FILE

    def _load_state(self) -> dict[str, Any]:
        try:
            data = json.loads(self._state_path().read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_state(self) -> None:
        self._state_path().write_text(json.dumps(self.state, indent=2), encoding="utf-8")

    def _analyze(self, timeout: int) -> None:
        t0 = time.monotonic()
        # The backend enforces the overall timeout by killing this process.
        self.cmd("aaa")
        elapsed = round(time.monotonic() - t0, 1)
        self.state.update(
            {
                "analysis_seconds": elapsed,
                "analysis_completed": elapsed < timeout,
                "analysis_timeout": timeout,
                "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        )
        self._save()

    def _save(self) -> None:
        self.cmd(f"Ps {PROJECT_NAME}")
        self._save_state()

    def close(self) -> None:
        with contextlib.suppress(Exception):  # already gone
            self.r2.quit()

    # -- resolution -------------------------------------------------------------

    def _functions(self) -> list[dict[str, Any]]:
        return list(self.cmdj("aflj") or [])

    def _function_at(self, addr: int) -> dict[str, Any] | None:
        info = self.cmdj(f"afij @ {addr}")
        return info[0] if isinstance(info, list) and info else None

    def _resolve(self, target: Any) -> tuple[int, dict[str, Any] | None]:
        if not isinstance(target, str) or not target.strip():
            raise BackendError("target is required (a name or a hex address)", "invalid_parameter")
        target = target.strip()
        fns = self._functions()
        for cand in (target, f"sym.{target}", f"sym.imp.{target}", f"fcn.{target}"):
            for f in fns:
                if f["name"] == cand:
                    return int(f["offset"]), f
        for f in fns:
            if _short(f["name"]) == target:
                return int(f["offset"]), f
        value = parse_hex(target)
        addr = None
        if value is not None:
            addr = value
        else:
            resolved = self.cmd(f"?v {target}").strip()
            try:
                addr = int(resolved, 16) if resolved not in ("", "0x0") else None
            except ValueError:
                addr = None
        if addr is None:
            raise BackendError(
                f"No function, symbol or address matches {target!r}. "
                "Use list_functions, imports or strings to find a valid target.",
                "not_found",
            )
        if not self.cmdj(f"pxj 1 @ {addr}"):
            raise BackendError(f"Address {hex_addr(addr)} is not mapped", "not_found")
        return addr, self._function_at(addr)

    def _resolve_function(self, target: Any) -> dict[str, Any]:
        addr, fn = self._resolve(target)
        if fn is None:
            raise BackendError(
                f"{target!r} ({hex_addr(addr)}) is not inside a function", "not_found"
            )
        if str(fn["name"]).startswith("sym.imp."):
            raise BackendError(
                f"{fn['name']} is an imported function: its code is not in this sample. "
                "Use xrefs to see who calls it.",
                "invalid_parameter",
            )
        return fn

    # -- descriptions -------------------------------------------------------------

    def _origin(self, name: str) -> str:
        if name in self._user_names:
            return "user"
        if name.startswith("fcn.") or name.startswith("sub."):
            return "unnamed"
        if name.startswith("flirt."):
            return "analysis"
        return "symbol"

    def _describe(self, f: dict[str, Any]) -> dict[str, Any]:
        name = str(f["name"])
        imported = name.startswith("sym.imp.")
        return {
            "name": name,
            "address": hex_addr(int(f["offset"])),
            "size": int(f.get("realsz") or f.get("size") or 0),
            "origin": self._origin(name),
            "library": imported or name.startswith("flirt."),
            "thunk": imported,
            "signature": str(f.get("signature") or name),
            "callers": int(f.get("indegree") or 0),
            "callees": int(f.get("outdegree") or 0),
        }

    # -- operations -----------------------------------------------------------------

    def op_info(self, _p: dict[str, Any]) -> dict[str, Any]:
        info = self.cmdj("ij") or {}
        binf = info.get("bin", {})
        fns = self._functions()
        described = [self._describe(f) for f in fns]
        origins: dict[str, int] = {}
        for d in described:
            origins[d["origin"]] = origins.get(d["origin"], 0) + 1
        entries = []
        for e in (self.cmdj("iej") or [])[:20]:
            fn = self._function_at(int(e["vaddr"]))
            entries.append(
                {"address": hex_addr(int(e["vaddr"])), "name": fn["name"] if fn else None}
            )
        return {
            "sample": str(self.sample),
            "program_name": self.sample.name,
            "format": str(binf.get("bintype") or info.get("core", {}).get("format", "")),
            "language": f"{binf.get('arch')}:{binf.get('endian', '')}:{binf.get('bits')}",
            "processor": str(binf.get("arch", "")),
            "address_size": int(binf.get("bits") or 0),
            "endian": str(binf.get("endian", "")),
            "compiler": str(binf.get("compiler") or binf.get("lang") or ""),
            "image_base": hex_addr(int(binf.get("baddr") or 0)),
            "sha256": self._sha256(),
            "functions": {
                "total": len(described),
                "library": sum(d["library"] for d in described),
                "thunk": sum(d["thunk"] for d in described),
                "by_origin": origins,
            },
            "imports": len(self.cmdj("iij") or []),
            "entry_points": entries,
            "analysis_seconds": self.state.get("analysis_seconds"),
            "analysis_completed": self.state.get("analysis_completed", True),
            "project_reused": self.reused,
            "project_dir": str(self.project_dir),
            "decompiler": "r2ghidra" if self._decompiler_available() else None,
        }

    def _sha256(self) -> str:
        import hashlib

        h = hashlib.sha256()
        with self.sample.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def op_list_functions(self, p: dict[str, Any]) -> dict[str, Any]:
        query = str(p.get("query") or "").lower()
        origins = {o.strip() for o in str(p.get("origin") or "").split(",") if o.strip()}
        bad = origins - {"unnamed", "symbol", "analysis", "user"}
        if bad:
            raise BackendError(
                f"Unknown origin {sorted(bad)}; use unnamed, symbol, analysis, user",
                "invalid_parameter",
            )
        include_library = bool(p.get("include_library", False))
        include_thunks = bool(p.get("include_thunks", False))
        sort = str(p.get("sort") or "address")
        if sort not in ("address", "size", "callers", "callees"):
            raise BackendError(
                f"sort must be address, size, callers or callees, got {sort!r}",
                "invalid_parameter",
            )
        rows = []
        hidden = 0
        for f in sorted(self._functions(), key=lambda f: int(f["offset"])):
            d = self._describe(f)
            if query and query not in d["name"].lower():
                continue
            if (d["thunk"] and not include_thunks) or (d["library"] and not include_library):
                hidden += 1
                continue
            if origins and d["origin"] not in origins:
                continue
            rows.append(d)
        if sort != "address":
            rows.sort(key=lambda d: -int(d[sort]))
        result = page(
            rows,
            clamp(p.get("offset"), 0, 0, 10**9, "offset"),
            clamp(p.get("limit"), 50, 1, MAX_PAGE, "limit"),
        )
        result["library_hidden"] = hidden
        return result

    def _decompiler_available(self) -> bool:
        if self._has_decompiler is None:
            plugins = self.cmd("Lc") + self.cmd("L")
            self._has_decompiler = "ghidra" in plugins.lower() or bool(self.cmd("pdg?").strip())
        return self._has_decompiler

    def _string_refs(self, fn: dict[str, Any], cap: int) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for ref in self.cmdj(f"axffj @ {int(fn['offset'])}") or []:
            if ref.get("type") != "DATA":
                continue
            text = self.cmd(f"psz 300 @ {int(ref['ref'])}").strip()
            if len(text) >= 4:
                out.append({"address": hex_addr(int(ref["ref"])), "value": text[:_STRING_CAP]})
            if len(out) >= cap:
                break
        return out

    def op_decompile(self, p: dict[str, Any]) -> dict[str, Any]:
        fn = self._resolve_function(p.get("target"))
        if not self._decompiler_available():
            raise BackendError(
                "radare2 has no decompiler: install the r2ghidra plugin "
                "(r2pm -ci r2ghidra). Use disassemble meanwhile.",
                "binary_missing",
            )
        addr = int(fn["offset"])
        code = self.cmd(f"pdg @ {addr}")
        if not code.strip():
            raise BackendError(
                f"r2ghidra returned nothing for {fn['name']}; try disassemble.", "backend_error"
            )
        lines = code.strip("\n").split("\n")
        offset = clamp(p.get("offset"), 0, 0, 10**9, "offset")
        limit = clamp(p.get("limit"), 200, 1, MAX_DECOMPILE_LINES, "limit")
        chunk = lines[offset : offset + limit]
        end = offset + len(chunk)
        callers = self.cmdj(f"axtj @ {addr}") or []
        callees = sorted(
            {
                str(r.get("name"))
                for r in self.cmdj(f"axffj @ {addr}") or []
                if r.get("type") == "CALL"
            }
        )
        return {
            "name": str(fn["name"]),
            "address": hex_addr(addr),
            "signature": str(fn.get("signature") or fn["name"]),
            "total_lines": len(lines),
            "start_line": offset,
            "next_offset": end if end < len(lines) else None,
            "code": "\n".join(chunk),
            "callees": callees,
            "callers_total": len(callers),
            "callers": [
                {"name": str(c.get("fcn_name")), "address": hex_addr(int(c.get("fcn_addr") or 0))}
                for c in callers[:20]
            ],
            "strings": self._string_refs(fn, 30),
        }

    def op_disassemble(self, p: dict[str, Any]) -> dict[str, Any]:
        addr, fn = self._resolve(p.get("target"))
        offset = clamp(p.get("offset"), 0, 0, 10**9, "offset")
        limit = clamp(p.get("limit"), 100, 1, MAX_DISASM_INSTRUCTIONS, "limit")
        if fn is not None and not str(fn["name"]).startswith("sym.imp."):
            ops = (self.cmdj(f"pdfj @ {int(fn['offset'])}") or {}).get("ops", [])
            scope = "function"
        else:
            ops = self.cmdj(f"pdj {offset + limit + 1} @ {addr}") or []
            scope = "address"
        chosen = ops[offset : offset + limit]
        lines = [
            f"{hex_addr(int(o.get('offset', 0)))}  {str(o.get('bytes', '')):<20}  "
            f"{o.get('disasm', o.get('type', ''))}"
            for o in chosen
        ]
        more = offset + len(chosen) < len(ops)
        result: dict[str, Any] = {
            "target": hex_addr(addr),
            "function": str(fn["name"]) if fn else None,
            "scope": scope,
            "offset": offset,
            "returned": len(lines),
            "next_offset": offset + len(lines) if more else None,
            "lines": lines,
        }
        if scope == "function":
            result["total"] = len(ops)
        return result

    def op_xrefs(self, p: dict[str, Any]) -> dict[str, Any]:
        addr, fn = self._resolve(p.get("target"))
        direction = str(p.get("direction") or "to")
        if direction not in ("to", "from"):
            raise BackendError("direction must be 'to' or 'from'", "invalid_parameter")
        target_name = str(fn["name"]) if fn and int(fn["offset"]) == addr else hex_addr(addr)
        rows: list[dict[str, Any]] = []
        if direction == "to":
            for r in self.cmdj(f"axtj @ {addr}") or []:
                rows.append(
                    {
                        "from_address": hex_addr(int(r.get("from", 0))),
                        "from_function": r.get("fcn_name"),
                        "to_address": hex_addr(addr),
                        "to_name": target_name,
                        "ref_type": str(r.get("type", "")),
                    }
                )
        else:
            cmd = f"axffj @ {int(fn['offset'])}" if fn else f"axfj @ {addr}"
            for r in self.cmdj(cmd) or []:
                rows.append(
                    {
                        "from_address": hex_addr(int(r.get("at", r.get("from", 0)))),
                        "from_function": str(fn["name"]) if fn else None,
                        "to_address": hex_addr(int(r.get("ref", r.get("to", 0)))),
                        "to_name": r.get("name"),
                        "ref_type": str(r.get("type", "")),
                    }
                )
        rows.sort(key=lambda r: (r["from_address"], r["to_address"]))
        result = page(
            rows,
            clamp(p.get("offset"), 0, 0, 10**9, "offset"),
            clamp(p.get("limit"), 50, 1, MAX_PAGE, "limit"),
        )
        result["target"] = target_name
        result["direction"] = direction
        return result

    def _code_users(self, addr: int) -> list[str]:
        names: list[str] = []
        for r in self.cmdj(f"axtj @ {addr}") or []:
            name = r.get("fcn_name")
            if name and name not in names:
                names.append(str(name))
        return names

    def _users_via_pointer(self, addr: int, cap: int) -> tuple[list[str], list[str]]:
        """Functions reaching *addr* through a pointer stored in data.

        The same fallback as the Ghidra worker: a string used only through an
        untyped structure field has no direct reference.
        """
        bits = int(((self.cmdj("ij") or {}).get("bin") or {}).get("bits") or 64)
        size = 8 if bits == 64 else 4
        names: list[str] = []
        via: list[str] = []
        for hit in (self.cmdj(f"/v{size}j {addr}") or [])[:5]:
            slot = int(hit.get("offset", 0))
            for back in range(0, 257, size):
                users = self._code_users(slot - back)
                if users:
                    via.append(f"pointer at {hex_addr(slot)} in data at {hex_addr(slot - back)}")
                    names += [u for u in users if u not in names]
                    break
            if len(names) >= cap:
                break
        return names[:cap], via

    def op_strings(self, p: dict[str, Any]) -> dict[str, Any]:
        query = str(p.get("query") or "").lower()
        min_length = clamp(p.get("min_length"), 4, 1, 1000, "min_length")
        if self._strings is None:
            self._strings = [
                {**s, "string": _unescape(str(s.get("string", "")))}
                for s in self.cmdj("izj") or []
            ]
        rows = [
            s
            for s in self._strings
            if int(s.get("length", 0)) >= min_length
            and (not query or query in str(s.get("string", "")).lower())
        ]
        result = page(
            rows,
            clamp(p.get("offset"), 0, 0, 10**9, "offset"),
            clamp(p.get("limit"), 50, 1, MAX_PAGE, "limit"),
        )
        items = []
        for s in result["items"]:
            vaddr = int(s.get("vaddr", 0))
            funcs = self._code_users(vaddr)
            via: list[str] = []
            if not funcs:
                funcs, via = self._users_via_pointer(vaddr, 10)
            value = str(s.get("string", ""))
            item: dict[str, Any] = {
                "address": hex_addr(vaddr),
                "value": value[:_STRING_CAP],
                "functions": funcs[:10],
            }
            if via:
                item["reached_via"] = via
            if len(value) > _STRING_CAP:
                item["value_truncated"] = len(value)
            items.append(item)
        result["items"] = items
        return result

    def op_imports(self, p: dict[str, Any]) -> dict[str, Any]:
        query = str(p.get("query") or "").lower()
        rows = []
        for i in self.cmdj("iij") or []:
            name, lib = str(i.get("name", "")), str(i.get("libname", ""))
            if query and query not in name.lower() and query not in lib.lower():
                continue
            rows.append(i)
        rows.sort(
            key=lambda i: (str(i.get("libname", "")).lower(), str(i.get("name", "")).lower())
        )
        result = page(
            rows,
            clamp(p.get("offset"), 0, 0, 10**9, "offset"),
            clamp(p.get("limit"), 50, 1, MAX_PAGE, "limit"),
        )
        items = []
        for i in result["items"]:
            plt = int(i.get("plt") or 0)
            callers: list[str] = []
            refs = self.cmdj(f"axtj @ {plt}") or [] if plt else []
            stub = self._function_at(plt) if plt else None
            if stub is not None:
                refs += self.cmdj(f"axtj @ {int(stub['offset'])}") or []
            for r in refs:
                name = r.get("fcn_name")
                if name and name not in callers and not str(name).startswith("sym.imp."):
                    callers.append(str(name))
            items.append(
                {
                    "library": i.get("libname"),
                    "name": i.get("name"),
                    "address": hex_addr(plt) if plt else None,
                    "callers_total": len(callers),
                    "callers": callers[:10],
                }
            )
        result["items"] = items
        return result

    def op_read_bytes(self, p: dict[str, Any]) -> dict[str, Any]:
        addr, _fn = self._resolve(p.get("target"))
        length = clamp(p.get("length"), 64, 1, MAX_BYTES, "length")
        values = self.cmdj(f"pxj {length} @ {addr}") or []
        raw = bytes(int(v) & 0xFF for v in values)
        section = self.cmdj(f"iSj. @ {addr}")
        return {
            "address": hex_addr(addr),
            "length": len(raw),
            "requested": length,
            "block": section.get("name") if isinstance(section, dict) else None,
            "hex": raw.hex(),
            "ascii_preview": "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in raw),
        }

    def op_annotate(self, p: dict[str, Any]) -> dict[str, Any]:
        new_name = p.get("new_name") or None
        comment = p.get("comment") or None
        if new_name is None and comment is None:
            raise BackendError("Give new_name, comment or both", "invalid_parameter")
        if new_name is not None:
            validate_name(str(new_name))
        addr, fn = self._resolve(p.get("target"))
        at_entry = fn is not None and int(fn["offset"]) == addr
        old_name = str(fn["name"]) if at_entry and fn else None
        if new_name is not None:
            if at_entry:
                self.cmd(f"afn {new_name} @ {addr}")
            else:
                old_name = self.cmd(f"fd @ {addr}").strip() or None
                self.cmd(f"f {new_name} @ {addr}")
            self._user_names.add(str(new_name))
            self.state["user_names"] = sorted(self._user_names)
        if comment is not None:
            text = (_COMMENT_PREFIX + str(comment)).replace("\n", " ")
            self.cmd(f"CCu base64:{_b64(text)} @ {addr}")
        self._save()
        self._strings = None
        return {
            "address": hex_addr(addr),
            "function": str(new_name) if at_entry and new_name else (fn["name"] if fn else None),
            "old_name": old_name,
            "new_name": new_name,
            "comment": comment,
            "saved": True,
        }

    _CALL_PATH_NODE_CAP = 50_000

    def op_call_path(self, p: dict[str, Any]) -> dict[str, Any]:
        target = self._resolve_function(p.get("target"))
        fns = {int(f["offset"]): f for f in self._functions()}
        roots: list[int] = []
        for e in self.cmdj("iej") or []:
            fn = self._function_at(int(e["vaddr"]))
            if fn:
                roots.append(int(fn["offset"]))
        for f in fns.values():
            if f["name"] in _ENTRY_NAMES:
                roots.append(int(f["offset"]))
        seen: dict[int, tuple[int | None, str]] = {r: (None, "entry") for r in roots}
        queue = list(dict.fromkeys(roots))
        goal = int(target["offset"])
        found = goal in seen
        head = 0
        while not found and head < len(queue) and len(seen) < self._CALL_PATH_NODE_CAP:
            cur = queue[head]
            head += 1
            for ref in (fns.get(cur) or {}).get("callrefs", []) or []:
                nxt = self._function_at(int(ref.get("addr", 0)))
                if nxt is None:
                    continue
                k = int(nxt["offset"])
                if k in seen:
                    continue
                edge = "call" if ref.get("type") == "CALL" else "address_taken"
                seen[k] = (cur, edge)
                fns.setdefault(k, nxt)
                if k == goal:
                    found = True
                    break
                queue.append(k)
        result: dict[str, Any] = {
            "target": str(target["name"]),
            "address": hex_addr(goal),
            "reachable": found,
            "entry_points": [str(fns[r]["name"]) for r in dict.fromkeys(roots) if r in fns][:20],
            "functions_visited": len(seen),
        }
        if found:
            chain: list[dict[str, str]] = []
            step: int | None = goal
            while step is not None:
                parent, edge = seen[step]
                chain.append(
                    {"name": str(fns[step]["name"]), "address": hex_addr(step), "edge": edge}
                )
                step = parent
            result["path"] = list(reversed(chain))
        else:
            result["note"] = (
                "No static path from an entry point. The function may be dead code, library "
                "code, or reached through a pointer computed at run time; check "
                "reverse_xrefs(direction='to') for DATA references."
            )
        return result


def _unescape(text: str) -> str:
    """Undo radare2's C-style escaping of string values (``\\\\`` -> ``\\``)."""
    if "\\" not in text:
        return text
    try:
        return text.encode("latin-1", "backslashreplace").decode("unicode_escape")
    except UnicodeDecodeError:
        return text


def _b64(text: str) -> str:
    import base64

    return base64.b64encode(text.encode("utf-8")).decode("ascii")


_OPS = {
    "info": Radare2Session.op_info,
    "list_functions": Radare2Session.op_list_functions,
    "decompile": Radare2Session.op_decompile,
    "disassemble": Radare2Session.op_disassemble,
    "xrefs": Radare2Session.op_xrefs,
    "strings": Radare2Session.op_strings,
    "imports": Radare2Session.op_imports,
    "read_bytes": Radare2Session.op_read_bytes,
    "annotate": Radare2Session.op_annotate,
    "call_path": Radare2Session.op_call_path,
}


def serve(session: Radare2Session, proto: IO[str], requests: IO[str]) -> None:
    for line in requests:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            _send(proto, {"id": None, "ok": False, "error": _error(ValueError(line[:100]))})
            continue
        rid, op = req.get("id"), req.get("op")
        if op == "shutdown":
            _send(proto, {"id": rid, "ok": True, "result": {}})
            return
        handler = _OPS.get(str(op))
        if handler is None:
            err = {"type": "invalid_parameter", "message": f"Unknown op {op!r}"}
            _send(proto, {"id": rid, "ok": False, "error": err})
            continue
        try:
            _send(
                proto,
                {"id": rid, "ok": True, "result": handler(session, dict(req.get("params") or {}))},
            )
        except Exception as exc:  # noqa: BLE001 - every failure goes back to the caller
            traceback.print_exc(file=sys.stderr)
            _send(proto, {"id": rid, "ok": False, "error": _error(exc)})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", required=True, type=Path)
    parser.add_argument("--project-dir", required=True, type=Path)
    parser.add_argument("--analysis-timeout", type=int, default=600)
    args = parser.parse_args(argv)
    proto = _protocol_stream()
    try:
        session = Radare2Session(args.sample, args.project_dir, args.analysis_timeout)
    except Exception as exc:  # noqa: BLE001
        traceback.print_exc(file=sys.stderr)
        err = _error(exc)
        if err["type"] == "backend_error":
            err["message"] = f"radare2 failed to open the sample: {err['message']}"
        _send(proto, {"id": 0, "ok": False, "error": err})
        return 1
    try:
        _send(proto, {"id": 0, "ok": True, "result": session.op_info({})})
        serve(session, proto, sys.stdin)
    finally:
        session.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
