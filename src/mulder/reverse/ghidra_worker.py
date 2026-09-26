"""Ghidra engine worker: one child process per analysed sample.

Launched by :class:`mulder.reverse.ghidra_backend.GhidraBackend` as
``python -m mulder.reverse.ghidra_worker --sample ... --project-dir ...``.
It starts a headless Ghidra through pyghidra, opens (or creates) the
project, imports and auto-analyses the sample the first time only, then
answers JSON requests, one per line, on stdin.

Protocol
--------
Request:  ``{"id": 3, "op": "decompile", "params": {"target": "main"}}``
Response: ``{"id": 3, "ok": true, "result": {...}}`` or
          ``{"id": 3, "ok": false, "error": {"type": "not_found", "message": "..."}}``

The first response (id 0) is sent once the program is ready and carries the
``info`` result. The JVM and Ghidra print to stdout (``Picked up
JAVA_TOOL_OPTIONS``, log lines), so before anything else the worker keeps a
private copy of its stdout for the protocol and points file descriptor 1 at
stderr. The parent sends ``{"op": "shutdown"}`` or closes stdin to stop it.

The sample is only ever *read*: nothing here loads it into a process,
emulates it or debugs it.
"""

from __future__ import annotations

import argparse
import json
import os
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
from mulder.reverse.protocol import clamp, hex_addr, page, parse_hex, validate_name

PROJECT_NAME = "mulder"
ANALYSIS_STATE_FILE = "analysis.json"
DECOMPILE_TIMEOUT_S = 60
_STRING_VALUE_CAP = 300
_BOOKMARK_CATEGORY = "mulder"
_COMMENT_PREFIX = "[mulder] "


def _java_bytes(buf: Any, n: int) -> bytes:
    """Python bytes from the first *n* entries of a Java ``byte[]``."""
    try:
        return bytes(memoryview(buf).cast("B")[:n])
    except (TypeError, ValueError):
        return bytes(b & 0xFF for b in buf[:n])


def _protocol_stream() -> IO[str]:
    """Keep the real stdout for the protocol; send fd 1 to stderr."""
    proto_fd = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    return os.fdopen(proto_fd, "w", buffering=1, encoding="utf-8")


def _send(stream: IO[str], msg: dict[str, Any]) -> None:
    stream.write(json.dumps(msg, default=str) + "\n")
    stream.flush()


class GhidraSession:
    """Everything the worker needs to answer operations on one program."""

    def __init__(
        self,
        sample: Path,
        project_dir: Path,
        analysis_timeout: int,
    ) -> None:
        import pyghidra

        self._pyghidra = pyghidra
        self.sample = sample
        self.project_dir = project_dir
        self.project_dir.mkdir(parents=True, exist_ok=True)
        self.project = self._open_project(pyghidra, project_dir)
        self.program_name = sample.name
        root = self.project.getProjectData().getRootFolder()
        self.reused = root.getFile(self.program_name) is not None
        if not self.reused:
            loader = (
                pyghidra.program_loader()
                .project(self.project)
                .source(str(sample))
                .name(self.program_name)
                .projectFolderPath("/")
            )
            with loader.load() as results:
                results.save(pyghidra.task_monitor())
        self.program, self._consumer = pyghidra.consume_program(
            self.project, "/" + self.program_name
        )
        self.state = self._load_state()
        from ghidra.program.util import GhidraProgramUtilities

        if not GhidraProgramUtilities.isAnalyzed(self.program):
            self._analyze(analysis_timeout)
        self._decompiler: Any = None
        self._decomp_cache: dict[int, dict[str, Any]] = {}
        self._call_counts: dict[int, tuple[int, int]] = {}
        self._strings: list[dict[str, Any]] | None = None
        self._ptr_slots: dict[int, list[int]] | None = None

    # -- lifecycle --------------------------------------------------------

    _LOCK_WAIT_S = 60.0

    @classmethod
    def _open_project(cls, pyghidra: Any, project_dir: Path) -> Any:
        """Open the project, waiting while another worker still holds its lock.

        Each agent session runs its own MCP server and so its own worker; the
        previous session's worker can still be closing the project when the
        next one starts.
        """
        deadline = time.monotonic() + cls._LOCK_WAIT_S
        while True:
            try:
                return pyghidra.open_project(str(project_dir), PROJECT_NAME, create=True)
            except Exception as exc:
                if "lock" not in str(exc).lower() or time.monotonic() > deadline:
                    raise
                print(f"project locked, waiting: {exc}", file=sys.stderr, flush=True)
                time.sleep(1.0)

    def _state_path(self) -> Path:
        return self.project_dir / ANALYSIS_STATE_FILE

    def _load_state(self) -> dict[str, Any]:
        try:
            data = json.loads(self._state_path().read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _analyze(self, timeout: int) -> None:
        pg = self._pyghidra
        monitor = pg.task_monitor(max(1, int(timeout)))
        t0 = time.monotonic()
        pg.analyze(self.program, monitor)
        elapsed = round(time.monotonic() - t0, 1)
        # pyghidra cancels the monitor itself when analysis ends, so the
        # only sign of a timeout is having used the whole budget.
        completed = elapsed < timeout
        self.program.save("mulder auto-analysis", pg.task_monitor())
        self.state = {
            "analysis_seconds": elapsed,
            "analysis_completed": bool(completed),
            "analysis_timeout": timeout,
            "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self._state_path().write_text(json.dumps(self.state, indent=2), encoding="utf-8")

    def close(self) -> None:
        try:
            if self._decompiler is not None:
                self._decompiler.dispose()
            self.program.release(self._consumer)
        finally:
            self.project.close()

    # -- resolution -------------------------------------------------------

    def _addr(self, value: int) -> Any:
        space = self.program.getAddressFactory().getDefaultAddressSpace()
        return space.getAddress(value)

    def _fm(self) -> Any:
        return self.program.getFunctionManager()

    def _functions_named(self, name: str) -> list[Any]:
        fm = self._fm()
        found = [f for f in fm.getFunctions(True) if f.getName() == name]
        if not found:
            found = [f for f in fm.getExternalFunctions() if f.getName() == name]
        return found

    def _resolve(self, target: Any) -> tuple[Any, Any]:
        """Return ``(address, function_or_None)`` for a name or hex address.

        For an external (imported) function the address is its EXTERNAL
        location; callers that need memory use :meth:`_resolve_memory`.
        """
        if not isinstance(target, str) or not target.strip():
            raise BackendError("target is required (a name or a hex address)", "invalid_parameter")
        target = target.strip()
        funcs = self._functions_named(target)
        if funcs:
            f = funcs[0]
            return f.getEntryPoint(), f
        st = self.program.getSymbolTable()
        for sym in st.getSymbols(target):
            addr = sym.getAddress()
            return addr, self._fm().getFunctionContaining(addr)
        value = parse_hex(target)
        if value is not None:
            addr = self._addr(value)
            if not self.program.getMemory().contains(addr):
                raise BackendError(
                    f"Address {hex_addr(value)} is not in the program's memory", "not_found"
                )
            return addr, self._fm().getFunctionContaining(addr)
        raise BackendError(
            f"No function, symbol or address matches {target!r}. "
            "Use list_functions, imports or strings to find a valid target.",
            "not_found",
        )

    def _resolve_function(self, target: Any) -> Any:
        addr, func = self._resolve(target)
        if func is None:
            raise BackendError(
                f"{target!r} ({self._fmt(addr)}) is not inside a function", "not_found"
            )
        if func.isExternal():
            raise BackendError(
                f"{func.getName()} is an imported function: its code is not in this sample. "
                "Use xrefs to see who calls it.",
                "invalid_parameter",
            )
        return func

    def _fmt(self, addr: Any) -> str:
        if addr is None:
            return ""
        if addr.isExternalAddress():
            return f"EXTERNAL:{addr.getOffset():x}"
        return hex_addr(int(addr.getOffset()))

    # -- descriptions -----------------------------------------------------

    def _origin(self, func: Any) -> str:
        from ghidra.program.model.symbol import SourceType

        src = func.getSymbol().getSource()
        if src == SourceType.DEFAULT:
            return "unnamed"
        if src == SourceType.USER_DEFINED:
            return "user"
        if src == SourceType.ANALYSIS:
            return "analysis"
        return "symbol"

    def _is_fid(self, func: Any) -> bool:
        bm = self.program.getBookmarkManager()
        for b in bm.getBookmarks(func.getEntryPoint()):
            if "Function ID" in str(b.getCategory()):
                return True
        return False

    def _is_library(self, func: Any) -> bool:
        return bool(func.isExternal() or func.isThunk() or self._is_fid(func))

    def _counts(self, func: Any) -> tuple[int, int]:
        key = int(func.getEntryPoint().getOffset())
        if key not in self._call_counts:
            mon = self._pyghidra.task_monitor()
            self._call_counts[key] = (
                int(func.getCallingFunctions(mon).size()),
                int(func.getCalledFunctions(mon).size()),
            )
        return self._call_counts[key]

    def _describe(self, func: Any) -> dict[str, Any]:
        callers, callees = self._counts(func)
        return {
            "name": str(func.getName()),
            "address": self._fmt(func.getEntryPoint()),
            "size": int(func.getBody().getNumAddresses()),
            "origin": self._origin(func),
            "library": self._is_library(func),
            "thunk": bool(func.isThunk()),
            "signature": str(func.getSignature().getPrototypeString()),
            "callers": callers,
            "callees": callees,
        }

    # -- operations -------------------------------------------------------

    def op_info(self, _p: dict[str, Any]) -> dict[str, Any]:
        prog = self.program
        fm = self._fm()
        total = lib = thunk = 0
        origins: dict[str, int] = {}
        for f in fm.getFunctions(True):
            total += 1
            if f.isThunk():
                thunk += 1
            if self._is_library(f):
                lib += 1
            o = self._origin(f)
            origins[o] = origins.get(o, 0) + 1
        imports = sum(1 for _ in fm.getExternalFunctions())
        entries: list[dict[str, Any]] = []
        it = prog.getSymbolTable().getExternalEntryPointIterator()
        while it.hasNext() and len(entries) < 20:
            a = it.next()
            f = fm.getFunctionAt(a)
            entries.append({"address": self._fmt(a), "name": f.getName() if f else None})
        lang = prog.getLanguage()
        return {
            "sample": str(self.sample),
            "program_name": self.program_name,
            "format": str(prog.getExecutableFormat()),
            "language": str(prog.getLanguageID()),
            "processor": str(lang.getProcessor()),
            "address_size": int(lang.getLanguageDescription().getSize()),
            "endian": "big" if lang.isBigEndian() else "little",
            "compiler": str(prog.getCompilerSpec().getCompilerSpecID()),
            "image_base": self._fmt(prog.getImageBase()),
            "sha256": str(prog.getExecutableSHA256() or ""),
            "functions": {
                "total": total,
                "library": lib,
                "thunk": thunk,
                "by_origin": origins,
            },
            "imports": imports,
            "entry_points": entries,
            "analysis_seconds": self.state.get("analysis_seconds"),
            "analysis_completed": self.state.get("analysis_completed", True),
            "project_reused": self.reused,
            "project_dir": str(self.project_dir),
            "project_file": str(self.project_dir / f"{PROJECT_NAME}.gpr"),
        }

    def op_list_functions(self, p: dict[str, Any]) -> dict[str, Any]:
        query = str(p.get("query") or "").lower()
        origins_raw = p.get("origin") or ""
        origins = {o.strip() for o in str(origins_raw).split(",") if o.strip()}
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
        offset = clamp(p.get("offset"), 0, 0, 10**9, "offset")
        limit = clamp(p.get("limit"), 50, 1, MAX_PAGE, "limit")
        rows = []
        hidden_library = 0
        for f in self._fm().getFunctions(True):
            if query and query not in f.getName().lower():
                continue
            if f.isThunk() and not include_thunks:
                if not include_library:
                    hidden_library += 1
                continue
            if not include_library and self._is_library(f):
                hidden_library += 1
                continue
            if origins and self._origin(f) not in origins:
                continue
            rows.append(f)
        if sort == "address":
            described = None
        else:
            described = [self._describe(f) for f in rows]
            described.sort(key=lambda d: -int(d[sort]))
        if described is None:
            result = page(rows, offset, limit)
            result["items"] = [self._describe(f) for f in result["items"]]
        else:
            result = page(described, offset, limit)
        result["library_hidden"] = hidden_library
        return result

    def _decompiler_iface(self) -> Any:
        if self._decompiler is None:
            from ghidra.app.decompiler import DecompileOptions, DecompInterface

            d = DecompInterface()
            opts = DecompileOptions()
            opts.grabFromProgram(self.program)
            d.setOptions(opts)
            if not d.openProgram(self.program):
                raise BackendError(
                    f"Decompiler failed to start: {d.getLastMessage()}", "backend_error"
                )
            self._decompiler = d
        return self._decompiler

    def _referenced_strings(self, func: Any, cap: int) -> list[dict[str, str]]:
        listing = self.program.getListing()
        out: list[dict[str, str]] = []
        seen: set[int] = set()
        for ins in listing.getInstructions(func.getBody(), True):
            for ref in ins.getReferencesFrom():
                to = ref.getToAddress()
                if not to.isMemoryAddress():
                    continue
                data = listing.getDataAt(to)
                value = self._string_value(data)
                if value is None and data is not None and data.isPointer():
                    # One level of indirection: a pointer to a string.
                    target = data.getValue()
                    if target is not None:
                        value = self._string_value(listing.getDataAt(target))
                        to = target
                if value is None or int(to.getOffset()) in seen:
                    continue
                seen.add(int(to.getOffset()))
                out.append({"address": self._fmt(to), "value": value[:_STRING_VALUE_CAP]})
                if len(out) >= cap:
                    return out
        return out

    @staticmethod
    def _string_value(data: Any) -> str | None:
        if data is None or not data.hasStringValue():
            return None
        v = data.getValue()
        return None if v is None else str(v)

    def _decompiled(self, func: Any) -> dict[str, Any]:
        key = int(func.getEntryPoint().getOffset())
        if key in self._decomp_cache:
            return self._decomp_cache[key]
        d = self._decompiler_iface()
        res = d.decompileFunction(func, DECOMPILE_TIMEOUT_S, self._pyghidra.task_monitor())
        if res is None or not res.decompileCompleted():
            msg = res.getErrorMessage() if res is not None else "no result"
            raise BackendError(
                f"Decompilation of {func.getName()} failed: {msg}. Try disassemble instead.",
                "backend_error",
            )
        code = str(res.getDecompiledFunction().getC())
        lines = code.strip("\n").split("\n")
        mon = self._pyghidra.task_monitor()
        callees = sorted({str(c.getName()) for c in func.getCalledFunctions(mon)}, key=str.lower)
        callers = [
            {"name": str(c.getName()), "address": self._fmt(c.getEntryPoint())}
            for c in func.getCallingFunctions(mon)
        ]
        entry = {
            "name": str(func.getName()),
            "address": self._fmt(func.getEntryPoint()),
            "signature": str(func.getSignature().getPrototypeString()),
            "lines": lines,
            "callees": callees,
            "callers_total": len(callers),
            "callers": callers[:20],
            "strings": self._referenced_strings(func, 30),
        }
        self._decomp_cache[key] = entry
        return entry

    def op_decompile(self, p: dict[str, Any]) -> dict[str, Any]:
        func = self._resolve_function(p.get("target"))
        offset = clamp(p.get("offset"), 0, 0, 10**9, "offset")
        limit = clamp(p.get("limit"), 200, 1, MAX_DECOMPILE_LINES, "limit")
        entry = self._decompiled(func)
        lines: list[str] = entry["lines"]
        chunk = lines[offset : offset + limit]
        end = offset + len(chunk)
        return {
            "name": entry["name"],
            "address": entry["address"],
            "signature": entry["signature"],
            "total_lines": len(lines),
            "start_line": offset,
            "next_offset": end if end < len(lines) else None,
            "code": "\n".join(chunk),
            "callees": entry["callees"],
            "callers_total": entry["callers_total"],
            "callers": entry["callers"],
            "strings": entry["strings"],
        }

    def op_disassemble(self, p: dict[str, Any]) -> dict[str, Any]:
        addr, func = self._resolve(p.get("target"))
        offset = clamp(p.get("offset"), 0, 0, 10**9, "offset")
        limit = clamp(p.get("limit"), 100, 1, MAX_DISASM_INSTRUCTIONS, "limit")
        listing = self.program.getListing()
        if func is not None and not func.isExternal():
            it = listing.getInstructions(func.getBody(), True)
            scope = "function"
        else:
            if addr.isExternalAddress():
                raise BackendError("An imported function has no code here", "invalid_parameter")
            it = listing.getInstructions(addr, True)
            scope = "address"
        lines: list[str] = []
        more = False
        for idx, ins in enumerate(it):
            if idx >= offset + limit:
                more = True
                break
            if idx >= offset:
                raw = bytes(b & 0xFF for b in ins.getBytes()).hex()
                lines.append(f"{self._fmt(ins.getAddress())}  {raw:<20}  {ins}")
        result: dict[str, Any] = {
            "target": self._fmt(addr),
            "function": func.getName() if func is not None else None,
            "scope": scope,
            "offset": offset,
            "returned": len(lines),
            "next_offset": offset + len(lines) if more else None,
            "lines": lines,
        }
        if scope == "function":
            result["total"] = sum(1 for _ in listing.getInstructions(func.getBody(), True))
        return result

    def _code_callers(self, addr: Any, depth: int = 0) -> list[tuple[Any, Any, str]]:
        """References to *addr* that come from code, following data hops.

        A PE calls an import through its IAT slot, and a string is often
        reached through a pointer in a data structure: when a reference
        starts in data, look one level further for the code that uses it.
        """
        rm = self.program.getReferenceManager()
        listing = self.program.getListing()
        fm = self._fm()
        out: list[tuple[Any, Any, str]] = []
        for ref in rm.getReferencesTo(addr):
            frm = ref.getFromAddress()
            if listing.getInstructionAt(frm) is not None:
                out.append((frm, fm.getFunctionContaining(frm), str(ref.getReferenceType())))
            elif depth < 1 and frm.isMemoryAddress():
                data = listing.getDataContaining(frm)
                start = data.getMinAddress() if data is not None else frm
                out.extend(self._code_callers(start, depth + 1))
        return out

    def _refs_to(self, addr: Any, func: Any) -> list[tuple[Any, Any, str]]:
        found = self._code_callers(addr)
        if func is None:
            return found
        # Calls that reach this function through a thunk count as calls to
        # it; the jump inside the thunk itself is plumbing, not a caller.
        thunks = [str(a) for a in (func.getFunctionThunkAddresses(True) or [])]
        for thunk_addr in func.getFunctionThunkAddresses(True) or []:
            found.extend(self._code_callers(thunk_addr))
        return [
            (frm, f, t) for frm, f, t in found if f is None or str(f.getEntryPoint()) not in thunks
        ]

    def op_xrefs(self, p: dict[str, Any]) -> dict[str, Any]:
        addr, func = self._resolve(p.get("target"))
        direction = str(p.get("direction") or "to")
        if direction not in ("to", "from"):
            raise BackendError("direction must be 'to' or 'from'", "invalid_parameter")
        offset = clamp(p.get("offset"), 0, 0, 10**9, "offset")
        limit = clamp(p.get("limit"), 50, 1, MAX_PAGE, "limit")
        target_name = func.getName() if func is not None else self._fmt(addr)
        rows: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        if direction == "to":
            for frm, f, rtype in self._refs_to(addr, func):
                key = (self._fmt(frm), "")
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    {
                        "from_address": self._fmt(frm),
                        "from_function": f.getName() if f is not None else None,
                        "to_address": self._fmt(addr),
                        "to_name": target_name,
                        "ref_type": rtype,
                    }
                )
        else:
            rm = self.program.getReferenceManager()
            fm = self._fm()
            st = self.program.getSymbolTable()
            if func is not None and not func.isExternal():
                sources = func.getBody().getAddresses(True)
            else:
                sources = [addr]
            for a in sources:
                for ref in rm.getReferencesFrom(a):
                    to = ref.getToAddress()
                    if not (to.isMemoryAddress() or to.isExternalAddress()):
                        continue  # stack and register references
                    key = (self._fmt(a), self._fmt(to))
                    if key in seen:
                        continue
                    seen.add(key)
                    tf = fm.getFunctionAt(to)
                    sym = st.getPrimarySymbol(to)
                    name = tf.getName() if tf is not None else (sym.getName() if sym else None)
                    rows.append(
                        {
                            "from_address": self._fmt(a),
                            "from_function": func.getName() if func is not None else None,
                            "to_address": self._fmt(to),
                            "to_name": name,
                            "ref_type": str(ref.getReferenceType()),
                        }
                    )
        rows.sort(key=lambda r: (r["from_address"], r["to_address"]))
        result = page(rows, offset, limit)
        result["target"] = target_name
        result["direction"] = direction
        return result

    def _all_strings(self) -> list[dict[str, Any]]:
        if self._strings is None:
            from ghidra.program.util import DefinedStringIterator

            rows: list[dict[str, Any]] = []
            for data in DefinedStringIterator.forProgram(self.program):
                value = self._string_value(data)
                if value is None:
                    continue
                rows.append({"addr": data.getAddress(), "value": value})
            self._strings = rows
        return self._strings

    def _functions_using(self, addr: Any, cap: int) -> tuple[list[str], list[str]]:
        """Functions that use the data at *addr*, and how they were found.

        Returns ``(names, via)``: *via* lists the pointer slots used when no
        direct reference exists (a string reached only through an
        undefined structure field, which Ghidra's analysis does not type).
        """
        names: list[str] = []
        via: list[str] = []
        for _frm, f, _t in self._code_callers(addr):
            if f is not None and f.getName() not in names:
                names.append(str(f.getName()))
            if len(names) >= cap:
                return names, via
        if names:
            return names, via
        for slot in self._pointer_slots().get(int(addr.getOffset()), [])[:5]:
            base = self._referenced_base(slot)
            if base is None:
                continue
            via.append(f"pointer at {self._fmt(self._addr(slot))} in data at {self._fmt(base)}")
            for _frm, f, _t in self._code_callers(base, depth=1):
                if f is not None and f.getName() not in names:
                    names.append(str(f.getName()))
                if len(names) >= cap:
                    return names, via
        return names, via

    _POINTER_SCAN_CAP = 64 * 1024 * 1024
    _STRUCT_LOOKBACK = 256

    def _pointer_slots(self) -> dict[int, list[int]]:
        """Map each in-memory address value to the data slots that hold it.

        Built once per session from initialised, non-executable blocks, and
        skipped for programs with more than 64 MiB of such data.
        """
        if self._ptr_slots is not None:
            return self._ptr_slots
        from jpype import JArray, JByte

        self._ptr_slots = {}
        mem = self.program.getMemory()
        size = int(self.program.getDefaultPointerSize())
        if size not in (4, 8):
            return self._ptr_slots
        blocks = [
            b
            for b in mem.getBlocks()
            if b.isInitialized() and not b.isExecute() and b.getStart().isMemoryAddress()
        ]
        if sum(int(b.getSize()) for b in blocks) > self._POINTER_SCAN_CAP:
            return self._ptr_slots
        lo = int(mem.getMinAddress().getOffset())
        hi = int(mem.getMaxAddress().getOffset())
        little = not self.program.getLanguage().isBigEndian()
        for b in blocks:
            n = int(b.getSize())
            buf = JArray(JByte)(n)
            got = int(b.getBytes(b.getStart(), buf))
            raw = _java_bytes(buf, got)
            start = int(b.getStart().getOffset())
            first = (-start) % size
            for i in range(first, got - size + 1, size):
                v = int.from_bytes(raw[i : i + size], "little" if little else "big")
                if lo <= v <= hi:
                    self._ptr_slots.setdefault(v, []).append(start + i)
        return self._ptr_slots

    def _referenced_base(self, slot: int) -> Any:
        """Closest address at or before *slot* that code references."""
        rm = self.program.getReferenceManager()
        listing = self.program.getListing()
        for back in range(0, self._STRUCT_LOOKBACK + 1):
            a = self._addr(slot - back)
            for ref in rm.getReferencesTo(a):
                if listing.getInstructionAt(ref.getFromAddress()) is not None:
                    return a
        return None

    def op_strings(self, p: dict[str, Any]) -> dict[str, Any]:
        query = str(p.get("query") or "").lower()
        min_length = clamp(p.get("min_length"), 4, 1, 1000, "min_length")
        offset = clamp(p.get("offset"), 0, 0, 10**9, "offset")
        limit = clamp(p.get("limit"), 50, 1, MAX_PAGE, "limit")
        rows = [
            s
            for s in self._all_strings()
            if len(s["value"]) >= min_length and (not query or query in s["value"].lower())
        ]
        result = page(rows, offset, limit)
        items = []
        for s in result["items"]:
            value: str = s["value"]
            names, via = self._functions_using(s["addr"], 10)
            item: dict[str, Any] = {
                "address": self._fmt(s["addr"]),
                "value": value[:_STRING_VALUE_CAP],
                "functions": names,
            }
            if via:
                item["reached_via"] = via
            if len(value) > _STRING_VALUE_CAP:
                item["value_truncated"] = len(value)
            items.append(item)
        result["items"] = items
        return result

    def op_imports(self, p: dict[str, Any]) -> dict[str, Any]:
        query = str(p.get("query") or "").lower()
        offset = clamp(p.get("offset"), 0, 0, 10**9, "offset")
        limit = clamp(p.get("limit"), 50, 1, MAX_PAGE, "limit")
        rows = []
        for f in self._fm().getExternalFunctions():
            name = str(f.getName())
            loc = f.getExternalLocation()
            lib = str(loc.getLibraryName()) if loc is not None else ""
            if query and query not in name.lower() and query not in lib.lower():
                continue
            rows.append((lib, name, f))
        rows.sort(key=lambda r: (r[0].lower(), r[1].lower()))
        result = page(rows, offset, limit)
        items = []
        rm = self.program.getReferenceManager()
        for lib, name, f in result["items"]:
            slot = None
            for ref in rm.getReferencesTo(f.getEntryPoint()):
                if ref.getFromAddress().isMemoryAddress():
                    slot = self._fmt(ref.getFromAddress())
                    break
            callers: list[str] = []
            for _frm, cf, _t in self._refs_to(f.getEntryPoint(), f):
                if cf is not None and cf.getName() not in callers:
                    callers.append(str(cf.getName()))
            items.append(
                {
                    "library": lib,
                    "name": name,
                    "address": slot,
                    "callers_total": len(callers),
                    "callers": callers[:10],
                }
            )
        result["items"] = items
        return result

    def op_read_bytes(self, p: dict[str, Any]) -> dict[str, Any]:
        addr, _func = self._resolve(p.get("target"))
        if addr.isExternalAddress():
            raise BackendError("An imported function has no bytes here", "invalid_parameter")
        length = clamp(p.get("length"), 64, 1, MAX_BYTES, "length")
        from jpype import JArray, JByte

        mem = self.program.getMemory()
        block = mem.getBlock(addr)
        available = int(block.getEnd().subtract(addr)) + 1 if block is not None else 0
        n = min(length, available)
        buf = JArray(JByte)(n)
        got = int(mem.getBytes(addr, buf)) if n > 0 else 0
        raw = _java_bytes(buf, got)
        return {
            "address": self._fmt(addr),
            "length": len(raw),
            "requested": length,
            "block": str(block.getName()) if block is not None else None,
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
        addr, func = self._resolve(p.get("target"))
        if addr.isExternalAddress():
            raise BackendError("Imported functions cannot be annotated", "invalid_parameter")
        from ghidra.program.model.listing import CommentType
        from ghidra.program.model.symbol import SourceType

        pg = self._pyghidra
        st = self.program.getSymbolTable()
        listing = self.program.getListing()
        old_name: str | None
        if func is not None and func.getEntryPoint().equals(addr):
            old_name = str(func.getName())
        else:
            sym = st.getPrimarySymbol(addr)
            old_name = str(sym.getName()) if sym is not None else None
        with pg.transaction(self.program, "mulder annotate"):
            if new_name is not None:
                if func is not None and func.getEntryPoint().equals(addr):
                    func.setName(str(new_name), SourceType.USER_DEFINED)
                else:
                    sym = st.getPrimarySymbol(addr)
                    if sym is not None and not sym.isDynamic():
                        sym.setName(str(new_name), SourceType.USER_DEFINED)
                    else:
                        st.createLabel(addr, str(new_name), SourceType.USER_DEFINED)
            if comment is not None:
                kind = (
                    CommentType.PLATE
                    if func is not None and func.getEntryPoint().equals(addr)
                    else CommentType.PRE
                )
                text = _COMMENT_PREFIX + str(comment)
                existing = listing.getComment(kind, addr)
                if existing and text not in existing:
                    text = f"{existing}\n{text}"
                listing.setComment(addr, kind, text)
            note = []
            if new_name is not None:
                note.append(f"renamed {old_name} -> {new_name}")
            if comment is not None:
                note.append(str(comment)[:200])
            from ghidra.program.model.listing import BookmarkType

            self.program.getBookmarkManager().setBookmark(
                addr, BookmarkType.NOTE, _BOOKMARK_CATEGORY, "; ".join(note)
            )
        self.program.save("mulder annotate", pg.task_monitor())
        # Names changed: decompiled text and caches are stale.
        self._decomp_cache.clear()
        self._strings = None
        return {
            "address": self._fmt(addr),
            "function": func.getName() if func is not None else None,
            "old_name": old_name,
            "new_name": new_name,
            "comment": comment,
            "saved": True,
        }

    _CALL_PATH_NODE_CAP = 50_000

    def _successors(self, func: Any) -> list[tuple[Any, str]]:
        """Functions *func* calls, or whose address its code takes."""
        mon = self._pyghidra.task_monitor()
        fm = self._fm()
        out: dict[int, tuple[Any, str]] = {}
        for callee in func.getCalledFunctions(mon):
            if callee.isThunk():
                real = callee.getThunkedFunction(True)
                callee = real if real is not None else callee
            out.setdefault(int(callee.getEntryPoint().getOffset()), (callee, "call"))
        listing = self.program.getListing()
        for ins in listing.getInstructions(func.getBody(), True):
            for ref in ins.getReferencesFrom():
                to = ref.getToAddress()
                if not to.isMemoryAddress():
                    continue
                target = fm.getFunctionAt(to)
                if target is not None and not target.equals(func):
                    out.setdefault(int(to.getOffset()), (target, "address_taken"))
        return list(out.values())

    def op_call_path(self, p: dict[str, Any]) -> dict[str, Any]:
        """Shortest static path from an entry point to *target*, if any."""
        target = self._resolve_function(p.get("target"))
        fm = self._fm()
        roots: list[Any] = []
        it = self.program.getSymbolTable().getExternalEntryPointIterator()
        while it.hasNext():
            f = fm.getFunctionAt(it.next())
            if f is not None:
                roots.append(f)
        for name in ("main", "wmain", "WinMain", "wWinMain", "DllMain"):
            roots.extend(self._functions_named(name))
        roots = [r for r in roots if not r.isExternal()]
        seen: dict[int, tuple[int | None, str]] = {}
        queue: list[Any] = []
        for r in roots:
            key = int(r.getEntryPoint().getOffset())
            if key not in seen:
                seen[key] = (None, "entry")
                queue.append(r)
        goal = int(target.getEntryPoint().getOffset())
        by_key: dict[int, Any] = {int(r.getEntryPoint().getOffset()): r for r in roots}
        found = goal in seen
        head = 0
        while not found and head < len(queue) and len(seen) < self._CALL_PATH_NODE_CAP:
            cur = queue[head]
            head += 1
            cur_key = int(cur.getEntryPoint().getOffset())
            for nxt, edge in self._successors(cur):
                k = int(nxt.getEntryPoint().getOffset())
                if k in seen or nxt.isExternal():
                    continue
                seen[k] = (cur_key, edge)
                by_key[k] = nxt
                if k == goal:
                    found = True
                    break
                queue.append(nxt)
        result: dict[str, Any] = {
            "target": str(target.getName()),
            "address": self._fmt(target.getEntryPoint()),
            "reachable": found,
            "entry_points": [str(r.getName()) for r in roots[:20]],
            "functions_visited": len(seen),
        }
        if found:
            chain: list[dict[str, str]] = []
            k: int | None = goal
            while k is not None:
                parent, edge = seen[k]
                f = by_key[k]
                chain.append(
                    {
                        "name": str(f.getName()),
                        "address": self._fmt(f.getEntryPoint()),
                        "edge": edge,
                    }
                )
                k = parent
            result["path"] = list(reversed(chain))
            result["note"] = (
                "edge=call is a direct call; edge=address_taken means the caller takes the "
                "function's address (callback, thread start, table) and may call it indirectly."
            )
        else:
            result["note"] = (
                "No static path from an entry point. The function may be dead code, library "
                "code, or reached through a pointer computed at run time (vtable, resolved "
                "API, callback); check reverse_xrefs(direction='to') for DATA references."
            )
            if len(seen) >= self._CALL_PATH_NODE_CAP:
                result["note"] += " The search stopped at its node limit."
        return result


_OPS = {
    "info": GhidraSession.op_info,
    "list_functions": GhidraSession.op_list_functions,
    "decompile": GhidraSession.op_decompile,
    "disassemble": GhidraSession.op_disassemble,
    "xrefs": GhidraSession.op_xrefs,
    "strings": GhidraSession.op_strings,
    "imports": GhidraSession.op_imports,
    "read_bytes": GhidraSession.op_read_bytes,
    "annotate": GhidraSession.op_annotate,
    "call_path": GhidraSession.op_call_path,
}


def _error(exc: BaseException) -> dict[str, str]:
    if isinstance(exc, BackendError):
        return {"type": exc.error_type, "message": str(exc)}
    return {"type": "backend_error", "message": f"{type(exc).__name__}: {exc}"}


def serve(session: GhidraSession, proto: IO[str], requests: IO[str]) -> None:
    """Answer requests until ``shutdown`` or end of input."""
    for line in requests:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            _send(proto, {"id": None, "ok": False, "error": _error(ValueError(line[:100]))})
            continue
        rid = req.get("id")
        op = req.get("op")
        if op == "shutdown":
            _send(proto, {"id": rid, "ok": True, "result": {}})
            return
        handler = _OPS.get(str(op))
        if handler is None:
            _send(
                proto,
                {
                    "id": rid,
                    "ok": False,
                    "error": {"type": "invalid_parameter", "message": f"Unknown op {op!r}"},
                },
            )
            continue
        try:
            result = handler(session, dict(req.get("params") or {}))
            _send(proto, {"id": rid, "ok": True, "result": result})
        except Exception as exc:  # noqa: BLE001 - every failure goes back to the caller
            traceback.print_exc(file=sys.stderr)
            _send(proto, {"id": rid, "ok": False, "error": _error(exc)})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", required=True, type=Path)
    parser.add_argument("--project-dir", required=True, type=Path)
    parser.add_argument("--ghidra-dir", required=True, type=Path)
    parser.add_argument("--analysis-timeout", type=int, default=600)
    parser.add_argument("--maxmem", default="4G")
    args = parser.parse_args(argv)

    proto = _protocol_stream()
    try:
        from pyghidra.launcher import HeadlessPyGhidraLauncher

        launcher = HeadlessPyGhidraLauncher(install_dir=args.ghidra_dir)
        launcher.add_vmargs(f"-Xmx{args.maxmem}", "-Djava.awt.headless=true")
        launcher.start()
        session = GhidraSession(args.sample, args.project_dir, args.analysis_timeout)
    except Exception as exc:  # noqa: BLE001
        traceback.print_exc(file=sys.stderr)
        err = _error(exc)
        if err["type"] == "backend_error":
            err["message"] = f"Ghidra failed to open the sample: {err['message']}"
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
