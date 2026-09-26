""".NET backend: decompile managed assemblies to C# with ILSpy (``ilspycmd``).

Ghidra reads .NET poorly: it sees the CLR loader stub and IL bytes, not
classes and methods. ILSpy decompiles the metadata and IL back to readable
C#. This backend runs ``ilspycmd`` once per sample to write the C# project
and the IL listing into the project directory, indexes types, methods,
string literals and P/Invoke imports from them, and answers the common
operations from that index:

* ``list_functions`` lists methods (``Namespace.Type::Method``);
* ``decompile`` returns a method, or a whole type, as C#;
* ``disassemble`` returns a method's IL;
* ``xrefs``, ``strings``, ``imports``, ``call_path`` work on the C# text.

Cross-references and call paths are computed from the source text, not
from resolved metadata tokens: an overloaded or common method name can
match more than it should, and every result says so (``approximate``).
``annotate`` cannot rename inside an assembly; it records the annotation
in ``annotations.jsonl`` only. The sample is never loaded into a runtime.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mulder.reverse.backend import (
    MAX_BYTES,
    MAX_DECOMPILE_LINES,
    MAX_DISASM_INSTRUCTIONS,
    MAX_PAGE,
    OPERATIONS,
    BackendError,
    BackendTimeout,
    BackendUnavailable,
)
from mulder.reverse.ghidra_backend import (
    ANNOTATIONS_FILE,
    SESSION_FILE,
    append_annotation,
    read_annotations,
)
from mulder.reverse.protocol import clamp, page, validate_name

__all__ = ["IlspyBackend", "find_ilspycmd"]

INDEX_FILE = "ilspy_index.json"
SOURCE_DIR = "csharp"
IL_DIR = "il"
_APPROXIMATE = (
    "Computed from the decompiled C# text (name matching), not from resolved metadata: "
    "overloads and common names can over-match."
)
_STRING_CAP = 300

_TYPE_RE = re.compile(
    r"^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static|sealed|abstract|"
    r"partial|unsafe|new|readonly|ref|file)\s+)*(class|struct|interface|enum|record)\s+"
    r"(@?[A-Za-z_][\w`]*)"
)
_NAMESPACE_RE = re.compile(r"^\s*namespace\s+([\w.]+)")
_METHOD_RE = re.compile(
    r"^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static|virtual|override|"
    r"abstract|sealed|async|extern|unsafe|new|partial|readonly)\s+)*"
    r"(?:[\w<>\[\],.?\s]+?\s+)?(@?[A-Za-z_]\w*|operator\s*\S+)\s*(?:<[^>]*>)?\s*\((.*)\)\s*"
    r"(?:where\s.*)?(?:;)?$"
)
_KEYWORDS = frozenset(
    {"if", "for", "foreach", "while", "switch", "catch", "using", "lock", "return", "new",
     "else", "fixed", "checked", "unchecked", "nameof", "typeof", "sizeof", "default", "when"}
)  # fmt: skip
_STRING_RE = re.compile(r'@?"(?:[^"\\]|\\.|"")*"')
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:<[^>()]*>)?\s*\(")
_DLLIMPORT_RE = re.compile(r'\[DllImport\(\s*"([^"]+)"')
_EXTERN_RE = re.compile(r"\bstatic\s+extern\s+[\w<>\[\],.?\s]+?\s+(\w+)\s*\(")
_REFERENCE_RE = re.compile(r'<Reference Include="([^"]+)"')
_IL_NAME_RE = re.compile(r"(\.ctor|\.cctor|[A-Za-z_][\w`]*|'[^']+')\s*\(")


def find_ilspycmd() -> str | None:
    """``MULDER_ILSPYCMD``, then ``ilspycmd`` on PATH, then ``~/.dotnet/tools``."""
    configured = os.environ.get("MULDER_ILSPYCMD")
    if configured:
        return configured if Path(configured).exists() else None
    found = shutil.which("ilspycmd")
    if found:
        return found
    candidate = Path.home() / ".dotnet" / "tools" / "ilspycmd"
    return str(candidate) if candidate.exists() else None


@dataclass
class _Method:
    type_name: str
    name: str
    signature: str
    file: str
    start: int
    end: int
    callees: list[str] = field(default_factory=list)

    @property
    def full(self) -> str:
        return f"{self.type_name}::{self.name}"

    @property
    def address(self) -> str:
        return f"{self.file}:{self.start + 1}"


def _strip_code(line: str) -> str:
    """The line without string literals and // comments, for brace counting."""
    line = _STRING_RE.sub('""', line)
    line = re.sub(r"'(?:[^'\\]|\\.)'", "''", line)
    idx = line.find("//")
    return line[:idx] if idx >= 0 else line


def _parse_file(rel: str, lines: list[str]) -> tuple[list[_Method], list[dict[str, Any]]]:
    """Methods and types of one C# file (ILSpy's Allman-style output)."""
    methods: list[_Method] = []
    types: list[dict[str, Any]] = []
    namespace = ""
    stack: list[tuple[str, int]] = []  # (type full name, depth at which its body opens)
    depth = 0
    pending_type: str | None = None
    pending_method: tuple[str, str, int] | None = None
    open_method: tuple[str, str, int, int] | None = None  # name, sig, start, body depth
    for i, raw in enumerate(lines):
        code = _strip_code(raw)
        m_ns = _NAMESPACE_RE.match(code)
        if m_ns and open_method is None:
            namespace = m_ns.group(1)
        m_type = _TYPE_RE.match(code) if open_method is None else None
        if m_type:
            outer = stack[-1][0] if stack else namespace
            name = m_type.group(2).lstrip("@")
            full = f"{outer}.{name}" if outer else name
            pending_type = full
            types.append({"name": full, "kind": m_type.group(1), "file": rel, "line": i + 1})
            if code.rstrip().endswith(";"):
                pending_type = None  # record/struct with positional syntax only
        elif open_method is None and stack and pending_type is None:
            m_meth = _METHOD_RE.match(code)
            if m_meth and m_meth.group(1) not in _KEYWORDS and "=" not in code.split("(")[0]:
                if code.rstrip().endswith(";"):  # abstract, interface, extern
                    methods.append(_Method(stack[-1][0], m_meth.group(1), raw.strip(), rel, i, i))
                else:
                    pending_method = (m_meth.group(1), raw.strip(), i)
        opens = code.count("{")
        closes = code.count("}")
        if opens:
            if pending_type is not None:
                stack.append((pending_type, depth + 1))
                pending_type = None
            elif pending_method is not None and open_method is None:
                name, sig, start = pending_method
                open_method = (name, sig, start, depth + 1)
                pending_method = None
        depth += opens - closes
        if open_method is not None and depth < open_method[3]:
            name, sig, start, _d = open_method
            methods.append(_Method(stack[-1][0], name, sig, rel, start, i))
            open_method = None
        while stack and depth < stack[-1][1]:
            stack.pop()
        if pending_method is not None and not opens and code.strip() and i > pending_method[2]:
            # Expression-bodied members and field initialisers are not methods with bodies.
            if "=>" in code:
                name, sig, start = pending_method
                methods.append(_Method(stack[-1][0] if stack else "", name, sig, rel, start, i))
            pending_method = None
    return methods, types


class _Index:
    """Everything answered from the decompiled output of one assembly."""

    def __init__(self, project_dir: Path) -> None:
        self.project_dir = project_dir
        self.src = project_dir / SOURCE_DIR
        self.files: dict[str, list[str]] = {}
        for path in sorted(self.src.rglob("*.cs")):
            rel = str(path.relative_to(self.src))
            self.files[rel] = path.read_text(encoding="utf-8", errors="replace").split("\n")
        self.methods: list[_Method] = []
        self.types: list[dict[str, Any]] = []
        for rel, lines in self.files.items():
            ms, ts = _parse_file(rel, lines)
            self.methods.extend(ms)
            self.types.extend(ts)
        names = {m.name for m in self.methods}
        for m in self.methods:
            body = "\n".join(_strip_code(x) for x in self.files[m.file][m.start + 1 : m.end + 1])
            m.callees = sorted({c for c in _CALL_RE.findall(body) if c in names and c != m.name})
        self.callers: dict[str, set[str]] = {}
        for m in self.methods:
            for c in m.callees:
                self.callers.setdefault(c, set()).add(m.full)
        self.il: list[str] = []
        for path in sorted((project_dir / IL_DIR).rglob("*.il")):
            self.il.extend(path.read_text(encoding="utf-8", errors="replace").split("\n"))
        self.references: list[str] = []
        for proj in self.src.rglob("*.csproj"):
            self.references += _REFERENCE_RE.findall(proj.read_text(errors="replace"))

    # -- lookup ---------------------------------------------------------------

    def method_at(self, file: str, line: int) -> _Method | None:
        for m in self.methods:
            if m.file == file and m.start <= line <= m.end:
                return m
        return None

    def resolve(self, target: Any) -> tuple[_Method | None, dict[str, Any] | None]:
        """``(method, None)`` or ``(None, type)`` for a target, else raise."""
        if not isinstance(target, str) or not target.strip():
            raise BackendError(
                "target is required (Type, Type::Method or Method)", "invalid_parameter"
            )
        t = target.strip().replace("::", "|").replace("..", "|.")
        if "|" in t:
            type_part, meth = t.split("|", 1)
        elif "." in t and not any(ty["name"] == t for ty in self.types):
            type_part, meth = t.rsplit(".", 1)
        else:
            type_part, meth = "", t
        if re.fullmatch(r".+\.cs:\d+", target.strip()):
            file, line = target.strip().rsplit(":", 1)
            m = self.method_at(file, int(line) - 1)
            if m is None:
                raise BackendError(f"No method at {target}", "not_found")
            return m, None
        cands = [
            m
            for m in self.methods
            if m.name == meth
            and (
                not type_part or m.type_name == type_part or m.type_name.endswith("." + type_part)
            )
        ]
        if cands:
            if len({c.full for c in cands}) > 1:
                raise BackendError(
                    f"{target!r} is ambiguous: {', '.join(sorted({c.full for c in cands})[:10])}. "
                    "Use Namespace.Type::Method.",
                    "invalid_parameter",
                )
            return cands[0], None
        for ty in self.types:
            if ty["name"] == target.strip() or ty["name"].endswith("." + target.strip()):
                return None, ty
        raise BackendError(
            f"No type or method matches {target!r}. Use list_functions to find one.", "not_found"
        )

    def method_lines(self, m: _Method) -> list[str]:
        return self.files[m.file][m.start : m.end + 1]

    def type_lines(self, ty: dict[str, Any]) -> list[str]:
        lines = self.files[ty["file"]]
        start = ty["line"] - 1
        depth = 0
        seen = False
        for i in range(start, len(lines)):
            code = _strip_code(lines[i])
            depth += code.count("{") - code.count("}")
            seen = seen or "{" in code
            if seen and depth <= 0:
                return lines[start : i + 1]
        return lines[start:]


def _run_ilspy(cmd: list[str], timeout_s: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd, capture_output=True, text=True, timeout=timeout_s, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise BackendTimeout(f"ilspycmd did not finish within {int(timeout_s)} s") from exc
    except OSError as exc:
        raise BackendUnavailable(f"Cannot run ilspycmd: {exc}") from exc


class IlspyBackend:
    """:class:`~mulder.reverse.backend.ReverseBackend` for .NET assemblies."""

    name = "ilspy"

    def __init__(self, ilspycmd: str | None = None) -> None:
        self.ilspycmd = ilspycmd or find_ilspycmd()
        self._indexes: dict[Path, _Index] = {}

    def check(self) -> str | None:
        if not self.ilspycmd:
            return (
                "ilspycmd was not found: install it with 'dotnet tool install -g ilspycmd' "
                "(needs a .NET SDK) or set MULDER_ILSPYCMD."
            )
        return None

    def is_open(self, project_dir: Path) -> bool:
        return project_dir in self._indexes

    def _decompile(self, sample: Path, project_dir: Path, timeout_s: float) -> None:
        assert self.ilspycmd is not None
        src = project_dir / SOURCE_DIR
        il = project_dir / IL_DIR
        for out, extra in ((src, ["-p"]), (il, ["-il"])):
            if out.exists():
                shutil.rmtree(out)
            out.mkdir(parents=True)
            base = [self.ilspycmd, str(sample), *extra, "-o", str(out)]
            proc = _run_ilspy([*base, "--disable-updatecheck"], timeout_s)
            if proc.returncode != 0 and "disable-updatecheck" in (proc.stderr + proc.stdout):
                proc = _run_ilspy(base, timeout_s)  # older ilspycmd without the flag
            if proc.returncode != 0:
                tail = "\n".join((proc.stderr or proc.stdout).strip().splitlines()[-10:])
                raise BackendError(
                    f"ilspycmd failed (exit {proc.returncode}): {tail}", "backend_error"
                )
        if not any(src.rglob("*.cs")):
            raise BackendError(
                "ilspycmd produced no C#: the file is probably not a .NET assembly.",
                "backend_error",
            )

    def analyze(self, sample: Path, project_dir: Path, timeout_s: float) -> dict[str, Any]:
        reason = self.check()
        if reason:
            raise BackendUnavailable(reason)
        project_dir.mkdir(parents=True, exist_ok=True)
        reused = (project_dir / INDEX_FILE).is_file() and any(
            (project_dir / SOURCE_DIR).rglob("*.cs")
        )
        if not reused:
            self._decompile(sample, project_dir, timeout_s)
        index = _Index(project_dir)
        self._indexes[project_dir] = index
        info = self._info(index, sample, reused)
        (project_dir / INDEX_FILE).write_text(json.dumps(info, indent=2), encoding="utf-8")
        state = {"sample": str(sample), "backend": self.name, "program_name": sample.name}
        (project_dir / SESSION_FILE).write_text(json.dumps(state, indent=2), encoding="utf-8")
        return info

    def _index(self, project_dir: Path) -> _Index:
        if project_dir in self._indexes:
            return self._indexes[project_dir]
        if not (project_dir / INDEX_FILE).is_file():
            raise BackendError(
                "This sample has not been analysed yet: call reverse_analyze first.",
                "not_analyzed",
            )
        index = _Index(project_dir)
        self._indexes[project_dir] = index
        return index

    def _info(self, index: _Index, sample: Path, reused: bool) -> dict[str, Any]:
        entry = [m for m in index.methods if m.name == "Main"]
        return {
            "sample": str(sample),
            "program_name": sample.name,
            "format": ".NET assembly (decompiled by ILSpy)",
            "language": "CIL / C#",
            "types": len(index.types),
            "functions": {
                "total": len(index.methods),
                "library": 0,
                "thunk": 0,
                "by_origin": {"symbol": len(index.methods)},
            },
            "imports": len(self._pinvokes(index)),
            "references": index.references[:50],
            "entry_points": [{"name": m.full, "address": m.address} for m in entry[:20]],
            "project_reused": reused,
            "project_dir": str(index.project_dir),
            "source_dir": str(index.src),
            "note": "Open the C# project in source_dir with any editor or ILSpy; "
            "annotations are recorded in annotations.jsonl.",
        }

    def close(self, project_dir: Path | None = None) -> None:
        if project_dir is None:
            self._indexes.clear()
        else:
            self._indexes.pop(project_dir, None)

    # -- operations ---------------------------------------------------------------

    def call(
        self, project_dir: Path, op: str, params: dict[str, Any], timeout_s: float
    ) -> dict[str, Any]:
        if op not in OPERATIONS:
            raise BackendError(f"Unknown operation {op!r}", "invalid_parameter")
        unknown = set(params) - set(OPERATIONS[op])
        if unknown:
            raise BackendError(
                f"Unexpected parameter(s) for {op}: {', '.join(sorted(unknown))}",
                "invalid_parameter",
            )
        p = {k: v for k, v in params.items() if v is not None}
        if op == "annotations":
            return read_annotations(project_dir)
        index = self._index(project_dir)
        handler = getattr(self, f"_op_{op}")
        result: dict[str, Any] = handler(index, p)
        if op == "annotate":
            append_annotation(project_dir, self.name, result)
        return result

    def _describe(self, index: _Index, m: _Method) -> dict[str, Any]:
        return {
            "name": m.full,
            "address": m.address,
            "size": m.end - m.start + 1,
            "origin": "symbol",
            "library": False,
            "thunk": False,
            "signature": m.signature,
            "callers": len(index.callers.get(m.name, ())),
            "callees": len(m.callees),
        }

    def _op_info(self, index: _Index, _p: dict[str, Any]) -> dict[str, Any]:
        state = json.loads((index.project_dir / SESSION_FILE).read_text(encoding="utf-8"))
        return self._info(index, Path(state["sample"]), True)

    def _op_list_functions(self, index: _Index, p: dict[str, Any]) -> dict[str, Any]:
        query = str(p.get("query") or "").lower()
        sort = str(p.get("sort") or "address")
        if sort not in ("address", "size", "callers", "callees"):
            raise BackendError(
                "sort must be address, size, callers or callees", "invalid_parameter"
            )
        rows = [self._describe(index, m) for m in index.methods if query in m.full.lower()]
        if sort != "address":
            rows.sort(key=lambda r: -int(r[sort]))
        result = page(
            rows,
            clamp(p.get("offset"), 0, 0, 10**9, "offset"),
            clamp(p.get("limit"), 50, 1, MAX_PAGE, "limit"),
        )
        result["library_hidden"] = 0
        result["approximate"] = "callers/callees: " + _APPROXIMATE
        return result

    def _op_decompile(self, index: _Index, p: dict[str, Any]) -> dict[str, Any]:
        m, ty = index.resolve(p.get("target"))
        lines = index.method_lines(m) if m else index.type_lines(ty or {})
        offset = clamp(p.get("offset"), 0, 0, 10**9, "offset")
        limit = clamp(p.get("limit"), 200, 1, MAX_DECOMPILE_LINES, "limit")
        chunk = lines[offset : offset + limit]
        end = offset + len(chunk)
        strings: list[dict[str, str]] = []
        for i, line in enumerate(lines):
            for lit in _STRING_RE.findall(line):
                value = lit[2:-1] if lit.startswith("@") else lit[1:-1]
                strings.append({"address": f"line {i + 1}", "value": value[:_STRING_CAP]})
        return {
            "name": m.full if m else (ty or {}).get("name"),
            "address": m.address if m else f"{(ty or {}).get('file')}:{(ty or {}).get('line')}",
            "signature": m.signature
            if m
            else f"{(ty or {}).get('kind')} {(ty or {}).get('name')}",
            "total_lines": len(lines),
            "start_line": offset,
            "next_offset": end if end < len(lines) else None,
            "code": "\n".join(chunk),
            "callees": m.callees if m else [],
            "callers_total": len(index.callers.get(m.name, ())) if m else 0,
            "callers": [{"name": c} for c in sorted(index.callers.get(m.name, ()))][:20]
            if m
            else [],
            "strings": strings[:30],
            "language": "C#",
        }

    def _op_disassemble(self, index: _Index, p: dict[str, Any]) -> dict[str, Any]:
        m, _ty = index.resolve(p.get("target"))
        if m is None:
            raise BackendError("disassemble needs a method, not a type", "invalid_parameter")
        start = None
        wanted = {m.name, ".ctor" if m.name == m.type_name.rsplit(".", 1)[-1] else m.name}
        for i, line in enumerate(index.il):
            if not line.lstrip().startswith(".method"):
                continue
            # ILSpy spreads the header over several lines; the name precedes "(".
            mm = _IL_NAME_RE.search(" ".join(index.il[i : i + 6]).split(".method", 1)[1])
            if mm and mm.group(1).strip("'") in wanted and self._il_owner(index.il, i, m):
                start = i
                break
        if start is None:
            raise BackendError(f"No IL found for {m.full}", "not_found")
        body: list[str] = []
        depth = 0
        seen = False
        for line in index.il[start:]:
            body.append(line)
            depth += line.count("{") - line.count("}")
            seen = seen or "{" in line
            if seen and depth <= 0:
                break
        offset = clamp(p.get("offset"), 0, 0, 10**9, "offset")
        limit = clamp(p.get("limit"), 100, 1, MAX_DISASM_INSTRUCTIONS, "limit")
        chunk = body[offset : offset + limit]
        end = offset + len(chunk)
        return {
            "target": m.full,
            "function": m.full,
            "scope": "function",
            "offset": offset,
            "returned": len(chunk),
            "next_offset": end if end < len(body) else None,
            "total": len(body),
            "lines": chunk,
            "language": "CIL",
        }

    @staticmethod
    def _il_owner(il: list[str], i: int, m: _Method) -> bool:
        """True when the .method at line *i* belongs to *m*'s type (best effort)."""
        short = m.type_name.rsplit(".", 1)[-1]
        for line in il[i : i + 400]:
            if "// end of method" in line:
                return f"{short}::" in line
        return True

    def _op_xrefs(self, index: _Index, p: dict[str, Any]) -> dict[str, Any]:
        m, ty = index.resolve(p.get("target"))
        name = m.name if m else str((ty or {}).get("name", "")).rsplit(".", 1)[-1]
        direction = str(p.get("direction") or "to")
        if direction not in ("to", "from"):
            raise BackendError("direction must be 'to' or 'from'", "invalid_parameter")
        rows: list[dict[str, Any]] = []
        if direction == "to":
            pattern = re.compile(rf"\b{re.escape(name)}\b")
            for rel, lines in index.files.items():
                for i, line in enumerate(lines):
                    if pattern.search(_strip_code(line)):
                        caller = index.method_at(rel, i)
                        if m is not None and caller is m:
                            continue
                        rows.append(
                            {
                                "from_address": f"{rel}:{i + 1}",
                                "from_function": caller.full if caller else None,
                                "to_address": m.address if m else None,
                                "to_name": m.full if m else name,
                                "ref_type": "text",
                            }
                        )
        elif m is not None:
            rows = [
                {
                    "from_address": m.address,
                    "from_function": m.full,
                    "to_address": None,
                    "to_name": c,
                    "ref_type": "call (text)",
                }
                for c in m.callees
            ]
        result = page(
            rows,
            clamp(p.get("offset"), 0, 0, 10**9, "offset"),
            clamp(p.get("limit"), 50, 1, MAX_PAGE, "limit"),
        )
        result["target"] = m.full if m else name
        result["direction"] = direction
        result["approximate"] = _APPROXIMATE
        return result

    def _op_strings(self, index: _Index, p: dict[str, Any]) -> dict[str, Any]:
        query = str(p.get("query") or "").lower()
        min_length = clamp(p.get("min_length"), 4, 1, 1000, "min_length")
        seen: dict[str, dict[str, Any]] = {}
        for rel, lines in index.files.items():
            for i, line in enumerate(lines):
                for lit in _STRING_RE.findall(line):
                    value = lit[2:-1] if lit.startswith("@") else lit[1:-1]
                    if len(value) < min_length or (query and query not in value.lower()):
                        continue
                    row = seen.setdefault(
                        value,
                        {
                            "address": f"{rel}:{i + 1}",
                            "value": value[:_STRING_CAP],
                            "functions": [],
                        },
                    )
                    owner = index.method_at(rel, i)
                    if owner and owner.full not in row["functions"] and len(row["functions"]) < 10:
                        row["functions"].append(owner.full)
        return page(
            list(seen.values()),
            clamp(p.get("offset"), 0, 0, 10**9, "offset"),
            clamp(p.get("limit"), 50, 1, MAX_PAGE, "limit"),
        )

    def _pinvokes(self, index: _Index) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for rel, lines in index.files.items():
            lib = None
            for i, line in enumerate(lines):
                dm = _DLLIMPORT_RE.search(line)
                if dm:
                    lib = dm.group(1)
                em = _EXTERN_RE.search(line)
                if em:
                    name = em.group(1)
                    callers = sorted(index.callers.get(name, ()))
                    rows.append(
                        {
                            "library": lib or "?",
                            "name": name,
                            "address": f"{rel}:{i + 1}",
                            "callers_total": len(callers),
                            "callers": callers[:10],
                            "kind": "P/Invoke",
                        }
                    )
                    lib = None
        return rows

    def _op_imports(self, index: _Index, p: dict[str, Any]) -> dict[str, Any]:
        query = str(p.get("query") or "").lower()
        rows = [
            r
            for r in self._pinvokes(index)
            if not query or query in r["name"].lower() or query in str(r["library"]).lower()
        ]
        rows += [
            {"library": ref, "name": "(assembly reference)", "address": None, "callers": []}
            for ref in index.references
            if not query or query in ref.lower()
        ]
        return page(
            rows,
            clamp(p.get("offset"), 0, 0, 10**9, "offset"),
            clamp(p.get("limit"), 50, 1, MAX_PAGE, "limit"),
        )

    def _op_read_bytes(self, index: _Index, p: dict[str, Any]) -> dict[str, Any]:
        target = str(p.get("target") or "")
        m = re.fullmatch(r"(?:0x)?([0-9a-fA-F]+)", target.strip())
        if not m:
            raise BackendError(
                "For a .NET assembly, read_bytes takes a file offset in hex (e.g. 0x2a0).",
                "invalid_parameter",
            )
        state = json.loads((index.project_dir / SESSION_FILE).read_text(encoding="utf-8"))
        length = clamp(p.get("length"), 64, 1, MAX_BYTES, "length")
        offset = int(m.group(1), 16)
        with open(state["sample"], "rb") as fh:
            fh.seek(offset)
            raw = fh.read(length)
        return {
            "address": f"0x{offset:x}",
            "length": len(raw),
            "requested": length,
            "block": "file",
            "hex": raw.hex(),
            "ascii_preview": "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in raw),
        }

    def _op_annotate(self, index: _Index, p: dict[str, Any]) -> dict[str, Any]:
        new_name = p.get("new_name") or None
        comment = p.get("comment") or None
        if new_name is None and comment is None:
            raise BackendError("Give new_name, comment or both", "invalid_parameter")
        if new_name is not None:
            validate_name(str(new_name))
        m, ty = index.resolve(p.get("target"))
        return {
            "address": m.address if m else f"{(ty or {}).get('file')}:{(ty or {}).get('line')}",
            "function": m.full if m else (ty or {}).get("name"),
            "old_name": m.full if m else (ty or {}).get("name"),
            "new_name": new_name,
            "comment": comment,
            "saved": False,
            "note": "An assembly is not modified: the annotation is recorded in "
            f"{ANNOTATIONS_FILE} only.",
        }

    def _op_call_path(self, index: _Index, p: dict[str, Any]) -> dict[str, Any]:
        target, _ty = index.resolve(p.get("target"))
        if target is None:
            raise BackendError("call_path needs a method, not a type", "invalid_parameter")
        by_name: dict[str, list[_Method]] = {}
        for m in index.methods:
            by_name.setdefault(m.name, []).append(m)
        roots = by_name.get("Main", [])
        seen: dict[str, str | None] = {r.full: None for r in roots}
        queue = list(roots)
        found = target.full in seen
        while queue and not found:
            cur = queue.pop(0)
            for callee in cur.callees:
                for nxt in by_name.get(callee, []):
                    if nxt.full not in seen:
                        seen[nxt.full] = cur.full
                        if nxt.full == target.full:
                            found = True
                            break
                        queue.append(nxt)
                if found:
                    break
        result: dict[str, Any] = {
            "target": target.full,
            "address": target.address,
            "reachable": found,
            "entry_points": [r.full for r in roots],
            "functions_visited": len(seen),
            "approximate": _APPROXIMATE,
        }
        if found:
            chain: list[dict[str, str]] = []
            cur_name: str | None = target.full
            while cur_name is not None:
                chain.append({"name": cur_name, "address": "", "edge": "call (text)"})
                cur_name = seen[cur_name]
            result["path"] = list(reversed(chain))
        else:
            result["note"] = (
                "No path from Main by name: the method may be reached through reflection, "
                "events, delegates or a framework entry point (service, form, handler)."
            )
        return result
