"""Export recorded annotations as a script that replays them in Ghidra.

``annotations.jsonl`` is engine-neutral: an analysis made with radare2
(or with Ghidra on another machine) can be carried into the analyst's own
Ghidra project by running the generated script from Ghidra's Script
Manager with the sample open. It renames functions and labels, adds the
``[mulder]`` comments and a Note bookmark in category ``mulder`` at each
annotated address. It works in both Jython and PyGhidra.
"""

from __future__ import annotations

import json
import pprint
import re
from pathlib import Path
from typing import Any

from mulder.reverse.ghidra_backend import ANNOTATIONS_FILE

__all__ = ["GHIDRA_SCRIPT_NAME", "ghidra_replay_script", "write_ghidra_replay_script"]

GHIDRA_SCRIPT_NAME = "mulder_annotations_ghidra.py"
_ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")

_TEMPLATE = """# Replays the annotations Mulder recorded for {sample}
# ({count} annotation(s), from {source}).
# Run it from Ghidra's Script Manager with that sample open.
# @category Mulder
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

ANNOTATIONS = {annotations}


def apply(program):
    space = program.getAddressFactory().getDefaultAddressSpace()
    functions = program.getFunctionManager()
    symbols = program.getSymbolTable()
    listing = program.getListing()
    bookmarks = program.getBookmarkManager()
    memory = program.getMemory()
    applied = skipped = 0
    tx = program.startTransaction("mulder annotations")
    try:
        for a in ANNOTATIONS:
            addr = space.getAddress(int(a["address"], 16))
            if not memory.contains(addr):
                skipped += 1
                continue
            func = functions.getFunctionAt(addr)
            note = []
            if a.get("new_name"):
                if func is not None:
                    func.setName(a["new_name"], SourceType.USER_DEFINED)
                else:
                    symbols.createLabel(addr, a["new_name"], SourceType.USER_DEFINED)
                note.append("renamed %s -> %s" % (a.get("old_name"), a["new_name"]))
            if a.get("comment"):
                kind = CodeUnit.PLATE_COMMENT if func is not None else CodeUnit.PRE_COMMENT
                text = "[mulder] " + a["comment"]
                old = listing.getComment(kind, addr)
                if old and text not in old:
                    text = old + "\\n" + text
                listing.setComment(addr, kind, text)
                note.append(a["comment"][:200])
            bookmarks.setBookmark(addr, "Note", "mulder", "; ".join(note))
            applied += 1
    finally:
        program.endTransaction(tx, True)
    return applied, skipped


applied, skipped = apply(currentProgram)  # noqa: F821 - provided by Ghidra
print("Mulder: %d annotation(s) applied, %d skipped (address not in memory)" % (applied, skipped))
"""


def _rows(project_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    path = project_dir / ANNOTATIONS_FILE
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return rows
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict) or not _ADDR_RE.fullmatch(str(row.get("address") or "")):
            continue  # ILSpy annotations (file:line) have no address to replay
        rows.append(
            {
                "address": row["address"],
                "old_name": row.get("old_name"),
                "new_name": row.get("new_name"),
                "comment": row.get("comment"),
            }
        )
    return rows


def ghidra_replay_script(project_dir: Path, sample: str) -> tuple[str, int]:
    """The script text and how many annotations it replays."""
    rows = _rows(project_dir)
    text = _TEMPLATE.format(
        sample=sample.replace("\n", " "),
        count=len(rows),
        source=project_dir / ANNOTATIONS_FILE,
        annotations=pprint.pformat(rows, indent=4, width=96),
    )
    return text, len(rows)


def write_ghidra_replay_script(project_dir: Path, sample: str) -> tuple[Path, int]:
    """Write the script beside the annotations; return its path and count."""
    text, count = ghidra_replay_script(project_dir, sample)
    path = project_dir / GHIDRA_SCRIPT_NAME
    path.write_text(text, encoding="utf-8")
    return path, count
