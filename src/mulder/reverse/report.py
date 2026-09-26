"""Reverse-engineering section of a ``mulder reverse`` report.

Appended by ``finalize_report`` to the rendered report of a reverse case:
the sample, what the pipeline established (priorities, capability
verdicts, counter-analysis), where the annotated Ghidra project is and what
was renamed in it, decoded script layers, and the candidate YARA rule,
marked for human validation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mulder.reverse.backend import project_dir_for, sample_sha256
from mulder.reverse.ghidra_backend import PROJECT_FILE, read_annotations
from mulder.reverse.scripts import LAYERS_MANIFEST
from mulder.reverse.state import SAMPLE_KEY, capa_capabilities, capability_coverage, load_state

__all__ = ["add_reverse_section", "build_reverse_section", "project_file_for_case"]

_ANNOTATIONS_SHOWN = 60


def _md_cell(text: object) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")[:300]


def analysis_project(db_dir: Path, case_id: str, sample: Path) -> tuple[str, Path | None]:
    """``(engine, what the analyst opens)``: Ghidra project, radare2 project or C# tree."""
    try:
        sha = sample_sha256(sample)
    except OSError:
        return "", None
    candidates = (
        ("ghidra", project_dir_for(db_dir, case_id, "ghidra", sample, sha) / PROJECT_FILE),
        ("radare2", project_dir_for(db_dir, case_id, "radare2", sample, sha) / "mulder"),
        ("ilspy", project_dir_for(db_dir, case_id, "ilspy", sample, sha) / "csharp"),
    )
    for kind, path in candidates:
        if path.exists():
            return kind, path
    return "", None


def project_file_for_case(db_dir: Path, case_id: str, sample: Path) -> Path | None:
    """What the analyst opens (see :func:`analysis_project`)."""
    return analysis_project(db_dir, case_id, sample)[1]


def _annotation_table(project_dir: Path, by_address: bool) -> list[str]:
    ann = read_annotations(project_dir)
    rows = ann["annotations"][-_ANNOTATIONS_SHOWN:]
    if not rows:
        return []
    if by_address:
        out = [
            f"Annotations ({ann['total']}):",
            "",
            "| Address | Old name | New name | Comment |",
            "|---|---|---|---|",
        ]
        out += [
            f"| `{_md_cell(r.get('address'))}` | {_md_cell(r.get('old_name'))} | "
            f"{_md_cell(r.get('new_name'))} | {_md_cell(r.get('comment'))} |"
            for r in rows
        ]
    else:
        out = ["| Method | Proposed name | Comment |", "|---|---|---|"]
        out += [
            f"| `{_md_cell(r.get('function'))}` | {_md_cell(r.get('new_name'))} | "
            f"{_md_cell(r.get('comment'))} |"
            for r in rows
        ]
    if ann["total"] > len(rows):
        out.append(f"\nFull history: `{ann['file']}`.")
    out.append("")
    return out


def _project_lines(kind: str, project: Path | None, sample: str) -> list[str]:
    if project is None:
        return ["### Analysis project", "", "No disassembler project was created.", ""]
    if kind == "ghidra":
        return [
            "### Ghidra project",
            "",
            f"Open `{project}` in Ghidra (File > Open Project) to check the analysis. "
            "Every function or label the agent renamed or commented carries a Note bookmark "
            'in category "mulder" (Window > Bookmarks), and its comments start with '
            "`[mulder]`.",
            "",
            *_annotation_table(project.parent, by_address=True),
        ]
    if kind == "radare2":
        from mulder.reverse.export import write_ghidra_replay_script

        script, count = write_ghidra_replay_script(project.parent, sample)
        return [
            "### radare2 project",
            "",
            f"The radare2 project is in `{project}` (r2 -e dir.projects={project.parent} "
            "then `Po mulder`). To carry the analysis into Ghidra, open the sample in "
            f"Ghidra and run `{script}` from the Script Manager: it replays the {count} "
            "annotation(s) below (renames, `[mulder]` comments, Note bookmarks).",
            "",
            *_annotation_table(project.parent, by_address=True),
        ]
    return [
        "### Decompiled C# project (ILSpy)",
        "",
        f"The assembly was decompiled to `{project}`: open it in an editor or in ILSpy "
        "to check the analysis. An assembly cannot be annotated in place, so renames "
        "and comments are listed below and kept in "
        f"`{project.parent / 'annotations.jsonl'}`.",
        "",
        *_annotation_table(project.parent, by_address=False),
    ]


def build_reverse_section(
    db_dir: Path, case_id: str, get: Any, sample_hint: str | None = None
) -> str:
    """Markdown for the reverse-engineering section of the report."""
    sample_str = sample_hint or get(SAMPLE_KEY) or ""
    sample = Path(sample_str) if sample_str else None
    state = load_state(get)
    lines: list[str] = ["", "---", "", "## Reverse engineering (static analysis)", ""]
    if sample is None:
        lines.append("No sample is recorded for this case.")
        return "\n".join(lines) + "\n"
    try:
        sha = sample_sha256(sample)
    except OSError:
        sha = "(sample no longer readable)"
    lines += [
        f"- **Sample:** `{sample}`",
        f"- **SHA-256:** `{sha}`",
        "- **Method:** static analysis only; the sample was never executed, emulated or debugged.",
        "",
    ]

    if state["packed"]:
        lines += [
            "### Packed sample: analysis stopped",
            "",
            f"{state['packed'].get('reason', '')}",
            "",
            "Unpacking is out of scope for this version; the code behind the packer was "
            "not studied.",
            "",
        ]

    kind, project = analysis_project(db_dir, case_id, sample)
    lines += _project_lines(kind, project, str(sample))

    if state["priorities"]:
        lines += ["### Functions studied", "", "| # | Function | Why |", "|---|---|---|"]
        lines += [
            f"| {p.get('rank')} | `{_md_cell(p.get('target'))}` | {_md_cell(p.get('reason'))} |"
            for p in state["priorities"]
        ]
        lines.append("")

    caps = capa_capabilities(get, str(sample))
    if caps is None:
        lines += [
            "### capa capabilities",
            "",
            "capa did not run on this sample: no automatic capability list was cross-checked "
            "against the code.",
            "",
        ]
    else:
        cov = capability_coverage(caps, state["verdicts"])
        lines += [
            "### capa capabilities checked against the code",
            "",
            f"{cov['decided']}/{cov['total']} decided: {len(cov['confirmed'])} confirmed, "
            f"{len(cov['refuted'])} refuted, {len(cov['open'])} not verified.",
            "",
            "| Capability | Verdict | Basis | What the code shows |",
            "|---|---|---|---|",
        ]
        for cap in caps:
            v = state["verdicts"].get(cap["name"])
            if v:
                lines.append(
                    f"| {_md_cell(cap['name'])} | {v['verdict']} | {v['basis']} | "
                    f"{_md_cell(v['note'])} |"
                )
            else:
                lines.append(f"| {_md_cell(cap['name'])} | **not verified** | | |")
        lines.append("")

    if state["challenges"]:
        lines += ["### Counter-analysis", "", "| Finding | Outcome | Reasoning |", "|---|---|---|"]
        lines += [
            f"| {fid} | {c['outcome']} | {_md_cell(c['reasoning'])} |"
            for fid, c in state["challenges"].items()
        ]
        lines.append("")

    layers_dir = project_dir_for(db_dir, case_id, "scripts", sample, sha)
    try:
        layers = json.loads((layers_dir / LAYERS_MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        layers = []
    if layers:
        lines += ["### Decoded script layers", "", "| Layer | Steps | SHA-256 | File |"]
        lines += ["|---|---|---|---|"]
        lines += [
            f"| {e.get('layer_id')} | {'+'.join(e.get('steps', []))} | "
            f"`{str(e.get('sha256', ''))[:16]}...` | `{e.get('path')}` |"
            for e in layers
        ]
        lines.append("")

    lines += ["### Candidate YARA rule", ""]
    if state["yara"]:
        lines += [
            "> **TO BE VALIDATED BY A HUMAN ANALYST.** Generated from the static analysis; "
            "test it against the sample and a clean corpus before deploying it anywhere.",
            "",
            "```",
            str(state["yara"]["rule"]),
            "```",
            "",
        ]
    else:
        lines += ["No YARA rule was proposed.", ""]
    return "\n".join(lines) + "\n"


def add_reverse_section(report_text: str, html_text: str) -> tuple[str, str]:
    """Append the section to the Markdown report and inside the HTML body."""
    from mulder.report.renderer import _markdown_to_safe_html
    from mulder.server.app import get_cfg, get_ctx

    ctx = get_ctx()
    section = build_reverse_section(get_cfg().db_dir, ctx.case_id, ctx.db.get_kv)
    report_text = report_text.rstrip("\n") + "\n" + section
    if html_text:
        block = f'<section class="reverse-engineering">{_markdown_to_safe_html(section)}</section>'
        marker = html_text.rfind("</body>")
        if marker >= 0:
            html_text = html_text[:marker] + block + html_text[marker:]
        else:
            html_text += block
    return report_text, html_text
