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


def project_file_for_case(db_dir: Path, case_id: str, sample: Path) -> Path | None:
    """The Ghidra project of the case's sample, if one was created."""
    try:
        sha = sample_sha256(sample)
    except OSError:
        return None
    project = project_dir_for(db_dir, case_id, "ghidra", sample, sha) / PROJECT_FILE
    return project if project.is_file() else None


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

    project = project_file_for_case(db_dir, case_id, sample)
    lines += ["### Ghidra project", ""]
    if project is None:
        lines += ["No Ghidra project was created for this sample.", ""]
    else:
        lines += [
            f"Open `{project}` in Ghidra (File > Open Project) to check the analysis. "
            "Every function or label the agent renamed or commented carries a Note bookmark "
            'in category "mulder" (Window > Bookmarks), and its comments start with '
            "`[mulder]`.",
            "",
        ]
        ann = read_annotations(project.parent)
        rows = ann["annotations"][-_ANNOTATIONS_SHOWN:]
        if rows:
            lines += [
                f"Annotations ({ann['total']}):",
                "",
                "| Address | Old name | New name | Comment |",
                "|---|---|---|---|",
            ]
            lines += [
                f"| `{_md_cell(r.get('address'))}` | {_md_cell(r.get('old_name'))} | "
                f"{_md_cell(r.get('new_name'))} | {_md_cell(r.get('comment'))} |"
                for r in rows
            ]
            if ann["total"] > len(rows):
                lines.append(f"\nFull history: `{ann['file']}`.")
            lines.append("")

    if state["priorities"]:
        lines += ["### Functions studied", "", "| # | Function | Why |", "|---|---|---|"]
        lines += [
            f"| {p.get('rank')} | `{_md_cell(p.get('target'))}` | {_md_cell(p.get('reason'))} |"
            for p in state["priorities"]
        ]
        lines.append("")

    caps = capa_capabilities(get, str(sample))
    if caps is not None:
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
