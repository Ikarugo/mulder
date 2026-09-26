"""Scripted demonstration of the reverse-engineering pipeline on the toy sample.

Plays, without any LLM, the tool calls the ``mulder reverse`` agents make on
``tests/fixtures/reverse/toy_beacon.c`` (a harmless program that only prints
text), then runs the real quality gates and ``finalize_report``. It checks
the deterministic half of the pipeline end to end and leaves a report and an
annotated Ghidra project to open:

    x86_64-w64-mingw32-gcc -O1 -o /tmp/toy.exe tests/fixtures/reverse/toy_beacon.c
    python scripts/reverse_toy_demo.py /tmp/toy.exe /tmp/toy-demo

Needs Ghidra, pyghidra and a JDK (see docs/reverse-engineering.md).
"""

from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    sample, db_dir = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()

    from mulder.orchestrator.reverse_gates import (
        validate_re_counter,
        validate_re_deep,
        validate_re_mapping,
    )
    from mulder.orchestrator.reverse_phases import RE_REPORT
    from mulder.orchestrator.reverse_runner import ReverseOrchestrator
    from mulder.orchestrator.types import PhaseResult
    from mulder.reverse import get_backend

    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = ReverseOrchestrator(
            sample_path=sample, cwd=db_dir / "workspace", case_id="toy-demo", db_dir=db_dir
        )
    orch.prepare_case()

    from mulder.server.app import _tool_dispatch_sync as tools

    def call(name: str, **kw: Any) -> dict[str, Any]:
        r: dict[str, Any] = tools[name](**kw)
        if r.get("status") == "error":
            raise SystemExit(f"{name} failed: {r.get('error_type')}: {r.get('error_message')}")
        return r

    s = str(sample)
    info = call("reverse_analyze", file_path=s)["results"]
    print(f"analysed: {info['format']}, {info['functions']['total']} functions")
    call("reverse_map_sample", file_path=s)
    main_fn = call("reverse_decompile", file_path=s, target="main")
    blob = re.search(r"xor_decode\((0x[0-9a-f]+)", main_fn["results"]["code"])
    if blob is None:
        raise SystemExit("unexpected decompilation of main")
    raw = call("reverse_read_bytes", file_path=s, target=blob.group(1), length=32)
    url = bytes(b ^ 0x5A for b in bytes.fromhex(raw["results"]["hex"])).decode()
    print(f"decoded C2 URL: {url}")
    persist = call("reverse_decompile", file_path=s, target="install_persistence")

    call(
        "reverse_prioritize",
        functions=[
            {
                "target": "xor_decode",
                "reason": "XOR loop over a .rdata blob that main then uses as a URL",
                "evidence_refs": [main_fn["tool_call_id"]],
                "rank": 1,
            },
            {
                "target": "install_persistence",
                "reason": "formats the Run key path from g_config",
                "evidence_refs": [persist["tool_call_id"]],
                "rank": 2,
            },
        ],
    )
    print("mapping gate:", validate_re_mapping(orch.snapshot()).passed)

    call(
        "reverse_annotate",
        file_path=s,
        target="xor_decode",
        new_name="decode_c2_url",
        comment="XORs the embedded C2 URL with key 0x5A",
    )
    f1 = call(
        "submit_finding",
        title="Decodes an embedded C2 URL with single-byte XOR 0x5A",
        description=f"main passes the blob at {blob.group(1)} to decode_c2_url (XOR 0x5A): {url}",
        severity="high",
        confidence="confirmed",
        evidence_refs=[main_fn["tool_call_id"], raw["tool_call_id"]],
        sources=["reverse.decompile"],
        mitre_attack_ids=["T1140"],
    )
    call(
        "submit_finding",
        title="Would persist through the HKCU Run key ToyBeacon",
        description="install_persistence formats HKCU\\Software\\Microsoft\\Windows\\"
        "CurrentVersion\\Run\\ToyBeacon but only prints it",
        severity="medium",
        confidence="inference",
        evidence_refs=[persist["tool_call_id"]],
        sources=["reverse.decompile"],
        mitre_attack_ids=["T1547.001"],
    )
    call(
        "reverse_submit_yara",
        rule="rule toy_beacon { strings: $enc = { 32 2e 2e 2a 60 75 75 39 } "
        '$run = "Run\\\\ToyBeacon" condition: uint16(0) == 0x5a4d and all of them }',
        evidence_refs=[raw["tool_call_id"]],
    )
    print("deep gate:", validate_re_deep(orch.snapshot()).passed)

    path = call("reverse_call_path", file_path=s, target="decode_c2_url")
    call(
        "reverse_challenge",
        finding_id=f1["finding_id"],
        outcome="upheld",
        reasoning="reachable from the entry point through main; not library code",
        evidence_refs=[path["tool_call_id"]],
    )
    call("audit_evidence_coverage")
    call("audit_tool_coverage")
    print("counter gate:", validate_re_counter(orch.snapshot()).passed)

    call(
        "submit_narrative",
        narrative="## Summary\nThe toy sample decodes a C2 URL with XOR 0x5A and would "
        "write a Run key; it only prints what it would do.\n",
    )
    orch._phase_started_at = time.time() - 1
    report = call("finalize_report")
    gate = asyncio.run(orch._validate_phase(RE_REPORT, PhaseResult(phase_name="re_report")))
    print("report gate:", gate.passed if gate else None)
    print("report:", report["report_path"])
    print("ghidra project:", info["project_file"])
    get_backend("ghidra").close()
    return 0 if gate and gate.passed else 1


if __name__ == "__main__":
    sys.exit(main())
