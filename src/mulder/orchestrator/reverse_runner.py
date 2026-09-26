"""Orchestrator of the static malware analysis pipeline (``mulder reverse``).

Reuses the forensic orchestrator's machinery (split-phase planner /
executor / analyst sessions, retries on gate failure, continuations,
dashboard, LiteLLM proxy) with its own phases, roles and gates:

    triage -> mapping -> deep analysis -> counter-analysis -> report

The route depends on the sample: native executables go through the
disassembler; scripts are read and decoded layer by layer during triage;
.NET assemblies, documents and unknown files get triage only, with a
clear warning. A packed sample stops after mapping.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from mulder.orchestrator.gates import GateResult
from mulder.orchestrator.phases import PhaseConfig
from mulder.orchestrator.reverse_gates import (
    NATIVE_KINDS,
    validate_re_counter,
    validate_re_deep,
    validate_re_mapping,
    validate_re_report,
    validate_re_triage,
)
from mulder.orchestrator.reverse_phases import (
    RE_COUNTER,
    RE_DEEP,
    RE_MAPPING,
    RE_REPORT,
    RE_TRIAGE,
)
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import InvestigationResult, PhaseResult

__all__ = ["ReverseOrchestrator", "SampleCaseError"]

logger = logging.getLogger(__name__)

SAMPLE_KIND_KEY = "reverse:sample_kind"


class SampleCaseError(RuntimeError):
    """The case for the sample could not be created."""


class ReverseOrchestrator(Orchestrator):
    """Runs the static analysis pipeline on one sample."""

    def __init__(self, sample_path: str | Path, **kwargs: Any) -> None:
        self.sample = Path(sample_path).expanduser().resolve()
        super().__init__(evidence_path=str(self.sample.parent), **kwargs)
        self.sample_kind = "unknown"
        self.sample_sha256 = ""
        self._phase_usage: list[dict[str, Any]] = []
        self._prompt_vars: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Case setup (direct, no LLM)
    # ------------------------------------------------------------------

    def prepare_case(self) -> None:
        """Create the case for the sample and record what kind of sample it is."""
        from mulder.reverse.backend import sample_sha256
        from mulder.reverse.sample import describe_kind, detect_sample_kind
        from mulder.reverse.state import CASE_KIND_KEY, REVERSE_KIND, SAMPLE_KEY

        if not self.sample.is_file():
            raise SampleCaseError(f"Sample not found: {self.sample}")
        self.sample_kind = detect_sample_kind(self.sample)
        self.sample_sha256 = sample_sha256(self.sample)

        import mulder.server.tools  # noqa: F401 - registers the tools
        from mulder.server.app import _tool_dispatch_sync, get_ctx

        self._server.ensure_config()
        result = _tool_dispatch_sync["scan_evidence"](
            evidence_path=str(self.sample), case_id=self._case_id
        )
        if result.get("status") not in ("success", "case_exists"):
            raise SampleCaseError(
                f"Cannot create case {self._case_id}: {result.get('error_message', result)}"
            )
        db = get_ctx().db
        existing_kind = db.get_kv(CASE_KIND_KEY)
        if existing_kind not in (None, REVERSE_KIND):
            raise SampleCaseError(
                f"Case {self._case_id} is a {existing_kind} case, not a reverse-engineering "
                "case: use another case ID."
            )
        previous = db.get_kv(SAMPLE_KEY)
        if previous and previous != str(self.sample):
            raise SampleCaseError(
                f"Case {self._case_id} already analyses {previous}; use another case ID."
            )
        db.set_kv(CASE_KIND_KEY, REVERSE_KIND)
        db.set_kv(SAMPLE_KEY, str(self.sample))
        db.set_kv(SAMPLE_KIND_KEY, self.sample_kind)
        registered = {str(row.get("file_path")) for row in db.get_evidence_registry()}
        if str(self.sample) not in registered:
            db.register_evidence_file(
                str(self.sample), self.sample_sha256, self.sample.stat().st_size
            )
        self._prompt_vars = {
            "case_id": self._case_id,
            "sample_path": str(self.sample),
            "sample_sha256": self.sample_sha256,
            "sample_kind": self.sample_kind,
            "sample_note": "  note: " + describe_kind(self.sample_kind),
            "case_briefing": "",
        }
        self.dashboard.log_info(
            f"Sample {self.sample.name}: {self.sample_kind} (sha256 {self.sample_sha256[:16]}...)"
        )

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    async def _run_pipeline(self, result: InvestigationResult) -> InvestigationResult:
        from mulder.orchestrator.gates import reset_gate_failure_counters

        reset_gate_failure_counters()
        self._total_phases = 5
        self._phase_counter = 0
        self.prepare_case()
        briefing = self._evidence.load_case_briefing()
        self._prompt_vars["case_briefing"] = f"\n{briefing}" if briefing else ""

        native = self.sample_kind in NATIVE_KINDS
        await self._phase(RE_TRIAGE, result)

        loaded = packed = False
        if native:
            await self._phase(RE_MAPPING, result)
            snap = self.snapshot()
            loaded = any(str(s).startswith("reverse.program") for s in snap["sources"])
            packed = bool(snap["status"].get("packed"))
            if packed:
                self._skip("re_deep", "sample is packed; unpacking is out of scope", result)
                self._skip("re_counter", "sample is packed", result)
            elif not loaded:
                self._skip("re_deep", "the disassembler could not load the sample", result)
            else:
                await self._phase(RE_DEEP, result)
        else:
            self._skip("re_mapping", f"{self.sample_kind} sample: no disassembler route", result)
            self._skip("re_deep", f"{self.sample_kind} sample: no disassembler route", result)

        if not packed:
            await self._phase(RE_COUNTER, result)

        self._write_model_usage()
        await self._phase(RE_REPORT, result)
        result.success = all(p.success for p in result.phases)
        self._write_model_usage()
        self._write_phase_usage()
        return result

    async def _phase(self, phase: PhaseConfig, result: InvestigationResult) -> PhaseResult:
        before = self._token_totals()
        if phase.mode == "single":
            phase_result = await self._run_single_phase(phase, prompt_vars=self._prompt_vars)
        else:
            phase_result = await self._run_split_phase(phase, prompt_vars=self._prompt_vars)
        result.phases.append(phase_result)
        self._accumulate(result, phase_result)
        self._record_phase_usage(phase.name, before, phase_result)
        return phase_result

    def _skip(self, name: str, reason: str, result: InvestigationResult) -> None:
        self._phase_counter += 1
        self.dashboard.set_phase(
            label=f"{name} (skipped: {reason})",
            phase_num=self._phase_counter,
            total_phases=self._total_phases,
            model="—",
            max_turns=0,
        )
        self.dashboard.log_info(f"Skipping {name}: {reason}")
        logger.info("Skipping phase %s: %s", name, reason)
        result.phases.append(PhaseResult(phase_name=name, success=True))

    # ------------------------------------------------------------------
    # Token usage per phase
    # ------------------------------------------------------------------

    def _token_totals(self) -> dict[str, dict[str, int]]:
        return {m: dict(c) for m, c in self.dashboard.model_tokens.items()}

    def _record_phase_usage(
        self, name: str, before: dict[str, dict[str, int]], phase_result: PhaseResult
    ) -> None:
        after = self._token_totals()
        per_model = {}
        for model, counts in after.items():
            prev = before.get(model, {"input": 0, "output": 0})
            delta_in = counts["input"] - prev.get("input", 0)
            delta_out = counts["output"] - prev.get("output", 0)
            if delta_in or delta_out:
                per_model[model] = {"input_tokens": delta_in, "output_tokens": delta_out}
        self._phase_usage.append(
            {
                "phase": name,
                "success": phase_result.success,
                "turns": phase_result.turns_used,
                "models": per_model,
                "input_tokens": sum(m["input_tokens"] for m in per_model.values()),
                "output_tokens": sum(m["output_tokens"] for m in per_model.values()),
            }
        )

    def _write_phase_usage(self) -> None:
        if not self._case_id:
            return
        path = self._db_dir / f"{self._case_id}.phase_usage.json"
        try:
            path.write_text(json.dumps(self._phase_usage, indent=2), encoding="utf-8")
            logger.info("Wrote per-phase token usage to %s", path)
        except OSError:
            logger.warning("Failed to write per-phase usage", exc_info=True)

    # ------------------------------------------------------------------
    # Gates
    # ------------------------------------------------------------------

    def snapshot(self, readiness: bool = False) -> dict[str, Any]:
        """What the gates look at, read directly from the case (no LLM)."""
        from mulder.reverse.report import project_file_for_case
        from mulder.server.app import get_ctx
        from mulder.server.tools.reverse_pipeline import status_snapshot

        self._server.ensure_config()
        self._server.ensure_context()
        ctx = get_ctx()
        findings = ctx.db.get_findings()
        snap: dict[str, Any] = {
            "sample_kind": self.sample_kind,
            "tool_counts": dict(ctx.audit.summary().tool_call_counts),
            "sources": sorted({s.source_name for s in ctx.db.get_sources() if s.line_count}),
            "findings_count": len(findings),
            "findings_with_mitre": sum(1 for f in findings if f.mitre_attack_ids),
            "status": status_snapshot(str(self.sample)),
            "project_file": project_file_for_case(self._db_dir, self._case_id, self.sample),
        }
        if readiness:
            snap["readiness"] = self._server.get_readiness()
        return snap

    def _export_iocs(self) -> str | None:
        """Write the IOC export and the ATT&CK Navigator layer next to the report."""
        from mulder.report.ioc_export import export_iocs
        from mulder.report.navigator import export_navigator_layer
        from mulder.server.app import get_ctx

        self._server.ensure_config()
        self._server.ensure_context()
        findings = get_ctx().db.get_findings()
        try:
            out = export_iocs(self._case_id, findings, self._db_dir, fmt="csv")
        except Exception:
            logger.warning("IOC export failed", exc_info=True)
            return None
        try:
            export_navigator_layer(self._case_id, findings, self._db_dir)
        except Exception:
            logger.warning("Navigator export failed", exc_info=True)
        return out.get("csv_path") or out.get("stix_path")

    async def _validate_phase(
        self, phase: PhaseConfig, phase_result: PhaseResult
    ) -> GateResult | None:
        try:
            if phase.name == "re_triage":
                return validate_re_triage(self.snapshot())
            if phase.name == "re_mapping":
                return validate_re_mapping(self.snapshot())
            if phase.name == "re_deep":
                return validate_re_deep(self.snapshot())
            if phase.name == "re_counter":
                return validate_re_counter(self.snapshot())
            if phase.name == "re_report":
                report_path = self._db_dir / f"{self._case_id}.report.md"
                snap = self.snapshot(readiness=True)
                written = (
                    report_path.is_file()
                    and report_path.stat().st_mtime >= self._phase_started_at - 1.0
                )
                snap["ioc_export"] = self._export_iocs() if written else None
                return validate_re_report(snap, report_path, self._phase_started_at)
        except Exception:
            logger.exception("Gate for %s could not read the case", phase.name)
            raise
        return await super()._validate_phase(phase, phase_result)
