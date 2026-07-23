"""标准 QA 产物路径的唯一事实源。"""

from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path
from typing import Mapping

ARTIFACT_FILENAMES = {
    "plan": "test-plan.json",
    "matrix": "test-matrix.json",
    "requirement": "requirement.md",
    "results": "results.json",
    "ledger": "evidence-ledger.json",
    "audit_summary": "audit-summary.json",
    "requirement_coverage": "requirement-coverage.json",
    "plan_audit_summary": "plan-audit-summary.json",
    "adapter_context": "adapter-context.json",
    "adapter_probes": "adapter-probes.json",
    "service_preflight": "service-preflight.json",
    "service_runtime": "service-runtime.json",
    "defects": "defects.json",
    "next_probes": "next-probes.json",
    "next_probe_application": "next-probe-application.json",
    "business_model": "business-model.json",
    "oracle_model": "oracle-model.json",
    "qa_metrics": "qa-metrics.json",
    "closeout_candidates": "closeout-candidates.json",
    "semantic_artifacts_summary": "semantic-artifacts-summary.json",
    "cycle_error": "qa-cycle-error.json",
    "verdict": "qa-verdict.json",
    "report": "report.md",
    "summary": "qa-run-summary.json",
}

INPUT_ARTIFACTS = frozenset({"plan", "matrix", "requirement", "adapter_context"})
TERMINAL_ARTIFACTS = ("verdict", "report", "cycle_error")


@dataclass(frozen=True, slots=True)
class ArtifactPaths:
    run_dir: Path
    plan: Path
    matrix: Path
    requirement: Path
    results: Path
    ledger: Path
    audit_summary: Path
    requirement_coverage: Path
    plan_audit_summary: Path
    adapter_context: Path
    adapter_probes: Path
    service_preflight: Path
    service_runtime: Path
    defects: Path
    next_probes: Path
    next_probe_application: Path
    business_model: Path
    oracle_model: Path
    qa_metrics: Path
    closeout_candidates: Path
    semantic_artifacts_summary: Path
    cycle_error: Path
    verdict: Path
    report: Path
    summary: Path

    @classmethod
    def from_overrides(cls, run_dir: Path, overrides: Mapping[str, str | None] | None = None) -> "ArtifactPaths":
        resolved_run_dir = run_dir.expanduser().resolve()
        provided = overrides or {}
        values: dict[str, Path] = {"run_dir": resolved_run_dir}
        for name, filename in ARTIFACT_FILENAMES.items():
            explicit = provided.get(name)
            values[name] = Path(explicit).expanduser().resolve() if explicit else resolved_run_dir / filename
        return cls(**values)

    def named_outputs(self) -> list[tuple[str, Path]]:
        return [
            (field.name, getattr(self, field.name))
            for field in fields(self)
            if field.name not in INPUT_ARTIFACTS and field.name != "run_dir"
        ]

    def terminal_outputs(self) -> list[tuple[str, Path]]:
        return [(name, getattr(self, name)) for name in TERMINAL_ARTIFACTS]

    def summary_paths(self, *, skip_report: bool = False) -> dict[str, str | None]:
        optional_existing = {
            "requirement",
            "next_probe_application",
            "business_model",
            "oracle_model",
            "qa_metrics",
            "closeout_candidates",
            "semantic_artifacts_summary",
            "adapter_context",
            "adapter_probes",
            "service_preflight",
            "service_runtime",
        }
        result: dict[str, str | None] = {}
        for name in ARTIFACT_FILENAMES:
            if name == "summary":
                continue
            path = getattr(self, name)
            if name == "report" and skip_report:
                result[name] = None
            elif name in optional_existing:
                result[name] = str(path) if path.exists() else None
            else:
                result[name] = str(path)
        return result
