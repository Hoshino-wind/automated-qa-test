"""Typed command-line contract for a QA cycle."""

from __future__ import annotations

import argparse
import math
from dataclasses import dataclass
from typing import Sequence

DEFAULT_TOTAL_TIMEOUT_SECONDS = 1800.0
DEFAULT_STAGE_TIMEOUT_SECONDS = 300.0
DEFAULT_MAX_PROBES = 500
DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
DEFAULT_TERMINATION_GRACE_SECONDS = 2.0


@dataclass(frozen=True, slots=True)
class CycleOptions:
    run_dir: str
    plan: str | None
    matrix: str | None
    requirement: str | None
    results: str | None
    ledger: str | None
    audit_summary: str | None
    requirement_coverage: str | None
    plan_audit_summary: str | None
    adapter_context: str | None
    runtime_mode: str | None
    data_boundary_status: str | None
    adapter_probes: str | None
    service_preflight: str | None
    service_runtime: str | None
    defects: str | None
    next_probes: str | None
    next_probe_application: str | None
    business_model: str | None
    oracle_model: str | None
    qa_metrics: str | None
    closeout_candidates: str | None
    semantic_artifacts_summary: str | None
    cycle_error: str | None
    verdict: str | None
    report: str | None
    summary: str | None
    node_bin: str
    strict_runtime: bool
    require_environment_boundary: bool
    allow_unconfirmed_environment: bool
    allow_missing_requirement_coverage: bool
    allow_unsafe_command: bool
    skip_requirement_coverage: bool
    allow_unmapped_requirement_source: bool
    preflight_runtime: bool
    start_missing_services: bool
    service_start_timeout: float
    service_start_no_wait: bool
    allow_preflight_blockers: bool
    refresh_adapter_context: bool
    synthesize_adapter_probes: bool
    apply_next_probes: bool
    allow_live_stream: bool
    allow_stopped_service: bool
    agent_id: str | None
    user_id: str | None
    marker: str | None
    question: str | None
    ws_path: str | None
    session_detail_path: str | None
    persistence_command: str | None
    allow_mutating_api_next_probes: bool
    project_root: str | None
    required_service: list[str] | None
    skip_probe: bool
    skip_report: bool
    allow_external_output_paths: bool
    total_timeout_seconds: float
    stage_timeout_seconds: float
    max_probes: int
    max_output_bytes: int
    termination_grace_seconds: float


def build_cycle_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a complete QA probe cycle: validate plan, execute probe, build ledger, audit evidence, and generate report."
    )
    parser.add_argument("--run-dir", required=True, help="QA artifact directory containing test-plan.json and test-matrix.json")
    parser.add_argument("--plan", help="Defaults to <run-dir>/test-plan.json")
    parser.add_argument("--matrix", help="Defaults to <run-dir>/test-matrix.json")
    parser.add_argument("--requirement", help="Defaults to <run-dir>/requirement.md when present")
    parser.add_argument("--results", help="Defaults to <run-dir>/results.json")
    parser.add_argument("--ledger", help="Defaults to <run-dir>/evidence-ledger.json")
    parser.add_argument("--audit-summary", help="Defaults to <run-dir>/audit-summary.json")
    parser.add_argument("--requirement-coverage", help="Defaults to <run-dir>/requirement-coverage.json")
    parser.add_argument("--plan-audit-summary", help="Defaults to <run-dir>/plan-audit-summary.json")
    parser.add_argument("--adapter-context", help="Defaults to <run-dir>/adapter-context.json when present")
    parser.add_argument("--runtime-mode", help="Declared runtime mode to write into adapter-context.json, such as local, test, staging, production, or ci.")
    parser.add_argument("--data-boundary-status", help="Declared data boundary to write into adapter-context.json.")
    parser.add_argument("--adapter-probes", help="Defaults to <run-dir>/adapter-probes.json when present")
    parser.add_argument("--service-preflight", help="Defaults to <run-dir>/service-preflight.json when present")
    parser.add_argument("--service-runtime", help="Defaults to <run-dir>/service-runtime.json when service startup is used")
    parser.add_argument("--defects", help="Defaults to <run-dir>/defects.json")
    parser.add_argument("--next-probes", help="Defaults to <run-dir>/next-probes.json")
    parser.add_argument("--next-probe-application", help="Defaults to <run-dir>/next-probe-application.json")
    parser.add_argument("--business-model", help="Defaults to <run-dir>/business-model.json when present")
    parser.add_argument("--oracle-model", help="Defaults to <run-dir>/oracle-model.json when present")
    parser.add_argument("--qa-metrics", help="Defaults to <run-dir>/qa-metrics.json when present")
    parser.add_argument("--closeout-candidates", help="Defaults to <run-dir>/closeout-candidates.json when present")
    parser.add_argument("--semantic-artifacts-summary", help="Defaults to <run-dir>/semantic-artifacts-summary.json")
    parser.add_argument("--cycle-error", help="Defaults to <run-dir>/qa-cycle-error.json")
    parser.add_argument("--verdict", help="Defaults to <run-dir>/qa-verdict.json")
    parser.add_argument("--report", help="Defaults to <run-dir>/report.md")
    parser.add_argument("--summary", help="Defaults to <run-dir>/qa-run-summary.json")
    parser.add_argument("--node-bin", default="node")
    parser.add_argument("--strict-runtime", action="store_true")
    parser.add_argument("--require-environment-boundary", action="store_true", help="Require adapter-context.json with confirmed runtime/data boundary before final pass can be claimed.")
    parser.add_argument("--allow-unconfirmed-environment", action="store_true", help="Explicitly allow a run without confirmed runtime/data boundaries; final evidence should not be treated as a real-environment pass.")
    parser.add_argument("--allow-missing-requirement-coverage", action="store_true", help="Explicitly allow a pass-quality run without requirement.md source coverage.")
    parser.add_argument("--allow-unsafe-command", action="store_true")
    parser.add_argument("--skip-requirement-coverage", action="store_true", help="Skip requirement.md to test-matrix.json source coverage audit.")
    parser.add_argument("--allow-unmapped-requirement-source", action="store_true", help="Write requirement coverage warnings instead of failing for unmapped source units.")
    parser.add_argument("--preflight-runtime", action="store_true", help="Check required services/tooling before validation and execution.")
    parser.add_argument("--start-missing-services", action="store_true", help="Start missing required services from service-preflight.json start_plan after an initial preflight.")
    parser.add_argument("--service-start-timeout", type=float, default=60.0, help="Seconds to wait for each started service port.")
    parser.add_argument("--service-start-no-wait", action="store_true", help="Start missing services but do not wait for port readiness.")
    parser.add_argument("--allow-preflight-blockers", action="store_true", help="Continue even when service-preflight.json contains blockers.")
    parser.add_argument("--refresh-adapter-context", action="store_true", help="Re-probe adapter context during runtime preflight.")
    parser.add_argument("--synthesize-adapter-probes", action="store_true", help="Apply adapter-aware probes before plan validation.")
    parser.add_argument("--apply-next-probes", action="store_true", help="Apply existing safe next-probes.json recommendations before plan validation.")
    parser.add_argument("--allow-live-stream", action="store_true", help="Forwarded to synthesize_adapter_probes.py when enabled.")
    parser.add_argument("--allow-stopped-service", action="store_true", help="Forwarded to synthesize_adapter_probes.py when enabled.")
    parser.add_argument("--agent-id", help="Forwarded to synthesize_adapter_probes.py.")
    parser.add_argument("--user-id", help="Forwarded to synthesize_adapter_probes.py.")
    parser.add_argument("--marker", help="Forwarded to synthesize_adapter_probes.py.")
    parser.add_argument("--question", help="Forwarded to synthesize_adapter_probes.py.")
    parser.add_argument("--ws-path", help="Forwarded to synthesize_adapter_probes.py.")
    parser.add_argument("--session-detail-path", help="Forwarded to synthesize_adapter_probes.py.")
    parser.add_argument("--persistence-command", help="Forwarded to synthesize_adapter_probes.py. Must be read-only.")
    parser.add_argument("--allow-mutating-api-next-probes", action="store_true", help="Forwarded to apply_next_probes.py for explicitly safe test data only.")
    parser.add_argument("--project-root", help="Forwarded to preflight_runtime.py.")
    parser.add_argument("--required-service", action="append", help="Forwarded to preflight_runtime.py. May be repeated.")
    parser.add_argument("--skip-probe", action="store_true", help="Use an existing results.json, or write an explicit skipped-results stub when it is missing.")
    parser.add_argument("--skip-report", action="store_true")
    parser.add_argument(
        "--allow-external-output-paths",
        action="store_true",
        help="Explicitly allow generated output files outside --run-dir. Directory-shaped targets are still rejected.",
    )
    parser.add_argument(
        "--total-timeout-seconds",
        type=_positive_float,
        default=DEFAULT_TOTAL_TIMEOUT_SECONDS,
        help="Maximum wall-clock seconds for the complete cycle.",
    )
    parser.add_argument(
        "--stage-timeout-seconds",
        type=_positive_float,
        default=DEFAULT_STAGE_TIMEOUT_SECONDS,
        help="Maximum wall-clock seconds for each helper or probe stage.",
    )
    parser.add_argument(
        "--max-probes",
        type=_positive_int,
        default=DEFAULT_MAX_PROBES,
        help="Maximum executable plan steps reserved by the probe stage.",
    )
    parser.add_argument(
        "--max-output-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_OUTPUT_BYTES,
        help="Maximum combined child-process stdout/stderr bytes for the cycle.",
    )
    parser.add_argument(
        "--termination-grace-seconds",
        type=_non_negative_float,
        default=DEFAULT_TERMINATION_GRACE_SECONDS,
        help="TERM-to-KILL grace period for a timed out or cancelled process group.",
    )
    return parser


def parse_cycle_options(argv: Sequence[str] | None = None) -> CycleOptions:
    values = vars(build_cycle_parser().parse_args(argv))
    values["require_environment_boundary"] = bool(
        values["require_environment_boundary"] or not values["allow_unconfirmed_environment"]
    )
    return CycleOptions(**values)


def _positive_float(value: str) -> float:
    normalized = _finite_float(value)
    if normalized <= 0:
        raise argparse.ArgumentTypeError("value must be > 0")
    return normalized


def _non_negative_float(value: str) -> float:
    normalized = _finite_float(value)
    if normalized < 0:
        raise argparse.ArgumentTypeError("value must be >= 0")
    return normalized


def _finite_float(value: str) -> float:
    try:
        normalized = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be numeric") from exc
    if not math.isfinite(normalized):
        raise argparse.ArgumentTypeError("value must be finite")
    return normalized


def _positive_int(value: str) -> int:
    try:
        normalized = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if normalized <= 0:
        raise argparse.ArgumentTypeError("value must be > 0")
    return normalized
