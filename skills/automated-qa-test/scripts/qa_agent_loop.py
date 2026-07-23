#!/usr/bin/env python3
import argparse
import json
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from qa_common import atomic_write_json, atomic_write_text, file_sha256

SNAPSHOT_FILES = [
    "adapter-context.json",
    "adapter-probes.json",
    "business-model.json",
    "oracle-model.json",
    "qa-metrics.json",
    "closeout-candidates.json",
    "semantic-artifacts-summary.json",
    "requirement-coverage.json",
    "plan-audit-summary.json",
    "service-preflight.json",
    "service-runtime.json",
    "results.json",
    "evidence-ledger.json",
    "audit-summary.json",
    "defects.json",
    "next-probes.json",
    "next-probe-application.json",
    "next-probe-preview.json",
    "qa-cycle-error.json",
    "qa-verdict.json",
    "qa-run-summary.json",
    "report.md",
    "test-plan.json",
    "test-matrix.json",
]
SETUP_BLOCKER_CODES = {
    "preflight_blocked",
    "service_runtime_failed",
    "service_runtime_not_all_ready",
    "missing_preflight",
    "missing_service_runtime",
    "service_preflight_omitted",
    "service_runtime_omitted",
}
PLANNING_BLOCKER_CODES = {
    "requirement_source_unmapped",
    "plan_validation_failed",
    "plan_audit_omitted",
}
STRATEGY_COVERAGE_CODES = {
    "strategy_dimension_gap",
}
EVIDENCE_PIPELINE_CODES = {
    "audit_failed",
    "cycle_error_omitted",
    "cycle_helper_failed",
    "helper_output_unreadable",
    "results_omitted",
    "audit_summary_omitted",
    "ledger_omitted",
}
ENVIRONMENT_BOUNDARY_CODES = {
    "missing_environment_boundary",
    "environment_unconfirmed",
    "data_boundary_unconfirmed",
}
PRODUCT_DEFECT_CODES = {
    "requirement_failed",
    "defects_present",
}
REQUIREMENT_BLOCKER_CODES = {
    "requirement_blocked",
    "adapter_probe_blocked",
}
AUTO_CONTINUE_CATEGORIES = {
    "runtime_evidence_gap",
    "untested_coverage_gap",
    "strategy_coverage_gap",
    "requirement_or_adapter_blocker",
    "non_pass_verdict",
}
CATEGORY_ACTION_POLICIES = {
    "product_defect": {
        "action": "report_product_defect",
        "reason": "A product defect is already supported by current-run evidence; report the defect instead of automatically applying more probes.",
        "operator_hint": "Report the defect with defects.json, evidence-ledger.json, and the current verdict.",
        "evidence": ["qa-verdict.json", "defects.json", "evidence-ledger.json", "report.md"],
    },
    "environment_boundary_unconfirmed": {
        "action": "confirm_environment_boundary",
        "reason": "The runtime or data boundary is unconfirmed, so follow-up probes cannot support a product conclusion yet.",
        "operator_hint": "Confirm runtime mode and data boundary, then resume the loop if the target is safe.",
        "evidence": ["qa-verdict.json", "adapter-context.json", "qa-run-summary.json"],
    },
    "evidence_pipeline_failure": {
        "action": "repair_evidence_pipeline",
        "reason": "The QA evidence pipeline failed or omitted required artifacts, so automatic probing could compound bad evidence.",
        "operator_hint": "Repair the named QA pipeline artifact before interpreting product behavior.",
        "evidence": ["qa-verdict.json", "qa-cycle-error.json", "audit-summary.json", "qa-run-summary.json"],
    },
    "setup_environment_blocker": {
        "action": "report_setup_blocker",
        "reason": "Setup or service readiness is blocking the run; product probes cannot be trusted until setup is fixed.",
        "operator_hint": "Resolve runtime setup before continuing.",
        "evidence": ["qa-verdict.json", "service-preflight.json", "service-runtime.json", "qa-run-summary.json"],
    },
    "planning_coverage_blocker": {
        "action": "report_planning_blocker",
        "reason": "Requirement coverage or plan validation is blocking execution; automatic probing would test an incomplete plan.",
        "operator_hint": "Map requirements or fix the plan before continuing.",
        "evidence": ["qa-verdict.json", "requirement-coverage.json", "plan-audit-summary.json", "qa-run-summary.json"],
    },
    "requirement_or_adapter_blocker": {
        "action": "request_authorization_or_inputs",
        "reason": "Requirement or adapter probes are blocked until safe execution inputs, authorization, selectors, or helpers are provided.",
        "operator_hint": "Provide the missing safe inputs or authorization before continuing the backtest loop.",
        "evidence": ["qa-verdict.json", "adapter-probes.json", "test-plan.json", "next-probe-preview.json"],
    },
}
STATUS_ORDER = ("Passed", "Failed", "Blocked", "Untested", "Inconclusive")
EVIDENCE_TYPE_LAYERS = {
    "screenshot": "ui",
    "ui_interaction": "ui",
    "ui_assertion": "ui",
    "ui_to_api": "api",
    "api_response": "api",
    "cleanup": "api",
    "websocket": "stream",
    "sse": "stream",
    "command": "command_or_persistence",
    "log_file": "command_or_persistence",
    "runtime": "runtime",
    "trace": "runtime",
    "video": "ui",
}


class InitializationError(RuntimeError):
    def __init__(self, message: str, *, result: dict[str, Any] | None = None, run_dir: Path | None = None) -> None:
        super().__init__(message)
        self.result = result
        self.run_dir = run_dir


def try_load_json(path: Path | None) -> tuple[dict[str, Any], str | None]:
    if not path or not path.exists():
        return {}, None
    if path.is_dir():
        return {}, "path_is_directory"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {}, f"invalid_json: {exc.msg}"
    except OSError as exc:
        return {}, f"read_error: {exc}"
    if not isinstance(value, dict):
        return {}, "json_root_not_object"
    return value, None


def load_json(path: Path | None) -> dict[str, Any]:
    data, _error = try_load_json(path)
    return data


def write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write_json(path, value)


def next_probes_sha256(run_dir: Path) -> str | None:
    return file_sha256(run_dir / "next-probes.json")


def markdown_cell(value: Any, limit: int = 900) -> str:
    text = str(value if value is not None else "").replace("\n", "<br>").replace("|", "\\|")
    return text[:limit] + ("...[truncated]" if len(text) > limit else "")


def compact_json(value: Any, limit: int = 1200) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return text[:limit] + ("...[truncated]" if len(text) > limit else "")


def agent_handoff_path(summary_path: Path, summary: dict[str, Any]) -> Path:
    run_dir = summary.get("run_dir")
    if run_dir:
        return Path(str(run_dir)).expanduser().resolve() / "qa-agent-handoff.md"
    return summary_path.with_name("qa-agent-handoff.md")


def evidence_artifact_entries(summary: dict[str, Any], evidence: Any) -> list[dict[str, Any]]:
    run_dir = summary.get("run_dir")
    base = Path(str(run_dir)).expanduser().resolve() if run_dir else None
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in as_list(evidence):
        name = str(raw).strip()
        if not name or name in seen:
            continue
        seen.add(name)
        path = Path(name).expanduser()
        resolved = path if path.is_absolute() else ((base / path) if base else path)
        exists = resolved.exists() if (resolved.is_absolute() or base) else False
        if exists and resolved.is_dir():
            kind = "directory"
        elif exists and resolved.is_file():
            kind = "file"
        elif not (resolved.is_absolute() or base):
            kind = "unresolved"
        else:
            kind = "missing"
        entry: dict[str, Any] = {
            "name": name,
            "path": str(resolved),
            "exists": exists,
            "kind": kind,
        }
        if kind == "file":
            try:
                stat_result = resolved.stat()
                entry["size_bytes"] = stat_result.st_size
                entry["mtime_epoch"] = stat_result.st_mtime
                entry["sha256"] = file_sha256(resolved)
            except OSError as exc:
                entry["metadata_error"] = str(exc)
        entries.append(entry)
    return entries


def write_agent_handoff(summary_path: Path, summary: dict[str, Any]) -> Path:
    path = agent_handoff_path(summary_path, summary)
    summary["handoff"] = str(path)
    next_action = summary.get("next_action") if isinstance(summary.get("next_action"), dict) else {}
    final = summary.get("final") if isinstance(summary.get("final"), dict) else {}
    control = summary.get("loop_control") if isinstance(summary.get("loop_control"), dict) else {}
    analysis = next_action.get("failure_analysis") if isinstance(next_action.get("failure_analysis"), dict) else {}
    if not analysis:
        analysis = final.get("failure_analysis") if isinstance(final.get("failure_analysis"), dict) else {}
    lines: list[str] = [
        "# QA Agent Handoff",
        "",
        f"- Status: `{summary.get('status')}`",
        f"- Stop reason: `{summary.get('stop_reason')}`",
        f"- Run directory: `{summary.get('run_dir')}`",
        f"- Summary artifact: `{summary_path}`",
        f"- Final verdict: `{final.get('verdict')}` (can_claim_pass={final.get('can_claim_pass')})",
        f"- Next action: `{next_action.get('action')}`",
        f"- Automatable now: `{next_action.get('automatable')}`",
        f"- Reason: {next_action.get('reason', '')}",
    ]
    if control:
        lines.extend(
            [
                f"- Loop terminal: `{control.get('terminal')}`",
                f"- Can continue automatically: `{control.get('can_continue_automatically')}`",
                f"- Pass claim allowed: `{control.get('pass_claim_allowed')}`",
                f"- Handoff required: `{control.get('handoff_required')}`",
            ]
        )
    if analysis:
        lines.extend(
            [
                f"- Failure category: `{analysis.get('category')}`",
                f"- Blocking layer: `{analysis.get('blocking_layer')}`",
                f"- Analysis source: `{analysis.get('source')}`",
            ]
        )
        if analysis.get("operator_hint"):
            lines.append(f"- Operator hint: {analysis.get('operator_hint')}")
    if next_action.get("requires_authorization") is not None:
        lines.append(f"- Requires authorization: `{next_action.get('requires_authorization')}`")
    if next_action.get("automatable_after_authorization") is not None:
        lines.append(f"- Automatable after authorization: `{next_action.get('automatable_after_authorization')}`")
    if next_action.get("recommended_flags"):
        lines.append(f"- Recommended flags: `{', '.join(str(item) for item in as_list(next_action.get('recommended_flags')))}`")
    if next_action.get("preview_applied_count") is not None:
        lines.append(f"- Previewed safe follow-ups: `{next_action.get('preview_applied_count')}`")
    if next_action.get("no_new_progress") or control.get("no_new_progress"):
        lines.append("- No new progress: `true`")
    if next_action.get("expected_next_probes_sha256"):
        lines.append(f"- Expected next-probes SHA256: `{next_action.get('expected_next_probes_sha256')}`")
    if next_action.get("current_next_probes_sha256"):
        lines.append(f"- Current next-probes SHA256: `{next_action.get('current_next_probes_sha256')}`")
    if next_action.get("blocked_auto_continue_reason"):
        lines.append(f"- Auto-continue blocked: {next_action.get('blocked_auto_continue_reason')}")
    route_model = control.get("agent_route_model") if isinstance(control.get("agent_route_model"), dict) else {}
    if route_model:
        lines.extend(["", "## Agent Route Model", ""])
        lines.append(f"- Mode: `{route_model.get('mode')}`")
        lines.append(f"- Primary action: `{route_model.get('primary_action')}`")
        if route_model.get("human_request_type"):
            lines.append(f"- Human request type: `{route_model.get('human_request_type')}`")
        if route_model.get("reason"):
            lines.append(f"- Route reason: {route_model.get('reason')}")
        lines.append(
            "- Gates: `"
            + ", ".join(
                f"{key}={route_model.get(key)}"
                for key in (
                    "terminal",
                    "can_continue_automatically",
                    "pass_claim_allowed",
                    "handoff_required",
                    "requires_authorization",
                    "requires_input_repair",
                    "can_continue_after_authorization",
                    "result_ready_to_report",
                    "no_new_progress",
                )
                if key in route_model
            )
            + "`"
        )
        first_step = route_model.get("first_recommended_step") if isinstance(route_model.get("first_recommended_step"), dict) else {}
        if first_step:
            step_bits = [
                str(first_step.get("kind") or ""),
                str(first_step.get("id") or ""),
            ]
            if first_step.get("gap_id"):
                step_bits.append(f"gap={first_step.get('gap_id')}")
            if first_step.get("category"):
                step_bits.append(f"category={first_step.get('category')}")
            if first_step.get("evidence_artifact_count") is not None:
                step_bits.append(f"evidence_artifacts={first_step.get('evidence_artifact_count')}")
            lines.append("- First recommended step: `" + " | ".join(bit for bit in step_bits if bit) + "`")
        first_gap = route_model.get("first_evidence_gap") if isinstance(route_model.get("first_evidence_gap"), dict) else {}
        if first_gap:
            lines.append(
                f"- First evidence gap: `{first_gap.get('priority')}` `{first_gap.get('id')}` "
                + f"({first_gap.get('category')} / {first_gap.get('layer')})"
            )
        lines.append(
            "- Counts: `"
            + ", ".join(
                f"{key}={route_model.get(key, 0)}"
                for key in (
                    "recommended_next_step_count",
                    "evidence_gap_count",
                    "evidence_artifact_count",
                    "current_artifact_count",
                )
            )
            + "`"
        )
        if route_model.get("recommended_next_step_ids"):
            lines.append("- Recommended step ids: `" + ", ".join(str(item) for item in as_list(route_model.get("recommended_next_step_ids"))) + "`")
        if route_model.get("recommended_gap_ids"):
            lines.append("- Recommended gap ids: `" + ", ".join(str(item) for item in as_list(route_model.get("recommended_gap_ids"))) + "`")
        if route_model.get("recommended_flags"):
            lines.append("- Recommended flags: `" + ", ".join(str(item) for item in as_list(route_model.get("recommended_flags"))) + "`")
        if route_model.get("confirmation_fields"):
            lines.append("- Confirmation fields: `" + ", ".join(str(item) for item in as_list(route_model.get("confirmation_fields"))) + "`")
        if route_model.get("required_inputs"):
            lines.append("- Required inputs: `" + ", ".join(str(item) for item in as_list(route_model.get("required_inputs"))) + "`")
        if route_model.get("manual_revision_targets"):
            lines.append("- Manual revision targets: `" + ", ".join(str(item) for item in as_list(route_model.get("manual_revision_targets"))) + "`")
    orchestration = control.get("orchestration_state") if isinstance(control.get("orchestration_state"), dict) else {}
    if orchestration:
        lines.extend(["", "## Orchestration State", ""])
        lines.append(f"- Mode: `{orchestration.get('mode')}`")
        lines.append(f"- Primary action: `{orchestration.get('primary_action')}`")
        lines.append(f"- Human request type: `{orchestration.get('human_request_type')}`")
        lines.append(
            "- Gates: `"
            + ", ".join(
                f"{key}={orchestration.get(key)}"
                for key in (
                    "terminal",
                    "can_continue_automatically",
                    "pass_claim_allowed",
                    "handoff_required",
                    "requires_authorization",
                    "requires_input_repair",
                    "can_continue_after_authorization",
                    "result_ready_to_report",
                    "no_new_progress",
                )
                if key in orchestration
            )
            + "`"
        )
        first_step = orchestration.get("first_recommended_step") if isinstance(orchestration.get("first_recommended_step"), dict) else {}
        if first_step:
            step_bits = [
                str(first_step.get("kind") or ""),
                str(first_step.get("id") or ""),
            ]
            if first_step.get("gap_id"):
                step_bits.append(f"gap={first_step.get('gap_id')}")
            if first_step.get("category"):
                step_bits.append(f"category={first_step.get('category')}")
            if first_step.get("evidence_artifact_count") is not None:
                step_bits.append(f"evidence_artifacts={first_step.get('evidence_artifact_count')}")
            lines.append("- First recommended step: `" + " | ".join(bit for bit in step_bits if bit) + "`")
        first_gap = orchestration.get("first_evidence_gap") if isinstance(orchestration.get("first_evidence_gap"), dict) else {}
        if first_gap:
            lines.append(
                f"- First evidence gap: `{first_gap.get('priority')}` `{first_gap.get('id')}` "
                + f"({first_gap.get('category')} / {first_gap.get('layer')})"
            )
        lines.append(
            "- Counts: `"
            + ", ".join(
                f"{key}={orchestration.get(key, 0)}"
                for key in (
                    "recommended_next_step_count",
                    "evidence_gap_count",
                    "evidence_artifact_count",
                    "current_artifact_count",
                )
            )
            + "`"
        )
        if orchestration.get("recommended_flags"):
            lines.append("- Recommended flags: `" + ", ".join(str(item) for item in as_list(orchestration.get("recommended_flags"))) + "`")
        if orchestration.get("confirmation_fields"):
            lines.append("- Confirmation fields: `" + ", ".join(str(item) for item in as_list(orchestration.get("confirmation_fields"))) + "`")
        if orchestration.get("required_inputs"):
            lines.append("- Required inputs: `" + ", ".join(str(item) for item in as_list(orchestration.get("required_inputs"))) + "`")
        if orchestration.get("manual_revision_targets"):
            lines.append("- Manual revision targets: `" + ", ".join(str(item) for item in as_list(orchestration.get("manual_revision_targets"))) + "`")
        if orchestration.get("resume_command_args"):
            lines.append("- Resume command args: `" + shlex.join(str(item) for item in as_list(orchestration.get("resume_command_args"))) + "`")
    human_request = control.get("human_action_required") if isinstance(control.get("human_action_required"), dict) else {}
    if human_request:
        lines.extend(["", "## Human Action Required", ""])
        lines.append(f"- Type: `{human_request.get('type')}`")
        lines.append(f"- Action: `{human_request.get('action')}`")
        lines.append(f"- Prompt: {human_request.get('prompt')}")
        if human_request.get("reason"):
            lines.append(f"- Reason: {human_request.get('reason')}")
        lines.append(f"- Requires authorization: `{human_request.get('requires_authorization')}`")
        lines.append(f"- Requires input repair: `{human_request.get('requires_input_repair')}`")
        lines.append(f"- Can continue after authorization: `{human_request.get('can_continue_after_authorization')}`")
        if human_request.get("recommended_next_step_ids"):
            lines.append("- Recommended step ids: `" + ", ".join(str(item) for item in as_list(human_request.get("recommended_next_step_ids"))) + "`")
        if human_request.get("recommended_gap_ids"):
            lines.append("- Recommended gap ids: `" + ", ".join(str(item) for item in as_list(human_request.get("recommended_gap_ids"))) + "`")
        top_gap = human_request.get("top_evidence_gap") if isinstance(human_request.get("top_evidence_gap"), dict) else {}
        if top_gap:
            lines.append(
                f"- Top evidence gap: `{top_gap.get('priority')}` `{top_gap.get('id')}` - {top_gap.get('recommended_action')}"
            )
        if human_request.get("recommended_flags"):
            lines.append("- Recommended flags: `" + ", ".join(str(item) for item in as_list(human_request.get("recommended_flags"))) + "`")
        if human_request.get("confirmation_fields"):
            lines.append("- Confirmation fields: `" + ", ".join(str(item) for item in as_list(human_request.get("confirmation_fields"))) + "`")
        if human_request.get("required_inputs"):
            lines.append("- Required inputs: `" + ", ".join(str(item) for item in as_list(human_request.get("required_inputs"))) + "`")
        if human_request.get("manual_revision_targets"):
            lines.append("- Manual revision targets: `" + ", ".join(str(item) for item in as_list(human_request.get("manual_revision_targets"))) + "`")
        if human_request.get("resume_command"):
            lines.extend(["", "```bash", str(human_request.get("resume_command")), "```"])
    evidence_health = control.get("evidence_health") if isinstance(control.get("evidence_health"), dict) else {}
    if evidence_health:
        lines.extend(["", "## Evidence Health", ""])
        lines.append(f"- Status: `{evidence_health.get('status')}`")
        flags = as_list(evidence_health.get("flags"))
        if flags:
            lines.append("- Flags: `" + ", ".join(str(item) for item in flags) + "`")
        lines.append(f"- Pass claim allowed: `{evidence_health.get('pass_claim_allowed')}`")
        lines.append(f"- Can continue automatically: `{evidence_health.get('can_continue_automatically')}`")
        lines.append(f"- Result ready to report: `{evidence_health.get('result_ready_to_report')}`")
        lines.append(f"- Runtime issues: `{evidence_health.get('runtime_issue_total', 0)}`")
        lines.append(f"- Defects: `{evidence_health.get('defect_count', 0)}`")
        lines.append(f"- Strategy gaps: `{evidence_health.get('strategy_gap_count', 0)}`")
        lines.append(f"- Source uncovered: `{evidence_health.get('source_uncovered_count', 0)}`")
        lines.append(
            f"- Current-run evidence: `{evidence_health.get('current_run_evidence_count', 0)}/{evidence_health.get('evidence_count', 0)}`"
        )
        artifacts = evidence_health.get("current_artifacts") if isinstance(evidence_health.get("current_artifacts"), dict) else {}
        if artifacts:
            lines.append(
                "- Current artifacts: `"
                + ", ".join(
                    f"{key}={artifacts.get(key, 0)}"
                    for key in ("total", "current", "missing", "unreadable", "stale_or_ignored")
                )
                + "`"
            )
        audit = evidence_health.get("audit") if isinstance(evidence_health.get("audit"), dict) else {}
        if audit:
            lines.append(
                f"- Audit: `passed={audit.get('passed')}, errors={audit.get('error_count', 0)}, warnings={audit.get('warning_count', 0)}`"
            )
    gap_plan = control.get("evidence_gap_plan") if isinstance(control.get("evidence_gap_plan"), dict) else {}
    if gap_plan:
        lines.extend(["", "## Evidence Gap Plan", ""])
        lines.append(f"- Gap count: `{gap_plan.get('gap_count', 0)}`")
        if gap_plan.get("highest_priority"):
            lines.append(f"- Highest priority: `{gap_plan.get('highest_priority')}`")
        recommended_order = as_list(gap_plan.get("recommended_order"))
        if recommended_order:
            lines.append("- Recommended order: `" + ", ".join(str(item) for item in recommended_order) + "`")
        gaps = [item for item in as_list(gap_plan.get("gaps")) if isinstance(item, dict)]
        if gaps:
            lines.extend(["", "| Priority | Gap | Layer | Summary | Recommended Action | Evidence |", "| --- | --- | --- | --- | --- | --- |"])
            for item in gaps[:8]:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            markdown_cell(item.get("priority", "")),
                            markdown_cell(item.get("id", "")),
                            markdown_cell(item.get("layer", "")),
                            markdown_cell(item.get("summary", ""), 900),
                            markdown_cell(item.get("recommended_action", ""), 900),
                            markdown_cell(", ".join(str(ref) for ref in as_list(item.get("evidence"))), 900),
                        ]
                    )
                    + " |"
                )
    decision = next_action.get("decision_summary") if isinstance(next_action.get("decision_summary"), dict) else {}
    if not decision:
        decision = final.get("decision_summary") if isinstance(final.get("decision_summary"), dict) else {}
    if decision:
        lines.extend(["", "## Decision Summary", ""])
        if decision.get("category"):
            lines.append(f"- Category: `{decision.get('category')}`")
        if decision.get("blocking_layer"):
            lines.append(f"- Blocking layer: `{decision.get('blocking_layer')}`")
        environment = decision.get("environment_boundary") if isinstance(decision.get("environment_boundary"), dict) else {}
        if environment:
            lines.extend(["", "### Environment Boundary", ""])
            if environment.get("adapter"):
                lines.append(f"- Adapter: `{environment.get('adapter')}`")
            lines.append(f"- Runtime mode: `{environment.get('runtime_mode', '')}` (confirmed={environment.get('runtime_mode_confirmed')})")
            lines.append(f"- Data boundary: {markdown_cell(environment.get('data_boundary_status', ''), 700)}")
            if environment.get("target_environment"):
                lines.append(f"- Target environment: `{environment.get('target_environment')}`")
            lines.append(f"- Needs confirmation: `{environment.get('needs_confirmation')}`")
            lines.append(
                "- Services: `"
                + ", ".join(
                    f"{key}={environment.get(key, 0)}"
                    for key in ("service_count", "reachable_service_count", "unreachable_service_count", "unknown_service_count")
                )
                + "`"
            )
        service_preflight = decision.get("service_preflight") if isinstance(decision.get("service_preflight"), dict) else {}
        service_runtime = decision.get("service_runtime") if isinstance(decision.get("service_runtime"), dict) else {}
        if service_preflight or service_runtime:
            lines.extend(["", "### Service Readiness", ""])
            if service_preflight:
                lines.append(
                    "- Preflight: `"
                    + ", ".join(
                        [
                            f"runnable={service_preflight.get('runnable')}",
                            f"services={service_preflight.get('service_count', 0)}",
                            f"blockers={service_preflight.get('blocker_count', 0)}",
                            f"warnings={service_preflight.get('warning_count', 0)}",
                            f"start_plan={service_preflight.get('start_plan_count', 0)}",
                        ]
                    )
                    + "`"
                )
                for item in as_list(service_preflight.get("blocker_examples"))[:5]:
                    if isinstance(item, dict):
                        lines.append(
                            f"- Preflight blocker `{item.get('service', item.get('artifact', 'unknown'))}`: "
                            + markdown_cell(first_text(item.get("reason"), item.get("error"), limit=500), 700)
                        )
            if service_runtime:
                lines.append(
                    "- Runtime: `"
                    + ", ".join(
                        f"{key}={service_runtime.get(key, 0)}"
                        for key in ("planned_count", "started_count", "ready_count", "failed_count", "dry_run_count", "skipped_count")
                        if key in service_runtime
                    )
                    + "`"
                )
        adapter_probe_summary = decision.get("adapter_probes") if isinstance(decision.get("adapter_probes"), dict) else {}
        if adapter_probe_summary:
            lines.extend(["", "### Adapter Probes", ""])
            lines.append(
                "- Counts: `"
                + ", ".join(
                    f"{key}={adapter_probe_summary.get(key, 0)}"
                    for key in (
                        "stream_test_count",
                        "session_api_test_count",
                        "persistence_test_count",
                        "proposed_step_count",
                        "applied_count",
                        "blocked_probe_count",
                    )
                )
                + "`"
            )
            for item in as_list(adapter_probe_summary.get("blocked_examples"))[:5]:
                if isinstance(item, dict):
                    lines.append(
                        f"- Blocked adapter probe `{item.get('id', 'unknown')}`: "
                        + markdown_cell(first_text(item.get("reason"), item.get("required_inputs"), limit=500), 700)
                    )
        cycle_error_summary = decision.get("cycle_error") if isinstance(decision.get("cycle_error"), dict) else {}
        if cycle_error_summary:
            lines.extend(["", "### Cycle Error", ""])
            lines.append(f"- Code: `{cycle_error_summary.get('code')}`")
            lines.append(f"- Phase: `{cycle_error_summary.get('phase')}`")
            lines.append(f"- Exit code: `{cycle_error_summary.get('exit_code')}`")
            lines.append(f"- Message: {markdown_cell(cycle_error_summary.get('message', ''), 900)}")
        defect_findings = as_list(decision.get("defect_findings"))
        if defect_findings:
            lines.extend(["", "### Defect Findings", "", "| Severity | Defect | Layers | Evidence |", "| --- | --- | --- | --- |"])
            for item in defect_findings:
                if not isinstance(item, dict):
                    continue
                defect_label = f"{item.get('id', '')}: {item.get('title', '')}".strip(": ")
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            markdown_cell(item.get("severity", "")),
                            markdown_cell(defect_label, 700),
                            markdown_cell(", ".join(str(layer) for layer in as_list(item.get("layers"))), 500),
                            markdown_cell(", ".join(str(ref) for ref in as_list(item.get("evidence_refs"))), 700),
                        ]
                    )
                    + " |"
                )
        runtime_counts = decision.get("runtime_issue_counts") if isinstance(decision.get("runtime_issue_counts"), dict) else {}
        if runtime_counts:
            lines.extend(["", "### Runtime Issues", ""])
            lines.append(
                "- Counts: `"
                + ", ".join(f"{key}={runtime_counts.get(key, 0)}" for key in ("console_errors", "failed_responses", "request_failures", "total"))
                + "`"
            )
            runtime_examples = decision.get("runtime_issue_examples") if isinstance(decision.get("runtime_issue_examples"), dict) else {}
            for category in ("failed_responses", "request_failures", "console_errors"):
                examples = [item for item in as_list(runtime_examples.get(category)) if isinstance(item, dict)]
                if not examples:
                    continue
                labels = [markdown_cell(item.get("label") or compact_json(item, 260), 260) for item in examples[:3]]
                lines.append(f"- {category}: " + "; ".join(labels))
        strategy = decision.get("strategy_coverage") if isinstance(decision.get("strategy_coverage"), dict) else {}
        if strategy:
            lines.extend(["", "### Strategy Coverage", ""])
            covered = ", ".join(str(item) for item in as_list(strategy.get("covered_dimensions")))
            lines.append(f"- Covered dimensions: `{covered}`")
            observed = ", ".join(str(item) for item in as_list(strategy.get("observed_dimensions")))
            if observed:
                lines.append(f"- Observed executable dimensions: `{observed}`")
            lines.append(f"- Strategy gaps: `{strategy.get('gap_count', 0)}`")
            gaps = [item for item in as_list(strategy.get("gaps")) if isinstance(item, dict)]
            for item in gaps[:5]:
                observed_count = item.get("observed_executable_count", 0)
                lines.append(
                    f"- Gap `{item.get('dimension')}`: {item.get('reason')} "
                    + f"({', '.join(str(test_id) for test_id in as_list(item.get('test_ids'))[:6])}; "
                    + f"observed_executable_count={observed_count})"
                )
        source_coverage = decision.get("source_coverage") if isinstance(decision.get("source_coverage"), dict) else {}
        if source_coverage:
            lines.extend(["", "### Requirement Source Coverage", ""])
            lines.append(
                f"- Source units covered: `{source_coverage.get('covered_count', 0)}/{source_coverage.get('requirement_unit_count', 0)}`"
            )
            lines.append(f"- Uncovered source units: `{source_coverage.get('uncovered_count', 0)}`")
            for item in as_list(source_coverage.get("uncovered_examples"))[:5]:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    f"- `{item.get('id')}` {markdown_cell(item.get('source', ''), 180)}: "
                    + markdown_cell(item.get("text", ""), 700)
                )
        followups = decision.get("follow_up_summary") if isinstance(decision.get("follow_up_summary"), dict) else {}
        if followups:
            lines.extend(["", "### Follow-Up Probes", ""])
            for key, label in (("application", "Applied this iteration"), ("preview", "Previewed for next iteration")):
                item = followups.get(key) if isinstance(followups.get(key), dict) else {}
                if not item:
                    continue
                lines.append(
                    f"- {label}: "
                    + "`"
                    + ", ".join(
                        [
                            f"recommendations={item.get('recommendation_count', 0)}",
                            f"applied={item.get('applied_count', 0)}",
                            f"skipped={item.get('skipped_count', 0)}",
                            f"actionable_skipped={item.get('actionable_skipped_count', 0)}",
                        ]
                    )
                    + "`"
                )
                applied_examples = [entry for entry in as_list(item.get("applied_examples")) if isinstance(entry, dict)]
                if applied_examples:
                    lines.extend(["", "| Mode | Probe | Layer | Step | Tests | Requirements |", "| --- | --- | --- | --- | --- | --- |"])
                    for entry in applied_examples[:5]:
                        lines.append(
                            "| "
                            + " | ".join(
                                [
                                    markdown_cell(key),
                                    markdown_cell(entry.get("id", "")),
                                    markdown_cell(entry.get("layer", "")),
                                    markdown_cell(entry.get("step_id", "")),
                                    markdown_cell(", ".join(str(test_id) for test_id in as_list(entry.get("test_ids"))), 500),
                                    markdown_cell(", ".join(str(req_id) for req_id in as_list(entry.get("requirement_ids"))), 500),
                                ]
                            )
                            + " |"
                        )
                skipped_examples = [entry for entry in as_list(item.get("actionable_skipped_examples")) if isinstance(entry, dict)]
                if skipped_examples:
                    lines.extend(["", "| Mode | Blocked Probe | Layer | Reason | Source Test |", "| --- | --- | --- | --- | --- |"])
                    for entry in skipped_examples[:5]:
                        lines.append(
                            "| "
                            + " | ".join(
                                [
                                    markdown_cell(key),
                                    markdown_cell(entry.get("id", "")),
                                    markdown_cell(entry.get("layer", "")),
                                    markdown_cell(entry.get("reason", ""), 900),
                                    markdown_cell(entry.get("source_test_id", "")),
                                ]
                            )
                            + " |"
                        )
        evidence_layers = decision.get("evidence_layer_summary") if isinstance(decision.get("evidence_layer_summary"), dict) else {}
        if evidence_layers:
            lines.extend(["", "### Evidence Layers", ""])
            req_counts = evidence_layers.get("requirement_status_counts") if isinstance(evidence_layers.get("requirement_status_counts"), dict) else {}
            test_counts = evidence_layers.get("test_status_counts") if isinstance(evidence_layers.get("test_status_counts"), dict) else {}
            proof_layers = evidence_layers.get("proof_layer_counts") if isinstance(evidence_layers.get("proof_layer_counts"), dict) else {}
            evidence_types = evidence_layers.get("evidence_type_counts") if isinstance(evidence_layers.get("evidence_type_counts"), dict) else {}
            if req_counts:
                lines.append("- Requirement statuses: `" + ", ".join(f"{key}={req_counts.get(key, 0)}" for key in STATUS_ORDER) + "`")
            if test_counts:
                lines.append("- Test statuses: `" + ", ".join(f"{key}={test_counts.get(key, 0)}" for key in STATUS_ORDER) + "`")
            if proof_layers:
                lines.append("- Proof layers: `" + ", ".join(f"{key}={value}" for key, value in sorted(proof_layers.items())) + "`")
            if evidence_types:
                lines.append("- Evidence types: `" + ", ".join(f"{key}={value}" for key, value in sorted(evidence_types.items())) + "`")
            lines.append(f"- Current-run evidence: `{evidence_layers.get('current_run_evidence_count', 0)}/{evidence_layers.get('evidence_count', 0)}`")
            audit = evidence_layers.get("audit") if isinstance(evidence_layers.get("audit"), dict) else {}
            if audit:
                lines.append(f"- Audit passed: `{audit.get('passed')}` (errors={audit.get('error_count', 0)}, warnings={audit.get('warning_count', 0)})")
                for item in as_list(audit.get("error_examples"))[:3]:
                    lines.append(f"- Audit error: {markdown_cell(item, 700)}")
    if next_action.get("resume_command"):
        lines.extend(["", "## Resume Command", "", "```bash", str(next_action.get("resume_command")), "```"])
    evidence_entries = as_list(control.get("evidence_artifacts"))
    if not evidence_entries or any(isinstance(item, dict) and item.get("kind") == "unresolved" for item in evidence_entries):
        evidence_entries = evidence_artifact_entries(summary, next_action.get("evidence"))
    if evidence_entries:
        lines.extend(["", "## Evidence To Read", "", "| Artifact | Exists | Kind | SHA256 | Size | Path |", "| --- | --- | --- | --- | --- | --- |"])
        for item in evidence_entries:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        markdown_cell(item.get("name", "")),
                        markdown_cell(item.get("exists", "")),
                        markdown_cell(item.get("kind", "")),
                        markdown_cell(item.get("sha256", ""), 80),
                        markdown_cell(item.get("size_bytes", "")),
                        markdown_cell(item.get("path", ""), 1200),
                    ]
                )
                + " |"
            )
    elif next_action.get("evidence"):
        lines.extend(["", "## Evidence To Read", ""])
        for item in as_list(next_action.get("evidence")):
            lines.append(f"- `{item}`")
    current_artifacts = as_list(control.get("current_artifacts"))
    if current_artifacts:
        summary_counts = control.get("artifact_status_summary") if isinstance(control.get("artifact_status_summary"), dict) else {}
        lines.extend(["", "## Current Artifact Status", ""])
        if summary_counts:
            lines.append(
                "- Counts: `"
                + ", ".join(f"{key}={value}" for key, value in summary_counts.items())
                + "`"
            )
        lines.extend(["", "| Artifact | Current | Exists | Kind | SHA256 | Note | Path |", "| --- | --- | --- | --- | --- | --- | --- |"])
        for item in current_artifacts:
            if not isinstance(item, dict):
                continue
            note = first_text(item.get("load_error"), item.get("ignored_reason"), "missing" if item.get("missing_current_artifact") else "", limit=500)
            lines.append(
                "| "
                + " | ".join(
                    [
                        markdown_cell(item.get("name", "")),
                        markdown_cell(item.get("current", "")),
                        markdown_cell(item.get("exists", "")),
                        markdown_cell(item.get("kind", "")),
                        markdown_cell(item.get("sha256", ""), 80),
                        markdown_cell(note, 700),
                        markdown_cell(item.get("path", ""), 1200),
                    ]
                )
                + " |"
            )
    next_steps = as_list(control.get("recommended_next_steps"))
    if not next_steps:
        next_steps = recommended_next_steps(next_action, control)
    if next_steps:
        lines.extend(["", "## Recommended Next Steps", "", "| Step | Type | Detail | Evidence | Command |", "| --- | --- | --- | --- | --- |"])
        for item in next_steps:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        markdown_cell(item.get("id", "")),
                        markdown_cell(item.get("kind", "")),
                        markdown_cell(item.get("description", ""), 1200),
                        markdown_cell(", ".join(str(ref) for ref in as_list(item.get("evidence"))), 1200),
                        markdown_cell(item.get("command", ""), 1200),
                    ]
                )
                + " |"
            )
    if next_action.get("reason_codes"):
        lines.extend(["", "## Reason Codes", "", "`" + ", ".join(str(item) for item in as_list(next_action.get("reason_codes"))) + "`"])
    input_errors = as_list(next_action.get("input_artifact_errors"))
    if input_errors:
        lines.extend(["", "## Input Artifacts To Fix", "", "| Artifact | Error | Path |", "| --- | --- | --- |"])
        for item in input_errors:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        markdown_cell(item.get("name", "")),
                        markdown_cell(item.get("error", "")),
                        markdown_cell(item.get("path", ""), 1200),
                    ]
                )
                + " |"
            )
    start_plan = as_list(next_action.get("service_start_plan"))
    if start_plan:
        lines.extend(["", "## Service Start Plan", "", "| Service | CWD | Command | Reason |", "| --- | --- | --- | --- |"])
        for item in start_plan:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        markdown_cell(item.get("service", "")),
                        markdown_cell(item.get("cwd", "")),
                        markdown_cell(" ".join(str(part) for part in as_list(item.get("command"))), 1200),
                        markdown_cell(item.get("reason", "")),
                    ]
                )
                + " |"
            )
    blocked = next_action.get("blocked_followups") if isinstance(next_action.get("blocked_followups"), dict) else {}
    if blocked:
        lines.extend(["", "## Blocked Follow-Ups", ""])
        lines.append(f"- Actionable skipped count: `{blocked.get('actionable_skipped_count', 0)}`")
        if blocked.get("skipped_reason_counts"):
            lines.append(f"- Skipped reasons: `{compact_json(blocked.get('skipped_reason_counts'))}`")
        examples = as_list(blocked.get("actionable_examples"))
        if examples:
            lines.extend(["", "| Probe | Layer | Reason | Source Test |", "| --- | --- | --- | --- |"])
            for item in examples:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            markdown_cell(item.get("id", "")),
                            markdown_cell(item.get("layer", "")),
                            markdown_cell(item.get("reason", ""), 900),
                            markdown_cell(item.get("source_test_id", "")),
                        ]
                )
                    + " |"
                )
    repeated = next_action.get("repeated_next_probes") if isinstance(next_action.get("repeated_next_probes"), dict) else {}
    if repeated:
        lines.extend(["", "## Repeated Next-Probes", ""])
        lines.append(f"- SHA256: `{repeated.get('sha256')}`")
        if repeated.get("previous_iteration") is not None:
            lines.append(f"- Previous iteration: `{repeated.get('previous_iteration')}`")
        else:
            lines.append("- Previous source: `resume binding`")
        if repeated.get("matched_field"):
            lines.append(f"- Matched field: `{repeated.get('matched_field')}`")
        if repeated.get("previous_action"):
            lines.append(f"- Previous action: `{repeated.get('previous_action')}`")
        lines.append("- Agent decision: stop automatic iteration and report or manually revise the plan/requirement.")
    non_actionable = next_action.get("non_actionable_followups") if isinstance(next_action.get("non_actionable_followups"), dict) else {}
    if non_actionable:
        lines.extend(["", "## Non-Actionable Follow-Ups", ""])
        lines.append(f"- Skipped count: `{non_actionable.get('skipped_count', 0)}`")
        lines.append(f"- Actionable skipped count: `{non_actionable.get('actionable_skipped_count', 0)}`")
        if non_actionable.get("skipped_reason_counts"):
            lines.append(f"- Skipped reasons: `{compact_json(non_actionable.get('skipped_reason_counts'))}`")
        examples = as_list(non_actionable.get("examples"))
        if examples:
            lines.extend(["", "| Probe | Layer | Reason | Source Test |", "| --- | --- | --- | --- |"])
            for item in examples:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            markdown_cell(item.get("id", "")),
                            markdown_cell(item.get("layer", "")),
                            markdown_cell(item.get("reason", ""), 900),
                            markdown_cell(item.get("source_test_id", "")),
                        ]
                    )
                    + " |"
                )
    iteration_timeline = as_list(control.get("iteration_timeline")) or compact_iteration_timeline(summary)
    if iteration_timeline:
        lines.extend(["", "## Iterations", "", "| Iteration | Applied | Cycle Exit | Preview Exit | Verdict | Next Action | Stop Before | Next-Probes SHA256 | Snapshot |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"])
        for item in iteration_timeline:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        markdown_cell(item.get("iteration", "")),
                        markdown_cell(item.get("applied_next_before_cycle", "")),
                        markdown_cell(item.get("cycle_exit_code", "")),
                        markdown_cell(item.get("preview_exit_code", "")),
                        markdown_cell(item.get("verdict", "")),
                        markdown_cell(item.get("next_action", "")),
                        markdown_cell(item.get("stop_before_cycle", "")),
                        markdown_cell(item.get("preview_next_probes_sha256", ""), 80),
                        markdown_cell(item.get("snapshot", ""), 1200),
                    ]
                )
                + " |"
            )
    lines.extend(["", f"_Generated at {datetime.now().isoformat(timespec='seconds')}._", ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, "\n".join(lines))
    return path


def run_command(args: list[str], cwd: Path) -> dict[str, Any]:
    started_at_epoch = time.time()
    started_at = datetime.now().isoformat(timespec="seconds")
    proc = subprocess.run(args, cwd=str(cwd), text=True, capture_output=True)
    return {
        "command": args,
        "cwd": str(cwd),
        "started_at": started_at,
        "started_at_epoch": started_at_epoch,
        "finished_at": datetime.now().isoformat(timespec="seconds"),
        "finished_at_epoch": time.time(),
        "exit_code": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
    }


def last_output_path(result: dict[str, Any]) -> Path | None:
    for line in reversed(str(result.get("stdout") or "").splitlines()):
        text = line.strip()
        if text:
            return Path(text).expanduser().resolve()
    return None


def bool_flag(cmd: list[str], flag: str, enabled: bool) -> None:
    if enabled:
        cmd.append(flag)


def option(cmd: list[str], flag: str, value: str | None) -> None:
    if value:
        cmd.extend([flag, value])


def arg_bool(args: argparse.Namespace, name: str, default: bool = False) -> bool:
    return bool(getattr(args, name, default))


def arg_value(args: argparse.Namespace, name: str) -> str | None:
    value = getattr(args, name, None)
    return str(value) if value is not None else None


def arg_list(args: argparse.Namespace, name: str) -> list[Any]:
    value = getattr(args, name, None)
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_iso_epoch(value: Any) -> float | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def result_start_epoch(result: dict[str, Any] | None) -> float | None:
    if not result:
        return None
    value = result.get("started_at_epoch")
    if isinstance(value, (int, float)):
        return float(value)
    return parse_iso_epoch(result.get("started_at"))


def artifact_written_since(path: Path, result: dict[str, Any] | None, data: dict[str, Any], timestamp_fields: tuple[str, ...] = ()) -> bool:
    if not path.exists():
        return False
    start_epoch = result_start_epoch(result)
    if start_epoch is None:
        return True
    for field in timestamp_fields:
        field_epoch = parse_iso_epoch(data.get(field))
        if field_epoch is not None and field_epoch + 1.0 < start_epoch:
            return False
    return path.stat().st_mtime + 0.001 >= start_epoch


def load_current_json(
    path: Path,
    *,
    result: dict[str, Any] | None,
    ignored_reason: str,
    timestamp_fields: tuple[str, ...] = (),
    require_current: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    exists = path.exists()
    data, load_error = try_load_json(path) if exists else ({}, None)
    current = bool(exists and not load_error and require_current and artifact_written_since(path, result, data, timestamp_fields))
    meta = {
        "path": str(path),
        "exists": exists,
        "current": current,
    }
    if load_error:
        meta["load_error"] = load_error
        meta["ignored_reason"] = "unreadable_json_artifact"
    elif exists and not current:
        meta["ignored_reason"] = ignored_reason
    if require_current and not exists:
        meta["missing_current_artifact"] = True
    return (data if current else {}), meta


def step_succeeded(summary: dict[str, Any], name: str) -> bool:
    for item in reversed(as_list(summary.get("steps"))):
        if not isinstance(item, dict) or item.get("name") != name:
            continue
        return item.get("exit_code") == 0 and item.get("skipped") is not True
    return False


def artifact_summary(path: Path, *, current: bool, ignored_reason: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    exists = path.exists()
    data, load_error = try_load_json(path) if exists else ({}, None)
    meta = {
        "path": str(path),
        "exists": exists,
        "current": bool(current and exists),
    }
    if load_error:
        meta["current"] = False
        meta["load_error"] = load_error
        meta["ignored_reason"] = "unreadable_json_artifact"
        return None, meta
    if exists and not current:
        meta["ignored_reason"] = ignored_reason
    if current and not exists:
        meta["missing_current_artifact"] = True
    if not current or not exists:
        return None, meta
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else None
    return summary, meta


ARTIFACT_STATUS_FIELDS = (
    ("run_summary_artifact", "qa-run-summary.json"),
    ("verdict_artifact", "qa-verdict.json"),
    ("cycle_error_artifact", "qa-cycle-error.json"),
    ("adapter_context_artifact", "adapter-context.json"),
    ("adapter_probes_artifact", "adapter-probes.json"),
    ("business_model_artifact", "business-model.json"),
    ("oracle_model_artifact", "oracle-model.json"),
    ("qa_metrics_artifact", "qa-metrics.json"),
    ("closeout_candidates_artifact", "closeout-candidates.json"),
    ("semantic_artifacts_summary_artifact", "semantic-artifacts-summary.json"),
    ("service_runtime_artifact", "service-runtime.json"),
    ("application_artifact", "next-probe-application.json"),
    ("preview_artifact", "next-probe-preview.json"),
    ("service_preflight_artifact", "service-preflight.json"),
    ("defects_artifact", "defects.json"),
    ("results_artifact", "results.json"),
    ("ledger_artifact", "evidence-ledger.json"),
    ("audit_artifact", "audit-summary.json"),
    ("plan_audit_artifact", "plan-audit-summary.json"),
    ("requirement_coverage_artifact", "requirement-coverage.json"),
)


def artifact_status_entries(status: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for field, default_name in ARTIFACT_STATUS_FIELDS:
        meta = status.get(field) if isinstance(status.get(field), dict) else {}
        if not meta:
            continue
        path_text = str(meta.get("path") or "")
        path = Path(path_text) if path_text else None
        entry: dict[str, Any] = {
            "name": path.name if path else default_name,
            "status_field": field,
            "path": path_text,
            "exists": bool(meta.get("exists")),
            "current": bool(meta.get("current")),
        }
        for key in ("load_error", "ignored_reason", "missing_current_artifact", "stable_input_artifact"):
            if key in meta:
                entry[key] = meta.get(key)
        if path and path.exists():
            if path.is_dir():
                entry["kind"] = "directory"
            elif path.is_file():
                entry["kind"] = "file"
                try:
                    stat_result = path.stat()
                    entry["size_bytes"] = stat_result.st_size
                    entry["mtime_epoch"] = stat_result.st_mtime
                    entry["sha256"] = file_sha256(path)
                except OSError as exc:
                    entry["metadata_error"] = str(exc)
            else:
                entry["kind"] = "other"
        else:
            entry["kind"] = "missing"
        entries.append(entry)
    return entries


def artifact_status_summary(entries: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(entries),
        "current": sum(1 for item in entries if item.get("current") is True),
        "missing": sum(1 for item in entries if item.get("exists") is not True),
        "unreadable": sum(1 for item in entries if item.get("load_error")),
        "stale_or_ignored": sum(1 for item in entries if item.get("exists") is True and item.get("current") is not True and not item.get("load_error")),
    }


def step_recorded(summary: dict[str, Any], *names: str) -> bool:
    wanted = {str(name) for name in names if str(name)}
    for item in as_list(summary.get("steps")):
        if isinstance(item, dict) and item.get("name") in wanted and item.get("skipped") is not True:
            return True
    return False


def optional_current_json(
    path: Path,
    *,
    result: dict[str, Any] | None,
    ignored_reason: str,
    expected: bool = False,
    timestamp_fields: tuple[str, ...] = (),
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not path.exists() and not expected:
        return {}, {}
    return load_current_json(path, result=result, ignored_reason=ignored_reason, timestamp_fields=timestamp_fields)


def stable_input_json(path: Path, *, ignored_reason: str = "stable_input_context") -> tuple[dict[str, Any], dict[str, Any]]:
    if not path.exists():
        return {}, {}
    data, load_error = try_load_json(path)
    meta: dict[str, Any] = {
        "path": str(path),
        "exists": True,
        "current": load_error is None,
        "stable_input_artifact": True,
    }
    if load_error:
        meta["current"] = False
        meta["load_error"] = load_error
        meta["ignored_reason"] = ignored_reason
        return {}, meta
    return data, meta


def compact_service_start_plan(preflight: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "service": item.get("service"),
            "cwd": item.get("cwd"),
            "command": as_list(item.get("command")),
            "reason": item.get("reason"),
        }
        for item in as_list(preflight.get("start_plan"))
        if isinstance(item, dict) and item.get("service")
    ]


def compact_service_blockers(preflight: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "service": item.get("service"),
            "reason": item.get("reason"),
            "url": item.get("url"),
            "path": item.get("path"),
            "artifact": item.get("artifact"),
            "error": item.get("error"),
        }
        for item in as_list(preflight.get("blockers"))
        if isinstance(item, dict)
    ]


def summarize_environment_boundary(adapter_context: dict[str, Any]) -> dict[str, Any]:
    if not adapter_context:
        return {}
    boundary = adapter_context.get("environment_boundary") if isinstance(adapter_context.get("environment_boundary"), dict) else {}
    runtime_mode = first_text(boundary.get("runtime_mode"), adapter_context.get("runtime_mode"), limit=160)
    data_boundary_status = first_text(boundary.get("data_boundary_status"), adapter_context.get("data_boundary_status"), limit=300)
    target_environment = first_text(boundary.get("target_environment"), adapter_context.get("target_environment"), limit=160)
    runtime_known = bool(runtime_mode and runtime_mode.lower() not in {"unconfirmed", "unknown"})
    data_lower = data_boundary_status.lower()
    data_known = bool(
        data_boundary_status
        and "unconfirmed" not in data_lower
        and "must be stated" not in data_lower
        and data_lower != "unknown"
    )
    services = [item for item in as_list(adapter_context.get("services")) if isinstance(item, dict)]
    reachable = [item for item in services if item.get("port_open") is True]
    unreachable = [item for item in services if item.get("port_open") is False]
    unknown = [item for item in services if item.get("port_open") is None]
    service_examples = []
    for item in services[:8]:
        service_examples.append(
            {
                "id": item.get("id") or item.get("name"),
                "url": item.get("default_url") or item.get("base_url"),
                "port_open": item.get("port_open"),
                "path_exists": item.get("path_exists"),
            }
        )
    summary = {
        "adapter": first_text(adapter_context.get("adapter"), limit=120),
        "project_root": first_text(adapter_context.get("project_root"), limit=500),
        "runtime_mode": runtime_mode,
        "data_boundary_status": data_boundary_status,
        "target_environment": target_environment,
        "runtime_mode_confirmed": runtime_known,
        "data_boundary_confirmed": data_known,
        "needs_confirmation": not (runtime_known and data_known),
        "service_count": len(services),
        "reachable_service_count": len(reachable),
        "unreachable_service_count": len(unreachable),
        "unknown_service_count": len(unknown),
        "service_examples": [
            {key: value for key, value in item.items() if value not in (None, "", [], {})}
            for item in service_examples
        ],
        "input_artifact_error_count": len(as_list(adapter_context.get("input_artifact_errors"))),
    }
    return {key: value for key, value in summary.items() if value not in (None, "", [], {})}


def summarize_service_preflight(preflight: dict[str, Any]) -> dict[str, Any]:
    if not preflight:
        return {}
    blockers = compact_service_blockers(preflight)
    warnings = [item for item in as_list(preflight.get("warnings")) if isinstance(item, dict)]
    services = [item for item in as_list(preflight.get("services")) if isinstance(item, dict)]
    start_plan = compact_service_start_plan(preflight)
    service_examples = [
        {
            "id": item.get("id") or item.get("service"),
            "url": item.get("default_url") or item.get("url"),
            "required": item.get("required"),
            "port_open": item.get("port_open"),
            "path_exists": item.get("path_exists"),
        }
        for item in services[:8]
    ]
    summary = {
        "adapter": first_text(preflight.get("adapter"), limit=120),
        "runnable": preflight.get("runnable"),
        "required_service_count": len(as_list(preflight.get("required_services"))),
        "service_count": len(services),
        "blocker_count": len(blockers),
        "warning_count": len(warnings),
        "start_plan_count": len(start_plan),
        "blocker_examples": blockers[:8],
        "warning_examples": [
            {
                "service": item.get("service"),
                "reason": item.get("reason"),
                "url": item.get("url"),
                "path": item.get("path"),
                "artifact": item.get("artifact"),
            }
            for item in warnings[:8]
        ],
        "service_examples": [
            {key: value for key, value in item.items() if value not in (None, "", [], {})}
            for item in service_examples
        ],
        "input_artifact_error_count": len(as_list(preflight.get("input_artifact_errors"))),
    }
    return {key: value for key, value in summary.items() if value not in (None, "", [], {})}


def summarize_service_runtime(runtime: dict[str, Any]) -> dict[str, Any]:
    if not runtime:
        return {}
    raw_summary = runtime.get("summary") if isinstance(runtime.get("summary"), dict) else {}
    services = [item for item in as_list(runtime.get("services")) if isinstance(item, dict)]
    keys = (
        "planned_count",
        "started_count",
        "ready_count",
        "failed_count",
        "dry_run_count",
        "stopped_count",
        "skipped_count",
        "input_artifact_error_count",
    )
    summary = {
        "mode": runtime.get("mode"),
        "service_count": len(services),
        "services_started": (runtime.get("safety") or {}).get("services_started") if isinstance(runtime.get("safety"), dict) else None,
    }
    for key in keys:
        if key in raw_summary:
            summary[key] = safe_int(raw_summary.get(key), 0)
    service_examples = []
    for item in services[:8]:
        readiness = item.get("post_start_readiness") if isinstance(item.get("post_start_readiness"), dict) else {}
        if not readiness:
            readiness = item.get("pre_start_readiness") if isinstance(item.get("pre_start_readiness"), dict) else {}
        service_examples.append(
            {
                "service": item.get("service") or item.get("id"),
                "ready": readiness.get("ready"),
                "status": item.get("status") or item.get("reason"),
                "exit_code": item.get("exit_code"),
                "pid": item.get("pid"),
                "log_path": item.get("log_path"),
            }
        )
    if service_examples:
        summary["service_examples"] = [
            {key: value for key, value in item.items() if value not in (None, "", [], {})}
            for item in service_examples
        ]
    return {key: value for key, value in summary.items() if value not in (None, "", [], {})}


def summarize_adapter_probes(adapter_probes: dict[str, Any]) -> dict[str, Any]:
    if not adapter_probes:
        return {}
    raw_summary = adapter_probes.get("summary") if isinstance(adapter_probes.get("summary"), dict) else {}
    recommendations = [item for item in as_list(adapter_probes.get("recommendations")) if isinstance(item, dict)]
    blocked = [item for item in as_list(adapter_probes.get("blocked")) if isinstance(item, dict)]
    added_step_ids = [str(item) for item in as_list(adapter_probes.get("added_step_ids")) if str(item)]
    proposed_step_ids = [str(item) for item in as_list(adapter_probes.get("proposed_step_ids")) if str(item)]
    summary = {
        "stream_test_count": safe_int(raw_summary.get("stream_test_count"), 0),
        "session_api_test_count": safe_int(raw_summary.get("session_api_test_count"), 0),
        "persistence_test_count": safe_int(raw_summary.get("persistence_test_count"), 0),
        "proposed_step_count": safe_int(raw_summary.get("proposed_step_count"), len(proposed_step_ids)),
        "applied_count": safe_int(raw_summary.get("applied_count"), len(added_step_ids)),
        "blocked_probe_count": safe_int(raw_summary.get("blocked_probe_count"), len(blocked)),
        "recommendation_count": len(recommendations),
        "input_artifact_error_count": len(as_list(adapter_probes.get("input_artifact_errors"))),
        "added_step_ids": added_step_ids[:8],
        "blocked_examples": [
            {
                "id": item.get("id"),
                "layer": item.get("layer"),
                "reason": item.get("reason"),
                "service": item.get("service"),
                "required_inputs": as_list(item.get("required_inputs")),
            }
            for item in blocked[:8]
        ],
    }
    return {key: value for key, value in summary.items() if value not in (None, "", [], {})}


def summarize_cycle_error(cycle_error: dict[str, Any]) -> dict[str, Any]:
    if not cycle_error:
        return {}
    result = cycle_error.get("result") if isinstance(cycle_error.get("result"), dict) else {}
    summary = {
        "code": cycle_error.get("code"),
        "phase": cycle_error.get("phase"),
        "message": first_text(cycle_error.get("message"), limit=700),
        "command": as_list(result.get("command")),
        "cwd": result.get("cwd"),
        "exit_code": result.get("exit_code"),
        "stderr": first_text(result.get("stderr"), limit=700),
    }
    return {key: value for key, value in summary.items() if value not in (None, "", [], {})}


def reason_code_set(status: dict[str, Any]) -> set[str]:
    return {str(item) for item in status.get("reason_codes") or [] if item}


def classify_status(status: dict[str, Any]) -> dict[str, Any]:
    reason_codes = reason_code_set(status)
    if status.get("can_claim_pass") is True:
        category = "passed"
        layer = "all_evidence_layers"
        source = "qa-verdict.json"
        operator_hint = "Report the pass only with the audited current-run evidence."
        confidence = "high"
    elif as_list(status.get("next_probe_input_artifact_errors")):
        category = "next_probe_input_integrity"
        layer = "follow_up_probe_input"
        source = "next-probe-preview.json"
        operator_hint = "Repair next-probe inputs before applying or previewing follow-up probes."
        confidence = "high"
    elif as_list(status.get("input_artifact_errors")):
        category = "input_artifact_integrity"
        layer = "artifact_input"
        source = "qa-verdict.json"
        operator_hint = "Repair the named unreadable or malformed artifacts before evaluating product behavior."
        confidence = "high"
    elif reason_codes.intersection(SETUP_BLOCKER_CODES):
        category = "setup_environment_blocker"
        layer = "runtime_setup"
        source = "service-preflight.json/service-runtime.json"
        operator_hint = "Resolve service readiness, tooling, or startup authorization before product probes can prove behavior."
        confidence = "high"
    elif reason_codes.intersection(PLANNING_BLOCKER_CODES):
        category = "planning_coverage_blocker"
        layer = "requirement_plan"
        source = "requirement-coverage.json/plan-audit-summary.json"
        operator_hint = "Map requirement units or fix invalid probes before executing product checks."
        confidence = "high"
    elif reason_codes.intersection(ENVIRONMENT_BOUNDARY_CODES):
        category = "environment_boundary_unconfirmed"
        layer = "environment_boundary"
        source = "adapter-context.json"
        operator_hint = "Confirm runtime mode and data boundary before any pass claim."
        confidence = "high"
    elif reason_codes.intersection(STRATEGY_COVERAGE_CODES):
        category = "strategy_coverage_gap"
        layer = "plan_strategy"
        source = "plan-audit-summary.json"
        operator_hint = "Add or apply safe probes for planned dimensions that currently have no executable coverage."
        confidence = "high"
    elif any(code.startswith("undispositioned_") for code in reason_codes):
        category = "runtime_evidence_gap"
        layer = "runtime_diagnostics"
        source = "results.json/evidence-ledger.json"
        operator_hint = "Disposition captured console, request, or failed-response evidence before claiming pass."
        confidence = "high"
    elif reason_codes.intersection(PRODUCT_DEFECT_CODES):
        category = "product_defect"
        layer = "feature_behavior"
        source = "defects.json/evidence-ledger.json"
        operator_hint = "Report the observed product defect with evidence instead of treating it as setup work."
        confidence = "high"
    elif reason_codes.intersection(REQUIREMENT_BLOCKER_CODES):
        category = "requirement_or_adapter_blocker"
        layer = "requirement_execution"
        source = "qa-verdict.json/adapter-probes.json"
        operator_hint = "Treat this as blocked test scope unless the missing adapter/input can be supplied safely."
        confidence = "medium"
    elif reason_codes.intersection(EVIDENCE_PIPELINE_CODES) or any(code.startswith("audit_") for code in reason_codes):
        category = "evidence_pipeline_failure"
        layer = "evidence_pipeline"
        source = "qa-cycle-error.json/audit-summary.json"
        operator_hint = "Repair the QA evidence pipeline before interpreting product behavior."
        confidence = "high"
    elif "requirement_untested" in reason_codes:
        category = "untested_coverage_gap"
        layer = "coverage"
        source = "qa-verdict.json"
        operator_hint = "Collect missing evidence or mark the remaining scope blocked/untested explicitly."
        confidence = "medium"
    elif reason_codes:
        category = "non_pass_verdict"
        layer = "verdict"
        source = "qa-verdict.json"
        operator_hint = "Read the verdict reason codes and current-run evidence before deciding the next probe."
        confidence = "medium"
    else:
        category = "unknown_agent_state"
        layer = "agent_loop"
        source = "qa-agent-summary.json"
        operator_hint = "Inspect agent artifacts because no pass or concrete follow-up was exposed."
        confidence = "low"
    return {
        "category": category,
        "blocking_layer": layer,
        "source": source,
        "reason_codes": sorted(reason_codes),
        "operator_hint": operator_hint,
        "confidence": confidence,
    }


def preview_text(value: Any, limit: int = 500) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return compact_json(value, limit)
    text = str(value).replace("\n", " ").strip()
    return text[:limit] + ("...[truncated]" if len(text) > limit else "")


def first_text(*values: Any, limit: int = 500) -> str:
    for value in values:
        text = preview_text(value, limit)
        if text:
            return text
    return ""


def evidence_ref_labels(finding: dict[str, Any], limit: int = 5) -> list[str]:
    refs: list[str] = []
    for item in as_list(finding.get("evidence_refs")):
        label = preview_text(item, 240)
        if label:
            refs.append(label)
    for item in as_list(finding.get("evidence")):
        if isinstance(item, dict):
            label = first_text(item.get("id"), item.get("locator"), item.get("observed_url"), item.get("action"), limit=240)
        else:
            label = preview_text(item, 240)
        if label:
            refs.append(label)
    return refs[:limit]


def summarize_defect_findings(defects: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    findings = [item for item in as_list(defects.get("findings")) if isinstance(item, dict)]
    summary_data = defects.get("summary") if isinstance(defects.get("summary"), dict) else {}
    summary = {
        "count": len(findings),
        "severity_counts": summary_data.get("severity_counts") if isinstance(summary_data.get("severity_counts"), dict) else {},
    }
    compact_findings: list[dict[str, Any]] = []
    for finding in findings[:5]:
        affected_requirements = []
        for item in as_list(finding.get("affected_requirements")):
            if isinstance(item, dict):
                affected_requirements.append(first_text(item.get("id"), item.get("text"), limit=160))
            else:
                affected_requirements.append(preview_text(item, 160))
        compact_findings.append(
            {
                "id": first_text(finding.get("id"), limit=80),
                "title": first_text(finding.get("title"), finding.get("summary"), finding.get("actual"), limit=500),
                "severity": first_text(finding.get("severity"), limit=80),
                "confidence": first_text(finding.get("confidence"), limit=80),
                "layers": [preview_text(item, 80) for item in as_list(finding.get("layers"))[:5] if preview_text(item, 80)],
                "affected_tests": [preview_text(item, 120) for item in as_list(finding.get("affected_tests"))[:5] if preview_text(item, 120)],
                "affected_requirements": [item for item in affected_requirements[:5] if item],
                "actual": preview_text(finding.get("actual"), 700),
                "expected": preview_text(finding.get("expected"), 500),
                "evidence_refs": evidence_ref_labels(finding),
            }
        )
    return summary, compact_findings


def runtime_issue_examples(category: str, items: list[Any], limit: int = 5) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    for item in items[:limit]:
        if not isinstance(item, dict):
            examples.append({"label": preview_text(item, 360)})
            continue
        if category == "failed_responses":
            label = f"HTTP {item.get('status')} {item.get('url', '')}".strip()
            examples.append(
                {
                    "label": preview_text(label, 360),
                    "status": item.get("status"),
                    "method": item.get("method"),
                    "url": preview_text(item.get("url"), 500),
                }
            )
        elif category == "request_failures":
            label = f"{item.get('method', '')} {item.get('url', '')}: {item.get('failure', '')}".strip()
            examples.append(
                {
                    "label": preview_text(label, 360),
                    "method": item.get("method"),
                    "url": preview_text(item.get("url"), 500),
                    "failure": preview_text(item.get("failure"), 500),
                }
            )
        else:
            label = f"{item.get('type', 'error')}: {item.get('text') or item.get('message') or item.get('error') or ''}".strip()
            examples.append(
                {
                    "label": preview_text(label, 360),
                    "type": item.get("type"),
                    "url": preview_text(item.get("url"), 500),
                }
            )
    return [item for item in examples if item.get("label")]


def summarize_runtime_issues(results: dict[str, Any]) -> tuple[dict[str, int], dict[str, list[dict[str, Any]]]]:
    console_errors = as_list(results.get("consoleErrors"))
    if not console_errors:
        console_errors = [
            item
            for item in as_list(results.get("console"))
            if isinstance(item, dict) and str(item.get("type") or "").lower() == "error"
        ]
    failed_responses = as_list(results.get("failedResponses"))
    request_failures = as_list(results.get("requestFailures"))
    counts = {
        "console_errors": len(console_errors),
        "failed_responses": len(failed_responses),
        "request_failures": len(request_failures),
    }
    counts["total"] = sum(counts.values())
    examples = {
        "console_errors": runtime_issue_examples("console_errors", console_errors),
        "failed_responses": runtime_issue_examples("failed_responses", failed_responses),
        "request_failures": runtime_issue_examples("request_failures", request_failures),
    }
    return counts, examples


def status_counts(items: list[Any]) -> dict[str, int]:
    counts = {status: 0 for status in STATUS_ORDER}
    for item in items:
        if isinstance(item, dict) and item.get("status") in counts:
            counts[str(item.get("status"))] += 1
    return counts


def normalized_status_counts(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {status: 0 for status in STATUS_ORDER}
    return {status: safe_int(value.get(status), 0) for status in STATUS_ORDER}


def evidence_layer_for_type(evidence_type: Any) -> str:
    text = str(evidence_type or "unknown")
    return EVIDENCE_TYPE_LAYERS.get(text, "other")


def summarize_evidence_layers(ledger: dict[str, Any], audit_summary: dict[str, Any]) -> dict[str, Any]:
    requirements = as_list(ledger.get("requirements"))
    tests = as_list(ledger.get("tests"))
    evidence = as_list(ledger.get("evidence"))
    audit_counts = audit_summary.get("status_counts") if isinstance(audit_summary.get("status_counts"), dict) else None
    requirement_counts = normalized_status_counts(audit_counts) if audit_counts else status_counts(requirements)
    test_counts = status_counts(tests)
    evidence_type_counts: dict[str, int] = {}
    proof_layer_counts: dict[str, int] = {}
    current_run_evidence_count = 0
    for item in evidence:
        if not isinstance(item, dict):
            continue
        evidence_type = str(item.get("type") or "unknown")
        evidence_type_counts[evidence_type] = evidence_type_counts.get(evidence_type, 0) + 1
        layer = evidence_layer_for_type(evidence_type)
        proof_layer_counts[layer] = proof_layer_counts.get(layer, 0) + 1
        if item.get("current_run") is True:
            current_run_evidence_count += 1
    audit_errors = [preview_text(item, 700) for item in as_list(audit_summary.get("errors")) if preview_text(item, 700)]
    audit_warnings = [preview_text(item, 700) for item in as_list(audit_summary.get("warnings")) if preview_text(item, 700)]
    return {
        "requirement_status_counts": requirement_counts,
        "test_status_counts": test_counts,
        "requirement_count": len(requirements) or safe_int(audit_summary.get("requirement_count"), 0),
        "test_count": len(tests) or safe_int(audit_summary.get("test_count"), 0),
        "evidence_count": len(evidence) or safe_int(audit_summary.get("evidence_count"), 0),
        "current_run_evidence_count": current_run_evidence_count,
        "evidence_type_counts": dict(sorted(evidence_type_counts.items())),
        "proof_layer_counts": dict(sorted(proof_layer_counts.items())),
        "runtime_summary": ledger.get("runtime_summary") if isinstance(ledger.get("runtime_summary"), dict) else {},
        "audit": {
            "passed": audit_summary.get("passed"),
            "error_count": len(audit_errors),
            "warning_count": len(audit_warnings),
            "error_examples": audit_errors[:5],
            "warning_examples": audit_warnings[:5],
        },
    }


def summarize_strategy_coverage(plan_audit: dict[str, Any]) -> dict[str, Any]:
    coverage = plan_audit.get("strategy_coverage") if isinstance(plan_audit.get("strategy_coverage"), dict) else {}
    if not coverage:
        return {}
    dimensions = coverage.get("dimensions") if isinstance(coverage.get("dimensions"), dict) else {}
    compact_dimensions: dict[str, dict[str, Any]] = {}
    for name, item in dimensions.items():
        if not isinstance(item, dict):
            continue
        compact_dimensions[str(name)] = {
            "planned_count": safe_int(item.get("planned_count"), 0),
            "executable_count": safe_int(item.get("executable_count"), 0),
            "observed_executable_count": safe_int(item.get("observed_executable_count"), 0),
            "incidental_executable_count": safe_int(item.get("incidental_executable_count"), 0),
            "blocked_count": safe_int(item.get("blocked_count"), 0),
            "untested_count": safe_int(item.get("untested_count"), 0),
            "inconclusive_count": safe_int(item.get("inconclusive_count"), 0),
            "test_ids": [str(test_id) for test_id in as_list(item.get("test_ids"))[:8]],
            "executable_test_ids": [str(test_id) for test_id in as_list(item.get("executable_test_ids"))[:8]],
            "observed_test_ids": [str(test_id) for test_id in as_list(item.get("observed_test_ids"))[:8]],
        }
    return {
        "gap_count": safe_int(coverage.get("gap_count"), 0),
        "covered_dimensions": [str(item) for item in as_list(coverage.get("covered_dimensions"))],
        "observed_dimensions": [str(item) for item in as_list(coverage.get("observed_dimensions"))],
        "dimensions": compact_dimensions,
        "gaps": [
            {
                "dimension": item.get("dimension"),
                "reason": item.get("reason"),
                "observed_executable_count": safe_int(item.get("observed_executable_count"), 0),
                "test_ids": [str(test_id) for test_id in as_list(item.get("test_ids"))[:8]],
                "observed_test_ids": [str(test_id) for test_id in as_list(item.get("observed_test_ids"))[:8]],
            }
            for item in as_list(coverage.get("gaps"))[:8]
            if isinstance(item, dict)
        ],
    }


def summarize_source_coverage(requirement_coverage: dict[str, Any]) -> dict[str, Any]:
    if not requirement_coverage:
        return {}
    uncovered = [
        item
        for item in as_list(requirement_coverage.get("coverage"))
        if isinstance(item, dict) and item.get("covered") is not True
    ]
    return {
        "passed": requirement_coverage.get("passed"),
        "requirement_unit_count": safe_int(requirement_coverage.get("requirement_unit_count"), 0),
        "matrix_requirement_count": safe_int(requirement_coverage.get("matrix_requirement_count"), 0),
        "covered_count": safe_int(requirement_coverage.get("covered_count"), 0),
        "uncovered_count": safe_int(requirement_coverage.get("uncovered_count"), len(uncovered)),
        "uncovered_examples": [
            {
                "id": first_text(item.get("id"), limit=80),
                "source": first_text(item.get("source"), limit=160),
                "text": first_text(item.get("text"), limit=700),
            }
            for item in uncovered[:5]
        ],
        "error_examples": [preview_text(item, 700) for item in as_list(requirement_coverage.get("errors"))[:5]],
        "warning_examples": [preview_text(item, 700) for item in as_list(requirement_coverage.get("warnings"))[:5]],
    }


def compact_followup_recommendation(item: dict[str, Any]) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    for key in ("id", "step_id", "layer", "reason", "source_test_id"):
        text = first_text(item.get(key), limit=240)
        if text:
            compact[key] = text
    test_ids = [str(test_id) for test_id in as_list(item.get("test_ids"))[:8]]
    if test_ids:
        compact["test_ids"] = test_ids
    requirement_ids = [str(req_id) for req_id in as_list(item.get("requirement_ids"))[:8]]
    if requirement_ids:
        compact["requirement_ids"] = requirement_ids
    return compact


def summarize_followup_report(data: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any]:
    if artifact.get("current") is not True or not data:
        return {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    applied = [item for item in as_list(data.get("applied_recommendations")) if isinstance(item, dict)]
    skipped = [item for item in as_list(data.get("skipped_recommendations")) if isinstance(item, dict)]
    non_actionable_reasons = {"equivalent step already exists in plan"}
    actionable_skipped = [
        item
        for item in skipped
        if str(item.get("reason") or "") not in non_actionable_reasons
    ]
    return {
        "applied_mode": bool(data.get("applied")),
        "recommendation_count": safe_int(summary.get("recommendation_count"), len(applied) + len(skipped)),
        "applied_count": safe_int(summary.get("applied_count"), len(applied)),
        "skipped_count": safe_int(summary.get("skipped_count"), len(skipped)),
        "actionable_skipped_count": len(actionable_skipped),
        "applied_layer_counts": summary.get("applied_layer_counts") if isinstance(summary.get("applied_layer_counts"), dict) else {},
        "skipped_reason_counts": summary.get("skipped_reason_counts") if isinstance(summary.get("skipped_reason_counts"), dict) else {},
        "applied_examples": [compact_followup_recommendation(item) for item in applied[:8]],
        "actionable_skipped_examples": [compact_followup_recommendation(item) for item in actionable_skipped[:8]],
        "skipped_examples": [compact_followup_recommendation(item) for item in skipped[:8]],
    }


def summarize_followups(
    *,
    application_data: dict[str, Any],
    application_artifact: dict[str, Any],
    preview_data: dict[str, Any],
    preview_artifact: dict[str, Any],
) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    application = summarize_followup_report(application_data, application_artifact)
    if application:
        summary["application"] = application
    preview = summarize_followup_report(preview_data, preview_artifact)
    if preview:
        summary["preview"] = preview
    return summary


def build_decision_summary(
    status: dict[str, Any],
    defects: dict[str, Any],
    results: dict[str, Any],
    ledger: dict[str, Any],
    audit_summary: dict[str, Any],
    plan_audit: dict[str, Any],
    requirement_coverage: dict[str, Any],
) -> dict[str, Any]:
    analysis = status.get("failure_analysis") if isinstance(status.get("failure_analysis"), dict) else classify_status(status)
    defect_summary, defect_findings = summarize_defect_findings(defects)
    runtime_counts, runtime_examples = summarize_runtime_issues(results)
    evidence_layer_summary = summarize_evidence_layers(ledger, audit_summary)
    return {
        "category": analysis.get("category"),
        "blocking_layer": analysis.get("blocking_layer"),
        "source": analysis.get("source"),
        "reason_codes": analysis.get("reason_codes", []),
        "environment_boundary": status.get("environment_boundary_summary") if isinstance(status.get("environment_boundary_summary"), dict) else {},
        "service_preflight": status.get("service_preflight_summary") if isinstance(status.get("service_preflight_summary"), dict) else {},
        "service_runtime": status.get("service_runtime_summary") if isinstance(status.get("service_runtime_summary"), dict) else {},
        "adapter_probes": status.get("adapter_probe_summary") if isinstance(status.get("adapter_probe_summary"), dict) else {},
        "cycle_error": status.get("cycle_error_summary") if isinstance(status.get("cycle_error_summary"), dict) else {},
        "defect_summary": defect_summary,
        "defect_findings": defect_findings,
        "runtime_issue_counts": runtime_counts,
        "runtime_issue_examples": runtime_examples,
        "evidence_layer_summary": evidence_layer_summary,
        "strategy_coverage": summarize_strategy_coverage(plan_audit),
        "source_coverage": summarize_source_coverage(requirement_coverage),
        "follow_up_summary": status.get("follow_up_summary") if isinstance(status.get("follow_up_summary"), dict) else {},
    }


def with_failure_analysis(
    action: dict[str, Any],
    status: dict[str, Any],
    *,
    category: str | None = None,
    blocking_layer: str | None = None,
    source: str | None = None,
    operator_hint: str | None = None,
    confidence: str | None = None,
) -> dict[str, Any]:
    analysis = dict(status.get("failure_analysis")) if isinstance(status.get("failure_analysis"), dict) else classify_status(status)
    if category:
        analysis["category"] = category
    if blocking_layer:
        analysis["blocking_layer"] = blocking_layer
    if source:
        analysis["source"] = source
    if operator_hint:
        analysis["operator_hint"] = operator_hint
    if confidence:
        analysis["confidence"] = confidence
    if action.get("reason_codes") and not analysis.get("reason_codes"):
        analysis["reason_codes"] = sorted(str(item) for item in as_list(action.get("reason_codes")) if item)
    action["failure_analysis"] = analysis
    if isinstance(status.get("decision_summary"), dict) and not isinstance(action.get("decision_summary"), dict):
        action["decision_summary"] = status["decision_summary"]
    return action


INPUT_REPAIR_ACTIONS = {
    "fix_initialization_inputs",
    "fix_input_artifacts",
    "fix_next_probe_inputs",
    "repreview_next_probes",
    "repair_evidence_pipeline",
}
REPORT_ACTIONS = {
    "report_pass",
    "report_current_verdict",
    "report_product_defect",
    "report_setup_blocker",
    "report_planning_blocker",
    "report_no_new_progress",
}
AUTHORIZATION_ACTIONS = {
    "request_authorization_or_inputs",
    "retry_with_service_start",
    "confirm_environment_boundary",
}


def collect_step_values(next_steps: list[dict[str, Any]], key: str, *, limit: int = 10) -> list[str]:
    values: list[str] = []
    for step in next_steps:
        if not isinstance(step, dict):
            continue
        for value in as_list(step.get(key)):
            text = first_text(value, limit=240)
            if text and text not in values:
                values.append(text)
            if len(values) >= limit:
                return values
    return values


def human_request_definition(action: str) -> tuple[str, str]:
    request_type = "manual_decision"
    prompt = "Review the current QA agent state before continuing or reporting."
    if action == "retry_with_service_start":
        request_type = "authorization"
        prompt = "Authorize local/test service startup with --start-missing-services, or fix service readiness manually."
    elif action == "confirm_environment_boundary":
        request_type = "environment_boundary_confirmation"
        prompt = "Confirm runtime mode and data boundary before treating observed behavior as a product conclusion."
    elif action == "request_authorization_or_inputs":
        request_type = "authorization_or_input"
        prompt = "Provide the missing authorization, safe payload, selector, helper, or lineage repair for blocked follow-up probes."
    elif action in INPUT_REPAIR_ACTIONS:
        request_type = "input_repair"
        prompt = "Repair the listed input artifacts before evaluating product behavior or continuing the loop."
    elif action == "resume_with_more_iterations":
        request_type = "iteration_budget_decision"
        prompt = "Approve and run the hash-bound resume command, or stop and report the current non-pass verdict."
    elif action == "report_no_new_progress":
        request_type = "manual_plan_revision_or_report"
        prompt = "Report the current non-pass verdict or manually revise the requirement/plan before another loop."
    elif action in REPORT_ACTIONS:
        request_type = "report_current_result"
        prompt = "Report the current verdict with the listed evidence artifacts; do not claim pass unless allowed."
    elif action in {"inspect_cycle_failure", "inspect_next_probe_preview_failure", "inspect_agent_artifacts", "repair_evidence_pipeline"}:
        request_type = "artifact_inspection"
        prompt = "Inspect the named QA artifacts before interpreting product behavior."
    return request_type, prompt


def route_model_requires_human(action: str, control: dict[str, Any]) -> bool:
    if not action:
        return False
    if control.get("pass_claim_allowed") is True or control.get("can_continue_automatically") is True:
        return False
    return bool(
        control.get("requires_human_decision")
        or control.get("handoff_required")
        or control.get("requires_authorization")
        or control.get("requires_input_repair")
        or action in REPORT_ACTIONS
    )


def first_gap_from_control(control: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    gap_plan = control.get("evidence_gap_plan") if isinstance(control.get("evidence_gap_plan"), dict) else {}
    gaps = [item for item in as_list(gap_plan.get("gaps")) if isinstance(item, dict)]
    return gap_plan, gaps[0] if gaps else {}, gaps


def operation_for_evidence_gap(gap: dict[str, Any]) -> dict[str, Any]:
    category = str(gap.get("category") or "")
    details = gap.get("details") if isinstance(gap.get("details"), dict) else {}
    operation: dict[str, Any] = {
        "kind": "inspect",
        "route_mode": "inspect",
    }
    if category == "environment_boundary_confirmation":
        operation.update(
            {
                "kind": "confirm",
                "route_mode": "await_confirmation",
                "confirmation_fields": ["runtime_mode", "data_boundary_status", "target_environment"],
            }
        )
    elif category in {"blocked_followup_inputs", "adapter_probe_blocker"}:
        operation.update({"kind": "authorize", "route_mode": "await_authorization", "requires_authorization": True})
    elif category == "runtime_setup_blocker":
        if safe_int(details.get("start_plan_count"), 0) > 0:
            operation.update(
                {
                    "kind": "authorize",
                    "route_mode": "await_authorization",
                    "requires_authorization": True,
                    "recommended_flags": ["--start-missing-services"],
                }
            )
        else:
            operation.update({"kind": "repair", "route_mode": "repair_evidence_pipeline", "requires_input_repair": True})
    elif category in {"runtime_evidence_gap", "strategy_coverage_gap", "source_coverage_gap"}:
        operation.update({"kind": "probe", "route_mode": "repair_evidence_pipeline"})
    elif category in {
        "input_artifact_integrity",
        "artifact_health",
        "evidence_audit",
        "current_run_evidence_gap",
        "qa_cycle_helper_failure",
    }:
        operation.update({"kind": "repair", "route_mode": "repair_evidence_pipeline", "requires_input_repair": True})
    return {key: value for key, value in operation.items() if value not in (None, "", [], {})}


def route_mode_for(
    control: dict[str, Any],
    action: str,
    first_step: dict[str, Any],
    first_gap: dict[str, Any],
) -> str:
    first_gap_operation = (
        first_gap.get("operation")
        if isinstance(first_gap.get("operation"), dict)
        else operation_for_evidence_gap(first_gap)
        if first_gap
        else {}
    )
    first_step_kind = str(first_step.get("kind") or "")
    if control.get("pass_claim_allowed") is True:
        return "report_pass"
    if control.get("can_continue_automatically") is True:
        return "auto_continue"
    if action == "confirm_environment_boundary" or first_gap_operation.get("route_mode") == "await_confirmation":
        return "await_confirmation"
    if action == "resume_with_more_iterations":
        return "await_iteration_budget"
    if (
        control.get("requires_authorization") is True
        or first_step.get("requires_authorization") is True
        or first_gap_operation.get("requires_authorization") is True
    ):
        return "await_authorization"
    if control.get("requires_input_repair") is True:
        return "repair_inputs"
    if control.get("no_new_progress") is True or action == "report_no_new_progress":
        return "manual_revision_or_report"
    if (
        first_gap_operation.get("route_mode") == "repair_evidence_pipeline"
        or first_step.get("requires_input_repair") is True
    ):
        return "repair_evidence_pipeline"
    if first_step_kind == "probe":
        return "repair_evidence_pipeline"
    if action in REPORT_ACTIONS:
        return "report"
    if action:
        return "inspect"
    return "idle"


def summarize_route_step(first_step: dict[str, Any]) -> dict[str, Any]:
    if not first_step:
        return {}
    step_summary = {
        "id": first_step.get("id"),
        "kind": first_step.get("kind"),
        "gap_id": first_step.get("gap_id"),
        "priority": first_step.get("priority"),
        "category": first_step.get("category"),
        "layer": first_step.get("layer"),
        "route_mode": first_step.get("route_mode"),
        "requires_authorization": first_step.get("requires_authorization"),
        "requires_input_repair": first_step.get("requires_input_repair"),
        "evidence_artifact_count": len(as_list(first_step.get("evidence_artifacts"))),
    }
    summary = {key: value for key, value in step_summary.items() if value not in (None, "", [], {})}
    if first_step.get("command_args"):
        summary["has_command_args"] = True
    return summary


def summarize_route_gap(first_gap: dict[str, Any]) -> dict[str, Any]:
    if not first_gap:
        return {}
    operation = (
        first_gap.get("operation")
        if isinstance(first_gap.get("operation"), dict)
        else operation_for_evidence_gap(first_gap)
    )
    gap_summary = {
        "id": first_gap.get("id"),
        "priority": first_gap.get("priority"),
        "category": first_gap.get("category"),
        "layer": first_gap.get("layer"),
        "operation": operation,
    }
    return {key: value for key, value in gap_summary.items() if value not in (None, "", [], {})}


def summarize_human_top_gap(first_gap: dict[str, Any]) -> dict[str, Any]:
    if not first_gap:
        return {}
    first_gap_category = str(first_gap.get("category") or "")
    first_gap_details = first_gap.get("details") if isinstance(first_gap.get("details"), dict) else {}
    top_gap: dict[str, Any] = {
        "id": first_gap.get("id"),
        "priority": first_gap.get("priority"),
        "category": first_gap.get("category"),
        "layer": first_gap.get("layer"),
        "recommended_action": first_text(
            first_gap.get("recommended_action"),
            first_gap.get("summary"),
            limit=700,
        ),
        "evidence": as_list(first_gap.get("evidence")),
    }
    if first_gap_details:
        top_gap["details"] = first_gap_details
    if first_gap_category == "environment_boundary_confirmation":
        top_gap["confirmation_fields"] = ["runtime_mode", "data_boundary_status", "target_environment"]
    if first_gap_category == "runtime_setup_blocker" and safe_int(first_gap_details.get("start_plan_count"), 0) > 0:
        top_gap["recommended_flags"] = ["--start-missing-services"]
    return {key: value for key, value in top_gap.items() if value not in (None, "", [], {})}


def build_agent_route_model(
    next_action: dict[str, Any],
    control: dict[str, Any],
    next_steps: list[dict[str, Any]],
) -> dict[str, Any]:
    action = str(next_action.get("action") or control.get("next_action") or "")
    gap_plan, first_gap, _gaps = first_gap_from_control(control)
    first_step = next((item for item in next_steps if isinstance(item, dict)), {})
    request_type, prompt = human_request_definition(action)
    requires_human = route_model_requires_human(action, control)
    mode = route_mode_for(control, action, first_step, first_gap)
    recommended_flags = [str(item) for item in as_list(control.get("recommended_flags")) if str(item)]
    for item in collect_step_values(next_steps, "recommended_flags", limit=8):
        if item not in recommended_flags:
            recommended_flags.append(item)
    confirmation_fields = collect_step_values(next_steps, "confirmation_fields", limit=8)
    if request_type == "environment_boundary_confirmation":
        confirmation_fields = ["runtime_mode", "data_boundary_status", "target_environment"]
    model: dict[str, Any] = {
        "schema_version": 1,
        "mode": mode,
        "primary_action": action or None,
        "requires_human_action": requires_human,
        "human_request_type": request_type if requires_human else None,
        "human_prompt": prompt if requires_human else None,
        "reason": first_text(control.get("reason"), next_action.get("reason"), limit=700),
        "terminal": bool(control.get("terminal")),
        "can_continue_automatically": bool(control.get("can_continue_automatically")),
        "pass_claim_allowed": bool(control.get("pass_claim_allowed")),
        "handoff_required": bool(control.get("handoff_required")),
        "requires_authorization": bool(control.get("requires_authorization")),
        "requires_input_repair": bool(control.get("requires_input_repair")),
        "can_continue_after_authorization": bool(control.get("can_continue_after_authorization")),
        "can_resume_with_command": bool(control.get("can_resume_with_command")),
        "result_ready_to_report": bool(control.get("result_ready_to_report")),
        "no_new_progress": bool(control.get("no_new_progress")),
        "recommended_next_step_count": len(next_steps),
        "recommended_next_step_ids": [
            str(item.get("id"))
            for item in next_steps
            if isinstance(item, dict) and item.get("id")
        ],
        "evidence_gap_count": safe_int(gap_plan.get("gap_count"), 0),
        "highest_gap_priority": gap_plan.get("highest_priority"),
        "recommended_gap_ids": [str(item) for item in as_list(gap_plan.get("recommended_order")) if str(item)][:5],
        "evidence_artifact_count": len(as_list(control.get("evidence_artifacts"))),
        "current_artifact_count": len(as_list(control.get("current_artifacts"))),
        "evidence": [str(item) for item in as_list(control.get("evidence")) if str(item)],
    }
    first_step_summary = summarize_route_step(first_step)
    if first_step_summary:
        model["first_recommended_step"] = first_step_summary
    first_gap_summary = summarize_route_gap(first_gap)
    if first_gap_summary:
        model["first_evidence_gap"] = first_gap_summary
    top_gap = summarize_human_top_gap(first_gap)
    if top_gap:
        model["top_evidence_gap"] = top_gap
    if confirmation_fields:
        model["confirmation_fields"] = confirmation_fields
    if recommended_flags:
        model["recommended_flags"] = recommended_flags
    required_inputs = collect_step_values(next_steps, "required_inputs")
    if required_inputs:
        model["required_inputs"] = required_inputs
    manual_revision_targets = collect_step_values(next_steps, "manual_revision_targets")
    if manual_revision_targets:
        model["manual_revision_targets"] = manual_revision_targets
    return {key: value for key, value in model.items() if value not in (None, "", [], {})}


def recommended_next_steps(next_action: dict[str, Any], control: dict[str, Any]) -> list[dict[str, Any]]:
    action = str(next_action.get("action") or "")
    evidence = [str(item) for item in as_list(next_action.get("evidence")) if str(item)]
    steps: list[dict[str, Any]] = []

    def add_step(
        step_id: str,
        kind: str,
        description: str,
        *,
        step_evidence: list[str] | None = None,
        command_args: list[Any] | None = None,
    ) -> None:
        item: dict[str, Any] = {
            "id": step_id,
            "kind": kind,
            "description": description,
        }
        if step_evidence is not None:
            item["evidence"] = step_evidence
        elif evidence:
            item["evidence"] = evidence
        if item.get("evidence") and control.get("run_dir"):
            item["evidence_artifacts"] = evidence_artifact_entries(
                {"run_dir": control.get("run_dir")},
                item.get("evidence"),
            )
        if command_args:
            command = [str(part) for part in command_args]
            item["command_args"] = command
            item["command"] = shlex.join(command)
        steps.append(item)

    def add_gap_steps(*, limit: int = 3) -> None:
        gap_plan = control.get("evidence_gap_plan") if isinstance(control.get("evidence_gap_plan"), dict) else {}
        gaps = [item for item in as_list(gap_plan.get("gaps")) if isinstance(item, dict)]
        for gap in gaps[:limit]:
            gap_id = str(gap.get("id") or "unknown-gap")
            priority = str(gap.get("priority") or "")
            category = str(gap.get("category") or "")
            details = gap.get("details") if isinstance(gap.get("details"), dict) else {}
            operation = gap.get("operation") if isinstance(gap.get("operation"), dict) else operation_for_evidence_gap(gap)
            kind = str(operation.get("kind") or "inspect")
            description = first_text(gap.get("recommended_action"), gap.get("summary"), limit=900)
            add_step(
                f"resolve_evidence_gap:{gap_id}",
                kind,
                f"{priority} {gap_id}: {description}".strip(),
                step_evidence=[str(item) for item in as_list(gap.get("evidence")) if str(item)],
            )
            steps[-1]["gap_id"] = gap_id
            if priority:
                steps[-1]["priority"] = priority
            for key in ("category", "layer"):
                if gap.get(key):
                    steps[-1][key] = gap.get(key)
            if details:
                steps[-1]["details"] = details
            for key in ("route_mode", "confirmation_fields", "recommended_flags"):
                if operation.get(key):
                    steps[-1][key] = operation.get(key)
            if operation.get("requires_authorization") is True:
                steps[-1]["requires_authorization"] = True
            if operation.get("requires_input_repair") is True:
                steps[-1]["requires_input_repair"] = True
            if category in {"adapter_probe_blocker", "blocked_followup_inputs"}:
                required_inputs: list[str] = []
                for example in as_list(details.get("examples")):
                    if not isinstance(example, dict):
                        continue
                    for value in as_list(example.get("required_inputs")):
                        text = first_text(value, limit=160)
                        if text and text not in required_inputs:
                            required_inputs.append(text)
                    reason = first_text(example.get("reason"), limit=240)
                    if reason and reason not in required_inputs:
                        required_inputs.append(reason)
                if required_inputs:
                    steps[-1]["required_inputs"] = required_inputs[:8]

    prioritize_gaps = (
        bool(control.get("evidence_gap_plan"))
        and not bool(control.get("can_continue_automatically"))
        and not bool(control.get("pass_claim_allowed"))
        and not bool(control.get("no_new_progress"))
        and action != "confirm_environment_boundary"
        and action != "report_no_new_progress"
    )
    if prioritize_gaps:
        add_gap_steps()

    if action == "continue_with_safe_next_probes":
        expected_hash = first_text(next_action.get("expected_next_probes_sha256"), next_action.get("preview_next_probes_sha256"), limit=80)
        suffix = f" with next-probes.json SHA256 {expected_hash}" if expected_hash else ""
        add_step(
            "continue_with_safe_next_probes",
            "continue",
            "Continue the bounded loop and apply only the previewed safe probes" + suffix + ".",
        )
    elif action == "resume_with_more_iterations":
        add_step(
            "resume_with_more_iterations",
            "run",
            "Resume the loop with a larger iteration budget and the hash-bound existing next-probes.json.",
            command_args=as_list(next_action.get("resume_command_args")),
        )
    elif action == "retry_with_service_start":
        add_step(
            "review_service_start_plan",
            "authorize",
            "Review the generated service start plan; if the target is local/test and safe, authorize service startup.",
            step_evidence=["service-preflight.json", "qa-verdict.json"],
        )
        if as_list(next_action.get("resume_command_args")):
            add_step(
                "retry_with_service_start",
                "run",
                "After authorization, rerun the loop with --start-missing-services.",
                command_args=as_list(next_action.get("resume_command_args")),
            )
    elif action in {"fix_initialization_inputs", "fix_input_artifacts", "fix_next_probe_inputs"}:
        add_step(
            action,
            "repair",
            "Repair the listed input_artifact_errors before evaluating product behavior or continuing the loop.",
            step_evidence=evidence + (["input_artifact_errors"] if control.get("input_artifact_errors") else []),
        )
    elif action == "request_authorization_or_inputs":
        add_step(
            "review_blocked_followups",
            "authorize",
            "Review blocked_followups and provide the missing authorization, safe payload, selector, helper, or lineage repair.",
        )
    elif action == "confirm_environment_boundary":
        add_step(
            "confirm_environment_boundary",
            "confirm",
            "Confirm runtime mode and data boundary before treating observed behavior as a product conclusion.",
        )
    elif action == "report_pass":
        add_step(
            "report_pass",
            "report",
            "Report a pass only with qa-verdict.json can_claim_pass=true and the audited current-run evidence.",
        )
    elif action == "report_no_new_progress":
        add_step(
            "report_no_new_progress",
            "report",
            "Report the current non-pass verdict or manually revise the requirement/plan; automatic follow-up generation has no new safe probe.",
        )
        add_step(
            "manual_revision_after_no_new_progress",
            "revise",
            "Before another loop, change the requirement, plan, safe inputs, authorization, or probe strategy; do not rerun the same next-probes unchanged.",
            step_evidence=["qa-agent-summary.json", "next-probes.json", "next-probe-preview.json"],
        )
        steps[-1]["manual_revision_targets"] = [
            "requirement.md scope or acceptance criteria",
            "test-plan.json probe strategy",
            "safe payloads, selectors, helpers, or authorization",
            "next-probes.json recommendation source inputs",
        ]
    elif action in {"report_product_defect", "report_setup_blocker", "report_planning_blocker", "report_current_verdict"}:
        add_step(
            action,
            "report",
            "Report the current verdict with the listed evidence artifacts; do not claim pass unless qa-verdict.json allows it.",
        )
    elif action in {"inspect_cycle_failure", "inspect_next_probe_preview_failure", "inspect_agent_artifacts", "repair_evidence_pipeline"}:
        add_step(
            action,
            "inspect",
            "Inspect the listed QA agent artifacts before interpreting product behavior.",
        )
    elif action:
        add_step(
            action,
            "inspect",
            "Inspect loop_control, next_action, and the listed evidence artifacts before choosing the next operation.",
        )

    if control.get("evidence_gap_plan") and not prioritize_gaps and action == "confirm_environment_boundary":
        add_gap_steps()

    return steps


def human_action_required(
    next_action: dict[str, Any],
    control: dict[str, Any],
    next_steps: list[dict[str, Any]],
    route_model: dict[str, Any] | None = None,
) -> dict[str, Any]:
    route = route_model or build_agent_route_model(next_action, control, next_steps)
    action = str(route.get("primary_action") or "")
    if not route.get("requires_human_action"):
        return {}

    request: dict[str, Any] = {
        "type": route.get("human_request_type"),
        "action": action,
        "prompt": route.get("human_prompt"),
        "reason": route.get("reason"),
        "blocking_category": control.get("blocking_category"),
        "blocking_layer": control.get("blocking_layer"),
        "requires_authorization": bool(route.get("requires_authorization")),
        "requires_input_repair": bool(route.get("requires_input_repair")),
        "can_continue_after_authorization": bool(route.get("can_continue_after_authorization")),
        "can_resume_with_command": bool(route.get("can_resume_with_command")),
        "recommended_next_step_ids": as_list(route.get("recommended_next_step_ids")),
        "evidence": as_list(route.get("evidence")),
    }
    if control.get("reason_codes"):
        request["reason_codes"] = as_list(control.get("reason_codes"))
    if route.get("recommended_flags"):
        request["recommended_flags"] = as_list(route.get("recommended_flags"))
    if control.get("resume_command_args"):
        request["resume_command_args"] = as_list(control.get("resume_command_args"))
    if control.get("resume_command"):
        request["resume_command"] = control.get("resume_command")
    if control.get("service_start_plan"):
        request["service_start_plan"] = as_list(control.get("service_start_plan"))
    if control.get("input_artifact_errors"):
        request["input_artifact_errors"] = as_list(control.get("input_artifact_errors"))
    if control.get("blocked_followups"):
        request["blocked_followups"] = control.get("blocked_followups")

    for key in ("required_inputs", "confirmation_fields", "manual_revision_targets"):
        if route.get(key):
            request[key] = as_list(route.get(key))
    if route.get("evidence_gap_count") is not None:
        request["evidence_gap_count"] = safe_int(route.get("evidence_gap_count"), 0)
    if route.get("highest_gap_priority"):
        request["highest_gap_priority"] = route.get("highest_gap_priority")
    if route.get("recommended_gap_ids"):
        request["recommended_gap_ids"] = as_list(route.get("recommended_gap_ids"))
    if route.get("top_evidence_gap"):
        request["top_evidence_gap"] = route.get("top_evidence_gap")
    return {key: value for key, value in request.items() if value not in (None, "", [], {})}


def build_orchestration_state(
    control: dict[str, Any],
    next_steps: list[dict[str, Any]],
    human_request: dict[str, Any],
    route_model: dict[str, Any] | None = None,
) -> dict[str, Any]:
    route = route_model or build_agent_route_model(
        {"action": control.get("next_action")},
        control,
        next_steps,
    )

    state: dict[str, Any] = {
        "schema_version": 1,
        "mode": route.get("mode"),
        "primary_action": route.get("primary_action"),
        "terminal": bool(route.get("terminal")),
        "can_continue_automatically": bool(route.get("can_continue_automatically")),
        "pass_claim_allowed": bool(route.get("pass_claim_allowed")),
        "handoff_required": bool(route.get("handoff_required")),
        "requires_authorization": bool(route.get("requires_authorization")),
        "requires_input_repair": bool(route.get("requires_input_repair")),
        "can_continue_after_authorization": bool(route.get("can_continue_after_authorization")),
        "result_ready_to_report": bool(route.get("result_ready_to_report")),
        "no_new_progress": bool(route.get("no_new_progress")),
        "recommended_next_step_count": safe_int(route.get("recommended_next_step_count"), len(next_steps)),
        "evidence_gap_count": safe_int(route.get("evidence_gap_count"), 0),
        "evidence_artifact_count": safe_int(route.get("evidence_artifact_count"), 0),
        "current_artifact_count": safe_int(route.get("current_artifact_count"), 0),
    }
    if route.get("human_request_type"):
        state["human_request_type"] = route.get("human_request_type")
    if route.get("first_recommended_step"):
        state["first_recommended_step"] = route.get("first_recommended_step")
    if route.get("first_evidence_gap"):
        state["first_evidence_gap"] = route.get("first_evidence_gap")

    for key in ("confirmation_fields", "recommended_flags", "required_inputs", "manual_revision_targets"):
        values = as_list(route.get(key)) or as_list(human_request.get(key)) or as_list(control.get(key))
        if values:
            state[key] = [str(item) for item in values if str(item)]
    if control.get("resume_command_args"):
        state["resume_command_args"] = as_list(control.get("resume_command_args"))
    return {key: value for key, value in state.items() if value not in (None, "", [], {})}


def health_status_for_route(route: dict[str, Any], flags: list[str]) -> str:
    mode = str(route.get("mode") or "")
    if route.get("pass_claim_allowed") is True or mode == "report_pass":
        return "pass_claim_ready"
    if route.get("can_continue_automatically") is True or mode == "auto_continue":
        return "needs_auto_continue"
    if route.get("requires_input_repair") is True or mode == "repair_inputs":
        return "blocked_input_repair"
    if route.get("requires_authorization") is True or mode in {"await_authorization", "await_confirmation"}:
        return "blocked_authorization_or_boundary"
    if route.get("no_new_progress") is True or mode == "manual_revision_or_report":
        return "report_or_manual_revision"
    if mode == "repair_evidence_pipeline":
        return "needs_evidence_repair"
    if "audit_errors_present" in flags or "unreadable_artifacts" in flags:
        return "needs_evidence_repair"
    if route.get("result_ready_to_report") is True or mode == "report":
        return "reportable_non_pass"
    return "needs_inspection"


def build_evidence_health(control: dict[str, Any]) -> dict[str, Any]:
    route_model = control.get("agent_route_model") if isinstance(control.get("agent_route_model"), dict) else {}
    route_source = route_model or control
    decision = control.get("decision_summary") if isinstance(control.get("decision_summary"), dict) else {}
    gap_plan = control.get("evidence_gap_plan") if isinstance(control.get("evidence_gap_plan"), dict) else {}
    artifact_summary = control.get("artifact_status_summary") if isinstance(control.get("artifact_status_summary"), dict) else {}
    evidence_layers = decision.get("evidence_layer_summary") if isinstance(decision.get("evidence_layer_summary"), dict) else {}
    audit = evidence_layers.get("audit") if isinstance(evidence_layers.get("audit"), dict) else {}
    runtime_counts = decision.get("runtime_issue_counts") if isinstance(decision.get("runtime_issue_counts"), dict) else {}
    defect_summary = decision.get("defect_summary") if isinstance(decision.get("defect_summary"), dict) else {}
    strategy = decision.get("strategy_coverage") if isinstance(decision.get("strategy_coverage"), dict) else {}
    source_coverage = decision.get("source_coverage") if isinstance(decision.get("source_coverage"), dict) else {}
    environment = decision.get("environment_boundary") if isinstance(decision.get("environment_boundary"), dict) else {}
    service_preflight = decision.get("service_preflight") if isinstance(decision.get("service_preflight"), dict) else {}
    service_runtime = decision.get("service_runtime") if isinstance(decision.get("service_runtime"), dict) else {}
    adapter_probes = decision.get("adapter_probes") if isinstance(decision.get("adapter_probes"), dict) else {}
    cycle_error = decision.get("cycle_error") if isinstance(decision.get("cycle_error"), dict) else {}
    current_run_evidence_count = safe_int(evidence_layers.get("current_run_evidence_count"), 0)
    evidence_count = safe_int(evidence_layers.get("evidence_count"), 0)
    flags: list[str] = []

    def add_flag(flag: str, enabled: bool) -> None:
        if enabled and flag not in flags:
            flags.append(flag)

    add_flag("pass_claim_allowed", route_source.get("pass_claim_allowed") is True)
    add_flag("can_continue_automatically", route_source.get("can_continue_automatically") is True)
    add_flag("result_ready_to_report", route_source.get("result_ready_to_report") is True)
    add_flag("handoff_required", route_source.get("handoff_required") is True)
    add_flag("requires_authorization", route_source.get("requires_authorization") is True)
    add_flag("requires_input_repair", route_source.get("requires_input_repair") is True)
    add_flag("no_new_progress", route_source.get("no_new_progress") is True)
    add_flag("missing_current_artifacts", safe_int(artifact_summary.get("missing"), 0) > 0)
    add_flag("unreadable_artifacts", safe_int(artifact_summary.get("unreadable"), 0) > 0)
    add_flag("stale_or_ignored_artifacts", safe_int(artifact_summary.get("stale_or_ignored"), 0) > 0)
    add_flag("audit_not_passed", audit.get("passed") is False)
    add_flag("audit_errors_present", safe_int(audit.get("error_count"), 0) > 0)
    add_flag("runtime_issues_present", safe_int(runtime_counts.get("total"), 0) > 0)
    add_flag("defects_present", safe_int(defect_summary.get("count"), 0) > 0)
    add_flag("strategy_gaps_present", safe_int(strategy.get("gap_count"), 0) > 0)
    add_flag("source_coverage_gaps_present", safe_int(source_coverage.get("uncovered_count"), 0) > 0)
    add_flag("no_current_run_evidence", evidence_count > 0 and current_run_evidence_count == 0)
    add_flag("environment_boundary_needs_confirmation", environment.get("needs_confirmation") is True)
    add_flag("service_preflight_blockers_present", safe_int(service_preflight.get("blocker_count"), 0) > 0)
    add_flag("service_runtime_failures_present", safe_int(service_runtime.get("failed_count"), 0) > 0)
    add_flag("adapter_probe_blockers_present", safe_int(adapter_probes.get("blocked_probe_count"), 0) > 0)
    add_flag("cycle_error_present", bool(cycle_error))

    health_status = health_status_for_route(route_source, flags)

    health = {
        "schema_version": 1,
        "status": health_status,
        "flags": flags,
        "pass_claim_allowed": bool(route_source.get("pass_claim_allowed")),
        "can_continue_automatically": bool(route_source.get("can_continue_automatically")),
        "result_ready_to_report": bool(route_source.get("result_ready_to_report")),
        "requires_human_decision": bool(control.get("requires_human_decision")),
        "current_artifacts": {
            "total": safe_int(artifact_summary.get("total"), 0),
            "current": safe_int(artifact_summary.get("current"), 0),
            "missing": safe_int(artifact_summary.get("missing"), 0),
            "unreadable": safe_int(artifact_summary.get("unreadable"), 0),
            "stale_or_ignored": safe_int(artifact_summary.get("stale_or_ignored"), 0),
        },
        "audit": {
            "passed": audit.get("passed"),
            "error_count": safe_int(audit.get("error_count"), 0),
            "warning_count": safe_int(audit.get("warning_count"), 0),
        },
        "runtime_issue_total": safe_int(runtime_counts.get("total"), 0),
        "defect_count": safe_int(defect_summary.get("count"), 0),
        "strategy_gap_count": safe_int(strategy.get("gap_count"), 0),
        "source_uncovered_count": safe_int(source_coverage.get("uncovered_count"), 0),
        "environment_boundary_needs_confirmation": environment.get("needs_confirmation") is True,
        "service_preflight_blocker_count": safe_int(service_preflight.get("blocker_count"), 0),
        "service_runtime_failed_count": safe_int(service_runtime.get("failed_count"), 0),
        "adapter_probe_blocker_count": safe_int(adapter_probes.get("blocked_probe_count"), 0),
        "cycle_error_code": cycle_error.get("code"),
        "evidence_count": evidence_count,
        "current_run_evidence_count": current_run_evidence_count,
        "proof_layer_counts": evidence_layers.get("proof_layer_counts") if isinstance(evidence_layers.get("proof_layer_counts"), dict) else {},
        "evidence_gap_count": safe_int(gap_plan.get("gap_count"), 0),
        "highest_gap_priority": gap_plan.get("highest_priority"),
    }
    if route_model:
        health["route_mode"] = route_model.get("mode")
        health["route_primary_action"] = route_model.get("primary_action")
        if route_model.get("human_request_type"):
            health["route_human_request_type"] = route_model.get("human_request_type")
    return {key: value for key, value in health.items() if value not in (None, "", [], {})}


def build_evidence_gap_plan(control: dict[str, Any]) -> dict[str, Any]:
    decision = control.get("decision_summary") if isinstance(control.get("decision_summary"), dict) else {}
    evidence_layers = decision.get("evidence_layer_summary") if isinstance(decision.get("evidence_layer_summary"), dict) else {}
    audit = evidence_layers.get("audit") if isinstance(evidence_layers.get("audit"), dict) else {}
    strategy = decision.get("strategy_coverage") if isinstance(decision.get("strategy_coverage"), dict) else {}
    source_coverage = decision.get("source_coverage") if isinstance(decision.get("source_coverage"), dict) else {}
    runtime_counts = decision.get("runtime_issue_counts") if isinstance(decision.get("runtime_issue_counts"), dict) else {}
    runtime_examples = decision.get("runtime_issue_examples") if isinstance(decision.get("runtime_issue_examples"), dict) else {}
    environment = decision.get("environment_boundary") if isinstance(decision.get("environment_boundary"), dict) else {}
    service_preflight = decision.get("service_preflight") if isinstance(decision.get("service_preflight"), dict) else {}
    service_runtime = decision.get("service_runtime") if isinstance(decision.get("service_runtime"), dict) else {}
    adapter_probes = decision.get("adapter_probes") if isinstance(decision.get("adapter_probes"), dict) else {}
    cycle_error = decision.get("cycle_error") if isinstance(decision.get("cycle_error"), dict) else {}
    reason_codes = {str(item) for item in as_list(control.get("reason_codes")) if str(item)}
    gaps: list[dict[str, Any]] = []

    def add_gap(
        gap_id: str,
        priority: str,
        category: str,
        layer: str,
        summary: str,
        recommended_action: str,
        *,
        evidence: list[str] | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        if any(item.get("id") == gap_id for item in gaps):
            return
        gap: dict[str, Any] = {
            "id": gap_id,
            "priority": priority,
            "category": category,
            "layer": layer,
            "summary": summary,
            "recommended_action": recommended_action,
        }
        if evidence:
            gap["evidence"] = evidence
        if details:
            gap["details"] = details
        gap["operation"] = operation_for_evidence_gap(gap)
        gaps.append(gap)

    input_errors = as_list(control.get("input_artifact_errors"))
    if input_errors:
        add_gap(
            "input-artifact-errors",
            "P0",
            "input_artifact_integrity",
            "artifact_input",
            "Required input artifacts are missing, unreadable, malformed, or mismatched.",
            "Repair the listed input_artifact_errors before running more probes or reporting product behavior.",
            evidence=["qa-verdict.json", "qa-agent-summary.json"],
            details={"count": len(input_errors), "examples": input_errors[:5]},
        )

    artifact_entries = [item for item in as_list(control.get("current_artifacts")) if isinstance(item, dict)]
    unhealthy_artifacts = [
        item
        for item in artifact_entries
        if item.get("exists") is not True or item.get("load_error") or item.get("current") is not True
    ]
    if unhealthy_artifacts:
        add_gap(
            "current-artifact-health",
            "P0",
            "artifact_health",
            "artifact_currentness",
            "One or more expected current-run conclusion artifacts are missing, stale, ignored, or unreadable.",
            "Regenerate or repair the named artifacts before trusting the loop verdict.",
            details={
                "count": len(unhealthy_artifacts),
                "examples": [
                    {
                        "name": item.get("name"),
                        "current": item.get("current"),
                        "exists": item.get("exists"),
                        "load_error": item.get("load_error"),
                        "ignored_reason": item.get("ignored_reason"),
                    }
                    for item in unhealthy_artifacts[:6]
                ],
            },
        )

    if environment.get("needs_confirmation") is True or reason_codes.intersection(ENVIRONMENT_BOUNDARY_CODES):
        add_gap(
            "environment-boundary",
            "P0",
            "environment_boundary_confirmation",
            "environment_boundary",
            "Runtime mode or data boundary is unconfirmed, so product conclusions and pass claims are unsafe.",
            "Confirm runtime_mode, data_boundary_status, and target_environment before treating observed behavior as a product conclusion.",
            evidence=["adapter-context.json", "qa-verdict.json"],
            details={
                "runtime_mode": environment.get("runtime_mode"),
                "data_boundary_status": environment.get("data_boundary_status"),
                "target_environment": environment.get("target_environment"),
                "reason_codes": sorted(reason_codes.intersection(ENVIRONMENT_BOUNDARY_CODES)),
            },
        )

    cycle_helper_codes = sorted(
        reason_codes.intersection({"cycle_helper_failed", "helper_output_unreadable", "cycle_error_omitted", "invalid_adapter_context"})
    )
    if cycle_helper_codes or cycle_error:
        add_gap(
            "cycle-helper-error",
            "P0",
            "qa_cycle_helper_failure",
            "evidence_pipeline",
            "The QA cycle helper pipeline failed or produced an unreadable required artifact.",
            "Inspect qa-cycle-error.json and repair the failed helper or its inputs before interpreting product behavior.",
            evidence=["qa-cycle-error.json", "qa-verdict.json", "qa-run-summary.json"],
            details={"reason_codes": cycle_helper_codes, "cycle_error": cycle_error},
        )

    service_blocker_count = safe_int(service_preflight.get("blocker_count"), 0)
    if service_blocker_count > 0:
        add_gap(
            "service-preflight-blockers",
            "P0",
            "runtime_setup_blocker",
            "service_preflight",
            f"{service_blocker_count} service preflight blocker(s) prevent trustworthy product probes.",
            "Resolve service readiness or authorize the generated local/test start plan before running broad product probes.",
            evidence=["service-preflight.json", "adapter-context.json", "qa-verdict.json"],
            details={
                "blocker_count": service_blocker_count,
                "start_plan_count": safe_int(service_preflight.get("start_plan_count"), 0),
                "examples": as_list(service_preflight.get("blocker_examples"))[:5],
            },
        )

    service_failed_count = safe_int(service_runtime.get("failed_count"), 0)
    if service_failed_count > 0:
        add_gap(
            "service-runtime-failures",
            "P0",
            "runtime_setup_blocker",
            "service_runtime",
            f"{service_failed_count} service startup/readiness failure(s) were captured.",
            "Inspect service-runtime.json and service logs, then repair or restart failed local/test services before product probes.",
            evidence=["service-runtime.json", "service-preflight.json", "qa-verdict.json"],
            details={
                "failed_count": service_failed_count,
                "planned_count": safe_int(service_runtime.get("planned_count"), 0),
                "ready_count": safe_int(service_runtime.get("ready_count"), 0),
                "examples": as_list(service_runtime.get("service_examples"))[:5],
            },
        )

    adapter_blocker_count = safe_int(adapter_probes.get("blocked_probe_count"), 0)
    if adapter_blocker_count > 0 or "adapter_probe_blocked" in reason_codes:
        add_gap(
            "adapter-probe-blockers",
            "P1",
            "adapter_probe_blocker",
            "adapter_probe_synthesis",
            f"{adapter_blocker_count} adapter-synthesized probe(s) are blocked or missing safe execution inputs.",
            "Provide the missing safe payload, auth state, stream permission, persistence helper, or reachable service, then re-synthesize adapter probes.",
            evidence=["adapter-probes.json", "adapter-context.json", "test-plan.json"],
            details={
                "blocked_probe_count": adapter_blocker_count,
                "examples": as_list(adapter_probes.get("blocked_examples"))[:5],
                "reason_codes": sorted(reason_codes.intersection({"adapter_probe_blocked"})),
            },
        )

    audit_error_count = safe_int(audit.get("error_count"), 0)
    if audit.get("passed") is False or audit_error_count > 0:
        add_gap(
            "audit-errors",
            "P0",
            "evidence_audit",
            "evidence_integrity",
            "Evidence audit is failing or has blocking errors.",
            "Repair the ledger/evidence binding errors before interpreting raw results as pass/fail.",
            evidence=["audit-summary.json", "evidence-ledger.json", "results.json"],
            details={"error_count": audit_error_count, "examples": as_list(audit.get("error_examples"))[:5]},
        )

    uncovered_count = safe_int(source_coverage.get("uncovered_count"), 0)
    if uncovered_count > 0:
        add_gap(
            "requirement-source-coverage",
            "P1",
            "source_coverage_gap",
            "requirement_source",
            f"{uncovered_count} requirement source unit(s) are not mapped to matrix rows.",
            "Map each uncovered requirement source unit to a test row, or explicitly mark it blocked, untested, or out of scope.",
            evidence=["requirement-coverage.json", "test-matrix.json"],
            details={"uncovered_count": uncovered_count, "examples": as_list(source_coverage.get("uncovered_examples"))[:5]},
        )

    runtime_total = safe_int(runtime_counts.get("total"), 0)
    if runtime_total > 0:
        add_gap(
            "runtime-disposition",
            "P1",
            "runtime_evidence_gap",
            "runtime_diagnostics",
            f"{runtime_total} runtime issue(s) need disposition before any pass claim.",
            "Run or apply focused runtime disposition probes for console errors, failed responses, and request failures.",
            evidence=["results.json", "defects.json", "next-probes.json"],
            details={
                "counts": runtime_counts,
                "examples": {
                    key: as_list(value)[:3]
                    for key, value in runtime_examples.items()
                    if as_list(value)
                },
            },
        )

    strategy_gap_count = safe_int(strategy.get("gap_count"), 0)
    if strategy_gap_count > 0:
        strategy_gaps = [item for item in as_list(strategy.get("gaps")) if isinstance(item, dict)]
        add_gap(
            "strategy-coverage",
            "P2",
            "strategy_coverage_gap",
            "plan_strategy",
            f"{strategy_gap_count} planned evidence dimension(s) have no direct executable coverage.",
            "Add or apply safe concrete probes for each uncovered strategy dimension before claiming full coverage.",
            evidence=["plan-audit-summary.json", "test-plan.json", "test-matrix.json"],
            details={
                "gap_count": strategy_gap_count,
                "dimensions": [str(item.get("dimension")) for item in strategy_gaps[:8] if item.get("dimension")],
                "examples": strategy_gaps[:5],
            },
        )

    blocked_followups = control.get("blocked_followups") if isinstance(control.get("blocked_followups"), dict) else {}
    actionable_skipped_count = safe_int(blocked_followups.get("actionable_skipped_count"), 0)
    if actionable_skipped_count > 0:
        add_gap(
            "blocked-followups",
            "P2",
            "blocked_followup_inputs",
            "follow_up_probe",
            f"{actionable_skipped_count} follow-up probe recommendation(s) need authorization or concrete inputs.",
            "Provide the missing authorization, safe payload, selector, helper, or lineage repair, then re-preview next probes.",
            evidence=["next-probe-preview.json", "next-probes.json"],
            details={"examples": as_list(blocked_followups.get("actionable_examples"))[:5]},
        )

    evidence_count = safe_int(evidence_layers.get("evidence_count"), 0)
    current_run_evidence_count = safe_int(evidence_layers.get("current_run_evidence_count"), 0)
    if evidence_count > 0 and current_run_evidence_count == 0:
        add_gap(
            "current-run-evidence",
            "P1",
            "current_run_evidence_gap",
            "evidence_freshness",
            "Evidence exists, but none is marked as current_run.",
            "Collect fresh current-run evidence or mark stale/historical evidence explicitly before reporting pass/fail.",
            evidence=["evidence-ledger.json", "audit-summary.json"],
            details={"evidence_count": evidence_count, "current_run_evidence_count": current_run_evidence_count},
        )

    priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    gaps.sort(key=lambda item: (priority_order.get(str(item.get("priority")), 9), str(item.get("id") or "")))
    return {
        "schema_version": 1,
        "gap_count": len(gaps),
        "highest_priority": gaps[0].get("priority") if gaps else None,
        "recommended_order": [str(item.get("id")) for item in gaps],
        "gaps": gaps,
    }


def latest_iteration_status(summary: dict[str, Any]) -> dict[str, Any]:
    item = latest_iteration(summary)
    if isinstance(item.get("status"), dict):
        return item["status"]
    return {}


def latest_iteration(summary: dict[str, Any]) -> dict[str, Any]:
    iterations = as_list(summary.get("iterations"))
    for item in reversed(iterations):
        if isinstance(item, dict):
            return item
    return {}


def compact_iteration_timeline(summary: dict[str, Any]) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = []
    for item in as_list(summary.get("iterations")):
        if not isinstance(item, dict):
            continue
        cycle = item.get("cycle") if isinstance(item.get("cycle"), dict) else {}
        preview = item.get("preview") if isinstance(item.get("preview"), dict) else {}
        status = item.get("status") if isinstance(item.get("status"), dict) else {}
        action = item.get("next_action") if isinstance(item.get("next_action"), dict) else {}
        analysis = action.get("failure_analysis") if isinstance(action.get("failure_analysis"), dict) else {}
        if not analysis and isinstance(status.get("failure_analysis"), dict):
            analysis = status["failure_analysis"]
        snapshot = item.get("snapshot_details") if isinstance(item.get("snapshot_details"), dict) else {}
        entry: dict[str, Any] = {
            "iteration": item.get("iteration"),
            "applied_next_before_cycle": bool(item.get("applied_next_before_cycle")),
            "cycle_exit_code": cycle.get("exit_code") if cycle else None,
            "preview_exit_code": preview.get("exit_code") if preview else None,
            "preview_skipped_reason": item.get("preview_skipped_reason"),
            "stop_before_cycle": item.get("stop_before_cycle"),
            "verdict": status.get("verdict"),
            "can_claim_pass": status.get("can_claim_pass"),
            "next_action": action.get("action"),
            "automatable": action.get("automatable"),
            "blocking_category": analysis.get("category"),
            "reason_codes": as_list(analysis.get("reason_codes")) or as_list(action.get("reason_codes")) or as_list(status.get("reason_codes")),
            "preview_next_probes_sha256": item.get("preview_next_probes_sha256")
            or action.get("preview_next_probes_sha256")
            or action.get("expected_next_probes_sha256"),
            "snapshot": item.get("snapshot"),
            "snapshot_copied_count": len(as_list(snapshot.get("copied"))),
            "snapshot_error_count": len(as_list(snapshot.get("errors"))),
        }
        timeline.append({key: value for key, value in entry.items() if value is not None and value != []})
    return timeline


def build_loop_control(summary: dict[str, Any]) -> dict[str, Any]:
    next_action = summary.get("next_action") if isinstance(summary.get("next_action"), dict) else {}
    final = summary.get("final") if isinstance(summary.get("final"), dict) else {}
    latest_item = latest_iteration(summary)
    latest_status = latest_iteration_status(summary)
    decision_status = final or latest_status
    decision_summary = next_action.get("decision_summary") if isinstance(next_action.get("decision_summary"), dict) else {}
    if not decision_summary and isinstance(summary.get("decision_summary"), dict):
        decision_summary = summary["decision_summary"]
    if not decision_summary and isinstance(final.get("decision_summary"), dict):
        decision_summary = final["decision_summary"]
    if not decision_summary and isinstance(latest_status.get("decision_summary"), dict):
        decision_summary = latest_status["decision_summary"]
    action_name = str(next_action.get("action") or "")
    analysis = summary.get("failure_analysis") if isinstance(summary.get("failure_analysis"), dict) else {}
    if not analysis and isinstance(next_action.get("failure_analysis"), dict):
        analysis = next_action["failure_analysis"]
    if not analysis and isinstance(decision_status.get("failure_analysis"), dict):
        analysis = decision_status["failure_analysis"]

    status = summary.get("status")
    terminal = status != "running" and bool(summary.get("finished_at") or summary.get("stop_reason"))
    pass_claim_allowed = decision_status.get("can_claim_pass") is True
    can_continue_automatically = next_action.get("automatable") is True and not terminal
    resume_args = as_list(next_action.get("resume_command_args"))
    input_artifact_errors = as_list(next_action.get("input_artifact_errors"))
    requires_input_repair = action_name in INPUT_REPAIR_ACTIONS or bool(input_artifact_errors)
    requires_authorization = bool(next_action.get("requires_authorization")) or action_name in AUTHORIZATION_ACTIONS
    can_continue_after_authorization = bool(next_action.get("automatable_after_authorization"))
    handoff_required = bool(
        terminal
        and action_name
        and not pass_claim_allowed
        and not can_continue_automatically
    )

    evidence_names = as_list(next_action.get("evidence"))
    control: dict[str, Any] = {
        "schema_version": 1,
        "terminal": terminal,
        "status": status,
        "stop_reason": summary.get("stop_reason"),
        "final_verdict": decision_status.get("verdict"),
        "pass_claim_allowed": pass_claim_allowed,
        "can_continue_automatically": can_continue_automatically,
        "can_continue_after_authorization": can_continue_after_authorization,
        "handoff_required": handoff_required,
        "next_action": action_name or None,
        "result_ready_to_report": action_name in REPORT_ACTIONS or pass_claim_allowed,
        "requires_authorization": requires_authorization,
        "requires_input_repair": requires_input_repair,
        "requires_human_decision": bool(
            action_name
            and not can_continue_automatically
            and not pass_claim_allowed
            and (action_name in AUTHORIZATION_ACTIONS or action_name in INPUT_REPAIR_ACTIONS or next_action.get("automatable") is False)
        ),
        "blocking_category": analysis.get("category"),
        "blocking_layer": analysis.get("blocking_layer"),
        "reason_codes": as_list(analysis.get("reason_codes")) or as_list(next_action.get("reason_codes")),
        "operator_hint": analysis.get("operator_hint"),
        "evidence": evidence_names,
    }
    if summary.get("run_dir"):
        control["run_dir"] = summary.get("run_dir")
    evidence_entries = evidence_artifact_entries(summary, evidence_names)
    if evidence_entries:
        control["evidence_artifacts"] = evidence_entries
    artifact_entries = artifact_status_entries(decision_status)
    if artifact_entries:
        control["current_artifacts"] = artifact_entries
        control["artifact_status_summary"] = artifact_status_summary(artifact_entries)
    if decision_summary:
        control["decision_summary"] = decision_summary
    if input_artifact_errors:
        control["input_artifact_errors"] = input_artifact_errors
    for key in (
        "expected_next_probes_sha256",
        "current_next_probes_sha256",
        "preview_next_probes_sha256",
    ):
        if next_action.get(key):
            control[key] = next_action.get(key)
    resume_binding = next_action.get("resume_binding") if isinstance(next_action.get("resume_binding"), dict) else {}
    if not resume_binding and isinstance(summary.get("resume_next_probes_binding"), dict):
        resume_binding = summary["resume_next_probes_binding"]
    if resume_binding:
        control["resume_next_probes_binding"] = resume_binding
    if latest_item.get("stop_before_cycle"):
        control["stop_before_cycle"] = latest_item.get("stop_before_cycle")
    if next_action.get("reason"):
        control["reason"] = next_action.get("reason")
    if next_action.get("recommended_flags"):
        control["recommended_flags"] = as_list(next_action.get("recommended_flags"))
    if resume_args:
        control["resume_command_args"] = resume_args
        control["can_resume_with_command"] = True
    else:
        control["can_resume_with_command"] = bool(next_action.get("resume_command"))
    if next_action.get("resume_command"):
        control["resume_command"] = next_action.get("resume_command")
    if next_action.get("service_start_plan"):
        control["service_start_plan"] = as_list(next_action.get("service_start_plan"))
    if next_action.get("blocked_followups"):
        control["blocked_followups"] = next_action.get("blocked_followups")
    if next_action.get("non_actionable_followups"):
        control["non_actionable_followups"] = next_action.get("non_actionable_followups")
    if next_action.get("repeated_next_probes"):
        control["repeated_next_probes"] = next_action.get("repeated_next_probes")
    if next_action.get("no_new_progress"):
        control["no_new_progress"] = True
    iteration_timeline = compact_iteration_timeline(summary)
    if iteration_timeline:
        control["iteration_timeline"] = iteration_timeline
        control["iteration_count"] = len(iteration_timeline)
        control["last_iteration"] = iteration_timeline[-1]
    gap_plan = build_evidence_gap_plan(control)
    if gap_plan.get("gap_count", 0) > 0:
        control["evidence_gap_plan"] = gap_plan
    next_steps = recommended_next_steps(next_action, control)
    if next_steps:
        control["recommended_next_steps"] = next_steps
    route_model = build_agent_route_model(next_action, control, next_steps)
    control["agent_route_model"] = route_model
    human_request = human_action_required(next_action, control, next_steps, route_model)
    if human_request:
        control["human_action_required"] = human_request
    control["orchestration_state"] = build_orchestration_state(control, next_steps, human_request, route_model)
    control["evidence_health"] = build_evidence_health(control)
    return control


def failure_category(status: dict[str, Any]) -> str:
    analysis = status.get("failure_analysis") if isinstance(status.get("failure_analysis"), dict) else classify_status(status)
    return str(analysis.get("category") or "")


def auto_continue_allowed(status: dict[str, Any]) -> bool:
    return failure_category(status) in AUTO_CONTINUE_CATEGORIES


def action_policy_for_category(category: str) -> dict[str, Any]:
    policy = CATEGORY_ACTION_POLICIES.get(category)
    if policy:
        return dict(policy)
    return {
        "action": "report_current_verdict",
        "reason": "No safe follow-up probe is available; report the current non-pass verdict with its reason codes.",
        "operator_hint": "Read the verdict and current-run evidence before deciding whether to resume manually.",
        "evidence": ["qa-verdict.json", "report.md"],
    }


def handoff_action_for_category(category: str) -> tuple[str, str, str]:
    policy = action_policy_for_category(category)
    return (
        str(policy.get("action") or "report_current_verdict"),
        str(policy.get("reason") or ""),
        str(policy.get("operator_hint") or ""),
    )


def category_policy_action(
    status: dict[str, Any],
    *,
    reason: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    category = failure_category(status)
    policy = action_policy_for_category(category)
    action: dict[str, Any] = {
        "action": policy.get("action") or "report_current_verdict",
        "automatable": False,
        "reason": reason or policy.get("reason"),
        "reason_codes": status.get("reason_codes"),
        "evidence": as_list(policy.get("evidence")),
    }
    if extra:
        action.update(extra)
    return action


def resume_loop_command(
    args: argparse.Namespace,
    run_dir: Path,
    *,
    max_iterations: int,
    force_preflight_runtime: bool = False,
    force_start_missing_services: bool = False,
    apply_existing_next_probes: bool = False,
    expected_next_probes_sha256: str | None = None,
) -> list[str]:
    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--run-dir",
        str(run_dir),
        "--max-iterations",
        str(max_iterations),
    ]
    bool_flag(cmd, "--preflight-runtime", force_preflight_runtime or arg_bool(args, "preflight_runtime"))
    bool_flag(cmd, "--start-missing-services", force_start_missing_services or arg_bool(args, "start_missing_services"))
    bool_flag(cmd, "--apply-existing-next-probes", apply_existing_next_probes)
    option(cmd, "--expected-next-probes-sha256", expected_next_probes_sha256 or arg_value(args, "expected_next_probes_sha256"))
    cmd.extend([
        "--service-start-timeout",
        str(getattr(args, "service_start_timeout", 60.0)),
    ])
    for flag, enabled in (
        ("--strict-runtime", arg_bool(args, "strict_runtime")),
        ("--require-environment-boundary", arg_bool(args, "require_environment_boundary")),
        ("--skip-probe", arg_bool(args, "skip_probe")),
        ("--service-start-no-wait", arg_bool(args, "service_start_no_wait")),
        ("--allow-preflight-blockers", arg_bool(args, "allow_preflight_blockers")),
        ("--refresh-adapter-context", arg_bool(args, "refresh_adapter_context")),
        ("--synthesize-adapter-probes", arg_bool(args, "synthesize_adapter_probes")),
        ("--allow-live-stream", arg_bool(args, "allow_live_stream")),
        ("--allow-stopped-service", arg_bool(args, "allow_stopped_service")),
        ("--allow-unsafe-command", arg_bool(args, "allow_unsafe_command")),
        ("--allow-mutating-api", arg_bool(args, "allow_mutating_api")),
        ("--allow-required-input-gaps", arg_bool(args, "allow_required_input_gaps")),
        ("--allow-unmapped-requirement-source", arg_bool(args, "allow_unmapped_requirement_source")),
        ("--skip-report", arg_bool(args, "skip_report")),
    ):
        bool_flag(cmd, flag, enabled)
    for flag, value in (
        ("--node-bin", arg_value(args, "node_bin")),
        ("--project-root", arg_value(args, "project_root")),
        ("--runtime-mode", arg_value(args, "runtime_mode")),
        ("--data-boundary-status", arg_value(args, "data_boundary_status")),
        ("--agent-id", arg_value(args, "agent_id")),
        ("--user-id", arg_value(args, "user_id")),
        ("--marker", arg_value(args, "marker")),
        ("--question", arg_value(args, "question")),
        ("--ws-path", arg_value(args, "ws_path")),
        ("--session-detail-path", arg_value(args, "session_detail_path")),
        ("--persistence-command", arg_value(args, "persistence_command")),
        ("--summary", arg_value(args, "summary")),
    ):
        option(cmd, flag, value)
    for service_id in arg_list(args, "required_service"):
        cmd.extend(["--required-service", str(service_id)])
    return cmd


def service_start_resume_command(args: argparse.Namespace, run_dir: Path) -> list[str]:
    return resume_loop_command(
        args,
        run_dir,
        max_iterations=int(getattr(args, "max_iterations", 1)),
        force_preflight_runtime=True,
        force_start_missing_services=True,
    )


def init_run_dir(args: argparse.Namespace, script_dir: Path, cwd: Path) -> tuple[Path, dict[str, Any] | None]:
    if args.run_dir:
        return Path(args.run_dir).expanduser().resolve(), None
    init_cmd = [
        sys.executable,
        str(script_dir / "init_qa_artifact.py"),
        "--base-url",
        args.base_url,
        "--out-dir",
        args.out_dir,
        "--project-root",
        args.project_root,
    ]
    option(init_cmd, "--requirement-file", args.requirement_file)
    option(init_cmd, "--requirement-text", args.requirement_text)
    option(init_cmd, "--entry-path", args.entry_path)
    option(init_cmd, "--persistence-command", args.persistence_command)
    option(init_cmd, "--slug", args.slug)
    option(init_cmd, "--runtime-mode", args.runtime_mode)
    option(init_cmd, "--data-boundary-status", args.data_boundary_status)
    bool_flag(init_cmd, "--allow-live-stream", args.allow_live_stream)
    bool_flag(init_cmd, "--allow-mutating-api", args.allow_mutating_api)
    bool_flag(init_cmd, "--skip-adapter-context", args.skip_adapter_context)
    bool_flag(init_cmd, "--no-http-probe", args.no_http_probe)
    result = run_command(init_cmd, cwd=cwd)
    run_dir = last_output_path(result)
    if result["exit_code"] != 0:
        raise InitializationError("Initialization failed.", result=result, run_dir=run_dir)
    if not run_dir:
        raise InitializationError("Initialization did not print a run directory.", result=result)
    return run_dir, result


def initialization_failure_summary_path(args: argparse.Namespace) -> Path:
    if args.summary:
        return Path(args.summary).expanduser().resolve()
    return Path(args.out_dir).expanduser().resolve() / "qa-agent-summary.json"


def write_initialization_failure_summary(
    args: argparse.Namespace,
    path: Path,
    error: InitializationError,
) -> None:
    now = datetime.now().isoformat(timespec="seconds")
    initialization_error = load_json(error.run_dir / "qa-initialization-error.json") if error.run_dir else {}
    input_artifact_errors = as_list(initialization_error.get("input_artifact_errors"))
    failure_analysis = {
        "category": "initialization_input_failure",
        "blocking_layer": "requirement_intake",
        "source": "qa-initialization-error.json",
        "reason_codes": ["initialization_failed"],
        "operator_hint": "Fix the requirement or project input artifacts before creating a runnable QA cycle.",
        "confidence": "high",
    }
    summary = {
        "schema_version": 1,
        "status": "failed",
        "started_at": now,
        "finished_at": now,
        "run_dir": str(error.run_dir) if error.run_dir else None,
        "max_iterations": args.max_iterations,
        "planning_only": bool(args.skip_probe),
        "init": error.result,
        "input_artifact_errors": input_artifact_errors,
        "stop_reason": "initialization_failed",
        "error": str(error),
        "iterations": [],
        "final": {},
        "failure_analysis": failure_analysis,
        "next_action": {
            "action": "fix_initialization_inputs",
            "automatable": False,
            "reason": "init_qa_artifact.py failed before a runnable QA cycle could be created.",
            "input_artifact_errors": input_artifact_errors,
            "evidence": ["qa-agent-summary.json", "init.command", "init.stdout", "init.stderr", "qa-initialization-error.json", "scaffold-summary.json"],
            "failure_analysis": failure_analysis,
        },
    }
    summary["loop_control"] = build_loop_control(summary)
    write_agent_handoff(path, summary)
    write_json(path, summary)


def build_cycle_cmd(args: argparse.Namespace, script_dir: Path, run_dir: Path, apply_next: bool) -> list[str]:
    cmd = [
        sys.executable,
        str(script_dir / "run_qa_cycle.py"),
        "--run-dir",
        str(run_dir),
    ]
    bool_flag(cmd, "--strict-runtime", args.strict_runtime)
    bool_flag(cmd, "--require-environment-boundary", args.require_environment_boundary)
    bool_flag(cmd, "--skip-probe", args.skip_probe)
    bool_flag(cmd, "--preflight-runtime", args.preflight_runtime)
    bool_flag(cmd, "--start-missing-services", args.start_missing_services)
    bool_flag(cmd, "--service-start-no-wait", args.service_start_no_wait)
    bool_flag(cmd, "--allow-preflight-blockers", args.allow_preflight_blockers)
    bool_flag(cmd, "--refresh-adapter-context", args.refresh_adapter_context)
    bool_flag(cmd, "--synthesize-adapter-probes", args.synthesize_adapter_probes)
    bool_flag(cmd, "--allow-live-stream", args.allow_live_stream)
    bool_flag(cmd, "--allow-stopped-service", args.allow_stopped_service)
    bool_flag(cmd, "--allow-unsafe-command", args.allow_unsafe_command)
    bool_flag(cmd, "--allow-unmapped-requirement-source", args.allow_unmapped_requirement_source)
    bool_flag(cmd, "--allow-mutating-api-next-probes", args.allow_mutating_api)
    bool_flag(cmd, "--skip-report", args.skip_report)
    if apply_next:
        cmd.append("--apply-next-probes")
    option(cmd, "--node-bin", args.node_bin)
    option(cmd, "--agent-id", args.agent_id)
    option(cmd, "--user-id", args.user_id)
    option(cmd, "--marker", args.marker)
    option(cmd, "--question", args.question)
    option(cmd, "--ws-path", args.ws_path)
    option(cmd, "--session-detail-path", args.session_detail_path)
    option(cmd, "--persistence-command", args.persistence_command)
    option(cmd, "--project-root", args.project_root)
    option(cmd, "--runtime-mode", args.runtime_mode)
    option(cmd, "--data-boundary-status", args.data_boundary_status)
    for service_id in args.required_service or []:
        cmd.extend(["--required-service", service_id])
    cmd.extend(["--service-start-timeout", str(args.service_start_timeout)])
    return cmd


def build_preview_cmd(args: argparse.Namespace, script_dir: Path, run_dir: Path) -> list[str]:
    cmd = [
        sys.executable,
        str(script_dir / "apply_next_probes.py"),
        "--run-dir",
        str(run_dir),
        "--out",
        str(run_dir / "next-probe-preview.json"),
    ]
    bool_flag(cmd, "--allow-live-stream", args.allow_live_stream)
    bool_flag(cmd, "--allow-command-probes", args.allow_unsafe_command)
    bool_flag(cmd, "--allow-mutating-api", args.allow_mutating_api)
    bool_flag(cmd, "--allow-required-input-gaps", args.allow_required_input_gaps)
    return cmd


def should_apply_existing_next_probes(args: argparse.Namespace, run_dir: Path) -> bool:
    return bool(args.run_dir and args.apply_existing_next_probes and (run_dir / "next-probes.json").is_file())


def existing_next_probes_unavailable_error(run_dir: Path) -> str:
    path = run_dir / "next-probes.json"
    if not path.exists():
        return "missing"
    if path.is_dir():
        return "path_is_directory"
    return "not_regular_file"


def unavailable_existing_next_probes_action(run_dir: Path) -> dict[str, Any]:
    error = existing_next_probes_unavailable_error(run_dir)
    return {
        "action": "repreview_next_probes",
        "automatable": False,
        "reason": "--apply-existing-next-probes was requested, but next-probes.json is missing or not a readable file; re-run preview or regenerate next probes before applying.",
        "input_artifact_errors": [
            {
                "name": "next_probes",
                "path": str(run_dir / "next-probes.json"),
                "error": error,
                "required": True,
            }
        ],
        "evidence": ["next-probes.json", "qa-agent-summary.json"],
        "failure_analysis": {
            "category": "next_probe_input_integrity",
            "blocking_layer": "follow_up_probe_input",
            "source": "next-probes.json",
            "confidence": "high",
            "operator_hint": "Regenerate next-probes.json or re-run next-probe preview before applying existing follow-up probes.",
        },
    }


def next_probes_hash_mismatch_action(run_dir: Path, expected_sha256: str, current_sha256: str | None) -> dict[str, Any]:
    next_probes_path = run_dir / "next-probes.json"
    error_code = "previewed_next_probes_hash_mismatch" if current_sha256 else "next_probes_missing_or_unreadable"
    return {
        "action": "repreview_next_probes",
        "automatable": False,
        "reason": "next-probes.json no longer matches the file that was previewed for safe application; re-run preview or regenerate next probes before applying.",
        "expected_next_probes_sha256": expected_sha256,
        "current_next_probes_sha256": current_sha256,
        "input_artifact_errors": [
            {
                "name": "next_probes",
                "path": str(next_probes_path),
                "error": error_code,
                "expected_sha256": expected_sha256,
                "current_sha256": current_sha256,
                "required": True,
            }
        ],
        "evidence": ["next-probes.json", "next-probe-preview.json", "qa-agent-summary.json"],
        "failure_analysis": {
            "category": "next_probe_input_integrity",
            "blocking_layer": "follow_up_probe_input",
            "source": "next-probes.json",
            "confidence": "high",
            "operator_hint": "Re-run next-probe preview or regenerate next-probes.json before applying follow-up probes.",
        },
    }


def prior_next_probes_hash_seen(summary: dict[str, Any], current_sha256: str) -> dict[str, Any] | None:
    current_hash = current_sha256.strip() if isinstance(current_sha256, str) else ""
    if not current_hash:
        return None

    resume_binding = summary.get("resume_next_probes_binding") if isinstance(summary.get("resume_next_probes_binding"), dict) else {}
    for key in ("expected_next_probes_sha256", "preview_next_probes_sha256"):
        if resume_binding.get(key) == current_hash:
            return {
                "sha256": current_hash,
                "previous_iteration": None,
                "matched_field": f"resume_next_probes_binding.{key}",
                "previous_action": "apply_existing_next_probes",
            }

    for item in reversed(as_list(summary.get("iterations"))):
        if not isinstance(item, dict):
            continue
        iteration = item.get("iteration")
        if item.get("preview_next_probes_sha256") == current_hash:
            return {
                "sha256": current_hash,
                "previous_iteration": iteration,
                "matched_field": "iterations.preview_next_probes_sha256",
                "previous_action": (item.get("next_action") or {}).get("action") if isinstance(item.get("next_action"), dict) else None,
            }
        action = item.get("next_action") if isinstance(item.get("next_action"), dict) else {}
        for key in ("expected_next_probes_sha256", "preview_next_probes_sha256"):
            if action.get(key) == current_hash:
                return {
                    "sha256": current_hash,
                    "previous_iteration": iteration,
                    "matched_field": f"iterations.next_action.{key}",
                    "previous_action": action.get("action"),
                }
    return None


def repeated_next_probes_action(status: dict[str, Any], repeated: dict[str, Any]) -> dict[str, Any]:
    current_hash = str(repeated.get("sha256") or "")
    previous_iteration = repeated.get("previous_iteration")
    previous_label = f"iteration {previous_iteration}" if previous_iteration is not None else "the resume binding"
    return with_failure_analysis(
        {
            "action": "report_no_new_progress",
            "automatable": False,
            "reason": f"Next-probe preview produced the same next-probes.json hash already seen in {previous_label}; stop instead of cycling the same follow-ups.",
            "reason_codes": status.get("reason_codes"),
            "no_new_progress": True,
            "repeated_next_probes": {
                "sha256": current_hash,
                "previous_iteration": previous_iteration,
                "matched_field": repeated.get("matched_field"),
                "previous_action": repeated.get("previous_action"),
            },
            "preview_next_probes_sha256": current_hash,
            "evidence": ["next-probe-preview.json", "next-probes.json", "qa-agent-summary.json"],
        },
        status,
        category="no_new_followup_progress",
        blocking_layer="follow_up_probe",
        source="next-probe-preview.json",
        operator_hint="Report the current verdict or change the plan/requirement manually; the automated follow-up loop is repeating the same safe probe set.",
        confidence="high",
    )


def latest_previewed_next_probes_sha256(summary: dict[str, Any]) -> str | None:
    def hash_from(value: Any) -> str | None:
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    top_action = summary.get("next_action") if isinstance(summary.get("next_action"), dict) else {}
    for key in ("expected_next_probes_sha256", "preview_next_probes_sha256"):
        found = hash_from(top_action.get(key))
        if found:
            return found
    for item in reversed(as_list(summary.get("iterations"))):
        if not isinstance(item, dict):
            continue
        found = hash_from(item.get("preview_next_probes_sha256"))
        if found:
            return found
        action = item.get("next_action") if isinstance(item.get("next_action"), dict) else {}
        for key in ("expected_next_probes_sha256", "preview_next_probes_sha256"):
            found = hash_from(action.get(key))
            if found:
                return found
    return None


def infer_resume_next_probes_sha256(agent_summary_path: Path, run_dir: Path) -> tuple[str | None, dict[str, Any]]:
    candidate_paths: list[Path] = [agent_summary_path]
    default_path = run_dir / "qa-agent-summary.json"
    if default_path != agent_summary_path:
        candidate_paths.append(default_path)
    detail: dict[str, Any] = {"candidate_summaries": []}
    for path in candidate_paths:
        item: dict[str, Any] = {"path": str(path)}
        if not path.exists():
            item["load_error"] = "missing"
            detail["candidate_summaries"].append(item)
            continue
        data, load_error = try_load_json(path)
        if load_error:
            item["load_error"] = load_error
            detail["candidate_summaries"].append(item)
            continue
        expected_hash = latest_previewed_next_probes_sha256(data)
        if expected_hash:
            item["expected_next_probes_sha256"] = expected_hash
            item["hash_found"] = True
            detail["candidate_summaries"].append(item)
            detail["source"] = str(path)
            detail["expected_next_probes_sha256"] = expected_hash
            return expected_hash, detail
        item["hash_found"] = False
        detail["candidate_summaries"].append(item)
    return None, detail


def missing_next_probes_hash_action(run_dir: Path, resume_binding: dict[str, Any]) -> dict[str, Any]:
    current_sha256 = next_probes_sha256(run_dir)
    return {
        "action": "repreview_next_probes",
        "automatable": False,
        "reason": "--apply-existing-next-probes was requested, but no expected next-probes SHA256 was provided or recoverable from qa-agent-summary.json; re-run preview before applying existing recommendations.",
        "current_next_probes_sha256": current_sha256,
        "resume_binding": resume_binding,
        "input_artifact_errors": [
            {
                "name": "next_probes",
                "path": str(run_dir / "next-probes.json"),
                "error": "missing_expected_next_probes_sha256",
                "current_sha256": current_sha256,
                "required": True,
            }
        ],
        "evidence": ["next-probes.json", "qa-agent-summary.json"],
        "failure_analysis": {
            "category": "next_probe_input_integrity",
            "blocking_layer": "follow_up_probe_input",
            "source": "qa-agent-summary.json",
            "confidence": "high",
            "operator_hint": "Re-run next-probe preview or resume with --expected-next-probes-sha256 before applying existing follow-up probes.",
        },
    }


def remove_snapshot_target(path: Path) -> None:
    if not path.exists():
        return
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def snapshot_iteration(run_dir: Path, iteration: int) -> dict[str, Any]:
    target = run_dir / "iterations" / f"{iteration:02d}"
    target.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "path": str(target),
        "copied": [],
        "errors": [],
    }
    for name in SNAPSHOT_FILES:
        source = run_dir / name
        destination = target / name
        if not source.exists():
            continue
        try:
            if source.is_dir():
                if destination.exists() and not destination.is_dir():
                    remove_snapshot_target(destination)
                shutil.copytree(source, destination, dirs_exist_ok=True)
            else:
                if destination.exists() and destination.is_dir():
                    remove_snapshot_target(destination)
                shutil.copy2(source, destination)
            result["copied"].append(name)
        except (OSError, shutil.Error) as exc:
            result["errors"].append({
                "name": name,
                "source": str(source),
                "target": str(destination),
                "error": str(exc),
            })
    return result


def cycle_status(
    run_dir: Path,
    *,
    cycle_result: dict[str, Any] | None = None,
    applied_next_before_cycle: bool = False,
    preview_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary, run_summary_artifact = load_current_json(
        run_dir / "qa-run-summary.json",
        result=cycle_result,
        ignored_reason="not_written_in_current_cycle",
        timestamp_fields=("started_at", "finished_at"),
    )
    preflight_expected = step_recorded(summary, "preflight_runtime", "preflight_runtime_after_start")
    service_runtime_expected = step_recorded(summary, "service_runtime_start")
    adapter_probes_expected = step_recorded(summary, "synthesize_adapter_probes")
    cycle_error_expected = bool(cycle_result and cycle_result.get("exit_code") != 0) or isinstance(summary.get("cycle_error"), dict)
    verdict, verdict_artifact = load_current_json(
        run_dir / "qa-verdict.json",
        result=cycle_result,
        ignored_reason="not_written_in_current_cycle",
        timestamp_fields=("generated_at",),
    )
    application_data, application_load_error = try_load_json(run_dir / "next-probe-application.json")
    application_current = (
        applied_next_before_cycle
        and run_summary_artifact.get("current") is True
        and step_succeeded(summary, "apply_next_probes")
        and not application_load_error
        and artifact_written_since(run_dir / "next-probe-application.json", cycle_result, application_data)
    )
    application_summary, application_artifact = artifact_summary(
        run_dir / "next-probe-application.json",
        current=application_current,
        ignored_reason="not_applied_in_current_iteration",
    )
    preview_data, preview_load_error = try_load_json(run_dir / "next-probe-preview.json")
    preview_written = bool(
        preview_result
        and not preview_load_error
        and artifact_written_since(run_dir / "next-probe-preview.json", preview_result, preview_data)
    )
    preview_current = bool(
        preview_result
        and preview_result.get("exit_code") == 0
        and not preview_load_error
        and preview_written
    )
    preview_summary, preview_artifact = artifact_summary(
        run_dir / "next-probe-preview.json",
        current=preview_current,
        ignored_reason="not_previewed_in_current_iteration",
    )
    cycle_error, cycle_error_artifact = optional_current_json(
        run_dir / "qa-cycle-error.json",
        result=cycle_result,
        ignored_reason="not_written_in_current_cycle",
        expected=cycle_error_expected,
        timestamp_fields=("generated_at",),
    )
    adapter_context, adapter_context_artifact = stable_input_json(run_dir / "adapter-context.json")
    business_model, business_model_artifact = stable_input_json(run_dir / "business-model.json")
    oracle_model, oracle_model_artifact = stable_input_json(run_dir / "oracle-model.json")
    qa_metrics, qa_metrics_artifact = stable_input_json(run_dir / "qa-metrics.json")
    closeout_candidates, closeout_candidates_artifact = stable_input_json(run_dir / "closeout-candidates.json")
    semantic_artifacts_summary, semantic_artifacts_summary_artifact = stable_input_json(run_dir / "semantic-artifacts-summary.json")
    adapter_probes, adapter_probes_artifact = optional_current_json(
        run_dir / "adapter-probes.json",
        result=cycle_result,
        ignored_reason="not_synthesized_in_current_cycle",
        expected=adapter_probes_expected,
        timestamp_fields=("generated_at",),
    )
    service_preflight, service_preflight_artifact = optional_current_json(
        run_dir / "service-preflight.json",
        result=cycle_result,
        ignored_reason="not_written_in_current_cycle",
        expected=preflight_expected,
        timestamp_fields=("generated_at",),
    )
    service_runtime, service_runtime_artifact = optional_current_json(
        run_dir / "service-runtime.json",
        result=cycle_result,
        ignored_reason="not_started_in_current_cycle",
        expected=service_runtime_expected,
        timestamp_fields=("generated_at",),
    )
    defects, defects_artifact = load_current_json(
        run_dir / "defects.json",
        result=cycle_result,
        ignored_reason="not_written_in_current_cycle",
    )
    results, results_artifact = load_current_json(
        run_dir / "results.json",
        result=cycle_result,
        ignored_reason="not_written_in_current_cycle",
    )
    ledger, ledger_artifact = load_current_json(
        run_dir / "evidence-ledger.json",
        result=cycle_result,
        ignored_reason="not_written_in_current_cycle",
    )
    audit_summary, audit_artifact = load_current_json(
        run_dir / "audit-summary.json",
        result=cycle_result,
        ignored_reason="not_written_in_current_cycle",
    )
    plan_audit, plan_audit_artifact = load_current_json(
        run_dir / "plan-audit-summary.json",
        result=cycle_result,
        ignored_reason="not_written_in_current_cycle",
    )
    requirement_coverage, requirement_coverage_artifact = load_current_json(
        run_dir / "requirement-coverage.json",
        result=cycle_result,
        ignored_reason="not_written_in_current_cycle",
    )
    status = {
        "run_status": summary.get("status"),
        "run_summary_artifact": run_summary_artifact,
        "verdict": verdict.get("verdict"),
        "can_claim_pass": verdict.get("can_claim_pass"),
        "reason_codes": [item.get("code") for item in verdict.get("reasons", [])],
        "input_artifact_errors": as_list(verdict.get("input_artifact_errors")),
        "verdict_artifact": verdict_artifact,
        "cycle_error": cycle_error,
        "cycle_error_artifact": cycle_error_artifact,
        "adapter_context_artifact": adapter_context_artifact,
        "business_model_artifact": business_model_artifact,
        "oracle_model_artifact": oracle_model_artifact,
        "qa_metrics_artifact": qa_metrics_artifact,
        "closeout_candidates_artifact": closeout_candidates_artifact,
        "semantic_artifacts_summary_artifact": semantic_artifacts_summary_artifact,
        "adapter_probes_artifact": adapter_probes_artifact,
        "service_runtime_artifact": service_runtime_artifact,
        "application_summary": application_summary,
        "application_artifact": application_artifact,
        "preview_summary": preview_summary,
        "preview_artifact": preview_artifact,
        "service_preflight_artifact": service_preflight_artifact,
        "defects_artifact": defects_artifact,
        "results_artifact": results_artifact,
        "ledger_artifact": ledger_artifact,
        "audit_artifact": audit_artifact,
        "plan_audit_artifact": plan_audit_artifact,
        "requirement_coverage_artifact": requirement_coverage_artifact,
        "service_start_plan": compact_service_start_plan(service_preflight),
        "service_preflight_blockers": compact_service_blockers(service_preflight),
        "environment_boundary_summary": summarize_environment_boundary(adapter_context),
        "service_preflight_summary": summarize_service_preflight(service_preflight),
        "service_runtime_summary": summarize_service_runtime(service_runtime),
        "adapter_probe_summary": summarize_adapter_probes(adapter_probes),
        "business_model_summary": (business_model.get("summary") if isinstance(business_model.get("summary"), dict) else {
            "actor_count": len(as_list(business_model.get("actors"))),
            "entity_count": len(as_list(business_model.get("entities"))),
            "workflow_count": len(as_list(business_model.get("workflows"))),
        }),
        "oracle_model_summary": oracle_model.get("summary") if isinstance(oracle_model.get("summary"), dict) else {},
        "qa_metrics_summary": qa_metrics.get("summary") if isinstance(qa_metrics.get("summary"), dict) else {},
        "closeout_candidate_summary": {
            "stable_count": len(as_list(closeout_candidates.get("stable_knowledge_candidates"))),
            "process_count": len(as_list(closeout_candidates.get("qa_process_improvement_candidates"))),
            "human_confirmation_required": closeout_candidates.get("human_confirmation_required"),
        },
        "semantic_artifacts_summary": semantic_artifacts_summary.get("summary") if isinstance(semantic_artifacts_summary.get("summary"), dict) else {},
        "cycle_error_summary": summarize_cycle_error(cycle_error),
        "next_probe_input_artifact_errors": as_list(preview_data.get("input_artifact_errors")) if preview_written else [],
        "follow_up_summary": summarize_followups(
            application_data=application_data,
            application_artifact=application_artifact,
            preview_data=preview_data,
            preview_artifact=preview_artifact,
        ),
    }
    status["failure_analysis"] = classify_status(status)
    status["decision_summary"] = build_decision_summary(
        status,
        defects,
        results,
        ledger,
        audit_summary,
        plan_audit,
        requirement_coverage,
    )
    return status


def skipped_preview_summary(run_dir: Path, *, preview_current: bool) -> dict[str, Any]:
    if not preview_current:
        return {
            "skipped_count": 0,
            "actionable_skipped_count": 0,
            "skipped_reason_counts": {},
            "examples": [],
            "actionable_examples": [],
        }
    preview = load_json(run_dir / "next-probe-preview.json")
    summary = preview.get("summary") if isinstance(preview.get("summary"), dict) else {}
    skipped = as_list(preview.get("skipped_recommendations"))
    non_actionable_reasons = {"equivalent step already exists in plan"}
    actionable = [
        item
        for item in skipped
        if isinstance(item, dict) and str(item.get("reason") or "") not in non_actionable_reasons
    ]
    return {
        "skipped_count": int(summary.get("skipped_count") or len(skipped) or 0),
        "actionable_skipped_count": len(actionable),
        "skipped_reason_counts": summary.get("skipped_reason_counts") if isinstance(summary.get("skipped_reason_counts"), dict) else {},
        "examples": [
            {
                "id": item.get("id"),
                "layer": item.get("layer"),
                "reason": item.get("reason"),
                "source_test_id": item.get("source_test_id"),
            }
            for item in skipped[:8]
            if isinstance(item, dict)
        ],
        "actionable_examples": [
            {
                "id": item.get("id"),
                "layer": item.get("layer"),
                "reason": item.get("reason"),
                "source_test_id": item.get("source_test_id"),
            }
            for item in actionable[:8]
        ],
    }


def blocked_preview_summary_from_status(run_dir: Path, status: dict[str, Any], *, preview_current: bool) -> dict[str, Any]:
    followups = status.get("follow_up_summary") if isinstance(status.get("follow_up_summary"), dict) else {}
    preview = followups.get("preview") if isinstance(followups.get("preview"), dict) else {}
    if preview:
        return {
            "skipped_count": safe_int(preview.get("skipped_count"), 0),
            "actionable_skipped_count": safe_int(preview.get("actionable_skipped_count"), 0),
            "skipped_reason_counts": preview.get("skipped_reason_counts") if isinstance(preview.get("skipped_reason_counts"), dict) else {},
            "examples": as_list(preview.get("skipped_examples")),
            "actionable_examples": as_list(preview.get("actionable_skipped_examples")),
        }
    if preview_current and "preview_artifact" in status:
        return skipped_preview_summary(run_dir, preview_current=True)
    return skipped_preview_summary(run_dir, preview_current=False)


def build_next_action(
    *,
    args: argparse.Namespace,
    run_dir: Path,
    iteration: int,
    cycle_result: dict[str, Any],
    preview_result: dict[str, Any] | None,
    status: dict[str, Any],
) -> dict[str, Any]:
    input_artifact_errors = as_list(status.get("input_artifact_errors"))
    def finish(action: dict[str, Any], **analysis_overrides: Any) -> dict[str, Any]:
        return with_failure_analysis(action, status, **analysis_overrides)

    if cycle_result.get("exit_code") != 0:
        reason_codes = set(str(item) for item in status.get("reason_codes") or [])
        if input_artifact_errors:
            return finish({
                "action": "fix_input_artifacts",
                "automatable": False,
                "reason": "qa-verdict.json reports unreadable or malformed input artifacts; fix those files before continuing the backtest loop.",
                "reason_codes": sorted(reason_codes),
                "input_artifact_errors": input_artifact_errors,
                "evidence": ["qa-verdict.json", "qa-run-summary.json"],
            })
        if status.get("verdict") and reason_codes.intersection(SETUP_BLOCKER_CODES):
            start_plan = as_list(status.get("service_start_plan"))
            if "preflight_blocked" in reason_codes and start_plan and not arg_bool(args, "start_missing_services"):
                resume_cmd = service_start_resume_command(args, run_dir)
                return finish({
                    "action": "retry_with_service_start",
                    "automatable": False,
                    "automatable_after_authorization": True,
                    "requires_authorization": True,
                    "reason": "Runtime preflight produced a concrete service start_plan, but this loop was not authorized with --start-missing-services.",
                    "reason_codes": sorted(reason_codes),
                    "recommended_flags": ["--start-missing-services"],
                    "resume_command": shlex.join(resume_cmd),
                    "resume_command_args": resume_cmd,
                    "service_start_plan": start_plan,
                    "service_preflight_blockers": as_list(status.get("service_preflight_blockers")),
                    "evidence": ["qa-verdict.json", "service-preflight.json", "qa-run-summary.json"],
                }, category="service_start_authorization_required", blocking_layer="runtime_setup", source="service-preflight.json")
            return finish({
                "action": "report_setup_blocker",
                "automatable": False,
                "reason": "run_qa_cycle.py stopped after writing a blocked setup/service verdict.",
                "reason_codes": sorted(reason_codes),
                "evidence": ["qa-verdict.json", "service-preflight.json", "service-runtime.json", "qa-run-summary.json"],
            })
        if status.get("verdict") and reason_codes.intersection(PLANNING_BLOCKER_CODES):
            return finish({
                "action": "report_planning_blocker",
                "automatable": False,
                "reason": "run_qa_cycle.py stopped after writing a blocked requirement/plan verdict.",
                "reason_codes": sorted(reason_codes),
                "evidence": ["qa-verdict.json", "requirement-coverage.json", "plan-audit-summary.json", "qa-run-summary.json"],
            })
        if status.get("verdict"):
            return finish(
                category_policy_action(
                    status,
                    reason="run_qa_cycle.py exited non-zero but wrote qa-verdict.json; follow the classified handoff action instead of claiming pass.",
                    extra={"cycle_exit_code": cycle_result.get("exit_code")},
                )
            )
        return finish({
            "action": "inspect_cycle_failure",
            "automatable": False,
            "reason": "run_qa_cycle.py exited non-zero before a complete agent iteration could be evaluated.",
            "evidence": ["qa-run-summary.json", "iterations"],
        }, category="cycle_execution_failure", blocking_layer="agent_loop", source="run_qa_cycle.py")
    if preview_result and preview_result.get("exit_code") != 0:
        next_probe_input_artifact_errors = as_list(status.get("next_probe_input_artifact_errors"))
        if next_probe_input_artifact_errors:
            return finish({
                "action": "fix_next_probe_inputs",
                "automatable": False,
                "reason": "apply_next_probes.py reports unreadable or malformed next-probe input artifacts; fix those files before continuing the loop.",
                "input_artifact_errors": next_probe_input_artifact_errors,
                "evidence": ["next-probe-preview.json", "next-probes.json", "test-plan.json", "test-matrix.json"],
            })
        return finish({
            "action": "inspect_next_probe_preview_failure",
            "automatable": False,
            "reason": "apply_next_probes.py failed while previewing safe follow-up probes.",
            "evidence": ["next-probe-preview.json", "iterations"],
        }, category="next_probe_preview_failure", blocking_layer="follow_up_probe", source="next-probe-preview.json")
    if status.get("can_claim_pass") is True:
        return finish({
            "action": "report_pass",
            "automatable": False,
            "reason": "qa-verdict.json allows a pass claim.",
            "evidence": ["qa-verdict.json", "audit-summary.json", "evidence-ledger.json", "report.md"],
        })

    if input_artifact_errors:
        return finish({
            "action": "fix_input_artifacts",
            "automatable": False,
            "reason": "qa-verdict.json reports unreadable or malformed input artifacts; fix those files before evaluating pass/fail.",
            "reason_codes": status.get("reason_codes"),
            "input_artifact_errors": input_artifact_errors,
            "evidence": ["qa-verdict.json", "qa-run-summary.json"],
        })

    preview_artifact = status.get("preview_artifact") if isinstance(status.get("preview_artifact"), dict) else {}
    preview_current = preview_artifact.get("current") is True if "preview_artifact" in status else True
    preview_summary = status.get("preview_summary") if preview_current and isinstance(status.get("preview_summary"), dict) else {}
    apply_count = int(preview_summary.get("applied_count") or 0)
    preview_next_probes_hash = next_probes_sha256(run_dir) if apply_count > 0 and preview_current else None
    skipped_summary = blocked_preview_summary_from_status(run_dir, status, preview_current=preview_current)
    if apply_count > 0 and not preview_next_probes_hash:
        return finish({
            "action": "fix_next_probe_inputs",
            "automatable": False,
            "reason": "next-probe preview found safe follow-ups, but next-probes.json is missing, unreadable, or directory-shaped before it could be bound for application.",
            "preview_applied_count": apply_count,
            "input_artifact_errors": [
                {
                    "name": "next_probes",
                    "path": str(run_dir / "next-probes.json"),
                    "error": "next_probes_missing_or_unreadable",
                    "required": True,
                }
            ],
            "evidence": ["next-probe-preview.json", "next-probes.json"],
        }, category="next_probe_input_integrity", blocking_layer="follow_up_probe_input", source="next-probes.json", operator_hint="Restore or regenerate next-probes.json, then re-run the preview before applying follow-up probes.", confidence="high")
    if apply_count > 0 and not auto_continue_allowed(status):
        category = failure_category(status)
        action_name, reason, hint = handoff_action_for_category(category)
        action = {
            "action": action_name,
            "automatable": False,
            "reason": reason,
            "reason_codes": status.get("reason_codes"),
            "preview_applied_count": apply_count,
            "preview_next_probes_sha256": preview_next_probes_hash,
            "blocked_auto_continue_reason": f"failure_analysis.category={category} is not in the automatic follow-up allowlist.",
            "evidence": ["qa-verdict.json", "defects.json", "next-probe-preview.json", "report.md"],
        }
        if skipped_summary["actionable_skipped_count"] > 0:
            action["blocked_followups"] = skipped_summary
        return finish(action, operator_hint=hint, confidence="high")
    if apply_count > 0 and skipped_summary["actionable_skipped_count"] > 0:
        return finish({
            "action": "request_authorization_or_inputs",
            "automatable": False,
            "reason": "Some follow-up probes are safe, but other actionable follow-ups still need authorization or concrete inputs; do not partially auto-continue until the operator sees those gaps.",
            "preview_applied_count": apply_count,
            "preview_next_probes_sha256": preview_next_probes_hash,
            "blocked_followups": skipped_summary,
            "blocked_auto_continue_reason": "preview contains actionable skipped follow-ups.",
            "evidence": ["next-probe-preview.json", "next-probes.json"],
        }, category="authorization_or_input_required", blocking_layer="follow_up_probe", source="next-probe-preview.json", operator_hint="Provide the missing authorization, safe payload, selector, or helper before continuing.", confidence="high")
    if apply_count > 0 and iteration < args.max_iterations:
        return finish({
            "action": "continue_with_safe_next_probes",
            "automatable": True,
            "reason": f"{apply_count} safe concrete follow-up probe(s) can be applied in the next iteration.",
            "next_iteration_applies_preview": True,
            "expected_next_probes_sha256": preview_next_probes_hash,
            "preview_next_probes_sha256": preview_next_probes_hash,
            "evidence": ["next-probe-preview.json"],
        }, category="safe_followup_available", blocking_layer="follow_up_probe", source="next-probe-preview.json", operator_hint="Continue automatically by applying the previewed safe probes in the next iteration.", confidence="high")
    if apply_count > 0 and iteration >= args.max_iterations:
        recommended_max_iterations = max(int(args.max_iterations) + 1, iteration + 1)
        resume_cmd = resume_loop_command(
            args,
            run_dir,
            max_iterations=recommended_max_iterations,
            apply_existing_next_probes=True,
            expected_next_probes_sha256=preview_next_probes_hash,
        )
        recommended_flags = [f"--max-iterations {recommended_max_iterations}", "--apply-existing-next-probes"]
        if preview_next_probes_hash:
            recommended_flags.append(f"--expected-next-probes-sha256 {preview_next_probes_hash}")
        return finish({
            "action": "resume_with_more_iterations",
            "automatable": False,
            "reason": f"{apply_count} safe follow-up probe(s) remain, but max_iterations={args.max_iterations} was reached.",
            "recommended_max_iterations": recommended_max_iterations,
            "recommended_flags": recommended_flags,
            "resume_command": shlex.join(resume_cmd),
            "resume_command_args": resume_cmd,
            "next_iteration_applies_existing_next_probes": True,
            "expected_next_probes_sha256": preview_next_probes_hash,
            "preview_next_probes_sha256": preview_next_probes_hash,
            "evidence": ["next-probe-preview.json", "qa-agent-summary.json"],
        }, category="iteration_budget_exhausted", blocking_layer="agent_loop", source="qa-agent-summary.json", operator_hint="Resume with a larger max iteration budget and explicitly apply the existing previewed probes.", confidence="high")

    if skipped_summary["actionable_skipped_count"] > 0:
        return finish({
            "action": "request_authorization_or_inputs",
            "automatable": False,
            "reason": "Follow-up probes exist, but none are safe and concrete enough to apply automatically.",
            "blocked_followups": skipped_summary,
            "evidence": ["next-probe-preview.json", "next-probes.json"],
        }, category="authorization_or_input_required", blocking_layer="follow_up_probe", source="next-probe-preview.json", operator_hint="Provide the missing authorization, safe payload, selector, or helper before continuing.", confidence="high")

    if preview_current and skipped_summary["skipped_count"] > 0:
        return finish({
            "action": "report_no_new_progress",
            "automatable": False,
            "reason": "Next-probe preview produced no safe new probes; remaining skipped follow-ups are non-actionable duplicates or already covered by the current plan.",
            "reason_codes": status.get("reason_codes"),
            "no_new_progress": True,
            "non_actionable_followups": skipped_summary,
            "evidence": ["qa-verdict.json", "next-probe-preview.json", "test-plan.json", "test-matrix.json"],
        }, category="no_new_followup_progress", blocking_layer="follow_up_probe", source="next-probe-preview.json", operator_hint="Report the current verdict or revise the plan/requirement manually; automatic follow-up generation has no new safe probe to add.", confidence="high")

    if status.get("reason_codes"):
        return finish(category_policy_action(status))
    return finish({
        "action": "inspect_agent_artifacts",
        "automatable": False,
        "reason": "The loop did not pass and did not expose a concrete follow-up; inspect generated artifacts before claiming a result.",
        "evidence": ["qa-agent-summary.json", "qa-run-summary.json"],
    })


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a bounded QA/backtest agent loop over a generated QA artifact directory.")
    parser.add_argument("--run-dir", help="Existing QA artifact directory. If omitted, init_qa_artifact.py is run first.")
    parser.add_argument("--requirement-file")
    parser.add_argument("--requirement-text")
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument("--entry-path")
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--runtime-mode", help="Declared runtime mode for adapter-context.json, such as local, test, staging, production, or ci.")
    parser.add_argument("--data-boundary-status", help="Declared data boundary for adapter-context.json.")
    parser.add_argument("--out-dir", default=str(Path("/tmp") / "automated-qa-test"))
    parser.add_argument("--slug")
    parser.add_argument("--max-iterations", type=int, default=3)
    parser.add_argument("--skip-probe", action="store_true", help="Planning-only mode; run_qa_cycle.py writes skipped probe results.")
    parser.add_argument("--strict-runtime", action="store_true")
    parser.add_argument("--require-environment-boundary", action="store_true", help="Require confirmed runtime/data boundary before pass can be claimed.")
    parser.add_argument("--node-bin", default="node")
    parser.add_argument("--preflight-runtime", action="store_true")
    parser.add_argument("--start-missing-services", action="store_true")
    parser.add_argument("--service-start-timeout", type=float, default=60.0)
    parser.add_argument("--service-start-no-wait", action="store_true")
    parser.add_argument("--allow-preflight-blockers", action="store_true")
    parser.add_argument("--refresh-adapter-context", action="store_true")
    parser.add_argument("--synthesize-adapter-probes", action="store_true")
    parser.add_argument("--allow-live-stream", action="store_true")
    parser.add_argument("--allow-stopped-service", action="store_true")
    parser.add_argument("--allow-unsafe-command", action="store_true")
    parser.add_argument("--allow-mutating-api", action="store_true")
    parser.add_argument("--allow-required-input-gaps", action="store_true")
    parser.add_argument("--allow-unmapped-requirement-source", action="store_true")
    parser.add_argument("--apply-existing-next-probes", action="store_true", help="Apply an existing next-probes.json before the first cycle. Leave unset to avoid stale cross-run recommendations.")
    parser.add_argument("--expected-next-probes-sha256", help="When applying existing next-probes.json, require this SHA256 so previewed follow-ups cannot be replaced before application.")
    parser.add_argument("--skip-report", action="store_true")
    parser.add_argument("--skip-adapter-context", action="store_true")
    parser.add_argument("--no-http-probe", action="store_true")
    parser.add_argument("--agent-id")
    parser.add_argument("--user-id")
    parser.add_argument("--marker")
    parser.add_argument("--question")
    parser.add_argument("--ws-path")
    parser.add_argument("--session-detail-path")
    parser.add_argument("--persistence-command")
    parser.add_argument("--required-service", action="append")
    parser.add_argument("--summary", help="Defaults to <run-dir>/qa-agent-summary.json")
    args = parser.parse_args()

    if args.max_iterations < 1:
        raise SystemExit("--max-iterations must be >= 1")
    if not args.run_dir and not (args.requirement_file or args.requirement_text):
        raise SystemExit("Provide --run-dir or requirement input.")

    script_dir = Path(__file__).resolve().parent
    cwd = Path.cwd()
    try:
        run_dir, init_result = init_run_dir(args, script_dir, cwd)
    except InitializationError as exc:
        agent_summary_path = Path(args.summary).expanduser().resolve() if args.summary else (exc.run_dir / "qa-agent-summary.json" if exc.run_dir else initialization_failure_summary_path(args))
        write_initialization_failure_summary(args, agent_summary_path, exc)
        print(agent_summary_path)
        print(str(exc), file=sys.stderr)
        return 1
    agent_summary_path = Path(args.summary).expanduser().resolve() if args.summary else run_dir / "qa-agent-summary.json"

    summary: dict[str, Any] = {
        "schema_version": 1,
        "status": "running",
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "run_dir": str(run_dir),
        "max_iterations": args.max_iterations,
        "planning_only": bool(args.skip_probe),
        "iterations": [],
    }
    if init_result:
        summary["init"] = init_result

    apply_existing_requested = bool(args.run_dir and args.apply_existing_next_probes)
    apply_next = should_apply_existing_next_probes(args, run_dir)
    pending_next_probes_sha256 = str(args.expected_next_probes_sha256).strip() if apply_next and args.expected_next_probes_sha256 else None
    resume_binding: dict[str, Any] = {}
    if apply_next and not pending_next_probes_sha256:
        pending_next_probes_sha256, resume_binding = infer_resume_next_probes_sha256(agent_summary_path, run_dir)
    elif apply_next and pending_next_probes_sha256:
        resume_binding = {
            "source": "cli",
            "expected_next_probes_sha256": pending_next_probes_sha256,
        }
    if resume_binding:
        summary["resume_next_probes_binding"] = resume_binding
    exit_code = 0
    for iteration in range(1, args.max_iterations + 1):
        if apply_existing_requested and not apply_next:
            status = cycle_status(run_dir)
            next_action = unavailable_existing_next_probes_action(run_dir)
            snapshot = snapshot_iteration(run_dir, iteration)
            item: dict[str, Any] = {
                "iteration": iteration,
                "applied_next_before_cycle": False,
                "cycle": None,
                "preview": None,
                "snapshot": snapshot.get("path"),
                "snapshot_details": snapshot,
                "status": status,
                "next_action": next_action,
                "stop_before_cycle": "next_probes_unavailable",
            }
            if snapshot.get("errors"):
                summary.setdefault("snapshot_errors", []).extend(snapshot["errors"])
            summary["iterations"].append(item)
            summary["status"] = "attention"
            summary["stop_reason"] = "next_probes_unavailable"
            summary["next_action"] = next_action
            summary["failure_analysis"] = next_action["failure_analysis"]
            summary["loop_control"] = build_loop_control(summary)
            write_json(agent_summary_path, summary)
            exit_code = 1
            break
        if apply_next and not pending_next_probes_sha256:
            status = cycle_status(run_dir)
            next_action = missing_next_probes_hash_action(run_dir, resume_binding)
            snapshot = snapshot_iteration(run_dir, iteration)
            item: dict[str, Any] = {
                "iteration": iteration,
                "applied_next_before_cycle": apply_next,
                "cycle": None,
                "preview": None,
                "snapshot": snapshot.get("path"),
                "snapshot_details": snapshot,
                "status": status,
                "next_action": next_action,
                "stop_before_cycle": "next_probes_hash_missing",
            }
            if snapshot.get("errors"):
                summary.setdefault("snapshot_errors", []).extend(snapshot["errors"])
            summary["iterations"].append(item)
            summary["status"] = "attention"
            summary["stop_reason"] = "next_probes_hash_missing"
            summary["next_action"] = next_action
            summary["failure_analysis"] = next_action["failure_analysis"]
            summary["loop_control"] = build_loop_control(summary)
            write_json(agent_summary_path, summary)
            exit_code = 1
            break
        if apply_next and pending_next_probes_sha256:
            current_next_probes_hash = next_probes_sha256(run_dir)
            if current_next_probes_hash != pending_next_probes_sha256:
                status = cycle_status(run_dir)
                next_action = next_probes_hash_mismatch_action(
                    run_dir,
                    pending_next_probes_sha256,
                    current_next_probes_hash,
                )
                snapshot = snapshot_iteration(run_dir, iteration)
                item: dict[str, Any] = {
                    "iteration": iteration,
                    "applied_next_before_cycle": apply_next,
                    "cycle": None,
                    "preview": None,
                    "snapshot": snapshot.get("path"),
                    "snapshot_details": snapshot,
                    "status": status,
                    "next_action": next_action,
                    "stop_before_cycle": "next_probes_hash_mismatch",
                }
                if snapshot.get("errors"):
                    summary.setdefault("snapshot_errors", []).extend(snapshot["errors"])
                summary["iterations"].append(item)
                summary["status"] = "attention"
                summary["stop_reason"] = "next_probes_hash_mismatch"
                summary["next_action"] = next_action
                summary["failure_analysis"] = next_action["failure_analysis"]
                summary["loop_control"] = build_loop_control(summary)
                write_json(agent_summary_path, summary)
                exit_code = 1
                break
        cycle_cmd = build_cycle_cmd(args, script_dir, run_dir, apply_next=apply_next)
        cycle_result = run_command(cycle_cmd, cwd=run_dir)
        preview_result: dict[str, Any] | None = None
        preview_skipped_reason: str | None = None
        status = cycle_status(run_dir, cycle_result=cycle_result, applied_next_before_cycle=apply_next, preview_result=None)
        if cycle_result["exit_code"] == 0:
            if status.get("can_claim_pass") is True:
                preview_skipped_reason = "verdict_passed"
            else:
                preview_result = run_command(build_preview_cmd(args, script_dir, run_dir), cwd=run_dir)
                status = cycle_status(run_dir, cycle_result=cycle_result, applied_next_before_cycle=apply_next, preview_result=preview_result)
        snapshot = snapshot_iteration(run_dir, iteration)
        next_action = build_next_action(
            args=args,
            run_dir=run_dir,
            iteration=iteration,
            cycle_result=cycle_result,
            preview_result=preview_result,
            status=status,
        )
        preview_next_probes_hash = next_action.get("preview_next_probes_sha256") or next_action.get("expected_next_probes_sha256")
        if next_action.get("automatable") is True and isinstance(preview_next_probes_hash, str) and preview_next_probes_hash:
            repeated_next_probes = prior_next_probes_hash_seen(summary, preview_next_probes_hash)
            if repeated_next_probes:
                next_action = repeated_next_probes_action(status, repeated_next_probes)
                preview_next_probes_hash = next_action.get("preview_next_probes_sha256")
        item: dict[str, Any] = {
            "iteration": iteration,
            "applied_next_before_cycle": apply_next,
            "cycle": cycle_result,
            "preview": preview_result,
            "snapshot": snapshot.get("path"),
            "snapshot_details": snapshot,
            "status": status,
            "next_action": next_action,
        }
        if preview_skipped_reason:
            item["preview_skipped_reason"] = preview_skipped_reason
        if isinstance(preview_next_probes_hash, str) and preview_next_probes_hash:
            item["preview_next_probes_sha256"] = preview_next_probes_hash
        if snapshot.get("errors"):
            summary.setdefault("snapshot_errors", []).extend(snapshot["errors"])
        summary["iterations"].append(item)
        summary["next_action"] = next_action
        summary["loop_control"] = build_loop_control(summary)
        write_json(agent_summary_path, summary)

        if cycle_result["exit_code"] != 0:
            if status.get("verdict"):
                summary["status"] = status.get("verdict")
                summary["stop_reason"] = "cycle_stopped_with_verdict"
            else:
                summary["status"] = "failed"
                summary["stop_reason"] = "cycle_failed"
            exit_code = 1
            break
        if preview_result and preview_result["exit_code"] != 0:
            summary["status"] = "failed"
            summary["stop_reason"] = "next_probe_preview_failed"
            exit_code = 1
            break
        if status.get("can_claim_pass") is True:
            summary["status"] = "passed"
            summary["stop_reason"] = "verdict_passed"
            break
        if next_action.get("automatable") is not True:
            summary["status"] = status.get("verdict") or "attention"
            summary["stop_reason"] = "next_action_requires_handoff"
            break
        preview_summary = (status.get("preview_summary") or {}) if isinstance(status.get("preview_summary"), dict) else {}
        next_apply_count = int(preview_summary.get("applied_count") or 0)
        if next_apply_count <= 0:
            summary["status"] = status.get("verdict") or "attention"
            summary["stop_reason"] = "no_safe_next_probe_to_apply"
            break
        if iteration >= args.max_iterations:
            summary["status"] = status.get("verdict") or "attention"
            summary["stop_reason"] = "max_iterations_reached"
            break
        if next_action.get("next_iteration_applies_preview") is not True:
            summary["status"] = status.get("verdict") or "attention"
            summary["stop_reason"] = "next_action_requires_handoff"
            break
        expected_next_probes_hash = next_action.get("expected_next_probes_sha256")
        if not isinstance(expected_next_probes_hash, str) or not expected_next_probes_hash:
            fix_action = {
                "action": "fix_next_probe_inputs",
                "automatable": False,
                "reason": "Safe next-probe preview did not expose an expected_next_probes_sha256 binding.",
                "evidence": ["next-probe-preview.json", "next-probes.json"],
                "failure_analysis": {
                    "category": "next_probe_input_integrity",
                    "blocking_layer": "follow_up_probe_input",
                    "source": "next-probes.json",
                    "confidence": "high",
                    "operator_hint": "Re-run preview so the next-probes file can be hash-bound before application.",
                },
            }
            summary["status"] = status.get("verdict") or "attention"
            summary["stop_reason"] = "next_probe_preview_hash_missing"
            summary["next_action"] = fix_action
            summary["iterations"][-1]["next_action"] = fix_action
            exit_code = 1
            break
        pending_next_probes_sha256 = expected_next_probes_hash
        apply_next = True

    summary["finished_at"] = datetime.now().isoformat(timespec="seconds")
    if summary.get("iterations"):
        last_iteration = summary["iterations"][-1]
        summary["final"] = cycle_status(
            run_dir,
            cycle_result=last_iteration.get("cycle"),
            applied_next_before_cycle=bool(last_iteration.get("applied_next_before_cycle")),
            preview_result=last_iteration.get("preview"),
        )
        summary["next_action"] = summary["iterations"][-1].get("next_action")
    else:
        summary["final"] = cycle_status(run_dir)
    next_action = summary.get("next_action") if isinstance(summary.get("next_action"), dict) else {}
    final = summary.get("final") if isinstance(summary.get("final"), dict) else {}
    if isinstance(next_action.get("failure_analysis"), dict):
        summary["failure_analysis"] = next_action["failure_analysis"]
    elif isinstance(final.get("failure_analysis"), dict):
        summary["failure_analysis"] = final["failure_analysis"]
    if isinstance(next_action.get("decision_summary"), dict):
        summary["decision_summary"] = next_action["decision_summary"]
    elif isinstance(final.get("decision_summary"), dict):
        summary["decision_summary"] = final["decision_summary"]
    summary["loop_control"] = build_loop_control(summary)
    write_agent_handoff(agent_summary_path, summary)
    write_json(agent_summary_path, summary)
    print(agent_summary_path)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
