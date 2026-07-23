"""Agent 下一步路由、handoff 与输入完整性回归夹具。"""

import os
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from .support import (
    assert_route_model_consistent,
    assert_true,
    file_sha256,
    load_qa_agent_loop_module,
    write_json,
)


@dataclass(frozen=True, slots=True)
class AgentRouteFixtureContext:
    """跨场景共享只读输入，场景自身仍独立生成与断言产物。"""

    module: Any
    action_dir: Path
    tmp_path: Path
    args: SimpleNamespace
    ok_cycle: dict[str, Any]
    ok_preview: dict[str, Any]
    nonpass_status: dict[str, Any]
    preview_next_probes_hash: str
    runtime_counts: dict[str, int]
    runtime_examples: dict[str, list[dict[str, Any]]]

def _build_agent_route_context(
    script_dir: Path,
    tmp_path: Path,
) -> AgentRouteFixtureContext:
    module = load_qa_agent_loop_module(script_dir)
    action_dir = tmp_path / "agent-next-action"
    action_dir.mkdir(parents=True, exist_ok=True)
    args = SimpleNamespace(
        max_iterations=2,
        strict_runtime=True,
        require_environment_boundary=True,
        preflight_runtime=True,
        runtime_mode="test",
        data_boundary_status="fixture data only; no production data",
        required_service=["fixture-api"],
        summary=str(action_dir / "external-agent-summary.json"),
    )
    ok_cycle = {"exit_code": 0}
    ok_preview = {"exit_code": 0}
    nonpass_status = {"can_claim_pass": False, "reason_codes": ["requirement_untested"]}
    write_json(
        action_dir / "next-probes.json",
        {
            "schema_version": 1,
            "summary": {"recommendation_count": 1},
            "recommendations": [{"id": "NP-runtime", "layer": "runtime", "reason": "fixture follow-up"}],
        },
    )
    write_json(action_dir / "next-probe-preview.json", {"summary": {"applied_count": 1, "skipped_count": 0}})
    write_json(action_dir / "audit-summary.json", {"schema_version": 1, "passed": False, "errors": ["fixture audit error"]})
    preview_next_probes_hash = file_sha256(action_dir / "next-probes.json")
    assert_true(module.classify_status({"can_claim_pass": False, "reason_codes": ["defects_present"]}).get("category") == "product_defect", "defect verdict reasons should classify as product defects.")
    assert_true(module.classify_status({"can_claim_pass": False, "reason_codes": ["undispositioned_failed_responses"]}).get("category") == "runtime_evidence_gap", "undispositioned failed responses should classify as runtime evidence gaps.")
    assert_true(module.classify_status({"can_claim_pass": False, "reason_codes": ["environment_unconfirmed"]}).get("blocking_layer") == "environment_boundary", "unconfirmed environment reasons should expose the environment boundary layer.")
    mixed_environment_analysis = module.classify_status({"can_claim_pass": False, "reason_codes": ["environment_unconfirmed", "defects_present", "strategy_dimension_gap"]})
    assert_true(mixed_environment_analysis.get("category") == "environment_boundary_unconfirmed", "unconfirmed environment/data boundary should take priority over defects or safe follow-up gaps.")
    assert_true(mixed_environment_analysis.get("blocking_layer") == "environment_boundary", "mixed environment verdicts should preserve the environment boundary layer.")
    strategy_analysis = module.classify_status({"can_claim_pass": False, "reason_codes": ["strategy_dimension_gap"]})
    assert_true(strategy_analysis.get("category") == "strategy_coverage_gap", "strategy coverage gaps should not collapse into a generic non-pass verdict.")
    assert_true(strategy_analysis.get("blocking_layer") == "plan_strategy", "strategy coverage gaps should expose plan_strategy as the blocking layer.")
    runtime_counts, runtime_examples = module.summarize_runtime_issues(
        {
            "console": [{"type": "error", "text": "fixture console error", "url": "http://127.0.0.1:9527/aibox"}],
            "failedResponses": [{"status": 500, "url": "http://127.0.0.1:9527/api/v1/agents/catalog"}],
            "requestFailures": [{"method": "GET", "url": "http://127.0.0.1:9527/api/v1/sessions/fixture", "failure": "net::ERR_FAILED"}],
        }
    )
    assert_true(runtime_counts.get("total") == 3, "runtime issue summary should count console, response, and request failure evidence.")
    assert_true("HTTP 500" in runtime_examples.get("failed_responses", [{}])[0].get("label", ""), "runtime issue summary should preserve failed response examples.")

    return AgentRouteFixtureContext(
        module=module,
        action_dir=action_dir,
        tmp_path=tmp_path,
        args=args,
        ok_cycle=ok_cycle,
        ok_preview=ok_preview,
        nonpass_status=nonpass_status,
        preview_next_probes_hash=preview_next_probes_hash,
        runtime_counts=runtime_counts,
        runtime_examples=runtime_examples,
    )

def _verify_automatic_and_stalled_routes(context: AgentRouteFixtureContext) -> None:
    module = context.module
    action_dir = context.action_dir
    args = context.args
    ok_cycle = context.ok_cycle
    ok_preview = context.ok_preview
    nonpass_status = context.nonpass_status
    preview_next_probes_hash = context.preview_next_probes_hash
    continue_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={**nonpass_status, "preview_summary": {"applied_count": 1}},
    )
    assert_true(continue_action.get("action") == "continue_with_safe_next_probes", "agent next_action should continue when safe follow-ups remain and iteration budget is available.")
    assert_true(continue_action.get("automatable") is True, "safe follow-up continuation should be marked automatable.")
    assert_true(continue_action.get("expected_next_probes_sha256") == preview_next_probes_hash, "safe follow-up continuation should bind the previewed next-probes.json hash.")
    assert_true(continue_action.get("preview_next_probes_sha256") == preview_next_probes_hash, "safe follow-up continuation should expose the previewed next-probes hash for handoff.")
    assert_true(continue_action.get("failure_analysis", {}).get("category") == "safe_followup_available", "safe follow-up continuation should expose an automatable follow-up failure category.")
    continue_control = module.build_loop_control({
        "status": "running",
        "run_dir": str(action_dir),
        "next_action": continue_action,
        "iterations": [{"status": {**nonpass_status, "preview_summary": {"applied_count": 1}}}],
    })
    assert_route_model_consistent(continue_control, "safe follow-up continuation")
    assert_true(continue_control.get("terminal") is False, "running agent loop control should not be terminal.")
    assert_true(continue_control.get("can_continue_automatically") is True, "loop_control should expose automatic continuation without reinterpreting next_action.")
    assert_true(continue_control.get("next_action") == "continue_with_safe_next_probes", "loop_control should carry the next action name.")
    continue_evidence = continue_control.get("evidence_artifacts") or []
    assert_true(continue_evidence and continue_evidence[0].get("name") == "next-probe-preview.json", "loop_control should expose resolved evidence artifact names.")
    assert_true(Path(str(continue_evidence[0].get("path"))).resolve() == (action_dir / "next-probe-preview.json").resolve(), "loop_control evidence artifacts should resolve relative evidence names against run_dir.")
    assert_true(continue_evidence[0].get("exists") is True and continue_evidence[0].get("kind") == "file", "loop_control evidence artifacts should include existence and kind.")
    assert_true(continue_evidence[0].get("sha256") == file_sha256(action_dir / "next-probe-preview.json"), "loop_control evidence artifacts should include the current file hash.")
    assert_true(continue_evidence[0].get("size_bytes") == (action_dir / "next-probe-preview.json").stat().st_size, "loop_control evidence artifacts should include the current file size.")
    continue_steps = continue_control.get("recommended_next_steps") or []
    assert_true(continue_steps and continue_steps[0].get("id") == "continue_with_safe_next_probes", "loop_control should expose machine-readable recommended next steps for automatic continuation.")
    assert_true(preview_next_probes_hash in continue_steps[0].get("description", ""), "automatic continuation next steps should preserve the expected next-probes hash.")
    continue_step_artifacts = continue_steps[0].get("evidence_artifacts") or []
    continue_preview_artifact = next((item for item in continue_step_artifacts if isinstance(item, dict) and item.get("name") == "next-probe-preview.json"), {})
    assert_true(continue_preview_artifact.get("exists") is True and continue_preview_artifact.get("kind") == "file", "recommended steps should resolve evidence artifacts against the run dir.")
    assert_true(continue_preview_artifact.get("sha256") == file_sha256(action_dir / "next-probe-preview.json"), "recommended step evidence artifacts should include current hashes.")
    assert_true("human_action_required" not in continue_control, "automatable continuation should not expose a human-action blocker.")
    continue_health = continue_control.get("evidence_health") or {}
    assert_true(continue_health.get("status") == "needs_auto_continue", "automatable continuation should expose needs_auto_continue evidence health.")
    assert_true("can_continue_automatically" in continue_health.get("flags", []), "evidence_health should flag automatic continuation.")
    assert_true(continue_health.get("pass_claim_allowed") is False, "evidence_health should not imply pass while follow-ups remain.")
    continue_orchestration = continue_control.get("orchestration_state") or {}
    assert_true(continue_orchestration.get("mode") == "auto_continue", "orchestration_state should classify safe follow-ups as auto_continue.")
    assert_true(continue_orchestration.get("primary_action") == "continue_with_safe_next_probes", "orchestration_state should carry the primary action.")
    assert_true((continue_orchestration.get("first_recommended_step") or {}).get("id") == "continue_with_safe_next_probes", "orchestration_state should expose the first recommended step.")
    assert_true((continue_orchestration.get("first_recommended_step") or {}).get("evidence_artifact_count", 0) >= 1, "orchestration_state should summarize first-step evidence artifacts.")
    repeated = module.prior_next_probes_hash_seen(
        {
            "iterations": [
                {
                    "iteration": 1,
                    "preview_next_probes_sha256": preview_next_probes_hash,
                    "next_action": {"action": "continue_with_safe_next_probes"},
                }
            ]
        },
        preview_next_probes_hash,
    )
    assert_true(repeated and repeated.get("previous_iteration") == 1, "agent loop should detect a next-probes hash already previewed in a prior iteration.")
    repeated_action = module.repeated_next_probes_action({**nonpass_status, "preview_summary": {"applied_count": 1}}, repeated)
    assert_true(repeated_action.get("action") == "report_no_new_progress", "repeated next-probes hashes should stop as no-new-progress handoffs.")
    assert_true(repeated_action.get("automatable") is False, "repeated next-probes hashes must not auto-continue.")
    assert_true(repeated_action.get("no_new_progress") is True, "repeated next-probes hashes should expose no_new_progress for orchestration.")
    assert_true(repeated_action.get("repeated_next_probes", {}).get("sha256") == preview_next_probes_hash, "repeated next-probes handoff should expose the repeated hash.")
    assert_true(repeated_action.get("failure_analysis", {}).get("category") == "no_new_followup_progress", "repeated next-probes handoff should classify as no-new-followup progress.")
    repeated_control = module.build_loop_control({
        "status": "blocked",
        "stop_reason": "next_action_requires_handoff",
        "finished_at": "2026-06-16T00:00:00",
        "next_action": repeated_action,
        "final": nonpass_status,
    })
    assert_route_model_consistent(repeated_control, "repeated next-probes no-progress")
    assert_true(repeated_control.get("no_new_progress") is True, "loop_control should expose repeated-hash no-new-progress states.")
    assert_true(repeated_control.get("repeated_next_probes", {}).get("sha256") == preview_next_probes_hash, "loop_control should preserve repeated next-probes metadata.")
    repeated_steps = repeated_control.get("recommended_next_steps") or []
    assert_true(repeated_steps and repeated_steps[0].get("id") == "report_no_new_progress", "no-new-progress handoffs should put report/manual revision before any evidence-gap repair.")
    assert_true(any(item.get("id") == "manual_revision_after_no_new_progress" and item.get("kind") == "revise" for item in repeated_steps if isinstance(item, dict)), "no-new-progress handoffs should include an explicit manual revision step.")
    assert_true(any(item.get("id") == "report_no_new_progress" and item.get("kind") == "report" for item in repeated_steps if isinstance(item, dict)), "loop_control should expose report-oriented next steps when no new progress is possible.")
    repeated_human = repeated_control.get("human_action_required") or {}
    assert_true(repeated_human.get("type") == "manual_plan_revision_or_report", "repeated next-probes loop_control should expose the needed human/manual action type.")
    assert_true(repeated_human.get("action") == "report_no_new_progress", "human_action_required should carry the no-new-progress action.")
    assert_true("report_no_new_progress" in repeated_human.get("recommended_next_step_ids", []), "human_action_required should point to the report/no-progress next step.")
    assert_true("test-plan.json probe strategy" in repeated_human.get("manual_revision_targets", []), "human_action_required should name concrete manual revision targets for no-new-progress stops.")
    repeated_health = repeated_control.get("evidence_health") or {}
    assert_true(repeated_health.get("status") == "report_or_manual_revision", "repeated next-probes evidence health should stop as report/manual revision.")
    assert_true("no_new_progress" in repeated_health.get("flags", []), "evidence_health should flag no-new-progress loops.")
    repeated_orchestration = repeated_control.get("orchestration_state") or {}
    assert_true(repeated_orchestration.get("mode") == "manual_revision_or_report", "orchestration_state should classify no-new-progress stops as manual revision/report.")
    assert_true(repeated_orchestration.get("human_request_type") == "manual_plan_revision_or_report", "orchestration_state should preserve the human request type for stalled loops.")
    assert_true((repeated_orchestration.get("first_recommended_step") or {}).get("id") == "report_no_new_progress", "no-new-progress orchestration should route first to reporting/manual revision.")
    assert_true("test-plan.json probe strategy" in repeated_orchestration.get("manual_revision_targets", []), "orchestration_state should carry manual revision targets for stalled loops.")
    repeated_summary = {
        "status": "blocked",
        "stop_reason": "next_action_requires_handoff",
        "run_dir": str(action_dir),
        "next_action": repeated_action,
        "loop_control": repeated_control,
        "final": nonpass_status,
        "iterations": [],
    }
    repeated_handoff = module.write_agent_handoff(action_dir / "repeated-agent-summary.json", repeated_summary).read_text(encoding="utf-8")
    assert_true("No new progress: `true`" in repeated_handoff, "repeated-hash handoff should make no-new-progress visible to humans.")
    assert_true("## Agent Route Model" in repeated_handoff, "handoff should render the single route model before projection sections.")
    assert_true(
        repeated_handoff.index("## Agent Route Model") < repeated_handoff.index("## Orchestration State"),
        "handoff should present agent_route_model before orchestration_state.",
    )
    assert_true("Human request type: `manual_plan_revision_or_report`" in repeated_handoff, "route model handoff should carry the human request type.")
    assert_true("## Repeated Next-Probes" in repeated_handoff, "repeated-hash handoff should render a dedicated repeated next-probes section.")
    assert_true(preview_next_probes_hash in repeated_handoff, "repeated-hash handoff should include the repeated next-probes hash.")
    assert_true("## Evidence To Read" in repeated_handoff and str(action_dir / "next-probes.json") in repeated_handoff, "handoff should render resolved evidence artifact paths.")
    assert_true(file_sha256(action_dir / "next-probes.json") in repeated_handoff, "handoff should render evidence artifact hashes.")
    assert_true("## Recommended Next Steps" in repeated_handoff and "report_no_new_progress" in repeated_handoff, "handoff should render machine-readable recommended next steps.")
    assert_true("## Human Action Required" in repeated_handoff and "manual_plan_revision_or_report" in repeated_handoff, "handoff should render the structured human action request.")
    assert_true("Manual revision targets" in repeated_handoff and "test-plan.json probe strategy" in repeated_handoff, "handoff should render manual revision targets for no-new-progress stops.")
    assert_true("## Evidence Health" in repeated_handoff and "report_or_manual_revision" in repeated_handoff, "handoff should render the compact evidence health section.")
    resume_repeated = module.prior_next_probes_hash_seen(
        {"resume_next_probes_binding": {"expected_next_probes_sha256": preview_next_probes_hash}},
        preview_next_probes_hash,
    )
    assert_true(resume_repeated and resume_repeated.get("matched_field") == "resume_next_probes_binding.expected_next_probes_sha256", "agent loop should detect a next-probes hash repeated from a resume binding.")

def _verify_runtime_and_environment_routes(context: AgentRouteFixtureContext) -> None:
    module = context.module
    action_dir = context.action_dir
    args = context.args
    ok_cycle = context.ok_cycle
    ok_preview = context.ok_preview
    nonpass_status = context.nonpass_status
    runtime_counts = context.runtime_counts
    runtime_examples = context.runtime_examples
    runtime_gap_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={
            "can_claim_pass": False,
            "reason_codes": ["undispositioned_failed_responses"],
            "preview_summary": {"applied_count": 1},
            "decision_summary": {"runtime_issue_counts": runtime_counts, "runtime_issue_examples": runtime_examples},
        },
    )
    assert_true(runtime_gap_action.get("action") == "continue_with_safe_next_probes", "runtime evidence gaps should auto-continue when safe disposition probes are available.")
    assert_true(runtime_gap_action.get("decision_summary", {}).get("runtime_issue_counts", {}).get("failed_responses") == 1, "runtime evidence gap actions should retain decision summaries for handoff/orchestration.")
    runtime_gap_control = module.build_loop_control({
        "status": "running",
        "next_action": runtime_gap_action,
        "iterations": [{"status": {"decision_summary": {"runtime_issue_counts": runtime_counts}}}],
    })
    assert_true(runtime_gap_control.get("decision_summary", {}).get("runtime_issue_counts", {}).get("failed_responses") == 1, "loop_control should expose runtime decision summaries for external orchestrators.")
    runtime_gap_health = runtime_gap_control.get("evidence_health") or {}
    assert_true(runtime_gap_health.get("status") == "needs_auto_continue", "runtime evidence gaps with safe follow-ups should expose auto-continue health.")
    assert_true(runtime_gap_health.get("runtime_issue_total") == 3, "evidence_health should carry compact runtime issue totals.")
    assert_true("runtime_issues_present" in runtime_gap_health.get("flags", []), "evidence_health should flag runtime issues.")
    assert_true((runtime_gap_control.get("evidence_gap_plan") or {}).get("gap_count", 0) >= 1, "runtime evidence gaps should expose a prioritized evidence_gap_plan.")
    assert_true("runtime-disposition" in (runtime_gap_control.get("evidence_gap_plan") or {}).get("recommended_order", []), "evidence_gap_plan should recommend runtime disposition.")
    mixed_gap_action = {
        "action": "report_current_verdict",
        "automatable": False,
        "reason": "fixture mixed evidence gaps",
        "reason_codes": ["audit_failed", "requirement_source_unmapped", "strategy_dimension_gap", "undispositioned_failed_responses"],
        "evidence": ["qa-verdict.json", "audit-summary.json", "results.json"],
        "failure_analysis": {
            "category": "evidence_pipeline_failure",
            "blocking_layer": "evidence_pipeline",
            "source": "audit-summary.json",
            "reason_codes": ["audit_failed", "requirement_source_unmapped", "strategy_dimension_gap", "undispositioned_failed_responses"],
        },
        "decision_summary": {
            "runtime_issue_counts": runtime_counts,
            "runtime_issue_examples": runtime_examples,
            "strategy_coverage": {
                "gap_count": 1,
                "gaps": [{"dimension": "persistence", "reason": "no_executable_probe", "test_ids": ["T-persist"]}],
            },
            "source_coverage": {
                "uncovered_count": 1,
                "uncovered_examples": [{"id": "R-src-1", "source": "requirement.md", "text": "must persist the streamed answer"}],
            },
            "evidence_layer_summary": {
                "evidence_count": 2,
                "current_run_evidence_count": 0,
                "audit": {"passed": False, "error_count": 1, "warning_count": 0, "error_examples": ["fixture audit error"]},
                "proof_layer_counts": {"api": 1, "stream": 1},
            },
        },
    }
    mixed_gap_control = module.build_loop_control({
        "status": "blocked",
        "stop_reason": "next_action_requires_handoff",
        "run_dir": str(action_dir),
        "finished_at": "2026-06-16T00:00:00",
        "next_action": mixed_gap_action,
        "final": nonpass_status,
    })
    assert_route_model_consistent(mixed_gap_control, "mixed evidence gaps")
    mixed_gap_plan = mixed_gap_control.get("evidence_gap_plan") or {}
    assert_true(mixed_gap_plan.get("highest_priority") == "P0", "mixed evidence gaps should surface the highest priority gap.")
    assert_true(mixed_gap_plan.get("recommended_order", [None])[0] == "audit-errors", "audit errors should be the first repair item in mixed evidence gaps.")
    assert_true("requirement-source-coverage" in mixed_gap_plan.get("recommended_order", []), "evidence_gap_plan should include source coverage gaps.")
    assert_true("strategy-coverage" in mixed_gap_plan.get("recommended_order", []), "evidence_gap_plan should include strategy coverage gaps.")
    assert_true("current-run-evidence" in mixed_gap_plan.get("recommended_order", []), "evidence_gap_plan should include missing current-run evidence gaps.")
    assert_true((mixed_gap_control.get("evidence_health") or {}).get("evidence_gap_count") == mixed_gap_plan.get("gap_count"), "evidence_health should summarize evidence gap count.")
    mixed_gap_steps = mixed_gap_control.get("recommended_next_steps") or []
    assert_true(mixed_gap_steps and mixed_gap_steps[0].get("id") == "resolve_evidence_gap:audit-errors", "recommended_next_steps should route the first action to the top evidence gap.")
    assert_true(mixed_gap_steps[0].get("kind") == "repair" and mixed_gap_steps[0].get("priority") == "P0", "top audit evidence gaps should be exposed as P0 repair steps.")
    audit_step_artifacts = mixed_gap_steps[0].get("evidence_artifacts") or []
    audit_step_artifact = next((item for item in audit_step_artifacts if isinstance(item, dict) and item.get("name") == "audit-summary.json"), {})
    assert_true(Path(str(audit_step_artifact.get("path"))).resolve() == (action_dir / "audit-summary.json").resolve(), "gap recommended steps should resolve their own evidence paths.")
    assert_true(audit_step_artifact.get("sha256") == file_sha256(action_dir / "audit-summary.json"), "gap recommended steps should expose evidence hashes for drift checks.")
    mixed_gap_orchestration = mixed_gap_control.get("orchestration_state") or {}
    assert_true(mixed_gap_orchestration.get("mode") == "repair_evidence_pipeline", "orchestration_state should route audit-led gaps to evidence-pipeline repair.")
    assert_true((mixed_gap_orchestration.get("first_evidence_gap") or {}).get("id") == "audit-errors", "orchestration_state should expose the first evidence gap id.")
    assert_true((mixed_gap_orchestration.get("first_recommended_step") or {}).get("gap_id") == "audit-errors", "orchestration_state should bind the first step back to its gap.")
    mixed_gap_human = mixed_gap_control.get("human_action_required") or {}
    assert_true("audit-errors" in mixed_gap_human.get("recommended_gap_ids", []), "human_action_required should expose recommended evidence gap ids.")
    assert_true((mixed_gap_human.get("top_evidence_gap") or {}).get("id") == "audit-errors", "human_action_required should expose the top evidence gap.")
    mixed_gap_summary = {
        "status": "blocked",
        "stop_reason": "next_action_requires_handoff",
        "run_dir": str(action_dir),
        "next_action": mixed_gap_action,
        "loop_control": mixed_gap_control,
        "final": nonpass_status,
        "iterations": [],
    }
    mixed_gap_handoff = module.write_agent_handoff(action_dir / "mixed-gap-agent-summary.json", mixed_gap_summary).read_text(encoding="utf-8")
    assert_true("## Agent Route Model" in mixed_gap_handoff, "mixed gap handoff should render the route model contract.")
    assert_true("## Orchestration State" in mixed_gap_handoff, "handoff should render compact orchestration state.")
    assert_true("Mode: `repair_evidence_pipeline`" in mixed_gap_handoff, "handoff orchestration should expose the current routing mode.")
    assert_true("First evidence gap: `P0` `audit-errors`" in mixed_gap_handoff, "handoff orchestration should expose the first evidence gap.")
    assert_true("First recommended step: `repair | resolve_evidence_gap:audit-errors" in mixed_gap_handoff, "handoff orchestration should expose the first recommended step.")
    assert_true("## Evidence Gap Plan" in mixed_gap_handoff and "audit-errors" in mixed_gap_handoff, "handoff should render prioritized evidence gap plans.")
    assert_true("resolve_evidence_gap:audit-errors" in mixed_gap_handoff and "Recommended gap ids" in mixed_gap_handoff, "handoff should render gap-driven next steps and human routing.")
    cycle_helper_action = {
        "action": "report_current_verdict",
        "automatable": False,
        "reason": "fixture helper failure",
        "reason_codes": ["cycle_helper_failed"],
        "evidence": ["qa-cycle-error.json", "qa-verdict.json"],
        "failure_analysis": {
            "category": "evidence_pipeline_failure",
            "blocking_layer": "evidence_pipeline",
            "source": "qa-cycle-error.json",
            "reason_codes": ["cycle_helper_failed"],
        },
    }
    cycle_helper_control = module.build_loop_control({
        "status": "blocked",
        "stop_reason": "next_action_requires_handoff",
        "finished_at": "2026-06-16T00:00:00",
        "next_action": cycle_helper_action,
        "final": {"can_claim_pass": False, "reason_codes": ["cycle_helper_failed"]},
    })
    cycle_helper_gap_plan = cycle_helper_control.get("evidence_gap_plan") or {}
    assert_true("cycle-helper-error" in cycle_helper_gap_plan.get("recommended_order", []), "cycle helper failures should become a prioritized evidence gap.")
    cycle_helper_steps = cycle_helper_control.get("recommended_next_steps") or []
    assert_true(cycle_helper_steps and cycle_helper_steps[0].get("id") == "resolve_evidence_gap:cycle-helper-error", "cycle helper gaps should route the next step to qa-cycle-error repair.")
    strategy_gap_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={"can_claim_pass": False, "reason_codes": ["strategy_dimension_gap"], "preview_summary": {"applied_count": 1}},
    )
    assert_true(strategy_gap_action.get("action") == "continue_with_safe_next_probes", "strategy coverage gaps should auto-continue when safe coverage probes are available.")
    assert_true(strategy_gap_action.get("automatable") is True, "safe strategy coverage follow-ups should be automatable.")
    write_json(
        action_dir / "next-probe-preview.json",
        {
            "summary": {
                "applied_count": 1,
                "skipped_count": 1,
                "skipped_reason_counts": {"stream probe requires --allow-live-stream": 1},
            },
            "applied_recommendations": [
                {"id": "NP-runtime", "layer": "runtime", "step_id": "next-np-runtime", "test_ids": ["T-runtime"]}
            ],
            "skipped_recommendations": [
                {"id": "NP-stream", "layer": "stream", "reason": "stream probe requires --allow-live-stream", "source_test_id": "T-stream"}
            ],
        },
    )
    mixed_followup_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={
            "can_claim_pass": False,
            "reason_codes": ["undispositioned_failed_responses"],
            "preview_summary": {"applied_count": 1, "skipped_count": 1},
            "preview_artifact": {"current": True},
        },
    )
    assert_true(mixed_followup_action.get("action") == "request_authorization_or_inputs", "mixed safe and blocked follow-ups should request authorization/input before auto-continuing.")
    assert_true(mixed_followup_action.get("automatable") is False, "mixed safe and blocked follow-ups should not be automatable.")
    assert_true(mixed_followup_action.get("preview_applied_count") == 1, "mixed follow-up handoff should preserve the safe preview count.")
    assert_true(mixed_followup_action.get("blocked_followups", {}).get("actionable_skipped_count") == 1, "mixed follow-up handoff should expose the actionable skipped follow-up count.")
    assert_true("actionable skipped" in mixed_followup_action.get("blocked_auto_continue_reason", ""), "mixed follow-up handoff should explain why auto-continue was blocked.")
    mixed_control = module.build_loop_control({
        "status": "blocked",
        "stop_reason": "next_action_requires_handoff",
        "finished_at": "2026-06-16T00:00:00",
        "next_action": mixed_followup_action,
        "final": nonpass_status,
    })
    mixed_human = mixed_control.get("human_action_required") or {}
    assert_true(mixed_human.get("type") == "authorization_or_input", "mixed follow-up loop_control should expose authorization/input as the human action type.")
    assert_true(mixed_human.get("blocked_followups", {}).get("actionable_skipped_count") == 1, "human_action_required should preserve actionable blocked follow-up counts.")
    assert_true("review_blocked_followups" in mixed_human.get("recommended_next_step_ids", []), "human_action_required should point to the blocked-followup review step.")
    mixed_health = mixed_control.get("evidence_health") or {}
    assert_true(mixed_health.get("status") == "blocked_authorization_or_boundary", "mixed follow-up evidence health should show authorization/input blockage.")
    assert_true("requires_authorization" in mixed_health.get("flags", []), "evidence_health should flag authorization requirements.")
    mixed_gap_plan = mixed_control.get("evidence_gap_plan") or {}
    assert_true("blocked-followups" in mixed_gap_plan.get("recommended_order", []), "blocked follow-ups should become an evidence gap plan item.")
    assert_true("blocked-followups" in mixed_human.get("recommended_gap_ids", []), "authorization human action should include blocked follow-up gap ids.")
    mixed_orchestration = mixed_control.get("orchestration_state") or {}
    assert_true(mixed_orchestration.get("mode") == "await_authorization", "orchestration_state should classify mixed blocked follow-ups as authorization/input waits.")
    assert_true(mixed_orchestration.get("human_request_type") == "authorization_or_input", "orchestration_state should expose authorization/input human routing.")
    product_defect_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={"can_claim_pass": False, "reason_codes": ["defects_present"], "preview_summary": {"applied_count": 1}},
    )
    assert_true(product_defect_action.get("action") == "report_product_defect", "product defects should stop for a defect-first handoff even when safe follow-ups preview.")
    assert_true(product_defect_action.get("automatable") is False, "product defect handoff should not auto-continue.")
    assert_true(product_defect_action.get("preview_applied_count") == 1, "product defect handoff should preserve previewed safe follow-up count.")
    assert_true("not in the automatic follow-up allowlist" in product_defect_action.get("blocked_auto_continue_reason", ""), "product defect handoff should explain why auto-continue was blocked.")
    environment_boundary_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={"can_claim_pass": False, "reason_codes": ["environment_unconfirmed"], "preview_summary": {"applied_count": 1}},
    )
    assert_true(environment_boundary_action.get("action") == "confirm_environment_boundary", "unconfirmed environment boundary should stop for boundary confirmation before more probes.")
    environment_control = module.build_loop_control({
        "status": "blocked",
        "stop_reason": "next_action_requires_handoff",
        "finished_at": "2026-06-16T00:00:00",
        "next_action": environment_boundary_action,
        "final": nonpass_status,
    })
    environment_human = environment_control.get("human_action_required") or {}
    assert_true(environment_human.get("type") == "environment_boundary_confirmation", "environment-boundary loop_control should expose a confirmation human action.")
    assert_true("data_boundary_status" in environment_human.get("confirmation_fields", []), "environment confirmation should name the data-boundary field.")
    environment_health = environment_control.get("evidence_health") or {}
    assert_true(environment_health.get("status") == "blocked_authorization_or_boundary", "environment-boundary evidence health should block on confirmation.")
    assert_true("requires_authorization" in environment_health.get("flags", []), "environment-boundary evidence health should flag a required human confirmation.")
    environment_orchestration = environment_control.get("orchestration_state") or {}
    assert_true(environment_orchestration.get("mode") == "await_confirmation", "orchestration_state should classify environment-boundary stops as confirmation waits.")
    assert_true("data_boundary_status" in environment_orchestration.get("confirmation_fields", []), "orchestration_state should carry required confirmation fields.")
    write_json(action_dir / "next-probe-preview.json", {"summary": {"applied_count": 0, "skipped_count": 0}, "skipped_recommendations": []})
    environment_no_followup_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={"can_claim_pass": False, "reason_codes": ["environment_unconfirmed"], "preview_summary": {"applied_count": 0}, "preview_artifact": {"current": True}},
    )
    assert_true(environment_no_followup_action.get("action") == "confirm_environment_boundary", "environment boundary states should request confirmation even when no safe follow-up probes are available.")
    environment_no_followup_control = module.build_loop_control({
        "status": "blocked",
        "stop_reason": "next_action_requires_handoff",
        "finished_at": "2026-06-16T00:00:00",
        "next_action": environment_no_followup_action,
        "final": {"can_claim_pass": False, "reason_codes": ["environment_unconfirmed"]},
    })
    assert_route_model_consistent(environment_no_followup_control, "environment boundary without follow-ups")
    assert_true((environment_no_followup_control.get("agent_route_model") or {}).get("human_request_type") == "environment_boundary_confirmation", "route model should not collapse boundary confirmation into generic reporting.")
    adapter_no_followup_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={"can_claim_pass": False, "reason_codes": ["adapter_probe_blocked"], "preview_summary": {"applied_count": 0}, "preview_artifact": {"current": True}},
    )
    assert_true(adapter_no_followup_action.get("action") == "request_authorization_or_inputs", "adapter blockers without safe follow-ups should request authorization or concrete inputs.")
    adapter_no_followup_control = module.build_loop_control({
        "status": "blocked",
        "stop_reason": "next_action_requires_handoff",
        "finished_at": "2026-06-16T00:00:00",
        "next_action": adapter_no_followup_action,
        "final": {"can_claim_pass": False, "reason_codes": ["adapter_probe_blocked"]},
    })
    assert_route_model_consistent(adapter_no_followup_control, "adapter blocker without follow-ups")
    assert_true((adapter_no_followup_control.get("agent_route_model") or {}).get("human_request_type") == "authorization_or_input", "route model should not collapse adapter input requests into generic reporting.")
    audit_no_followup_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={"can_claim_pass": False, "reason_codes": ["audit_failed"], "preview_summary": {"applied_count": 0}, "preview_artifact": {"current": True}},
    )
    assert_true(audit_no_followup_action.get("action") == "repair_evidence_pipeline", "audit failures without safe follow-ups should request evidence-pipeline repair.")
    audit_no_followup_control = module.build_loop_control({
        "status": "blocked",
        "stop_reason": "next_action_requires_handoff",
        "finished_at": "2026-06-16T00:00:00",
        "next_action": audit_no_followup_action,
        "final": {"can_claim_pass": False, "reason_codes": ["audit_failed"]},
    })
    assert_route_model_consistent(audit_no_followup_control, "audit failure without follow-ups")

def _verify_handoff_and_pass_routes(context: AgentRouteFixtureContext) -> None:
    module = context.module
    action_dir = context.action_dir
    args = context.args
    ok_cycle = context.ok_cycle
    ok_preview = context.ok_preview
    nonpass_status = context.nonpass_status
    preview_next_probes_hash = context.preview_next_probes_hash
    setup_gap_action = {
        "action": "report_current_verdict",
        "automatable": False,
        "reason": "fixture setup/context gaps",
        "reason_codes": ["environment_unconfirmed", "preflight_blocked", "service_runtime_failed", "adapter_probe_blocked"],
        "evidence": ["adapter-context.json", "service-preflight.json", "service-runtime.json", "adapter-probes.json", "qa-cycle-error.json"],
        "failure_analysis": {
            "category": "setup_environment_blocker",
            "blocking_layer": "runtime_setup",
            "source": "service-preflight.json/service-runtime.json",
            "reason_codes": ["environment_unconfirmed", "preflight_blocked", "service_runtime_failed", "adapter_probe_blocked"],
        },
        "decision_summary": {
            "environment_boundary": {
                "runtime_mode": "unconfirmed",
                "data_boundary_status": "must be stated before pass/fail",
                "needs_confirmation": True,
            },
            "service_preflight": {
                "blocker_count": 1,
                "start_plan_count": 1,
                "blocker_examples": [{"service": "fixture-api", "reason": "required service port is not reachable"}],
            },
            "service_runtime": {
                "planned_count": 1,
                "ready_count": 0,
                "failed_count": 1,
                "service_examples": [{"service": "fixture-api", "status": "timed out waiting for service readiness"}],
            },
            "adapter_probes": {
                "blocked_probe_count": 2,
                "blocked_examples": [
                    {"id": "adapter-stream", "reason": "stream probe requires --allow-live-stream"},
                    {"id": "adapter-persistence", "reason": "missing persistence helper"},
                ],
            },
            "cycle_error": {"code": "cycle_helper_failed", "phase": "generate_verdict", "message": "helper failed"},
        },
    }
    setup_gap_control = module.build_loop_control({
        "status": "blocked",
        "stop_reason": "next_action_requires_handoff",
        "finished_at": "2026-06-16T00:00:00",
        "next_action": setup_gap_action,
        "final": {"can_claim_pass": False, "reason_codes": setup_gap_action["reason_codes"]},
    })
    assert_route_model_consistent(setup_gap_control, "setup and adapter evidence gaps")
    setup_gap_plan = setup_gap_control.get("evidence_gap_plan") or {}
    setup_order = setup_gap_plan.get("recommended_order", [])
    assert_true("environment-boundary" in setup_order, "evidence_gap_plan should include environment-boundary confirmation gaps.")
    assert_true("service-preflight-blockers" in setup_order, "evidence_gap_plan should include service preflight blocker gaps.")
    assert_true("service-runtime-failures" in setup_order, "evidence_gap_plan should include service runtime failure gaps.")
    assert_true("adapter-probe-blockers" in setup_order, "evidence_gap_plan should include adapter probe blocker gaps.")
    assert_true("cycle-helper-error" in setup_order, "evidence_gap_plan should include cycle helper gaps from compact cycle_error summaries.")
    setup_steps = setup_gap_control.get("recommended_next_steps") or []
    setup_steps_by_id = {item.get("id"): item for item in setup_steps if isinstance(item, dict)}
    assert_true(setup_steps_by_id.get("resolve_evidence_gap:environment-boundary", {}).get("kind") == "confirm", "environment-boundary gaps should route as confirmation steps.")
    assert_true("data_boundary_status" in setup_steps_by_id.get("resolve_evidence_gap:environment-boundary", {}).get("confirmation_fields", []), "environment-boundary steps should name required confirmation fields.")
    assert_true(setup_steps_by_id.get("resolve_evidence_gap:environment-boundary", {}).get("details", {}).get("runtime_mode") == "unconfirmed", "environment-boundary steps should carry compact boundary details.")
    assert_true(setup_steps_by_id.get("resolve_evidence_gap:cycle-helper-error", {}).get("requires_input_repair") is True, "cycle helper gaps should mark input/tooling repair as required.")
    assert_true(setup_steps_by_id.get("resolve_evidence_gap:service-preflight-blockers", {}).get("kind") == "authorize", "service preflight blockers with start plans should route as authorization steps.")
    assert_true(setup_steps_by_id.get("resolve_evidence_gap:service-preflight-blockers", {}).get("requires_authorization") is True, "service preflight blocker steps should mark authorization as required.")
    assert_true("--start-missing-services" in setup_steps_by_id.get("resolve_evidence_gap:service-preflight-blockers", {}).get("recommended_flags", []), "service preflight blocker steps should recommend the service-start flag when a start plan exists.")
    assert_true((setup_gap_control.get("evidence_health") or {}).get("service_runtime_failed_count") == 1, "evidence_health should preserve service runtime failure counts with gap planning.")
    setup_orchestration = setup_gap_control.get("orchestration_state") or {}
    assert_true(setup_orchestration.get("mode") == "repair_evidence_pipeline", "orchestration_state should repair QA cycle errors before interpreting setup conclusions.")
    assert_true((setup_orchestration.get("first_evidence_gap") or {}).get("id") == "cycle-helper-error", "orchestration_state should expose setup/context top gap ids.")
    setup_human = setup_gap_control.get("human_action_required") or {}
    assert_true("environment-boundary" in setup_human.get("recommended_gap_ids", []), "human_action_required should include environment-boundary gap ids.")
    assert_true((setup_human.get("top_evidence_gap") or {}).get("details"), "human_action_required should carry compact details for the top evidence gap.")
    adapter_only_action = {
        "action": "request_authorization_or_inputs",
        "automatable": False,
        "reason": "fixture adapter blocker",
        "reason_codes": ["adapter_probe_blocked"],
        "evidence": ["adapter-probes.json", "adapter-context.json"],
        "failure_analysis": {
            "category": "requirement_or_adapter_blocker",
            "blocking_layer": "requirement_execution",
            "source": "adapter-probes.json",
            "reason_codes": ["adapter_probe_blocked"],
        },
        "decision_summary": {
            "adapter_probes": {
                "blocked_probe_count": 1,
                "blocked_examples": [{"id": "adapter-stream", "reason": "stream probe requires --allow-live-stream"}],
            }
        },
    }
    adapter_only_control = module.build_loop_control({
        "status": "blocked",
        "stop_reason": "next_action_requires_handoff",
        "finished_at": "2026-06-16T00:00:00",
        "next_action": adapter_only_action,
        "final": {"can_claim_pass": False, "reason_codes": ["adapter_probe_blocked"]},
    })
    assert_route_model_consistent(adapter_only_control, "adapter blocker only")
    adapter_only_steps = adapter_only_control.get("recommended_next_steps") or []
    assert_true(adapter_only_steps and adapter_only_steps[0].get("id") == "resolve_evidence_gap:adapter-probe-blockers", "adapter probe blockers should route to the adapter gap first when no P0 gap exists.")
    assert_true(adapter_only_steps[0].get("kind") == "authorize", "adapter probe blockers should route as authorization/input steps.")
    assert_true(adapter_only_steps[0].get("requires_authorization") is True, "adapter probe blocker steps should mark authorization/input requirements.")
    assert_true("stream probe requires --allow-live-stream" in adapter_only_steps[0].get("required_inputs", []), "adapter probe blocker steps should expose concrete missing inputs.")
    adapter_orchestration = adapter_only_control.get("orchestration_state") or {}
    assert_true(adapter_orchestration.get("mode") == "await_authorization", "orchestration_state should classify adapter probe blockers as authorization waits.")
    assert_true("stream probe requires --allow-live-stream" in adapter_orchestration.get("required_inputs", []), "orchestration_state should carry concrete missing adapter inputs.")
    adapter_human = adapter_only_control.get("human_action_required") or {}
    assert_true("stream probe requires --allow-live-stream" in adapter_human.get("required_inputs", []), "human_action_required should promote concrete adapter missing inputs to the checklist.")
    assert_true((adapter_human.get("top_evidence_gap") or {}).get("details", {}).get("blocked_probe_count") == 1, "adapter human handoff should carry top-gap details.")
    mixed_environment_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={"can_claim_pass": False, "reason_codes": ["environment_unconfirmed", "defects_present", "strategy_dimension_gap"], "preview_summary": {"applied_count": 1}},
    )
    assert_true(mixed_environment_action.get("action") == "confirm_environment_boundary", "mixed non-pass verdicts should confirm environment/data boundary before reporting defects or auto-continuing.")
    assert_true(mixed_environment_action.get("automatable") is False, "mixed environment-boundary states should not auto-continue even when safe follow-ups preview.")
    assert_true(mixed_environment_action.get("failure_analysis", {}).get("category") == "environment_boundary_unconfirmed", "mixed environment actions should expose the boundary category.")

    resume_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=2,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={**nonpass_status, "preview_summary": {"applied_count": 1}},
    )
    assert_true(resume_action.get("action") == "resume_with_more_iterations", "agent next_action should request more iterations when budget is exhausted but safe follow-ups remain.")
    assert_true(resume_action.get("automatable") is False, "budget exhaustion should not silently continue.")
    assert_true(resume_action.get("failure_analysis", {}).get("category") == "iteration_budget_exhausted", "iteration budget stops should be classified for resume handoff.")
    resume_args = resume_action.get("resume_command_args") or []
    assert_true(resume_action.get("recommended_max_iterations") == 3, "resume action should recommend a concrete larger iteration budget.")
    assert_true("--apply-existing-next-probes" in resume_args, "resume command must intentionally apply the already-previewed safe next probes.")
    assert_true("--expected-next-probes-sha256" in resume_args and preview_next_probes_hash in resume_args, "resume command must bind the existing next-probes.json to the previewed hash.")
    assert_true(resume_action.get("expected_next_probes_sha256") == preview_next_probes_hash, "budget-exhausted resume action should expose the expected next-probes hash.")
    assert_true("--strict-runtime" in resume_args and "--require-environment-boundary" in resume_args, "resume command should preserve strict evidence gates.")
    assert_true("fixture-api" in resume_args, "resume command should preserve required service filters.")
    assert_true("--summary" in resume_args and str(action_dir / "external-agent-summary.json") in resume_args, "resume command should preserve custom summary output paths for external orchestrators.")
    assert_true("<larger-number>" not in str(resume_action.get("resume_command")), "resume command should be runnable, not a placeholder.")
    resume_control = module.build_loop_control({
        "status": "blocked",
        "stop_reason": "max_iterations_reached",
        "finished_at": "2026-06-16T00:00:00",
        "next_action": resume_action,
        "final": nonpass_status,
    })
    assert_true(resume_control.get("terminal") is True, "budget-exhausted loop control should be terminal for the current process.")
    assert_true(resume_control.get("can_resume_with_command") is True, "loop_control should expose that a runnable resume command is available.")
    assert_true("--apply-existing-next-probes" in resume_control.get("resume_command_args", []), "loop_control should preserve resume command args for external orchestrators.")
    resume_human = resume_control.get("human_action_required") or {}
    assert_true(resume_human.get("type") == "iteration_budget_decision", "budget-exhausted loop_control should expose an iteration-budget human action.")
    assert_true("--apply-existing-next-probes" in resume_human.get("resume_command_args", []), "human_action_required should preserve runnable resume args.")
    resume_health = resume_control.get("evidence_health") or {}
    assert_true(resume_health.get("status") == "needs_inspection", "budget-exhausted evidence health should not pretend it can auto-continue inside the stopped process.")
    resume_orchestration = resume_control.get("orchestration_state") or {}
    assert_true(resume_orchestration.get("mode") == "await_iteration_budget", "orchestration_state should classify iteration-budget stops separately from generic reports.")
    assert_true("--apply-existing-next-probes" in resume_orchestration.get("resume_command_args", []), "orchestration_state should preserve runnable resume args.")
    mismatch_action = module.next_probes_hash_mismatch_action(action_dir, "0" * 64, preview_next_probes_hash)
    assert_true(mismatch_action.get("action") == "repreview_next_probes", "next-probes hash mismatch should stop for a repreview handoff.")
    assert_true(mismatch_action.get("input_artifact_errors", [{}])[0].get("error") == "previewed_next_probes_hash_mismatch", "hash mismatch handoff should expose an artifact-input error code.")
    assert_true(mismatch_action.get("failure_analysis", {}).get("category") == "next_probe_input_integrity", "hash mismatch should be classified as next-probe input integrity.")

    write_json(
        action_dir / "next-probe-preview.json",
        {
            "summary": {
                "applied_count": 0,
                "skipped_count": 1,
                "skipped_reason_counts": {"stream probe requires --allow-live-stream": 1},
            },
            "skipped_recommendations": [
                {"id": "NP-stream", "layer": "stream", "reason": "stream probe requires --allow-live-stream", "source_test_id": "T-stream"}
            ],
        },
    )
    input_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={**nonpass_status, "preview_summary": {"applied_count": 0}, "preview_artifact": {"current": True}},
    )
    assert_true(input_action.get("action") == "request_authorization_or_inputs", "agent next_action should request inputs or authorization for blocked follow-ups.")
    assert_true(input_action.get("blocked_followups", {}).get("actionable_skipped_count") == 1, "blocked follow-up count should exclude only non-actionable duplicate skips.")
    assert_true(input_action.get("failure_analysis", {}).get("category") == "authorization_or_input_required", "blocked follow-ups should be classified as authorization/input needs.")

    write_json(
        action_dir / "next-probe-preview.json",
        {
            "summary": {
                "applied_count": 0,
                "skipped_count": 1,
                "skipped_reason_counts": {"equivalent step already exists in plan": 1},
            },
            "skipped_recommendations": [
                {"id": "NP-duplicate", "layer": "stream", "reason": "equivalent step already exists in plan", "source_test_id": "T-stream"}
            ],
        },
    )
    report_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={**nonpass_status, "preview_summary": {"applied_count": 0}, "preview_artifact": {"current": True}},
    )
    assert_true(report_action.get("action") == "report_no_new_progress", "duplicate-only skipped follow-ups should stop as a no-new-progress handoff.")
    assert_true(report_action.get("no_new_progress") is True, "duplicate-only skipped follow-ups should expose no_new_progress for orchestration.")
    assert_true(report_action.get("non_actionable_followups", {}).get("skipped_count") == 1, "duplicate-only skipped follow-ups should preserve the non-actionable skipped count.")
    assert_true(report_action.get("failure_analysis", {}).get("category") == "no_new_followup_progress", "duplicate-only skipped follow-ups should classify as no-new-followup progress.")
    report_control = module.build_loop_control({
        "status": "blocked",
        "stop_reason": "next_action_requires_handoff",
        "finished_at": "2026-06-16T00:00:00",
        "next_action": report_action,
        "final": nonpass_status,
    })
    assert_true(report_control.get("no_new_progress") is True, "loop_control should expose duplicate-only no-new-progress states.")
    assert_true(report_control.get("non_actionable_followups", {}).get("skipped_count") == 1, "loop_control should expose non-actionable follow-up summaries.")
    assert_true(report_control.get("result_ready_to_report") is True, "no-new-progress handoffs should be reportable without another automatic cycle.")
    report_steps = report_control.get("recommended_next_steps") or []
    assert_true(report_steps and report_steps[0].get("id") == "report_no_new_progress", "duplicate-only no-new-progress handoffs should report before proposing more probe work.")
    assert_true(any(item.get("id") == "manual_revision_after_no_new_progress" for item in report_steps if isinstance(item, dict)), "duplicate-only no-new-progress handoffs should expose manual revision as the next way forward.")
    duplicate_summary = {
        "status": "blocked",
        "stop_reason": "next_action_requires_handoff",
        "run_dir": str(action_dir),
        "next_action": report_action,
        "loop_control": report_control,
        "final": nonpass_status,
        "iterations": [],
    }
    duplicate_handoff = module.write_agent_handoff(action_dir / "duplicate-agent-summary.json", duplicate_summary).read_text(encoding="utf-8")
    assert_true("Mode: `manual_revision_or_report`" in duplicate_handoff, "no-new-progress handoff should expose manual revision/report orchestration.")
    assert_true("No new progress: `true`" in duplicate_handoff, "duplicate-only handoff should make no-new-progress visible to humans.")
    assert_true("## Non-Actionable Follow-Ups" in duplicate_handoff, "duplicate-only handoff should render non-actionable follow-ups.")
    assert_true("NP-duplicate" in duplicate_handoff and "equivalent step already exists in plan" in duplicate_handoff, "duplicate-only handoff should show the duplicate skipped probe.")

    pass_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={"can_claim_pass": True, "preview_summary": {"applied_count": 0}},
    )
    assert_true(pass_action.get("action") == "report_pass", "agent next_action should report pass only when verdict allows a pass claim.")
    pass_control = module.build_loop_control({
        "status": "passed",
        "stop_reason": "verdict_passed",
        "finished_at": "2026-06-16T00:00:01",
        "next_action": pass_action,
        "final": {"verdict": "passed", "can_claim_pass": True},
    })
    assert_route_model_consistent(pass_control, "pass-ready route")
    assert_true(pass_control.get("terminal") is True, "passed loop control should be terminal.")
    assert_true(pass_control.get("pass_claim_allowed") is True, "loop_control should expose the final pass claim gate.")
    assert_true(pass_control.get("handoff_required") is False, "pass-ready loop control should not require a non-pass handoff.")
    assert_true("human_action_required" not in pass_control, "pass-ready loop_control should not require human unblock work.")
    pass_health = pass_control.get("evidence_health") or {}
    assert_true(pass_health.get("status") == "pass_claim_ready", "pass-ready loop_control should expose pass_claim_ready evidence health.")
    assert_true("pass_claim_allowed" in pass_health.get("flags", []), "evidence_health should flag pass-claim readiness.")
    pass_orchestration = pass_control.get("orchestration_state") or {}
    assert_true(pass_orchestration.get("mode") == "report_pass", "orchestration_state should classify pass-ready terminal states as report_pass.")
    assert_true(pass_orchestration.get("pass_claim_allowed") is True, "orchestration_state should preserve the pass-claim gate.")

    write_json(
        action_dir / "next-probe-preview.json",
        {
            "summary": {"applied_count": 3, "skipped_count": 0},
            "applied_steps": [{"id": "stale-preview-step"}],
        },
    )
    write_json(
        action_dir / "next-probe-application.json",
        {
            "summary": {"applied_count": 2, "skipped_count": 0},
            "applied_steps": [{"id": "stale-application-step"}],
        },
    )
    write_json(
        action_dir / "qa-verdict.json",
        {
            "verdict": "blocked",
            "can_claim_pass": False,
            "reasons": [{"code": "requirement_untested"}],
        },
    )
    write_json(action_dir / "qa-run-summary.json", {"status": "blocked", "steps": []})

def _verify_stale_and_invalid_artifact_routes(context: AgentRouteFixtureContext) -> None:
    module = context.module
    action_dir = context.action_dir
    tmp_path = context.tmp_path
    args = context.args
    ok_cycle = context.ok_cycle
    ok_preview = context.ok_preview
    stale_status = module.cycle_status(action_dir, applied_next_before_cycle=False, preview_result=None)
    assert_true(stale_status.get("preview_summary") is None, "agent loop must ignore stale next-probe preview summaries when the current iteration did not preview.")
    assert_true(stale_status.get("application_summary") is None, "agent loop must ignore stale next-probe application summaries when the current iteration did not apply probes.")
    assert_true(stale_status.get("preview_artifact", {}).get("current") is False, "stale preview artifact should be marked non-current.")
    assert_true(stale_status.get("application_artifact", {}).get("current") is False, "stale application artifact should be marked non-current.")
    stale_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=None,
        status=stale_status,
    )
    assert_true(stale_action.get("action") == "report_current_verdict", "stale preview applied_count must not make the agent continue automatically.")
    guarded_stale_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=None,
        status={**stale_status, "preview_summary": {"applied_count": 3}, "preview_artifact": {"current": False}},
    )
    assert_true(guarded_stale_action.get("action") == "report_current_verdict", "non-current preview metadata should override a stale applied_count.")

    write_json(
        action_dir / "qa-verdict.json",
        {
            "verdict": "inconclusive",
            "can_claim_pass": False,
            "reasons": [{"code": "input_artifact_unreadable"}],
            "input_artifact_errors": [
                {"name": "results", "path": str(action_dir / "results.json"), "error": "path_is_directory"}
            ],
        },
    )
    write_json(action_dir / "qa-run-summary.json", {"status": "inconclusive", "steps": []})
    input_error_status = module.cycle_status(action_dir, applied_next_before_cycle=False, preview_result=None)
    assert_true(input_error_status.get("input_artifact_errors", [{}])[0].get("name") == "results", "agent loop status should expose verdict input artifact errors.")
    assert_true(input_error_status.get("failure_analysis", {}).get("category") == "input_artifact_integrity", "unreadable verdict inputs should be classified as artifact integrity failures.")
    fix_input_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result={"exit_code": 1},
        preview_result=None,
        status=input_error_status,
    )
    assert_true(fix_input_action.get("action") == "fix_input_artifacts", "unreadable verdict inputs should produce a targeted fix_input_artifacts action after non-zero cycle exit.")
    assert_true(fix_input_action.get("input_artifact_errors", [{}])[0].get("name") == "results", "fix_input_artifacts should name the artifact that must be repaired.")
    assert_true(fix_input_action.get("failure_analysis", {}).get("blocking_layer") == "artifact_input", "fix_input_artifacts should preserve the artifact-input blocking layer.")
    fix_input_after_zero = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=ok_preview,
        status={**input_error_status, "preview_summary": {"applied_count": 0}},
    )
    assert_true(fix_input_after_zero.get("action") == "fix_input_artifacts", "unreadable verdict inputs should be prioritized even when the cycle command exits zero.")
    repair_control = module.build_loop_control({
        "status": "inconclusive",
        "stop_reason": "next_action_requires_handoff",
        "finished_at": "2026-06-16T00:00:02",
        "next_action": fix_input_after_zero,
        "final": input_error_status,
    })
    assert_true(repair_control.get("requires_input_repair") is True, "loop_control should expose input artifact repair as a first-class state.")
    assert_true(repair_control.get("handoff_required") is True, "input repair should require a handoff instead of automatic continuation.")
    repair_orchestration = repair_control.get("orchestration_state") or {}
    assert_true(repair_orchestration.get("mode") == "repair_inputs", "orchestration_state should classify input-artifact errors as repair_inputs.")
    assert_true(repair_orchestration.get("requires_input_repair") is True, "orchestration_state should expose input repair requirements.")

    write_json(
        action_dir / "next-probes.json",
        {
            "schema_version": 1,
            "summary": {"recommendation_count": 1},
            "recommendations": [{"id": "NP-stale-existing", "layer": "ui", "reason": "stale existing recommendation"}],
        },
    )
    resume_without_apply = SimpleNamespace(run_dir=str(action_dir), apply_existing_next_probes=False)
    resume_with_apply = SimpleNamespace(run_dir=str(action_dir), apply_existing_next_probes=True)
    assert_true(module.should_apply_existing_next_probes(resume_without_apply, action_dir) is False, "agent loop must not apply existing next-probes.json on the first cycle without explicit opt-in.")
    assert_true(module.should_apply_existing_next_probes(resume_with_apply, action_dir) is True, "agent loop should allow explicit resume application of an existing next-probes.json.")
    directory_next_probes_dir = tmp_path / "agent-directory-next-probes"
    directory_next_probes_dir.mkdir(parents=True, exist_ok=True)
    (directory_next_probes_dir / "next-probes.json").mkdir()
    assert_true(module.should_apply_existing_next_probes(resume_with_apply, directory_next_probes_dir) is False, "directory-shaped next-probes.json must not count as applyable existing recommendations.")

    write_json(action_dir / "qa-run-summary.json", {"status": "blocked", "steps": [{"name": "apply_next_probes", "exit_code": 0}]})
    current_status = module.cycle_status(action_dir, applied_next_before_cycle=True, preview_result=ok_preview)
    assert_true(current_status.get("application_summary", {}).get("applied_count") == 2, "current application summary should load only when apply-next ran in the current cycle.")
    assert_true(current_status.get("preview_summary", {}).get("applied_count") == 3, "current preview summary should load when the current preview command succeeded.")

    stale_verdict_dir = tmp_path / "agent-stale-verdict"
    stale_verdict_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        stale_verdict_dir / "qa-verdict.json",
        {
            "schema_version": 1,
            "generated_at": "2000-01-01T00:00:00",
            "verdict": "passed",
            "can_claim_pass": True,
            "reasons": [],
        },
    )
    write_json(
        stale_verdict_dir / "qa-run-summary.json",
        {
            "schema_version": 1,
            "status": "failed",
            "started_at": "2026-06-15T12:00:00",
            "finished_at": "2026-06-15T12:00:01",
            "steps": [{"name": "probe", "exit_code": 1}],
        },
    )
    os.utime(stale_verdict_dir / "qa-verdict.json", (1000, 1000))
    os.utime(stale_verdict_dir / "qa-run-summary.json", (2001, 2001))
    failed_cycle = {"exit_code": 1, "started_at_epoch": 2000.0}
    stale_verdict_status = module.cycle_status(stale_verdict_dir, cycle_result=failed_cycle)
    assert_true(stale_verdict_status.get("verdict") is None, "agent loop must ignore a stale qa-verdict.json when the current cycle did not write it.")
    assert_true(stale_verdict_status.get("can_claim_pass") is None, "stale pass verdict must not leak into current cycle status.")
    assert_true(stale_verdict_status.get("verdict_artifact", {}).get("current") is False, "stale verdict artifact should be marked non-current.")
    stale_verdict_action = module.build_next_action(
        args=args,
        run_dir=stale_verdict_dir,
        iteration=1,
        cycle_result=failed_cycle,
        preview_result=None,
        status=stale_verdict_status,
    )
    assert_true(stale_verdict_action.get("action") == "inspect_cycle_failure", "current cycle failure must not report an old verdict.")

    bad_artifact_dir = tmp_path / "agent-bad-artifacts"
    bad_artifact_dir.mkdir(parents=True, exist_ok=True)
    (bad_artifact_dir / "qa-run-summary.json").mkdir()
    (bad_artifact_dir / "qa-verdict.json").write_text("{not-json", encoding="utf-8")
    (bad_artifact_dir / "next-probe-preview.json").mkdir()
    (bad_artifact_dir / "next-probe-application.json").write_text("{not-json", encoding="utf-8")
    bad_status = module.cycle_status(
        bad_artifact_dir,
        cycle_result={"exit_code": 1, "started_at_epoch": 0.0},
        applied_next_before_cycle=True,
        preview_result={"exit_code": 0, "started_at_epoch": 0.0},
    )
    assert_true(bad_status.get("run_summary_artifact", {}).get("load_error") == "path_is_directory", "agent loop should mark directory-shaped run summaries unreadable instead of crashing.")
    assert_true(str(bad_status.get("verdict_artifact", {}).get("load_error", "")).startswith("invalid_json"), "agent loop should mark malformed verdict JSON unreadable instead of crashing.")
    assert_true(bad_status.get("preview_artifact", {}).get("load_error") == "path_is_directory", "agent loop should mark directory-shaped preview artifacts unreadable instead of crashing.")
    assert_true(str(bad_status.get("application_artifact", {}).get("load_error", "")).startswith("invalid_json"), "agent loop should mark malformed application JSON unreadable instead of crashing.")
    assert_true(bad_status.get("preview_summary") is None and bad_status.get("application_summary") is None, "unreadable follow-up artifacts must not drive next actions.")

    non_object_artifact_dir = tmp_path / "agent-non-object-artifacts"
    non_object_artifact_dir.mkdir(parents=True, exist_ok=True)
    (non_object_artifact_dir / "qa-run-summary.json").write_text("[]", encoding="utf-8")
    (non_object_artifact_dir / "qa-verdict.json").write_text("[]", encoding="utf-8")
    (non_object_artifact_dir / "next-probe-preview.json").write_text("[]", encoding="utf-8")
    (non_object_artifact_dir / "next-probe-application.json").write_text("[]", encoding="utf-8")
    non_object_status = module.cycle_status(
        non_object_artifact_dir,
        cycle_result={"exit_code": 1, "started_at_epoch": 0.0},
        applied_next_before_cycle=True,
        preview_result={"exit_code": 0, "started_at_epoch": 0.0},
    )
    assert_true(non_object_status.get("run_summary_artifact", {}).get("load_error") == "json_root_not_object", "agent loop should mark non-object run summaries unreadable instead of crashing.")
    assert_true(non_object_status.get("verdict_artifact", {}).get("load_error") == "json_root_not_object", "agent loop should mark non-object verdict artifacts unreadable instead of crashing.")
    assert_true(non_object_status.get("preview_artifact", {}).get("load_error") == "json_root_not_object", "agent loop should mark non-object preview artifacts unreadable instead of crashing.")
    assert_true(non_object_status.get("application_artifact", {}).get("load_error") == "json_root_not_object", "agent loop should mark non-object application artifacts unreadable instead of crashing.")
    assert_true(non_object_status.get("preview_summary") is None and non_object_status.get("application_summary") is None, "non-object follow-up artifacts must not drive next actions.")

    write_json(
        action_dir / "next-probe-preview.json",
        {
            "schema_version": 1,
            "input_artifact_errors": [
                {"name": "next_probes", "path": str(action_dir / "next-probes.json"), "error": "invalid_json: fixture", "required": True}
            ],
            "summary": {"recommendation_count": 0, "applied_count": 0, "skipped_count": 0},
        },
    )
    preview_failure = {"exit_code": 1, "started_at_epoch": 0.0}
    preview_input_status = module.cycle_status(action_dir, cycle_result=ok_cycle, preview_result=preview_failure)
    assert_true(preview_input_status.get("next_probe_input_artifact_errors", [{}])[0].get("name") == "next_probes", "agent loop status should expose next-probe preview input artifact errors.")
    assert_true(preview_input_status.get("failure_analysis", {}).get("category") == "next_probe_input_integrity", "next-probe input errors should be classified separately from product failures.")
    preview_input_action = module.build_next_action(
        args=args,
        run_dir=action_dir,
        iteration=1,
        cycle_result=ok_cycle,
        preview_result=preview_failure,
        status=preview_input_status,
    )
    assert_true(preview_input_action.get("action") == "fix_next_probe_inputs", "next-probe preview input errors should produce a targeted fix_next_probe_inputs action.")
    assert_true(preview_input_action.get("input_artifact_errors", [{}])[0].get("name") == "next_probes", "fix_next_probe_inputs should name the next-probe artifact that must be repaired.")

_AGENT_ROUTE_FAMILIES: tuple[
    Callable[[AgentRouteFixtureContext], None], ...
] = (
    _verify_automatic_and_stalled_routes,
    _verify_runtime_and_environment_routes,
    _verify_handoff_and_pass_routes,
    _verify_stale_and_invalid_artifact_routes,
)

def run_agent_next_action_fixture(script_dir: Path, tmp_path: Path) -> None:
    """按路由族验证 Agent 决策，并保留原公开夹具入口。"""
    context = _build_agent_route_context(script_dir, tmp_path)
    for family in _AGENT_ROUTE_FAMILIES:
        try:
            family(context)
        except AssertionError as exc:
            raise AssertionError(f"{family.__name__}: {exc}") from exc
