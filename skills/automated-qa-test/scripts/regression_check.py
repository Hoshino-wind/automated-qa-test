#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from qa_regression import agent as agent_fixtures
from qa_regression import contracts as contract_fixtures
from qa_regression import evidence as evidence_fixtures
from qa_regression.support import (
    ASYNC_FOLLOWUP_REQUIREMENT,
    BUSINESS_REQUIREMENT,
    CLICK_REQUIREMENT,
    CLICK_RESPONSE_REQUIREMENT,
    FOLLOWUP_REQUIREMENT,
    REQUIREMENT,
    STATUS_CODE_FOLLOWUP_REQUIREMENT,
    assert_true,
    last_path,
    load_json,
    run_cmd,
    write_json,
    write_runtime_console_disposition_fixture,
    write_synthetic_passing_audit_summary,
)

REGRESSION_GROUP_ORDER = ("contracts", "modeling", "evidence", "runtime", "agent", "browser")
FIXTURE_MODULES = (agent_fixtures, contract_fixtures, evidence_fixtures)


def regression_fixture_groups() -> dict[str, list[tuple[str, Any]]]:
    """把可独立运行的夹具稳定分组；完整回归仍保留原有编排顺序。"""
    fixtures = {
        name: value
        for module in FIXTURE_MODULES
        for name, value in vars(module).items()
        if name.startswith("run_") and name.endswith("_fixture") and callable(value)
    }
    groups: dict[str, list[tuple[str, Any]]] = {name: [] for name in REGRESSION_GROUP_ORDER}
    browser_tokens = ("browser", "request_absence", "probe_redaction", "live_backtest")
    agent_tokens = ("agent_", "next_probe", "planning_handoff")
    runtime_tokens = ("runtime", "preflight", "service_", "adapter_", "discover_project_context")
    modeling_tokens = (
        "scaffold",
        "requirement_coverage",
        "gold_modeling",
        "qa_metrics",
        "json_extension",
        "graphql",
        "versioned_api",
        "responsive_ui",
        "context_reset",
        "unmapped_source",
        "semantic",
        "analytics",
    )
    evidence_tokens = (
        "evidence",
        "audit_",
        "ledger_",
        "defect_",
        "verdict_",
        "report_",
        "current_run",
        "screenshot",
        "artifact_",
        "response_header",
        "secret_like",
        "environment_boundary",
    )
    for name, fixture in sorted(fixtures.items()):
        if any(token in name for token in browser_tokens):
            group = "browser"
        elif any(token in name for token in agent_tokens):
            group = "agent"
        elif any(token in name for token in runtime_tokens):
            group = "runtime"
        elif any(token in name for token in modeling_tokens):
            group = "modeling"
        elif any(token in name for token in evidence_tokens):
            group = "evidence"
        else:
            group = "contracts"
        groups[group].append((name, fixture))
    return groups


def run_selected_regression_groups(script_dir: Path, tmp_path: Path, selected: list[str]) -> dict[str, Any]:
    groups = regression_fixture_groups()
    completed: list[dict[str, Any]] = []
    for group_name in selected:
        fixtures = groups[group_name]
        for fixture_name, fixture in fixtures:
            fixture(script_dir, tmp_path)
        completed.append({"group": group_name, "fixture_count": len(fixtures)})
    return {
        "status": "passed",
        "selected_groups": selected,
        "groups": completed,
        "fixture_count": sum(item["fixture_count"] for item in completed),
    }


def prepare_full_regression_inputs(tmp_path: Path) -> dict[str, Path]:
    requirement_path = tmp_path / "requirement.md"
    requirement_path.write_text(REQUIREMENT, encoding="utf-8")
    click_requirement_path = tmp_path / "click-requirement.md"
    click_requirement_path.write_text(CLICK_REQUIREMENT, encoding="utf-8")
    click_response_requirement_path = tmp_path / "click-response-requirement.md"
    click_response_requirement_path.write_text(CLICK_RESPONSE_REQUIREMENT, encoding="utf-8")
    followup_requirement_path = tmp_path / "followup-requirement.md"
    followup_requirement_path.write_text(FOLLOWUP_REQUIREMENT, encoding="utf-8")
    async_followup_requirement_path = tmp_path / "async-followup-requirement.md"
    async_followup_requirement_path.write_text(ASYNC_FOLLOWUP_REQUIREMENT, encoding="utf-8")
    status_code_followup_requirement_path = tmp_path / "status-code-followup-requirement.md"
    status_code_followup_requirement_path.write_text(STATUS_CODE_FOLLOWUP_REQUIREMENT, encoding="utf-8")
    business_requirement_path = tmp_path / "business-requirement.md"
    business_requirement_path.write_text(BUSINESS_REQUIREMENT, encoding="utf-8")
    return {
        "requirement": requirement_path,
        "click": click_requirement_path,
        "click_response": click_response_requirement_path,
        "followup": followup_requirement_path,
        "async_followup": async_followup_requirement_path,
        "status_code_followup": status_code_followup_requirement_path,
        "business": business_requirement_path,
    }


def run_modeling_and_fixture_phase(
    script_dir: Path,
    tmp_path: Path,
    inputs: dict[str, Path],
    *,
    with_browser: bool,
) -> dict[str, bool]:
    browser_hit_test_checked = False
    request_absence_checked = False
    skipped_step_recording_checked = False
    probe_redaction_checked = False
    live_backtest_checked = False
    evidence_layer_gate_checked = False
    evidence_freshness_checked = False
    screenshot_integrity_checked = False
    text_artifact_assertions_checked = False
    json_artifact_assertions_checked = False
    api_body_defect_evidence_checked = False
    extraction_artifact_assertions_checked = False
    response_header_consistency_checked = False
    strategy_coverage_checked = False
    command_strategy_dimension_mapping_checked = False
    generated_requirement_strategy_suffix_checked = False
    current_run_required_checked = False
    secret_like_ledger_audit_checked = False
    evidence_disposition_gate_checked = False
    evidence_lineage_checked = False
    runner_result_binding_checked = False
    requirement_status_consistency_checked = False
    verdict_artifact_binding_checked = False
    report_input_errors_checked = False
    next_probe_input_errors_checked = False
    environment_boundary_checked = False
    agent_next_action_checked = False
    agent_loop_control_checked = False
    agent_preview_hash_binding_checked = False
    agent_pass_skips_preview_checked = False
    agent_product_defect_handoff_checked = False
    agent_initialization_failure_checked = False
    scaffold_input_errors_checked = False
    init_input_errors_checked = False
    init_adapter_context_input_errors_checked = False
    agent_snapshot_shape_checked = False
    cycle_terminal_cleanup_checked = False
    required_artifact_unreadable_checked = False
    adapter_context_unreadable_checked = False
    skip_probe_unreadable_results_checked = False
    preflight_handoff_checked = False
    service_start_next_action_checked = False
    authorized_service_start_checked = False
    agent_repeated_next_probe_stall_checked = False
    agent_runtime_autorecovery_checked = False
    api_next_probe_path_reuse_checked = False
    next_probe_scenario_step_binding_checked = False
    next_probe_lineage_gate_checked = False
    next_probe_generated_from_binding_checked = False
    next_probe_missing_generated_from_checked = False
    next_probe_generated_from_hash_checked = False
    next_probe_embedded_input_errors_checked = False
    runtime_failed_response_auth_guard_checked = False
    planning_handoff_checked = False
    requirement_coverage_input_errors_checked = False
    code_pr_scaffold_checked = False
    json_extension_api_path_checked = False
    graphql_root_endpoint_checked = False
    versioned_api_endpoint_checked = False
    cn_responsive_ui_context_checked = False
    stale_api_context_reset_checked = False
    same_route_ui_action_context_reset_checked = False
    unmapped_source_allow_gate_checked = False
    stale_scaffold_summary_refresh_checked = False
    analytics_semantic_layer_filter_checked = False
    adapter_probe_input_errors_checked = False
    preflight_input_errors_checked = False
    preflight_missing_required_service_checked = False
    generic_service_ids_checked = False
    preflight_local_dependency_checked = False
    preflight_command_prerequisite_checked = False
    command_project_root_cwd_checked = False
    service_runtime_input_errors_checked = False
    discover_project_context_input_errors_checked = False
    preflight_project_root_input_errors_checked = False
    plan_validation_input_errors_checked = False
    command_prerequisite_validation_checked = False
    storage_state_validation_checked = False
    auth_material_validation_checked = False
    audit_input_errors_checked = False
    defect_input_errors_checked = False
    next_probe_generation_input_errors_checked = False
    ledger_input_errors_checked = False
    audit_failure_handoff_checked = False
    helper_failure_handoff_checked = False
    helper_output_unreadable_checked = False
    business_model_checked = False
    oracle_model_checked = False
    qa_metrics_checked = False
    qa_metrics_definition_quality_checked = False
    gold_modeling_benchmark_checked = False
    semantic_report_checked = False
    semantic_artifact_refresh_checked = False
    semantic_report_guard_checked = False

    click_requirement_path = inputs["click"]
    business_requirement_path = inputs["business"]

    click_run_dir = tmp_path / "click-scaffold"
    run_cmd(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(click_requirement_path),
            "--run-dir",
            str(click_run_dir),
            "--base-url",
            "http://127.0.0.1:9527",
        ],
        cwd=tmp_path,
    )
    click_plan = load_json(click_run_dir / "test-plan.json")
    click_matrix = load_json(click_run_dir / "test-matrix.json")
    click_summary = load_json(click_run_dir / "scaffold-summary.json")
    click_steps = [
        step
        for scenario in click_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if step.get("action") == "expectClickable"
    ]
    blocked_interactions = [
        test
        for test in click_matrix.get("tests", [])
        if test.get("type") == "interaction" and test.get("status") == "Blocked"
    ]
    assert_true(click_summary.get("clickability_probe_count") == 1, "scaffold should create one concrete clickability probe.")
    assert_true(click_summary.get("blocked_clickability_test_count") == 1, "scaffold should block one unlocatable click target.")
    assert_true(len(click_steps) == 1 and click_steps[0].get("role") == "button" and click_steps[0].get("name") == "Save", "Save button should become an expectClickable role/name probe.")
    assert_true(len(blocked_interactions) == 1, "Unlabeled button click should remain a blocked interaction test.")

    business_run_dir = tmp_path / "business-scaffold"
    run_cmd(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(business_requirement_path),
            "--run-dir",
            str(business_run_dir),
            "--base-url",
            "http://127.0.0.1:9527",
            "--entry-path",
            "/orders",
        ],
        cwd=tmp_path,
    )
    business_plan = load_json(business_run_dir / "test-plan.json")
    business_matrix = load_json(business_run_dir / "test-matrix.json")
    business_summary = load_json(business_run_dir / "scaffold-summary.json")
    business_model = load_json(business_run_dir / "business-model.json")
    oracle_model = load_json(business_run_dir / "oracle-model.json")
    qa_metrics = load_json(business_run_dir / "qa-metrics.json")
    closeout_candidates = load_json(business_run_dir / "closeout-candidates.json")
    business_charter = (business_run_dir / "test-charter.md").read_text(encoding="utf-8")
    entity_names = {str(entity.get("name")).lower() for entity in business_model.get("entities", [])}
    actor_names = {str(actor.get("name")).lower() for actor in business_model.get("actors", [])}
    workflow_labels = " ".join(str(item.get("label", "")) for item in business_model.get("workflows", [])).lower()
    oracle_requirements = oracle_model.get("requirements", [])
    assert_true("order" in entity_names, "business model should extract the order entity.")
    assert_true(any("merchant" in name or "operator" in name for name in actor_names), "business model should extract the merchant/operator actor.")
    assert_true("approve" in workflow_labels, "business model should preserve the approval workflow intent.")
    assert_true(
        business_model.get("agent_team_contract", {}).get("qa_agent", {}).get("consumes"),
        "business model should expose a QA-facing agent-team contract.",
    )
    assert_true(
        business_model.get("source_bindings", {}).get("requirement", {}).get("sha256")
        and oracle_model.get("source_bindings", {}).get("matrix", {}).get("sha256")
        and qa_metrics.get("source_bindings", {}).get("plan", {}).get("sha256")
        and closeout_candidates.get("source_bindings", {}).get("oracle_model", {}).get("sha256"),
        "semantic artifacts should be source-hash bound so stale or fabricated planning artifacts can be detected.",
    )
    assert_true(
        len(oracle_requirements) == len(business_matrix.get("requirements", []))
        and all(item.get("required_evidence_layers") and item.get("pass_rule") for item in oracle_requirements),
        "oracle model should define a pass rule and evidence layers for every requirement.",
    )
    assert_true(
        business_plan.get("metadata", {}).get("businessModel") == "business-model.json"
        and business_plan.get("metadata", {}).get("oracleModel") == "oracle-model.json",
        "plan metadata should reference business and oracle models.",
    )
    assert_true(
        business_summary.get("business_model", {}).get("entity_count", 0) >= 1
        and qa_metrics.get("summary", {}).get("requirement_count") == len(business_matrix.get("requirements", [])),
        "scaffold summary and qa metrics should expose business-model and requirement counts.",
    )
    quality_scores = qa_metrics.get("quality_scores") or {}
    quality_targets = qa_metrics.get("quality_targets") or {}
    coverage_breakdown = qa_metrics.get("coverage_breakdown") or {}
    assert_true(
        quality_targets.get("target_percent") == 95.0
        and quality_scores.get("requirement_mapping_percent") == 100.0
        and quality_scores.get("source_mapped_coverage_percent") == 100.0
        and "executable_coverage_percent" in quality_scores
        and quality_scores.get("pass_claim_coverage_percent") is None
        and quality_scores.get("oracle_coverage_percent") == 100.0
        and quality_scores.get("business_modeling_proxy_percent", 0) >= 95.0,
        "qa metrics should expose 95%-targeted planning coverage/modeling quality scores.",
    )
    assert_true(
        coverage_breakdown.get("source_mapped", {}).get("semantics", "").startswith("planning coverage")
        and coverage_breakdown.get("executable", {}).get("semantics", "").startswith("planned executable")
        and coverage_breakdown.get("pass_claim", {}).get("status") == "not_evaluated",
        "qa metrics should split source-mapped, executable, and pass-claim coverage semantics.",
    )
    assert_true(
        closeout_candidates.get("human_confirmation_required") is True
        and "stable_knowledge_candidates" in closeout_candidates
        and "qa_process_improvement_candidates" in closeout_candidates,
        "closeout candidates should separate human-confirmed knowledge from process-improvement candidates.",
    )
    assert_true("## Business Intent Model" in business_charter and "## Oracle Model" in business_charter, "charter should render business and oracle sections.")
    business_model_checked = True
    oracle_model_checked = True
    qa_metrics_checked = True

    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(click_run_dir / "test-plan.json"),
            "--matrix",
            str(click_run_dir / "test-matrix.json"),
            "--summary",
            str(click_run_dir / "plan-audit-summary.json"),
        ],
        cwd=click_run_dir,
    )
    if with_browser:
        evidence_fixtures.run_browser_hit_test_fixture(script_dir, tmp_path)
        browser_hit_test_checked = True
        skipped_step_recording_checked = True
        evidence_fixtures.run_request_absence_fixture(script_dir, tmp_path)
        request_absence_checked = True
        evidence_fixtures.run_probe_redaction_fixture(script_dir, tmp_path)
        probe_redaction_checked = True
        evidence_fixtures.run_live_backtest_fixture(script_dir, tmp_path)
        live_backtest_checked = True
    evidence_fixtures.run_evidence_layer_gate_fixture(script_dir, tmp_path)
    evidence_layer_gate_checked = True
    evidence_fixtures.run_evidence_freshness_fixture(script_dir, tmp_path)
    evidence_freshness_checked = True
    evidence_fixtures.run_screenshot_integrity_fixture(script_dir, tmp_path)
    screenshot_integrity_checked = True
    evidence_fixtures.run_text_artifact_assertion_fixture(script_dir, tmp_path)
    text_artifact_assertions_checked = True
    evidence_fixtures.run_json_artifact_assertion_fixture(script_dir, tmp_path)
    json_artifact_assertions_checked = True
    evidence_fixtures.run_api_body_defect_evidence_fixture(script_dir, tmp_path)
    api_body_defect_evidence_checked = True
    evidence_fixtures.run_extraction_artifact_assertion_fixture(script_dir, tmp_path)
    extraction_artifact_assertions_checked = True
    evidence_fixtures.run_response_header_consistency_fixture(script_dir, tmp_path)
    response_header_consistency_checked = True
    evidence_fixtures.run_strategy_coverage_fixture(script_dir, tmp_path)
    strategy_coverage_checked = True
    evidence_fixtures.run_command_strategy_dimension_mapping_fixture(script_dir, tmp_path)
    command_strategy_dimension_mapping_checked = True
    evidence_fixtures.run_generated_requirement_strategy_suffix_fixture(script_dir, tmp_path)
    generated_requirement_strategy_suffix_checked = True
    evidence_fixtures.run_current_run_required_fixture(script_dir, tmp_path)
    current_run_required_checked = True
    evidence_fixtures.run_secret_like_ledger_audit_fixture(script_dir, tmp_path)
    secret_like_ledger_audit_checked = True
    evidence_fixtures.run_evidence_disposition_gate_fixture(script_dir, tmp_path)
    evidence_disposition_gate_checked = True
    evidence_fixtures.run_evidence_lineage_fixture(script_dir, tmp_path)
    evidence_lineage_checked = True
    evidence_fixtures.run_runner_result_binding_fixture(script_dir, tmp_path)
    runner_result_binding_checked = True
    evidence_fixtures.run_requirement_status_consistency_fixture(script_dir, tmp_path)
    requirement_status_consistency_checked = True
    evidence_fixtures.run_verdict_artifact_binding_fixture(script_dir, tmp_path)
    verdict_artifact_binding_checked = True
    evidence_fixtures.run_report_input_error_fixture(script_dir, tmp_path)
    report_input_errors_checked = True
    evidence_fixtures.run_next_probe_input_error_fixture(script_dir, tmp_path)
    next_probe_input_errors_checked = True
    evidence_fixtures.run_environment_boundary_fixture(script_dir, tmp_path)
    environment_boundary_checked = True
    agent_fixtures.run_agent_next_action_fixture(script_dir, tmp_path)
    agent_next_action_checked = True
    agent_loop_control_checked = True
    agent_fixtures.run_agent_preview_hash_binding_fixture(script_dir, tmp_path)
    agent_preview_hash_binding_checked = True
    agent_fixtures.run_agent_pass_skips_preview_fixture(script_dir, tmp_path)
    agent_pass_skips_preview_checked = True
    agent_fixtures.run_agent_product_defect_handoff_fixture(script_dir, tmp_path)
    agent_product_defect_handoff_checked = True
    agent_fixtures.run_agent_initialization_failure_fixture(script_dir, tmp_path)
    agent_initialization_failure_checked = True
    agent_fixtures.run_scaffold_input_error_fixture(script_dir, tmp_path)
    scaffold_input_errors_checked = True
    agent_fixtures.run_init_input_error_fixture(script_dir, tmp_path)
    init_input_errors_checked = True
    agent_fixtures.run_init_adapter_context_input_error_fixture(script_dir, tmp_path)
    init_adapter_context_input_errors_checked = True
    agent_fixtures.run_agent_snapshot_shape_fixture(script_dir, tmp_path)
    agent_snapshot_shape_checked = True
    agent_fixtures.run_cycle_terminal_cleanup_fixture(script_dir, tmp_path)
    cycle_terminal_cleanup_checked = True
    agent_fixtures.run_required_artifact_unreadable_fixture(script_dir, tmp_path)
    required_artifact_unreadable_checked = True
    agent_fixtures.run_adapter_context_unreadable_fixture(script_dir, tmp_path)
    adapter_context_unreadable_checked = True
    agent_fixtures.run_skip_probe_unreadable_results_fixture(script_dir, tmp_path)
    skip_probe_unreadable_results_checked = True
    agent_fixtures.run_preflight_blocker_handoff_fixture(script_dir, tmp_path)
    preflight_handoff_checked = True
    agent_fixtures.run_agent_service_start_next_action_fixture(script_dir, tmp_path)
    service_start_next_action_checked = True
    agent_fixtures.run_agent_authorized_service_start_fixture(script_dir, tmp_path)
    authorized_service_start_checked = True
    agent_fixtures.run_agent_repeated_next_probe_stall_fixture(script_dir, tmp_path)
    agent_repeated_next_probe_stall_checked = True
    agent_fixtures.run_agent_runtime_autorecovery_fixture(script_dir, tmp_path)
    agent_runtime_autorecovery_checked = True
    agent_fixtures.run_api_next_probe_path_reuse_fixture(script_dir, tmp_path)
    api_next_probe_path_reuse_checked = True
    agent_fixtures.run_next_probe_scenario_step_binding_fixture(script_dir, tmp_path)
    next_probe_scenario_step_binding_checked = True
    agent_fixtures.run_next_probe_lineage_gate_fixture(script_dir, tmp_path)
    next_probe_lineage_gate_checked = True
    agent_fixtures.run_next_probe_generated_from_binding_fixture(script_dir, tmp_path)
    next_probe_generated_from_binding_checked = True
    agent_fixtures.run_next_probe_missing_generated_from_fixture(script_dir, tmp_path)
    next_probe_missing_generated_from_checked = True
    agent_fixtures.run_next_probe_generated_from_hash_fixture(script_dir, tmp_path)
    next_probe_generated_from_hash_checked = True
    agent_fixtures.run_next_probe_embedded_input_error_fixture(script_dir, tmp_path)
    next_probe_embedded_input_errors_checked = True
    agent_fixtures.run_runtime_failed_response_auth_guard_fixture(script_dir, tmp_path)
    runtime_failed_response_auth_guard_checked = True
    agent_fixtures.run_planning_blocker_handoff_fixture(script_dir, tmp_path)
    planning_handoff_checked = True
    contract_fixtures.run_requirement_coverage_input_error_fixture(script_dir, tmp_path)
    requirement_coverage_input_errors_checked = True
    contract_fixtures.run_code_pr_scaffold_fixture(script_dir, tmp_path)
    code_pr_scaffold_checked = True
    contract_fixtures.run_json_extension_api_path_fixture(script_dir, tmp_path)
    json_extension_api_path_checked = True
    contract_fixtures.run_graphql_root_endpoint_fixture(script_dir, tmp_path)
    graphql_root_endpoint_checked = True
    contract_fixtures.run_versioned_api_endpoint_fixture(script_dir, tmp_path)
    versioned_api_endpoint_checked = True
    contract_fixtures.run_cn_responsive_ui_context_fixture(script_dir, tmp_path)
    cn_responsive_ui_context_checked = True
    contract_fixtures.run_stale_api_context_reset_fixture(script_dir, tmp_path)
    stale_api_context_reset_checked = True
    contract_fixtures.run_same_route_ui_action_context_reset_fixture(script_dir, tmp_path)
    same_route_ui_action_context_reset_checked = True
    contract_fixtures.run_qa_metrics_definition_quality_fixture(script_dir, tmp_path)
    qa_metrics_definition_quality_checked = True
    contract_fixtures.run_gold_modeling_benchmark_fixture(script_dir, tmp_path)
    gold_modeling_benchmark_checked = True
    contract_fixtures.run_unmapped_source_allow_gate_fixture(script_dir, tmp_path)
    unmapped_source_allow_gate_checked = True
    contract_fixtures.run_stale_scaffold_summary_refresh_fixture(script_dir, tmp_path)
    stale_scaffold_summary_refresh_checked = True
    contract_fixtures.run_analytics_semantic_layer_filter_fixture(script_dir, tmp_path)
    analytics_semantic_layer_filter_checked = True
    contract_fixtures.run_adapter_probe_input_error_fixture(script_dir, tmp_path)
    adapter_probe_input_errors_checked = True
    contract_fixtures.run_preflight_input_error_fixture(script_dir, tmp_path)
    preflight_input_errors_checked = True
    contract_fixtures.run_preflight_missing_required_service_fixture(script_dir, tmp_path)
    preflight_missing_required_service_checked = True
    contract_fixtures.run_generic_service_id_and_preflight_dependency_fixture(script_dir, tmp_path)
    generic_service_ids_checked = True
    preflight_local_dependency_checked = True
    contract_fixtures.run_preflight_command_prerequisite_fixture(script_dir, tmp_path)
    preflight_command_prerequisite_checked = True
    contract_fixtures.run_command_project_root_cwd_fixture(script_dir, tmp_path)
    command_project_root_cwd_checked = True
    contract_fixtures.run_service_runtime_input_error_fixture(script_dir, tmp_path)
    service_runtime_input_errors_checked = True
    contract_fixtures.run_discover_project_context_input_error_fixture(script_dir, tmp_path)
    discover_project_context_input_errors_checked = True
    contract_fixtures.run_preflight_project_root_input_error_fixture(script_dir, tmp_path)
    preflight_project_root_input_errors_checked = True
    agent_fixtures.run_plan_validation_input_error_fixture(script_dir, tmp_path)
    plan_validation_input_errors_checked = True
    contract_fixtures.run_command_prerequisite_validation_fixture(script_dir, tmp_path)
    command_prerequisite_validation_checked = True
    contract_fixtures.run_storage_state_validation_fixture(script_dir, tmp_path)
    storage_state_validation_checked = True
    auth_material_validation_checked = True
    contract_fixtures.run_audit_input_error_fixture(script_dir, tmp_path)
    audit_input_errors_checked = True
    contract_fixtures.run_defect_input_error_fixture(script_dir, tmp_path)
    defect_input_errors_checked = True
    contract_fixtures.run_next_probe_generation_input_error_fixture(script_dir, tmp_path)
    next_probe_generation_input_errors_checked = True
    contract_fixtures.run_ledger_input_error_fixture(script_dir, tmp_path)
    ledger_input_errors_checked = True
    contract_fixtures.run_audit_failure_handoff_fixture(script_dir, tmp_path)
    audit_failure_handoff_checked = True
    contract_fixtures.run_helper_failure_handoff_fixture(script_dir, tmp_path)
    helper_failure_handoff_checked = True
    contract_fixtures.run_helper_output_unreadable_fixture(script_dir, tmp_path)
    helper_output_unreadable_checked = True
    return {name: value for name, value in locals().items() if name.endswith("_checked")}


def run_interaction_flow_phase(script_dir: Path, tmp_path: Path, inputs: dict[str, Path]) -> None:
    click_response_requirement_path = inputs["click_response"]
    followup_requirement_path = inputs["followup"]
    async_followup_requirement_path = inputs["async_followup"]
    status_code_followup_requirement_path = inputs["status_code_followup"]

    click_response_blocked_dir = tmp_path / "click-response-scaffold-blocked"
    run_cmd(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(click_response_requirement_path),
            "--run-dir",
            str(click_response_blocked_dir),
            "--base-url",
            "http://127.0.0.1:9527",
        ],
        cwd=tmp_path,
    )
    blocked_response_plan = load_json(click_response_blocked_dir / "test-plan.json")
    blocked_response_matrix = load_json(click_response_blocked_dir / "test-matrix.json")
    blocked_response_summary = load_json(click_response_blocked_dir / "scaffold-summary.json")
    blocked_response_steps = [
        step
        for scenario in blocked_response_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
    ]
    assert_true(blocked_response_summary.get("click_response_probe_count") == 0, "unsafe mutating click-to-response should not become executable by default.")
    assert_true(blocked_response_summary.get("blocked_click_response_test_count") == 1, "unsafe mutating click-to-response should be blocked by default.")
    assert_true(not any(step.get("action") == "api" for step in blocked_response_steps), "click-to-response requirements should not create redundant direct API probes.")
    assert_true(any(test.get("type") == "ui_to_api" and test.get("status") == "Blocked" for test in blocked_response_matrix.get("tests", [])), "blocked click-to-response test should remain in the matrix.")
    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(click_response_blocked_dir / "test-plan.json"),
            "--matrix",
            str(click_response_blocked_dir / "test-matrix.json"),
            "--summary",
            str(click_response_blocked_dir / "plan-audit-summary.json"),
        ],
        cwd=click_response_blocked_dir,
    )

    click_response_allowed_dir = tmp_path / "click-response-scaffold-allowed"
    run_cmd(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(click_response_requirement_path),
            "--run-dir",
            str(click_response_allowed_dir),
            "--base-url",
            "http://127.0.0.1:9527",
            "--allow-mutating-api",
        ],
        cwd=tmp_path,
    )
    allowed_response_plan = load_json(click_response_allowed_dir / "test-plan.json")
    allowed_response_summary = load_json(click_response_allowed_dir / "scaffold-summary.json")
    allowed_response_steps = [
        step
        for scenario in allowed_response_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
    ]
    click_response_steps = [step for step in allowed_response_steps if step.get("action") == "clickAndWaitForResponse"]
    assert_true(allowed_response_summary.get("click_response_probe_count") == 1, "authorized click-to-response should create one executable probe.")
    assert_true(allowed_response_summary.get("blocked_click_response_test_count") == 0, "authorized click-to-response should not stay blocked.")
    assert_true(len(click_response_steps) == 1, "authorized scaffold should emit exactly one clickAndWaitForResponse step.")
    assert_true(click_response_steps[0].get("method") == "POST" and click_response_steps[0].get("responseUrlContains") == "/api/v1/settings", "click-to-response step should preserve method and response path.")
    assert_true(not any(step.get("action") == "api" for step in allowed_response_steps), "authorized click-to-response should avoid redundant direct API probe.")
    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(click_response_allowed_dir / "test-plan.json"),
            "--matrix",
            str(click_response_allowed_dir / "test-matrix.json"),
            "--summary",
            str(click_response_allowed_dir / "plan-audit-summary.json"),
        ],
        cwd=click_response_allowed_dir,
    )

    followup_dir = tmp_path / "followup-scaffold"
    run_cmd(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(followup_requirement_path),
            "--run-dir",
            str(followup_dir),
            "--base-url",
            "http://127.0.0.1:9527",
            "--allow-mutating-api",
        ],
        cwd=tmp_path,
    )
    followup_plan = load_json(followup_dir / "test-plan.json")
    followup_summary = load_json(followup_dir / "scaffold-summary.json")
    followup_steps = [
        step
        for scenario in followup_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
    ]
    followup_click_steps = [step for step in followup_steps if step.get("action") == "clickAndWaitForResponse"]
    followup_api_steps = [step for step in followup_steps if step.get("action") == "api" and step.get("pathTemplate")]
    followup_cleanup_steps = [step for step in followup_steps if step.get("action") == "cleanupApi"]
    assert_true(followup_summary.get("followup_api_probe_count") == 1, "same-object follow-up should create one pathTemplate API probe.")
    assert_true(followup_summary.get("cleanup_api_probe_count") == 1, "authorized create follow-up should create one cleanupApi probe.")
    assert_true(len(followup_click_steps) == 1, "same-object follow-up should keep one click-to-response producer.")
    assert_true(followup_click_steps[0].get("extractJson", {}).get("id", {}).get("paths") == ["id", "data.id", "result.id"], "producer should extract id from candidate JSON paths.")
    assert_true(len(followup_api_steps) == 1 and followup_api_steps[0].get("method") == "GET" and followup_api_steps[0].get("pathTemplate") == "/api/v1/items/{id}", "follow-up API should use the GET placeholder path template.")
    assert_true(
        len(followup_cleanup_steps) == 1
        and followup_cleanup_steps[0].get("method") == "DELETE"
        and followup_cleanup_steps[0].get("pathTemplate") == "/api/v1/items/{id}"
        and followup_cleanup_steps[0].get("alwaysRun") is True
        and followup_cleanup_steps[0].get("skipIfMissingVars") is True
        and followup_cleanup_steps[0].get("expectStatusAny") == [200, 202, 204, 404],
        "cleanupApi should use the extracted id, run always, and accept bounded cleanup statuses.",
    )
    assert_true(
        followup_api_steps[0].get("expectJsonAny") == [
            {"id": {"var": "id"}},
            {"data.id": {"var": "id"}},
            {"result.id": {"var": "id"}},
        ],
        "follow-up API should assert the response body contains the same extracted id.",
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(followup_dir / "test-plan.json"),
            "--matrix",
            str(followup_dir / "test-matrix.json"),
            "--summary",
            str(followup_dir / "plan-audit-summary.json"),
        ],
        cwd=followup_dir,
    )

    async_followup_dir = tmp_path / "async-followup-scaffold"
    run_cmd(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(async_followup_requirement_path),
            "--run-dir",
            str(async_followup_dir),
            "--base-url",
            "http://127.0.0.1:9527",
            "--allow-mutating-api",
        ],
        cwd=tmp_path,
    )
    async_followup_plan = load_json(async_followup_dir / "test-plan.json")
    async_followup_summary = load_json(async_followup_dir / "scaffold-summary.json")
    async_followup_steps = [
        step
        for scenario in async_followup_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
    ]
    poll_steps = [step for step in async_followup_steps if step.get("action") == "pollApi"]
    assert_true(async_followup_summary.get("poll_api_probe_count") == 1, "async same-object follow-up should create one pollApi probe.")
    assert_true(async_followup_summary.get("cleanup_api_probe_count") == 1, "async authorized create follow-up should also create cleanupApi.")
    assert_true(len(poll_steps) == 1 and poll_steps[0].get("pathTemplate") == "/api/v1/jobs/{job_id}", "async follow-up should poll the placeholder detail path.")
    assert_true(
        {"job_id": {"var": "job_id"}, "status": "completed"} in poll_steps[0].get("expectJsonAny", []),
        "pollApi should assert both same-object id and completed status.",
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(async_followup_dir / "test-plan.json"),
            "--matrix",
            str(async_followup_dir / "test-matrix.json"),
            "--summary",
            str(async_followup_dir / "plan-audit-summary.json"),
        ],
        cwd=async_followup_dir,
    )

    status_code_followup_dir = tmp_path / "status-code-followup-scaffold"
    run_cmd(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(status_code_followup_requirement_path),
            "--run-dir",
            str(status_code_followup_dir),
            "--base-url",
            "http://127.0.0.1:9527",
            "--allow-mutating-api",
        ],
        cwd=tmp_path,
    )
    status_code_followup_plan = load_json(status_code_followup_dir / "test-plan.json")
    status_code_followup_steps = [
        step
        for scenario in status_code_followup_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
    ]
    create_status_steps = [
        step
        for step in status_code_followup_steps
        if step.get("action") == "clickAndWaitForResponse"
        and step.get("method") == "POST"
        and step.get("responseUrlContains") == "/api/v1/widgets"
    ]
    read_status_steps = [
        step
        for step in status_code_followup_steps
        if step.get("action") == "api"
        and step.get("method") == "GET"
        and step.get("pathTemplate") == "/api/v1/widgets/{id}"
    ]
    delete_status_steps = [
        step
        for step in status_code_followup_steps
        if step.get("action") == "clickAndWaitForResponse"
        and step.get("method") == "DELETE"
        and step.get("responseUrlContains") == "/api/v1/widgets/widget_123"
    ]
    assert_true(len(create_status_steps) == 1, "status-code follow-up should create one POST producer click response.")
    assert_true(create_status_steps[0].get("expectStatus") == 201, "POST producer should preserve explicit 201 Created expectation.")
    assert_true(create_status_steps[0].get("extractJson", {}).get("id", {}).get("paths") == ["id", "data.id", "result.id"], "201 producer should still extract id from the response.")
    assert_true(len(read_status_steps) == 1 and read_status_steps[0].get("expectStatus") == 200, "same-object GET follow-up should preserve explicit 200 OK expectation.")
    assert_true(len(delete_status_steps) == 1 and delete_status_steps[0].get("expectStatus") == 204, "DELETE click-to-response should preserve explicit 204 No Content expectation.")
    status_code_followup_coverage_path = status_code_followup_dir / "requirement-coverage.json"
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(status_code_followup_dir / "requirement.md"),
            "--matrix",
            str(status_code_followup_dir / "test-matrix.json"),
            "--out",
            str(status_code_followup_coverage_path),
        ],
        cwd=status_code_followup_dir,
    )
    status_code_followup_coverage = load_json(status_code_followup_coverage_path)
    assert_true(status_code_followup_coverage.get("requirement_unit_count") == 5, "status-code follow-up requirement should split UI, 201 create, 200 read, UI delete, and 204 delete clauses.")
    assert_true(status_code_followup_coverage.get("covered_count") == 5, "status-code follow-up scaffold should cover all split source units.")
    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(status_code_followup_dir / "test-plan.json"),
            "--matrix",
            str(status_code_followup_dir / "test-matrix.json"),
            "--summary",
            str(status_code_followup_dir / "plan-audit-summary.json"),
        ],
        cwd=status_code_followup_dir,
    )

    response_run_dir = tmp_path / "click-response"
    (response_run_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (response_run_dir / "evidence" / "click-response-body.json").write_text('{"ok":true}\n', encoding="utf-8")
    write_json(
        response_run_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "fixture",
                    "text": "Clicking Save triggers a successful settings API response.",
                    "test_ids": ["T1"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "ui_to_api",
                    "steps": ["Click Save and capture the settings API response."],
                    "expected": "The click triggers POST /api/v1/settings and returns ok=true.",
                    "required_evidence": ["ui_to_api", "HTTP status", "checked JSON"],
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        response_run_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(response_run_dir),
            "scenarios": [
                {
                    "id": "click-response",
                    "steps": [
                        {
                            "action": "clickAndWaitForResponse",
                            "id": "T1-save-response",
                            "testIds": ["T1"],
                            "requirementIds": ["R1"],
                            "role": "button",
                            "name": "Save",
                            "method": "POST",
                            "responseUrlContains": "/api/v1/settings",
                            "expectStatus": 200,
                            "expectJson": {"ok": True},
                            "evidenceType": "ui_to_api",
                            "proves": "Clicking Save triggers the settings API and returns ok=true.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        response_run_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "artifactDir": str(response_run_dir),
            "scenarios": [
                {
                    "id": "click-response",
                    "status": "passed",
                    "steps": [
                        {
                            "scenarioId": "click-response",
                            "stepId": "T1-save-response",
                            "testIds": ["T1"],
                            "requirementIds": ["R1"],
                            "action": "clickAndWaitForResponse",
                            "status": "passed",
                            "evidenceType": "ui_to_api",
                            "proves": "Clicking Save triggers the settings API and returns ok=true.",
                            "pageUrl": "http://127.0.0.1:9527/settings",
                            "locator": "role=button name=Save",
                            "method": "POST",
                            "url": "http://127.0.0.1:9527/api/v1/settings",
                            "statusCode": 200,
                            "bodyPath": str(response_run_dir / "evidence" / "click-response-body.json"),
                            "responseAfterClick": True,
                            "checkedJson": {"ok": True},
                            "hitTest": {
                                "receivesPointerEvents": True,
                                "disabled": False,
                                "ariaDisabled": False,
                                "inert": False,
                                "actionability": "trial-click-passed",
                            },
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(response_run_dir / "test-plan.json"),
            "--matrix",
            str(response_run_dir / "test-matrix.json"),
            "--summary",
            str(response_run_dir / "plan-audit-summary.json"),
        ],
        cwd=response_run_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "ledger_from_probe.py"),
            "--matrix",
            str(response_run_dir / "test-matrix.json"),
            "--results",
            str(response_run_dir / "results.json"),
            "--out",
            str(response_run_dir / "evidence-ledger.json"),
        ],
        cwd=response_run_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(response_run_dir / "test-matrix.json"),
            "--results",
            str(response_run_dir / "results.json"),
            "--ledger",
            str(response_run_dir / "evidence-ledger.json"),
            "--summary",
            str(response_run_dir / "audit-summary.json"),
        ],
        cwd=response_run_dir,
    )
    response_ledger = load_json(response_run_dir / "evidence-ledger.json")
    response_audit = load_json(response_run_dir / "audit-summary.json")
    response_evidence = response_ledger.get("evidence", [{}])[0]
    assert_true(response_audit.get("passed") is True, "click-to-response evidence should pass ledger audit.")
    assert_true(response_ledger.get("requirements", [{}])[0].get("status") == "Passed", "click-to-response requirement should be passed by fixture evidence.")
    assert_true(response_evidence.get("type") == "ui_to_api" and response_evidence.get("response_after_click") is True, "click-to-response evidence should preserve ui_to_api response_after_click.")


def run_evidence_flow_phase(script_dir: Path, tmp_path: Path) -> None:
    cleanup_run_dir = tmp_path / "cleanup-ledger"
    write_json(
        cleanup_run_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-clean",
                    "source": "fixture",
                    "text": "Created test data must be cleaned up.",
                    "test_ids": ["T-clean"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-clean",
                    "requirement_ids": ["R-clean"],
                    "type": "cleanup",
                    "steps": ["Delete the runtime object created by the test."],
                    "expected": "DELETE /api/v1/items/{id} returns an accepted cleanup status.",
                    "required_evidence": ["cleanup HTTP status"],
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        cleanup_run_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(cleanup_run_dir),
            "scenarios": [
                {
                    "id": "cleanup",
                    "steps": [
                        {
                            "action": "cleanupApi",
                            "id": "T-clean-cleanup",
                            "testIds": ["T-clean"],
                            "requirementIds": ["R-clean"],
                            "method": "DELETE",
                            "pathTemplate": "/api/v1/items/{id}",
                            "expectStatusAny": [200, 202, 204, 404],
                            "alwaysRun": True,
                            "skipIfMissingVars": True,
                            "evidenceType": "cleanup",
                            "proves": "The runtime item is removed or already absent.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        cleanup_run_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "artifactDir": str(cleanup_run_dir),
            "scenarios": [
                {
                    "id": "cleanup",
                    "status": "passed",
                    "steps": [
                        {
                            "scenarioId": "cleanup",
                            "stepId": "T-clean-cleanup",
                            "testIds": ["T-clean"],
                            "requirementIds": ["R-clean"],
                            "action": "cleanupApi",
                            "status": "passed",
                            "evidenceType": "cleanup",
                            "proves": "The runtime item is removed or already absent.",
                            "method": "DELETE",
                            "url": "http://127.0.0.1:9527/api/v1/items/item-1",
                            "statusCode": 204,
                            "cleanupAttempted": True,
                            "expectedStatusAny": [200, 202, 204, 404],
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(cleanup_run_dir / "test-plan.json"),
            "--matrix",
            str(cleanup_run_dir / "test-matrix.json"),
            "--summary",
            str(cleanup_run_dir / "plan-audit-summary.json"),
        ],
        cwd=cleanup_run_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "ledger_from_probe.py"),
            "--matrix",
            str(cleanup_run_dir / "test-matrix.json"),
            "--results",
            str(cleanup_run_dir / "results.json"),
            "--out",
            str(cleanup_run_dir / "evidence-ledger.json"),
        ],
        cwd=cleanup_run_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(cleanup_run_dir / "test-matrix.json"),
            "--results",
            str(cleanup_run_dir / "results.json"),
            "--ledger",
            str(cleanup_run_dir / "evidence-ledger.json"),
            "--summary",
            str(cleanup_run_dir / "audit-summary.json"),
        ],
        cwd=cleanup_run_dir,
    )
    cleanup_ledger = load_json(cleanup_run_dir / "evidence-ledger.json")
    cleanup_audit = load_json(cleanup_run_dir / "audit-summary.json")
    cleanup_evidence = cleanup_ledger.get("evidence", [{}])[0]
    assert_true(cleanup_audit.get("passed") is True, "cleanup evidence should pass ledger audit.")
    assert_true(cleanup_ledger.get("requirements", [{}])[0].get("status") == "Passed", "cleanup requirement should pass when cleanupApi records status evidence.")
    assert_true(cleanup_evidence.get("type") == "cleanup" and cleanup_evidence.get("cleanup_attempted") is True, "cleanup evidence should preserve cleanup type and attempt flag.")

    marker_run_dir = tmp_path / "current-run-marker"
    write_json(
        marker_run_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-marker",
                    "source": "fixture",
                    "text": "The response must contain the current-run marker.",
                    "test_ids": ["T-marker"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-marker",
                    "requirement_ids": ["R-marker"],
                    "type": "api",
                    "steps": ["Send a unique marker and assert it returns in the response."],
                    "expected": "The API response includes qa_marker from this run.",
                    "required_evidence": ["current-run marker", "HTTP status", "checked JSON"],
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        marker_run_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(marker_run_dir),
            "scenarios": [
                {
                    "id": "marker",
                    "steps": [
                        {
                            "action": "api",
                            "id": "T-marker-api",
                            "testIds": ["T-marker"],
                            "requirementIds": ["R-marker"],
                            "method": "POST",
                            "path": "/api/v1/echo",
                            "json": {"message": {"template": "probe {qa_marker}"}},
                            "expectStatus": 200,
                            "expectRequestTextContains": {"var": "qa_marker"},
                            "expectRequestJson": {"message": {"op": "contains", "value": {"var": "qa_marker"}}},
                            "expectJson": {"reply": {"op": "contains", "value": {"var": "qa_marker"}}},
                            "captureRequestBody": True,
                            "captureBody": True,
                            "evidenceType": "api_response",
                            "proves": "The response contains the current-run marker rather than stale data.",
                        }
                    ],
                }
            ],
        },
    )
    marker_request_body_path = marker_run_dir / "evidence" / "marker-request-body.txt"
    marker_response_body_path = marker_run_dir / "evidence" / "marker-response-body.txt"
    marker_request_body_path.parent.mkdir(parents=True, exist_ok=True)
    marker_request_body_path.write_text('{"message":"probe QA_MARKER_qa_fixture"}', encoding="utf-8")
    marker_response_body_path.write_text('{"reply":"echo QA_MARKER_qa_fixture"}', encoding="utf-8")
    write_json(
        marker_run_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "artifactDir": str(marker_run_dir),
            "run": {
                "qaRunId": "qa_fixture",
                "qaMarker": "QA_MARKER_qa_fixture",
                "runtimeVarNames": ["qa_marker", "qa_run_id", "qa_started_at"],
            },
            "scenarios": [
                {
                    "id": "marker",
                    "status": "passed",
                    "steps": [
                        {
                            "scenarioId": "marker",
                            "stepId": "T-marker-api",
                            "testIds": ["T-marker"],
                            "requirementIds": ["R-marker"],
                            "action": "api",
                            "status": "passed",
                            "evidenceType": "api_response",
                            "proves": "The response contains the current-run marker rather than stale data.",
                            "method": "POST",
                            "url": "http://127.0.0.1:9527/api/v1/echo",
                            "statusCode": 200,
                            "requestBodyCaptured": True,
                            "requestBodyPreview": '{"message":"probe QA_MARKER_qa_fixture"}',
                            "requestBodyPath": str(marker_request_body_path),
                            "bodyPath": str(marker_response_body_path),
                            "requestTextContainsMatched": "QA_MARKER_qa_fixture",
                            "checkedRequestJson": {"message": "probe QA_MARKER_qa_fixture"},
                            "checkedJson": {"reply": "echo QA_MARKER_qa_fixture"},
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(marker_run_dir / "test-plan.json"),
            "--matrix",
            str(marker_run_dir / "test-matrix.json"),
            "--summary",
            str(marker_run_dir / "plan-audit-summary.json"),
        ],
        cwd=marker_run_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "ledger_from_probe.py"),
            "--matrix",
            str(marker_run_dir / "test-matrix.json"),
            "--results",
            str(marker_run_dir / "results.json"),
            "--out",
            str(marker_run_dir / "evidence-ledger.json"),
        ],
        cwd=marker_run_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(marker_run_dir / "test-matrix.json"),
            "--results",
            str(marker_run_dir / "results.json"),
            "--ledger",
            str(marker_run_dir / "evidence-ledger.json"),
            "--summary",
            str(marker_run_dir / "audit-summary.json"),
        ],
        cwd=marker_run_dir,
    )
    marker_ledger = load_json(marker_run_dir / "evidence-ledger.json")
    marker_audit = load_json(marker_run_dir / "audit-summary.json")
    marker_evidence = marker_ledger.get("evidence", [{}])[0]
    assert_true(marker_audit.get("passed") is True, "current-run marker evidence should pass ledger audit.")
    assert_true(marker_ledger.get("runtime_summary", {}).get("qa_marker") == "QA_MARKER_qa_fixture", "ledger should preserve qa_marker in runtime summary.")
    assert_true(marker_evidence.get("request_body_captured") is True and "QA_MARKER_qa_fixture" in marker_evidence.get("request_body_preview", ""), "marker evidence should preserve request-body marker proof.")
    assert_true(marker_evidence.get("request_text_contains_matched") == "QA_MARKER_qa_fixture", "marker evidence should preserve request text assertion.")
    assert_true(marker_evidence.get("checked_request_json", {}).get("message") == "probe QA_MARKER_qa_fixture", "marker evidence should preserve checked request JSON assertion.")
    assert_true(marker_ledger.get("requirements", [{}])[0].get("status") == "Passed", "marker requirement should pass with checked current-run evidence.")

    response_header_dir = tmp_path / "response-header-ledger"
    write_json(
        response_header_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-trace-header",
                    "source": "fixture",
                    "text": "The API response must expose an auditable trace header.",
                    "test_ids": ["T-trace-header"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-trace-header",
                    "requirement_ids": ["R-trace-header"],
                    "type": "api",
                    "steps": ["Call the API and assert content-type plus trace response headers."],
                    "expected": "The response has a JSON content type and trace id header.",
                    "required_evidence": ["HTTP status", "response headers", "extracted trace id"],
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        response_header_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(response_header_dir),
            "scenarios": [
                {
                    "id": "trace-header",
                    "steps": [
                        {
                            "action": "api",
                            "id": "T-trace-header-api",
                            "testIds": ["T-trace-header"],
                            "requirementIds": ["R-trace-header"],
                            "method": "GET",
                            "path": "/api/v1/trace",
                            "expectStatus": 200,
                            "expectResponseHeader": {"content-type": {"op": "contains", "value": "application/json"}},
                            "expectResponseHeaderContains": {"x-trace-id": "trace-"},
                            "expectResponseHeaderMatches": {"x-trace-id": "^trace-[a-z0-9-]+$"},
                            "extractResponseHeader": {"trace_id": "x-trace-id"},
                            "captureResponseHeaders": True,
                            "evidenceType": "api_response",
                            "proves": "The API response exposes a JSON content type and trace header for this request.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        response_header_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "artifactDir": str(response_header_dir),
            "scenarios": [
                {
                    "id": "trace-header",
                    "status": "passed",
                    "steps": [
                        {
                            "scenarioId": "trace-header",
                            "stepId": "T-trace-header-api",
                            "testIds": ["T-trace-header"],
                            "requirementIds": ["R-trace-header"],
                            "action": "api",
                            "status": "passed",
                            "evidenceType": "api_response",
                            "proves": "The API response exposes a JSON content type and trace header for this request.",
                            "method": "GET",
                            "url": "http://127.0.0.1:9527/api/v1/trace",
                            "statusCode": 200,
                            "responseHeaders": {
                                "content-type": "application/json; charset=utf-8",
                                "x-trace-id": "trace-qa-fixture",
                            },
                            "checkedResponseHeaders": {
                                "content-type": "application/json; charset=utf-8",
                                "x-trace-id": "trace-qa-fixture",
                            },
                            "extractedResponseHeaders": {"trace_id": "trace-qa-fixture"},
                            "extractedResponseHeaderNames": {"trace_id": "x-trace-id"},
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(response_header_dir / "test-plan.json"),
            "--matrix",
            str(response_header_dir / "test-matrix.json"),
            "--summary",
            str(response_header_dir / "plan-audit-summary.json"),
        ],
        cwd=response_header_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "ledger_from_probe.py"),
            "--matrix",
            str(response_header_dir / "test-matrix.json"),
            "--results",
            str(response_header_dir / "results.json"),
            "--out",
            str(response_header_dir / "evidence-ledger.json"),
        ],
        cwd=response_header_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(response_header_dir / "test-matrix.json"),
            "--results",
            str(response_header_dir / "results.json"),
            "--ledger",
            str(response_header_dir / "evidence-ledger.json"),
            "--summary",
            str(response_header_dir / "audit-summary.json"),
        ],
        cwd=response_header_dir,
    )
    response_header_ledger = load_json(response_header_dir / "evidence-ledger.json")
    response_header_audit = load_json(response_header_dir / "audit-summary.json")
    response_header_evidence = response_header_ledger.get("evidence", [{}])[0]
    assert_true(response_header_audit.get("passed") is True, "response header evidence should pass ledger audit.")
    assert_true(response_header_ledger.get("requirements", [{}])[0].get("status") == "Passed", "response header requirement should pass.")
    assert_true(response_header_evidence.get("checked_response_headers", {}).get("x-trace-id") == "trace-qa-fixture", "ledger should preserve checked response headers.")
    assert_true(response_header_evidence.get("extracted_response_headers", {}).get("trace_id") == "trace-qa-fixture", "ledger should preserve extracted response header variables.")

    command_json_dir = tmp_path / "command-json-ledger"
    write_json(
        command_json_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-persist",
                    "source": "fixture",
                    "text": "Persistence helper should prove completed turn state.",
                    "test_ids": ["T-persist"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-persist",
                    "requirement_ids": ["R-persist"],
                    "type": "persistence",
                    "steps": ["Run a read-only helper and assert JSON stdout."],
                    "expected": "stdout JSON contains completed status and at least two messages.",
                    "required_evidence": ["command", "stdout JSON"],
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        command_json_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "artifactDir": str(command_json_dir),
            "scenarios": [
                {
                    "id": "persistence",
                    "steps": [
                        {
                            "action": "command",
                            "id": "T-persist-command",
                            "testIds": ["T-persist"],
                            "requirementIds": ["R-persist"],
                            "command": ["python3", "-c", "import json; print(json.dumps({'turn_id':'turn-1','status':'completed','message_count':2}))"],
                            "expectExitCode": 0,
                            "expectStdoutJson": {"status": "completed", "message_count": {"op": "gte", "value": 2}},
                            "extractStdoutJson": {"turn_id": "turn_id"},
                            "captureStdout": True,
                            "evidenceType": "command",
                            "proves": "A read-only helper reports the persisted turn as completed with messages.",
                        }
                    ],
                }
            ],
        },
    )
    command_stdout_path = command_json_dir / "evidence" / "persistence-command-stdout.txt"
    command_stdout_path.parent.mkdir(parents=True, exist_ok=True)
    command_stdout_path.write_text('{"turn_id":"turn-1","status":"completed","message_count":2}\n', encoding="utf-8")
    write_json(
        command_json_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "artifactDir": str(command_json_dir),
            "scenarios": [
                {
                    "id": "persistence",
                    "status": "passed",
                    "steps": [
                        {
                            "scenarioId": "persistence",
                            "stepId": "T-persist-command",
                            "testIds": ["T-persist"],
                            "requirementIds": ["R-persist"],
                            "action": "command",
                            "status": "passed",
                            "evidenceType": "command",
                            "proves": "A read-only helper reports the persisted turn as completed with messages.",
                            "exitCode": 0,
                            "stdoutPath": str(command_stdout_path),
                            "stdoutPreview": '{"turn_id":"turn-1","status":"completed","message_count":2}',
                            "checkedStdoutJson": {"status": "completed", "message_count": 2},
                            "extractedStdoutJson": {"turn_id": "turn-1"},
                            "extractedStdoutJsonPaths": {"turn_id": "turn_id"},
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(command_json_dir / "test-plan.json"),
            "--matrix",
            str(command_json_dir / "test-matrix.json"),
            "--summary",
            str(command_json_dir / "plan-audit-summary.json"),
        ],
        cwd=command_json_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "ledger_from_probe.py"),
            "--matrix",
            str(command_json_dir / "test-matrix.json"),
            "--results",
            str(command_json_dir / "results.json"),
            "--out",
            str(command_json_dir / "evidence-ledger.json"),
        ],
        cwd=command_json_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(command_json_dir / "test-matrix.json"),
            "--results",
            str(command_json_dir / "results.json"),
            "--ledger",
            str(command_json_dir / "evidence-ledger.json"),
            "--summary",
            str(command_json_dir / "audit-summary.json"),
        ],
        cwd=command_json_dir,
    )
    command_json_ledger = load_json(command_json_dir / "evidence-ledger.json")
    command_json_audit = load_json(command_json_dir / "audit-summary.json")
    command_json_evidence = command_json_ledger.get("evidence", [{}])[0]
    assert_true(command_json_audit.get("passed") is True, "command stdout JSON evidence should pass ledger audit.")
    assert_true(command_json_ledger.get("requirements", [{}])[0].get("status") == "Passed", "command stdout JSON requirement should pass.")
    assert_true(command_json_evidence.get("checked_stdout_json", {}).get("status") == "completed", "ledger should preserve checked stdout JSON.")
    assert_true(command_json_evidence.get("extracted_stdout_json", {}).get("turn_id") == "turn-1", "ledger should preserve extracted stdout JSON variables.")


def run_runtime_guard_phase(script_dir: Path, tmp_path: Path) -> None:
    cleanup_run_dir = tmp_path / "cleanup-ledger"

    runtime_issue_dir = tmp_path / "undispositioned-runtime"
    write_json(
        runtime_issue_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-runtime",
                    "source": "fixture",
                    "text": "The visible workflow should pass without hidden runtime errors.",
                    "test_ids": ["T-runtime"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-runtime",
                    "requirement_ids": ["R-runtime"],
                    "type": "ui",
                    "steps": ["Run the workflow and inspect runtime signals."],
                    "expected": "The workflow passes and runtime issues are explicitly dispositioned.",
                    "required_evidence": ["workflow evidence", "runtime disposition"],
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        runtime_issue_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(runtime_issue_dir),
            "scenarios": [
                {
                    "id": "runtime",
                    "steps": [
                        {
                            "action": "expectText",
                            "id": "T-runtime-visible",
                            "testIds": ["T-runtime"],
                            "requirementIds": ["R-runtime"],
                            "text": "Ready",
                            "evidenceType": "ui_assertion",
                            "proves": "The visible workflow reached the ready state.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        runtime_issue_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "artifactDir": str(runtime_issue_dir),
            "baseUrl": "http://127.0.0.1:9527",
            "scenarios": [
                {
                    "id": "runtime",
                    "status": "passed",
                    "steps": [
                        {
                            "scenarioId": "runtime",
                            "stepId": "T-runtime-visible",
                            "testIds": ["T-runtime"],
                            "requirementIds": ["R-runtime"],
                            "action": "expectText",
                            "status": "passed",
                            "evidenceType": "ui_assertion",
                            "proves": "The visible workflow reached the ready state.",
                            "count": 1,
                        }
                    ],
                }
            ],
            "console": [
                {"type": "error", "text": "Uncaught fixture runtime error", "url": "http://127.0.0.1:9527/aibox", "time": "2026-06-15T00:00:00Z"}
            ],
            "failedResponses": [
                {"status": 500, "url": "http://127.0.0.1:9527/api/v1/runtime-fixture", "time": "2026-06-15T00:00:01Z"}
            ],
            "requestFailures": [
                {"method": "GET", "url": "http://127.0.0.1:9527/api/v1/socket-fixture", "failure": "net::ERR_CONNECTION_RESET", "time": "2026-06-15T00:00:02Z"}
            ],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(runtime_issue_dir),
            "--skip-probe",
            "--strict-runtime",
            "--skip-report",
        ],
        cwd=runtime_issue_dir,
    )
    runtime_summary = load_json(runtime_issue_dir / "qa-run-summary.json")
    runtime_defects = load_json(runtime_issue_dir / "defects.json")
    runtime_next = load_json(runtime_issue_dir / "next-probes.json")
    runtime_verdict = load_json(runtime_issue_dir / "qa-verdict.json")
    runtime_actions = {rec.get("plan_step_hint", {}).get("action") for rec in runtime_next.get("recommendations", [])}
    runtime_api_recs = [
        rec
        for rec in runtime_next.get("recommendations", [])
        if rec.get("suggested_probe_type") == "api" and rec.get("plan_step_hint", {}).get("path") == "/api/v1/runtime-fixture"
    ]
    assert_true(runtime_summary.get("runtime_disposition_audit_failed") is True, "strict runtime audit failure should continue to defect handoff.")
    assert_true(runtime_defects.get("summary", {}).get("finding_count") == 3, "undispositioned runtime issues should generate three findings.")
    assert_true(
        {"expectNoConsoleErrors", "expectNoFailedResponses", "expectNoRequestFailures"}.issubset(runtime_actions),
        "next-probes should recommend focused runtime disposition probes.",
    )
    assert_true(runtime_api_recs, "failed runtime HTTP responses should also recommend a same-endpoint API body-capture diagnostic.")
    assert_true(runtime_api_recs[0].get("required_inputs") == ["baseUrl"], "500 runtime response diagnostics should be safe when the failed endpoint is already captured.")
    assert_true(runtime_verdict.get("can_claim_pass") is False and runtime_verdict.get("verdict") == "failed", "runtime findings must block pass claim.")
    run_cmd(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(runtime_issue_dir),
            "--out",
            str(runtime_issue_dir / "runtime-next-probe-preview.json"),
        ],
        cwd=runtime_issue_dir,
    )
    runtime_preview = load_json(runtime_issue_dir / "runtime-next-probe-preview.json")
    assert_true(runtime_preview.get("summary", {}).get("applied_count") == 4, "runtime disposition and failed-response body-capture probes should be safe to preview without extra flags.")
    run_cmd(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(runtime_issue_dir),
            "--apply",
            "--out",
            str(runtime_issue_dir / "runtime-next-probe-application.json"),
        ],
        cwd=runtime_issue_dir,
    )
    runtime_application = load_json(runtime_issue_dir / "runtime-next-probe-application.json")
    runtime_plan_after = load_json(runtime_issue_dir / "test-plan.json")
    runtime_matrix_after = load_json(runtime_issue_dir / "test-matrix.json")
    runtime_followup_actions = {
        step.get("action")
        for scenario in runtime_plan_after.get("scenarios", [])
        if scenario.get("id") == "next-probe-followups"
        for step in scenario.get("steps", [])
    }
    runtime_followup_api_paths = {
        step.get("path")
        for scenario in runtime_plan_after.get("scenarios", [])
        if scenario.get("id") == "next-probe-followups"
        for step in scenario.get("steps", [])
        if step.get("action") == "api"
    }
    assert_true(runtime_application.get("summary", {}).get("applied_count") == 4, "runtime disposition and failed-response body-capture probes should apply without extra flags.")
    assert_true("R-runtime-issue-disposition" in {req.get("id") for req in runtime_matrix_after.get("requirements", [])}, "runtime apply should create a runtime disposition requirement.")
    assert_true(runtime_actions.issubset(runtime_followup_actions), "runtime apply should append all focused runtime probes.")
    assert_true("/api/v1/runtime-fixture" in runtime_followup_api_paths, "runtime apply should append the failed-response API body-capture diagnostic path.")
    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(runtime_issue_dir / "test-plan.json"),
            "--matrix",
            str(runtime_issue_dir / "test-matrix.json"),
            "--summary",
            str(runtime_issue_dir / "runtime-plan-audit-after-next-probes.json"),
        ],
        cwd=runtime_issue_dir,
    )
    runtime_plan_audit = load_json(runtime_issue_dir / "runtime-plan-audit-after-next-probes.json")
    assert_true(runtime_plan_audit.get("passed") is True, "plan should validate after applying runtime disposition probes.")

    runtime_fake_dir = tmp_path / "runtime-fake-zero-disposition"
    write_runtime_console_disposition_fixture(runtime_fake_dir)
    runtime_fake_audit = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(runtime_fake_dir / "test-matrix.json"),
            "--ledger",
            str(runtime_fake_dir / "evidence-ledger.json"),
            "--results",
            str(runtime_fake_dir / "results.json"),
            "--strict-runtime",
            "--summary",
            str(runtime_fake_dir / "audit-summary.json"),
        ],
        cwd=runtime_fake_dir,
        text=True,
        capture_output=True,
    )
    assert_true(runtime_fake_audit.returncode != 0, "audit should reject fake runtime disposition when results still contain console errors.")
    runtime_fake_summary = load_json(runtime_fake_dir / "audit-summary.json")
    runtime_fake_errors = "\n".join(runtime_fake_summary.get("errors", []))
    assert_true("claims checked_console_errors=0" in runtime_fake_errors, "audit should explain the checked=0/results-count contradiction.")
    assert_true("Missing runtime disposition for console_errors=1" in runtime_fake_errors, "audit should still mark the runtime issue undispositioned.")

    runtime_ignored_dir = tmp_path / "runtime-ignored-zero-disposition"
    write_runtime_console_disposition_fixture(runtime_ignored_dir, ignored_console_errors=1)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(runtime_ignored_dir / "test-matrix.json"),
            "--ledger",
            str(runtime_ignored_dir / "evidence-ledger.json"),
            "--results",
            str(runtime_ignored_dir / "results.json"),
            "--strict-runtime",
            "--summary",
            str(runtime_ignored_dir / "audit-summary.json"),
        ],
        cwd=runtime_ignored_dir,
    )
    runtime_ignored_summary = load_json(runtime_ignored_dir / "audit-summary.json")
    assert_true(runtime_ignored_summary.get("passed") is True, "audit should accept runtime disposition when ignored issue count matches results.")

    runtime_verdict_guard_dir = tmp_path / "runtime-verdict-count-aware"
    write_runtime_console_disposition_fixture(runtime_verdict_guard_dir)
    write_synthetic_passing_audit_summary(runtime_verdict_guard_dir)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(runtime_verdict_guard_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(runtime_verdict_guard_dir / "audit-summary.json"),
            "--results",
            str(runtime_verdict_guard_dir / "results.json"),
            "--out",
            str(runtime_verdict_guard_dir / "qa-verdict.json"),
        ],
        cwd=runtime_verdict_guard_dir,
    )
    runtime_guard_verdict = load_json(runtime_verdict_guard_dir / "qa-verdict.json")
    runtime_guard_codes = {reason.get("code") for reason in runtime_guard_verdict.get("reasons", [])}
    assert_true(runtime_guard_verdict.get("can_claim_pass") is False, "verdict should reject fake runtime disposition even if audit input claims passed.")
    assert_true("undispositioned_console_errors" in runtime_guard_codes, "verdict should independently flag undispositioned console errors.")

    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_defects.py"),
            "--ledger",
            str(runtime_verdict_guard_dir / "evidence-ledger.json"),
            "--results",
            str(runtime_verdict_guard_dir / "results.json"),
            "--matrix",
            str(runtime_verdict_guard_dir / "test-matrix.json"),
            "--out",
            str(runtime_verdict_guard_dir / "defects.json"),
        ],
        cwd=runtime_verdict_guard_dir,
    )
    runtime_guard_defects = load_json(runtime_verdict_guard_dir / "defects.json")
    runtime_guard_defect_titles = {finding.get("title") for finding in runtime_guard_defects.get("findings", [])}
    assert_true(
        any(str(title).startswith("Undispositioned console errors captured") for title in runtime_guard_defect_titles),
        "defects should not suppress runtime findings from fake checked=0 evidence.",
    )

    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_defects.py"),
            "--ledger",
            str(runtime_ignored_dir / "evidence-ledger.json"),
            "--results",
            str(runtime_ignored_dir / "results.json"),
            "--matrix",
            str(runtime_ignored_dir / "test-matrix.json"),
            "--out",
            str(runtime_ignored_dir / "defects.json"),
        ],
        cwd=runtime_ignored_dir,
    )
    runtime_ignored_defects = load_json(runtime_ignored_dir / "defects.json")
    assert_true(runtime_ignored_defects.get("summary", {}).get("finding_count") == 0, "defects should suppress runtime findings when ignored issue count matches results.")

    skipped_cleanup_dir = tmp_path / "skipped-cleanup-ledger"
    write_json(skipped_cleanup_dir / "test-matrix.json", load_json(cleanup_run_dir / "test-matrix.json"))
    write_json(
        skipped_cleanup_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "artifactDir": str(skipped_cleanup_dir),
            "scenarios": [
                {
                    "id": "cleanup",
                    "status": "passed",
                    "steps": [
                        {
                            "scenarioId": "cleanup",
                            "stepId": "T-clean-cleanup",
                            "testIds": ["T-clean"],
                            "requirementIds": ["R-clean"],
                            "action": "cleanupApi",
                            "status": "skipped",
                            "evidenceType": "cleanup",
                            "proves": "The runtime item is removed or already absent.",
                            "skipped": True,
                            "skipReason": "Missing runtime variable for template: id",
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "ledger_from_probe.py"),
            "--matrix",
            str(skipped_cleanup_dir / "test-matrix.json"),
            "--results",
            str(skipped_cleanup_dir / "results.json"),
            "--out",
            str(skipped_cleanup_dir / "evidence-ledger.json"),
        ],
        cwd=skipped_cleanup_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(skipped_cleanup_dir / "test-matrix.json"),
            "--results",
            str(skipped_cleanup_dir / "results.json"),
            "--ledger",
            str(skipped_cleanup_dir / "evidence-ledger.json"),
            "--summary",
            str(skipped_cleanup_dir / "audit-summary.json"),
        ],
        cwd=skipped_cleanup_dir,
    )
    skipped_cleanup_ledger = load_json(skipped_cleanup_dir / "evidence-ledger.json")
    assert_true(
        skipped_cleanup_ledger.get("requirements", [{}])[0].get("status") == "Inconclusive",
        "skipped cleanup must not be converted into a passed requirement.",
    )


def run_cycle_and_agent_phase(
    script_dir: Path,
    tmp_path: Path,
    inputs: dict[str, Path],
) -> tuple[dict[str, Any], dict[str, bool]]:
    requirement_path = inputs["requirement"]

    init_proc = run_cmd(
        [
            sys.executable,
            str(script_dir / "init_qa_artifact.py"),
            "--requirement-file",
            str(requirement_path),
            "--out-dir",
            str(tmp_path),
            "--slug",
            "regression",
            "--base-url",
            "http://127.0.0.1:9527",
            "--skip-adapter-context",
        ],
        cwd=tmp_path,
    )
    run_dir = last_path(init_proc.stdout)
    fabricated_sentinel = "FABRICATED_SEMANTIC_SENTINEL"
    write_json(
        run_dir / "business-model.json",
        {
            "schema_version": 1,
            "actors": [{"id": "A-fake", "name": fabricated_sentinel, "source_requirement_ids": ["R-fake"]}],
            "entities": [],
            "workflows": [{"id": "W-fake", "label": fabricated_sentinel, "source_requirement_ids": ["R-fake"], "evidence_layers": ["ui"], "blocked": False}],
        },
    )
    write_json(
        run_dir / "oracle-model.json",
        {
            "schema_version": 1,
            "requirements": [{
                "requirement_id": "R-fake",
                "oracle_tests": ["T-fake"],
                "required_evidence_layers": ["ui"],
                "pass_rule": fabricated_sentinel,
                "weak_signals_to_avoid": [],
                "blocked_until": [],
            }],
            "summary": {"requirement_count": 999, "evidence_layer_counts": {"ui": 999}, "blocked_oracle_count": 0},
        },
    )
    write_json(
        run_dir / "qa-metrics.json",
        {
            "schema_version": 1,
            "summary": {"requirement_count": 999, "test_count": 999},
            "effectiveness_metrics": {"automation_readiness": fabricated_sentinel},
        },
    )
    write_json(
        run_dir / "closeout-candidates.json",
        {
            "schema_version": 1,
            "human_confirmation_required": False,
            "stable_knowledge_candidates": [{"source": "manual", "type": "business_rule", "text": fabricated_sentinel, "confirmation_required": False}],
            "qa_process_improvement_candidates": [],
            "rule": fabricated_sentinel,
        },
    )

    run_cmd(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(run_dir),
            "--skip-probe",
            "--strict-runtime",
        ],
        cwd=run_dir,
    )
    summary = load_json(run_dir / "qa-run-summary.json")
    verdict = load_json(run_dir / "qa-verdict.json")
    next_probes = load_json(run_dir / "next-probes.json")
    report_text = (run_dir / "report.md").read_text(encoding="utf-8")
    refreshed_business_model = load_json(run_dir / "business-model.json")
    refreshed_oracle_model = load_json(run_dir / "oracle-model.json")
    refreshed_metrics = load_json(run_dir / "qa-metrics.json")
    refreshed_closeout = load_json(run_dir / "closeout-candidates.json")
    assert_true(summary.get("status") == "blocked", "skip-probe cycle should produce blocked status for incomplete evidence.")
    assert_true(verdict.get("can_claim_pass") is False, "skip-probe verdict must not allow pass claim.")
    assert_true(next_probes.get("summary", {}).get("recommendation_count", 0) >= 1, "next-probes should recommend follow-up coverage.")
    assert_true(
        "## Business Intent Model" in report_text
        and "## Oracle Model" in report_text
        and "## QA Metrics" in report_text
        and "## Closeout Candidates" in report_text,
        "report should render business model, oracle, metrics, and closeout candidate sections when those artifacts exist.",
    )
    assert_true(
        "coverage_proxy_percent" in report_text
        and "coverage_breakdown.source_mapped" in report_text
        and "coverage_breakdown.executable" in report_text
        and "coverage_breakdown.pass_claim.actual" in report_text
        and "pass_claim_coverage_percent" in report_text
        and "test_accuracy_proxy_percent" in report_text
        and "business_modeling_proxy_percent" in report_text
        and "target_percent" in report_text,
        "report should render separated coverage semantics, planning quality scores, and the 95% target from qa-metrics.json.",
    )
    assert_true(fabricated_sentinel not in report_text, "run_qa_cycle should refresh stale semantic artifacts before report generation.")
    assert_true(
        refreshed_metrics.get("summary", {}).get("requirement_count") == len(load_json(run_dir / "test-matrix.json").get("requirements", []))
        and refreshed_business_model.get("source_bindings", {}).get("matrix", {}).get("sha256")
        and refreshed_oracle_model.get("source_bindings", {}).get("matrix", {}).get("sha256")
        and refreshed_closeout.get("source_bindings", {}).get("oracle_model", {}).get("sha256"),
        "refreshed semantic artifacts should match the current matrix/plan and carry source hashes.",
    )

    write_json(
        run_dir / "business-model.json",
        {
            "schema_version": 1,
            "actors": [{"id": "A-fake", "name": fabricated_sentinel, "source_requirement_ids": ["R-fake"]}],
            "entities": [],
            "workflows": [{"id": "W-fake", "label": fabricated_sentinel, "source_requirement_ids": ["R-fake"], "evidence_layers": ["ui"], "blocked": False}],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(run_dir / "test-plan.json"),
            "--results",
            str(run_dir / "results.json"),
            "--requirement",
            str(run_dir / "requirement.md"),
            "--ledger",
            str(run_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(run_dir / "audit-summary.json"),
            "--defects",
            str(run_dir / "defects.json"),
            "--plan-audit-summary",
            str(run_dir / "plan-audit-summary.json"),
            "--requirement-coverage",
            str(run_dir / "requirement-coverage.json"),
            "--next-probes",
            str(run_dir / "next-probes.json"),
            "--verdict",
            str(run_dir / "qa-verdict.json"),
            "--business-model",
            str(run_dir / "business-model.json"),
            "--oracle-model",
            str(run_dir / "oracle-model.json"),
            "--qa-metrics",
            str(run_dir / "qa-metrics.json"),
            "--closeout-candidates",
            str(run_dir / "closeout-candidates.json"),
            "--out",
            str(run_dir / "report-stale-semantic.md"),
        ],
        cwd=run_dir,
    )
    stale_semantic_report = (run_dir / "report-stale-semantic.md").read_text(encoding="utf-8")
    assert_true("Semantic artifact binding: BLOCKED" in stale_semantic_report, "direct report generation should block stale or fabricated semantic artifacts.")
    assert_true(fabricated_sentinel not in stale_semantic_report, "direct report generation must not render stale or fabricated semantic artifact content.")
    semantic_report_guard_checked = True
    semantic_report_checked = True
    semantic_artifact_refresh_checked = True

    run_cmd(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(run_dir),
            "--out",
            str(run_dir / "next-probe-application-dry.json"),
        ],
        cwd=run_dir,
    )
    dry = load_json(run_dir / "next-probe-application-dry.json")
    assert_true(dry.get("summary", {}).get("applied_count") == 0, "default next-probe application should not apply gated probes.")

    run_cmd(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(run_dir),
            "--allow-live-stream",
            "--apply",
        ],
        cwd=run_dir,
    )
    applied = load_json(run_dir / "next-probe-application.json")
    assert_true(applied.get("summary", {}).get("applied_count") == 1, "allow-live-stream should apply exactly the concrete WebSocket follow-up.")

    validate_proc = run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(run_dir / "test-plan.json"),
            "--matrix",
            str(run_dir / "test-matrix.json"),
            "--summary",
            str(run_dir / "plan-audit-after-next-probes.json"),
        ],
        cwd=run_dir,
    )
    plan_audit = load_json(run_dir / "plan-audit-after-next-probes.json")
    assert_true(plan_audit.get("passed") is True, "plan should validate after applying next probes.")
    assert_true(plan_audit.get("mapped_executable_requirement_count", 0) >= 3, "applied follow-up should increase executable requirement mapping.")

    init_loop_proc = run_cmd(
        [
            sys.executable,
            str(script_dir / "init_qa_artifact.py"),
            "--requirement-file",
            str(requirement_path),
            "--out-dir",
            str(tmp_path),
            "--slug",
            "agent-loop-regression",
            "--base-url",
            "http://127.0.0.1:9527",
            "--skip-adapter-context",
        ],
        cwd=tmp_path,
    )
    loop_run_dir = last_path(init_loop_proc.stdout)
    write_json(
        loop_run_dir / "adapter-context.json",
        {
            "schema_version": 1,
            "adapter": "fixture",
            "environment_boundary": {
                "runtime_mode": "test",
                "data_boundary_status": "synthetic regression data; no production data",
            },
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(loop_run_dir),
            "--skip-probe",
            "--strict-runtime",
        ],
        cwd=loop_run_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "qa_agent_loop.py"),
            "--run-dir",
            str(loop_run_dir),
            "--skip-probe",
            "--strict-runtime",
            "--allow-live-stream",
            "--max-iterations",
            "2",
        ],
        cwd=loop_run_dir,
    )
    agent_summary = load_json(loop_run_dir / "qa-agent-summary.json")
    agent_final = agent_summary.get("final") or {}
    agent_application = agent_final.get("application_summary") or {}
    agent_preview = agent_final.get("preview_summary") or {}
    agent_next_action = agent_summary.get("next_action") or {}
    assert_true(agent_preview.get("applied_count") == 1, "agent loop should preview one concrete WebSocket follow-up when live stream is authorized.")
    assert_true(not agent_application or agent_application.get("applied_count", 0) == 0, "agent loop should not partially apply safe follow-ups while other actionable follow-ups still need input.")
    assert_true(agent_final.get("can_claim_pass") is False, "agent loop must not claim pass after planning-only evidence.")
    assert_true(agent_next_action.get("action") == "request_authorization_or_inputs", "mixed safe and blocked follow-ups should stop for an authorization/input handoff.")
    assert_true(agent_next_action.get("blocked_followups", {}).get("actionable_skipped_count", 0) >= 1, "mixed follow-up handoff should expose the blocked follow-up count.")
    assert_true(agent_next_action.get("automatable") is False, "stopped agent loop should not imply it can keep going automatically without a safe follow-up.")
    assert_true(all((item.get("next_action") or {}).get("action") for item in agent_summary.get("iterations", [])), "each agent-loop iteration should record its own next action.")
    summary = {
        "mapped_executable_requirement_count": plan_audit.get("mapped_executable_requirement_count"),
        "agent_loop_stop_reason": agent_summary.get("stop_reason"),
        "agent_loop_next_action": agent_next_action.get("action"),
        "validate_stdout": validate_proc.stdout.strip(),
    }
    checks = {
        "semantic_report_checked": semantic_report_checked,
        "semantic_artifact_refresh_checked": semantic_artifact_refresh_checked,
        "semantic_report_guard_checked": semantic_report_guard_checked,
    }
    return summary, checks


def run_full_regression_suite(script_dir: Path, tmp_path: Path, *, with_browser: bool) -> dict[str, Any]:
    inputs = prepare_full_regression_inputs(tmp_path)
    checks = run_modeling_and_fixture_phase(script_dir, tmp_path, inputs, with_browser=with_browser)
    run_interaction_flow_phase(script_dir, tmp_path, inputs)
    run_evidence_flow_phase(script_dir, tmp_path)
    run_runtime_guard_phase(script_dir, tmp_path)
    summary, cycle_checks = run_cycle_and_agent_phase(script_dir, tmp_path, inputs)
    checks.update(cycle_checks)

    result = {
        "status": "passed",
        "mapped_executable_requirement_count": summary["mapped_executable_requirement_count"],
        "agent_loop_stop_reason": summary["agent_loop_stop_reason"],
        "agent_loop_next_action": summary["agent_loop_next_action"],
    }
    result.update(checks)
    result["validate_stdout"] = summary["validate_stdout"]
    return result


def keep_regression_artifacts(tmp_path: Path) -> Path:
    kept = Path(tempfile.mkdtemp(prefix="automated-qa-test-regression-kept-", dir="/tmp"))
    for item in tmp_path.iterdir():
        target = kept / item.name
        if item.is_dir():
            subprocess.run(["cp", "-R", str(item), str(target)], check=True)
        else:
            target.write_bytes(item.read_bytes())
    return kept


def main() -> int:
    parser = argparse.ArgumentParser(description="Run isolated self-regression checks for automated-qa-test helper scripts.")
    parser.add_argument("--keep", action="store_true", help="Keep the temporary regression directory.")
    parser.add_argument("--with-browser", action="store_true", help="Also launch Playwright/Chrome against a local hit-test fixture.")
    parser.add_argument("--group", action="append", choices=REGRESSION_GROUP_ORDER, help="Run only one focused fixture group. May be repeated.")
    parser.add_argument("--list-groups", action="store_true", help="List focused regression groups and fixture counts, then exit.")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    if args.list_groups:
        groups = regression_fixture_groups()
        print(json.dumps({name: [fixture_name for fixture_name, _ in groups[name]] for name in REGRESSION_GROUP_ORDER}, indent=2, ensure_ascii=False))
        return 0
    if args.group:
        selected = list(dict.fromkeys(args.group))
        with tempfile.TemporaryDirectory(prefix="automated-qa-test-regression-group-", dir="/tmp", delete=not args.keep) as tmp:
            result = run_selected_regression_groups(script_dir, Path(tmp), selected)
            if args.keep:
                result["kept_path"] = tmp
            print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    with tempfile.TemporaryDirectory(prefix="automated-qa-test-regression-", dir="/tmp", delete=not args.keep) as tmp:
        tmp_path = Path(tmp)
        result = run_full_regression_suite(script_dir, tmp_path, with_browser=args.with_browser)
        if args.keep:
            print(keep_regression_artifacts(tmp_path))
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
