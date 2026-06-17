#!/usr/bin/env python3
import argparse
import base64
import contextlib
import hashlib
import http.server
import io
import importlib.util
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any


REQUIREMENT = """# Chat Backtest Requirement

- The AI Box page at /aibox should show the authenticated toolbox entry.
- GET /api/v1/agents/catalog should return the available agents.
- WebSocket /api/v1/agents/ask/ws must emit answer_done.
- The session detail API /api/v1/sessions/{session_id} should contain user and assistant messages.
- The persisted turn should reach completed.
"""

CLICK_REQUIREMENT = """# Clickability Requirement

- User can open /settings and click the Save button.
- User can open /profile and click the button.
"""

CLICK_RESPONSE_REQUIREMENT = """# Click-To-Response Requirement

- User can open /settings and click the Save button; POST /api/v1/settings returns 200.
"""

FOLLOWUP_REQUIREMENT = """# Same Object Follow-Up Requirement

- User can open /items and click the Create button; POST /api/v1/items returns id; GET /api/v1/items/{id} returns 200.
"""

ASYNC_FOLLOWUP_REQUIREMENT = """# Async Same Object Follow-Up Requirement

- User can open /jobs and click the Run button; POST /api/v1/jobs returns job_id; GET /api/v1/jobs/{job_id} eventually reaches status completed.
"""

BUSINESS_REQUIREMENT = """# Order Approval Requirement

- An authenticated merchant operator can open /orders and click the Approve button; POST /api/v1/orders/{id}/approve moves the order from pending to approved and records an audit log.
- Guest users must not approve orders.
- The order detail must show approved status after refresh and the database must persist approved_at.
"""

VALID_PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a"
    "0000000d49484452000000010000000108060000001f15c489"
    "0000000a49444154789c63000100000500010d0a2db4"
    "0000000049454e44ae426082"
)
EVIDENCE_ARTIFACT_PATH_FIELDS = (
    "path",
    "file",
    "body_path",
    "response_body_path",
    "request_body_path",
    "messages_path",
    "stdout_path",
    "stderr_path",
)


def run_cmd(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(args, cwd=str(cwd), text=True, capture_output=True)
    if proc.returncode != 0:
        raise AssertionError(
            "Command failed:\n"
            + " ".join(args)
            + f"\nexit={proc.returncode}\nstdout={proc.stdout[-4000:]}\nstderr={proc.stderr[-4000:]}"
        )
    return proc


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_path_values(value: Any):
    if isinstance(value, str) and value.strip():
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from iter_path_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_path_values(child)


def evidence_artifact_hashes(run_dir: Path, ledger: dict[str, Any]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for item in ledger.get("evidence", []):
        if not isinstance(item, dict):
            continue
        for field in EVIDENCE_ARTIFACT_PATH_FIELDS:
            for raw in iter_path_values(item.get(field)):
                path = Path(raw).expanduser()
                resolved = path.resolve() if path.is_absolute() else (run_dir / path).resolve()
                if resolved.exists() and not resolved.is_dir():
                    hashes[str(resolved)] = file_sha256(resolved)
    return dict(sorted(hashes.items()))


def write_runtime_console_disposition_fixture(run_dir: Path, ignored_console_errors: int | None = None) -> None:
    runtime_evidence: dict[str, Any] = {
        "id": "e-runtime",
        "type": "runtime",
        "current_run": True,
        "test_ids": ["T-runtime"],
        "requirement_ids": ["R-runtime"],
        "checked_console_errors": 0,
        "assertions": ["No console errors"],
        "proves": "No console errors remain.",
        "value": "console_errors=0",
    }
    if ignored_console_errors is not None:
        runtime_evidence["ignored_console_errors"] = ignored_console_errors
    write_json(
        run_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-runtime",
                    "source": "fixture",
                    "text": "Visible workflow has no hidden runtime errors.",
                    "test_ids": ["T-runtime"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-runtime",
                    "requirement_ids": ["R-runtime"],
                    "type": "ui",
                    "expected": "Ready and no runtime errors.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        run_dir / "evidence-ledger.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-runtime",
                    "source": "fixture",
                    "text": "Visible workflow has no hidden runtime errors.",
                    "test_ids": ["T-runtime"],
                    "status": "Passed",
                    "evidence_ids": ["e-ui", "e-runtime"],
                }
            ],
            "tests": [
                {
                    "id": "T-runtime",
                    "requirement_ids": ["R-runtime"],
                    "type": "ui",
                    "expected": "Ready and no runtime errors.",
                    "status": "Passed",
                    "evidence_ids": ["e-ui", "e-runtime"],
                }
            ],
            "evidence": [
                {
                    "id": "e-ui",
                    "type": "ui_assertion",
                    "current_run": True,
                    "test_ids": ["T-runtime"],
                    "requirement_ids": ["R-runtime"],
                    "status": "passed",
                    "proves": "Ready text was visible.",
                    "count": 1,
                    "value": "Ready",
                },
                runtime_evidence,
            ],
        },
    )
    write_json(
        run_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "console": [
                {
                    "type": "error",
                    "text": "Uncaught fixture runtime error",
                    "url": "http://127.0.0.1:9527/aibox",
                    "time": "2026-06-15T00:00:00Z",
                }
            ],
            "failedResponses": [],
            "requestFailures": [],
        },
    )


def write_synthetic_passing_audit_summary(run_dir: Path) -> None:
    ledger_path = (run_dir / "evidence-ledger.json").resolve()
    matrix_path = (run_dir / "test-matrix.json").resolve()
    results_path = (run_dir / "results.json").resolve()
    ledger = load_json(ledger_path)
    write_json(
        run_dir / "audit-summary.json",
        {
            "ledger": str(ledger_path),
            "matrix": str(matrix_path),
            "results": str(results_path),
            "artifact_hashes": {
                "ledger_sha256": file_sha256(ledger_path),
                "matrix_sha256": file_sha256(matrix_path),
                "results_sha256": file_sha256(results_path),
                "evidence_artifacts_sha256": evidence_artifact_hashes(run_dir, ledger),
            },
            "requirement_count": 1,
            "test_count": 1,
            "evidence_count": 2,
            "status_counts": {"Blocked": 0, "Failed": 0, "Inconclusive": 0, "Passed": 1, "Untested": 0},
            "passed": True,
            "errors": [],
            "warnings": [],
            "input_artifact_errors": [],
        },
    )


def unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def last_path(stdout: str) -> Path:
    for line in reversed(stdout.splitlines()):
        text = line.strip()
        if text:
            return Path(text).expanduser().resolve()
    raise AssertionError("No output path found.")


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def expected_health_status_for_route(route: dict[str, Any]) -> str:
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
    if route.get("result_ready_to_report") is True or mode == "report":
        return "reportable_non_pass"
    return "needs_inspection"


def assert_route_model_consistent(control: dict[str, Any], label: str) -> None:
    route = control.get("agent_route_model") if isinstance(control.get("agent_route_model"), dict) else {}
    orchestration = control.get("orchestration_state") if isinstance(control.get("orchestration_state"), dict) else {}
    human = control.get("human_action_required") if isinstance(control.get("human_action_required"), dict) else {}
    health = control.get("evidence_health") if isinstance(control.get("evidence_health"), dict) else {}
    steps = [item for item in control.get("recommended_next_steps", []) if isinstance(item, dict)]
    gap_plan = control.get("evidence_gap_plan") if isinstance(control.get("evidence_gap_plan"), dict) else {}
    gaps = [item for item in gap_plan.get("gaps", []) if isinstance(item, dict)]
    assert_true(bool(route), f"{label}: loop_control should expose a single agent_route_model.")
    assert_true(bool(orchestration), f"{label}: orchestration_state should still be projected.")
    assert_true(bool(health), f"{label}: evidence_health should still be projected.")
    for key in (
        "mode",
        "primary_action",
        "terminal",
        "can_continue_automatically",
        "pass_claim_allowed",
        "handoff_required",
        "requires_authorization",
        "requires_input_repair",
        "can_continue_after_authorization",
        "result_ready_to_report",
        "no_new_progress",
    ):
        assert_true(
            orchestration.get(key) == route.get(key),
            f"{label}: orchestration_state.{key} should be projected from agent_route_model.",
        )
    assert_true(health.get("route_mode") == route.get("mode"), f"{label}: evidence_health should name the route mode it projects.")
    assert_true(health.get("route_primary_action") == route.get("primary_action"), f"{label}: evidence_health should name the route action it projects.")
    assert_true(
        health.get("status") == expected_health_status_for_route(route),
        f"{label}: evidence_health.status should be projected from agent_route_model.",
    )
    assert_true(
        route.get("recommended_next_step_count") == len(steps),
        f"{label}: route model step count should match recommended_next_steps.",
    )
    steps_by_gap = {item.get("gap_id"): item for item in steps if item.get("gap_id")}
    for gap in gaps:
        operation = gap.get("operation") if isinstance(gap.get("operation"), dict) else {}
        assert_true(bool(operation.get("kind")) and bool(operation.get("route_mode")), f"{label}: each evidence gap should carry resolved operation semantics.")
        matching_step = steps_by_gap.get(gap.get("id"))
        if matching_step:
            assert_true(matching_step.get("kind") == operation.get("kind"), f"{label}: gap step kind should match gap operation.")
            assert_true(matching_step.get("route_mode") == operation.get("route_mode"), f"{label}: gap step route mode should match gap operation.")
    if steps:
        first_step = steps[0]
        route_first = route.get("first_recommended_step") if isinstance(route.get("first_recommended_step"), dict) else {}
        route_gap = route.get("first_evidence_gap") if isinstance(route.get("first_evidence_gap"), dict) else {}
        orch_first = orchestration.get("first_recommended_step") if isinstance(orchestration.get("first_recommended_step"), dict) else {}
        assert_true(route_first.get("id") == first_step.get("id"), f"{label}: route model should summarize the first recommended step.")
        assert_true(orch_first.get("id") == first_step.get("id"), f"{label}: orchestration should project the first recommended step.")
        if first_step.get("gap_id"):
            assert_true(route_first.get("gap_id") == first_step.get("gap_id"), f"{label}: route model should preserve first-step gap id.")
            assert_true(orch_first.get("gap_id") == first_step.get("gap_id"), f"{label}: orchestration should preserve first-step gap id.")
            gap_operation = route_gap.get("operation") if isinstance(route_gap.get("operation"), dict) else {}
            assert_true(gap_operation.get("kind") == first_step.get("kind"), f"{label}: recommended step kind should come from the first gap operation.")
            assert_true(gap_operation.get("route_mode") == first_step.get("route_mode"), f"{label}: recommended step route mode should come from the first gap operation.")
    step_ids = [str(item.get("id")) for item in steps if item.get("id")]
    assert_true(string_list(route.get("recommended_next_step_ids")) == step_ids, f"{label}: route model step ids should match recommended_next_steps order.")
    if human:
        assert_true(route.get("requires_human_action") is True, f"{label}: human projection should only exist when route requires human action.")
        assert_true(human.get("type") == route.get("human_request_type"), f"{label}: human type should be projected from route model.")
        assert_true(human.get("recommended_next_step_ids") == step_ids, f"{label}: human step ids should match recommended_next_steps order.")
        assert_true(orchestration.get("human_request_type") == route.get("human_request_type"), f"{label}: orchestration human type should be projected from route model.")
        assert_true(health.get("route_human_request_type") == route.get("human_request_type"), f"{label}: evidence_health human type should be projected from route model.")
    else:
        assert_true(route.get("requires_human_action") is not True, f"{label}: route should not require human action when no human checklist is present.")
    for key in ("recommended_flags", "confirmation_fields", "required_inputs", "manual_revision_targets"):
        expected = string_list(route.get(key))
        actual_orchestration = string_list(orchestration.get(key))
        if expected or actual_orchestration:
            assert_true(actual_orchestration == expected, f"{label}: orchestration {key} should match route model.")
        if human:
            actual_human = string_list(human.get(key))
            if expected or actual_human:
                assert_true(actual_human == expected, f"{label}: human {key} should match route model.")


def load_qa_agent_loop_module(script_dir: Path) -> Any:
    spec = importlib.util.spec_from_file_location("qa_agent_loop_under_test", script_dir / "qa_agent_loop.py")
    if not spec or not spec.loader:
        raise AssertionError("Unable to load qa_agent_loop.py for regression checks.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_agent_next_action_fixture(script_dir: Path, tmp_path: Path) -> None:
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
    assert_true((audit_no_followup_control.get("agent_route_model") or {}).get("primary_action") == "repair_evidence_pipeline", "route model should keep evidence-pipeline repair as the primary action.")
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
    assert_true(preview_input_action.get("failure_analysis", {}).get("blocking_layer") == "follow_up_probe_input", "fix_next_probe_inputs should expose the follow-up input blocking layer.")


def run_agent_pass_skips_preview_fixture(script_dir: Path, tmp_path: Path) -> None:
    module = load_qa_agent_loop_module(script_dir)
    run_dir = tmp_path / "agent-pass-skips-preview"
    run_dir.mkdir(parents=True, exist_ok=True)
    write_json(run_dir / "test-matrix.json", {"schemaVersion": 2, "requirements": [], "tests": []})
    write_json(run_dir / "test-plan.json", {"schemaVersion": 2, "baseUrl": "http://127.0.0.1:9527", "scenarios": []})

    calls: list[str] = []
    original_argv = sys.argv[:]
    original_run_command = module.run_command

    def fake_run_command(command: list[str], cwd: Path) -> dict[str, Any]:
        joined = " ".join(str(item) for item in command)
        if "run_qa_cycle.py" in joined:
            calls.append("cycle")
            now = datetime_now_for_fixture()
            write_json(
                run_dir / "qa-run-summary.json",
                {
                    "schema_version": 1,
                    "status": "passed",
                    "started_at": now,
                    "finished_at": now,
                    "steps": [{"name": "generate_verdict", "exit_code": 0}],
                },
            )
            write_json(
                run_dir / "qa-verdict.json",
                {
                    "schema_version": 1,
                    "generated_at": now,
                    "verdict": "passed",
                    "can_claim_pass": True,
                    "reasons": [],
                },
            )
            start = time.time() - 1.0
            return {
                "command": command,
                "cwd": str(cwd),
                "started_at": now,
                "started_at_epoch": start,
                "finished_at": now,
                "finished_at_epoch": time.time(),
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
            }
        if "apply_next_probes.py" in joined:
            calls.append("preview")
            return {
                "command": command,
                "cwd": str(cwd),
                "started_at": datetime_now_for_fixture(),
                "started_at_epoch": time.time(),
                "finished_at": datetime_now_for_fixture(),
                "finished_at_epoch": time.time(),
                "exit_code": 1,
                "stdout": "",
                "stderr": "preview should not run after pass",
            }
        return original_run_command(command, cwd)

    try:
        module.run_command = fake_run_command
        sys.argv = ["qa_agent_loop.py", "--run-dir", str(run_dir), "--max-iterations", "1"]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = module.main()
    finally:
        module.run_command = original_run_command
        sys.argv = original_argv

    agent_summary = load_json(run_dir / "qa-agent-summary.json")
    first_iteration = (agent_summary.get("iterations") or [{}])[0]
    assert_true(exit_code == 0, "agent loop should return success when the current verdict is pass-claimable.")
    assert_true(str(run_dir / "qa-agent-summary.json") in stdout.getvalue(), "agent loop should still print the summary path when preview is skipped after pass.")
    assert_true(calls == ["cycle"], "agent loop must not run next-probe preview after a pass-claimable verdict.")
    assert_true(agent_summary.get("status") == "passed", "agent summary should preserve the pass verdict.")
    assert_true(agent_summary.get("stop_reason") == "verdict_passed", "agent loop should stop directly on the pass verdict.")
    assert_true(first_iteration.get("preview") is None, "pass iteration should record no preview command result.")
    assert_true(first_iteration.get("preview_skipped_reason") == "verdict_passed", "pass iteration should explain that preview was skipped.")
    assert_true((agent_summary.get("next_action") or {}).get("action") == "report_pass", "pass verdict should expose report_pass next_action.")
    pass_control = agent_summary.get("loop_control") or {}
    assert_true(pass_control.get("terminal") is True, "agent summary loop_control should mark pass as terminal.")
    assert_true(pass_control.get("pass_claim_allowed") is True, "agent summary loop_control should expose pass claim allowance.")
    assert_true(pass_control.get("can_continue_automatically") is False, "passed agent loop should not ask orchestrators to keep probing.")


def run_agent_preview_hash_binding_fixture(script_dir: Path, tmp_path: Path) -> None:
    module = load_qa_agent_loop_module(script_dir)
    run_dir = tmp_path / "agent-preview-hash-binding"
    run_dir.mkdir(parents=True, exist_ok=True)
    write_json(run_dir / "test-matrix.json", {"schemaVersion": 2, "requirements": [], "tests": []})
    write_json(run_dir / "test-plan.json", {"schemaVersion": 2, "baseUrl": "http://127.0.0.1:9527", "scenarios": []})
    write_json(
        run_dir / "next-probes.json",
        {
            "schema_version": 1,
            "summary": {"recommendation_count": 1},
            "recommendations": [{"id": "NP-current", "layer": "runtime", "reason": "current file"}],
        },
    )

    calls: list[str] = []
    original_argv = sys.argv[:]
    original_run_command = module.run_command

    def fake_run_command(command: list[str], cwd: Path) -> dict[str, Any]:
        calls.append(" ".join(str(item) for item in command))
        return {
            "command": command,
            "cwd": str(cwd),
            "started_at": datetime_now_for_fixture(),
            "started_at_epoch": time.time(),
            "finished_at": datetime_now_for_fixture(),
            "finished_at_epoch": time.time(),
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
        }

    try:
        module.run_command = fake_run_command
        sys.argv = [
            "qa_agent_loop.py",
            "--run-dir",
            str(run_dir),
            "--max-iterations",
            "1",
            "--apply-existing-next-probes",
            "--expected-next-probes-sha256",
            "0" * 64,
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = module.main()
    finally:
        module.run_command = original_run_command
        sys.argv = original_argv

    agent_summary = load_json(run_dir / "qa-agent-summary.json")
    first_iteration = (agent_summary.get("iterations") or [{}])[0]
    next_action = agent_summary.get("next_action") or {}
    control = agent_summary.get("loop_control") or {}
    assert_true(exit_code == 1, "agent loop should exit non-zero when the expected next-probes hash does not match.")
    assert_true(calls == [], "agent loop must not start run_qa_cycle.py before resolving a next-probes hash mismatch.")
    assert_true(str(run_dir / "qa-agent-summary.json") in stdout.getvalue(), "hash mismatch loop should still print the summary path.")
    assert_true(agent_summary.get("stop_reason") == "next_probes_hash_mismatch", "agent summary should name the next-probes hash mismatch stop reason.")
    assert_true(next_action.get("action") == "repreview_next_probes", "hash mismatch should produce a repreview_next_probes handoff.")
    assert_true(next_action.get("expected_next_probes_sha256") == "0" * 64, "hash mismatch action should preserve the expected hash.")
    assert_true(next_action.get("current_next_probes_sha256") == file_sha256(run_dir / "next-probes.json"), "hash mismatch action should expose the current hash.")
    assert_true(next_action.get("input_artifact_errors", [{}])[0].get("error") == "previewed_next_probes_hash_mismatch", "hash mismatch should be exposed as an input artifact error.")
    assert_true(control.get("requires_input_repair") is True, "loop_control should treat hash mismatch as input repair.")
    assert_true(control.get("input_artifact_errors", [{}])[0].get("error") == "previewed_next_probes_hash_mismatch", "loop_control should carry next-probe hash mismatch artifact errors for orchestrators.")
    assert_true(control.get("expected_next_probes_sha256") == "0" * 64, "loop_control should preserve the expected next-probes hash.")
    assert_true(control.get("current_next_probes_sha256") == file_sha256(run_dir / "next-probes.json"), "loop_control should expose the current next-probes hash.")
    assert_true(control.get("stop_before_cycle") == "next_probes_hash_mismatch", "loop_control should expose that the loop stopped before running a cycle.")
    assert_true(first_iteration.get("stop_before_cycle") == "next_probes_hash_mismatch", "hash mismatch iteration should record that it stopped before running a cycle.")

    inferred_dir = tmp_path / "agent-preview-hash-inferred"
    inferred_dir.mkdir(parents=True, exist_ok=True)
    write_json(inferred_dir / "test-matrix.json", {"schemaVersion": 2, "requirements": [], "tests": []})
    write_json(inferred_dir / "test-plan.json", {"schemaVersion": 2, "baseUrl": "http://127.0.0.1:9527", "scenarios": []})
    write_json(
        inferred_dir / "next-probes.json",
        {
            "schema_version": 1,
            "summary": {"recommendation_count": 1},
            "recommendations": [{"id": "NP-inferred", "layer": "runtime", "reason": "previously previewed"}],
        },
    )
    inferred_hash = file_sha256(inferred_dir / "next-probes.json")
    write_json(
        inferred_dir / "qa-agent-summary.json",
        {
            "schema_version": 1,
            "status": "blocked",
            "iterations": [
                {
                    "iteration": 1,
                    "preview_next_probes_sha256": inferred_hash,
                    "next_action": {
                        "action": "resume_with_more_iterations",
                        "expected_next_probes_sha256": inferred_hash,
                    },
                }
            ],
        },
    )
    inferred_calls: list[list[str]] = []

    def fake_inferred_run_command(command: list[str], cwd: Path) -> dict[str, Any]:
        inferred_calls.append(command)
        now = datetime_now_for_fixture()
        start = time.time() - 1.0
        assert_true("run_qa_cycle.py" in " ".join(str(item) for item in command), "inferred hash resume should only run the cycle command.")
        write_json(
            inferred_dir / "qa-run-summary.json",
            {
                "schema_version": 1,
                "status": "passed",
                "started_at": now,
                "finished_at": now,
                "steps": [{"name": "apply_next_probes", "exit_code": 0}, {"name": "generate_verdict", "exit_code": 0}],
            },
        )
        write_json(
            inferred_dir / "qa-verdict.json",
            {
                "schema_version": 1,
                "generated_at": now,
                "verdict": "passed",
                "can_claim_pass": True,
                "reasons": [],
            },
        )
        return {
            "command": command,
            "cwd": str(cwd),
            "started_at": now,
            "started_at_epoch": start,
            "finished_at": now,
            "finished_at_epoch": time.time(),
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
        }

    try:
        module.run_command = fake_inferred_run_command
        sys.argv = [
            "qa_agent_loop.py",
            "--run-dir",
            str(inferred_dir),
            "--max-iterations",
            "1",
            "--apply-existing-next-probes",
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            inferred_exit = module.main()
    finally:
        module.run_command = original_run_command
        sys.argv = original_argv

    inferred_summary = load_json(inferred_dir / "qa-agent-summary.json")
    inferred_control = inferred_summary.get("loop_control") or {}
    assert_true(inferred_exit == 0, "agent loop should resume successfully when it can infer the previewed next-probes hash from summary.")
    assert_true(len(inferred_calls) == 1 and "--apply-next-probes" in inferred_calls[0], "inferred hash resume should apply existing next-probes in the first cycle.")
    assert_true(inferred_summary.get("resume_next_probes_binding", {}).get("expected_next_probes_sha256") == inferred_hash, "agent summary should record the inferred next-probes hash binding.")
    assert_true(Path(str(inferred_summary.get("resume_next_probes_binding", {}).get("source"))).resolve() == (inferred_dir / "qa-agent-summary.json").resolve(), "agent summary should record which summary supplied the inferred hash.")
    assert_true(inferred_control.get("resume_next_probes_binding", {}).get("expected_next_probes_sha256") == inferred_hash, "loop_control should expose inferred next-probe hash bindings for external orchestrators.")

    missing_dir = tmp_path / "agent-preview-hash-missing"
    missing_dir.mkdir(parents=True, exist_ok=True)
    write_json(missing_dir / "test-matrix.json", {"schemaVersion": 2, "requirements": [], "tests": []})
    write_json(missing_dir / "test-plan.json", {"schemaVersion": 2, "baseUrl": "http://127.0.0.1:9527", "scenarios": []})
    write_json(
        missing_dir / "next-probes.json",
        {
            "schema_version": 1,
            "summary": {"recommendation_count": 1},
            "recommendations": [{"id": "NP-unbound", "layer": "runtime", "reason": "not preview-bound"}],
        },
    )
    missing_calls: list[list[str]] = []

    def fake_missing_run_command(command: list[str], cwd: Path) -> dict[str, Any]:
        missing_calls.append(command)
        return {"command": command, "cwd": str(cwd), "exit_code": 0, "stdout": "", "stderr": ""}

    try:
        module.run_command = fake_missing_run_command
        sys.argv = [
            "qa_agent_loop.py",
            "--run-dir",
            str(missing_dir),
            "--max-iterations",
            "1",
            "--apply-existing-next-probes",
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            missing_exit = module.main()
    finally:
        module.run_command = original_run_command
        sys.argv = original_argv

    missing_summary = load_json(missing_dir / "qa-agent-summary.json")
    missing_action = missing_summary.get("next_action") or {}
    missing_control = missing_summary.get("loop_control") or {}
    assert_true(missing_exit == 1, "agent loop should stop when existing next-probes cannot be hash-bound from CLI or summary.")
    assert_true(missing_calls == [], "agent loop must not start a cycle for unbound existing next-probes.")
    assert_true(missing_summary.get("stop_reason") == "next_probes_hash_missing", "unbound existing next-probes should produce a specific stop reason.")
    assert_true(missing_action.get("action") == "repreview_next_probes", "unbound existing next-probes should ask for repreview.")
    assert_true(missing_action.get("input_artifact_errors", [{}])[0].get("error") == "missing_expected_next_probes_sha256", "unbound existing next-probes should expose a missing expected hash error.")
    assert_true(missing_control.get("input_artifact_errors", [{}])[0].get("error") == "missing_expected_next_probes_sha256", "loop_control should carry missing expected hash input artifact errors.")
    assert_true(missing_control.get("current_next_probes_sha256") == file_sha256(missing_dir / "next-probes.json"), "loop_control should expose the current next-probes hash when expected hash binding is missing.")
    assert_true(missing_control.get("stop_before_cycle") == "next_probes_hash_missing", "loop_control should expose the missing-hash pre-cycle stop.")

    unavailable_dir = tmp_path / "agent-preview-unavailable"
    unavailable_dir.mkdir(parents=True, exist_ok=True)
    write_json(unavailable_dir / "test-matrix.json", {"schemaVersion": 2, "requirements": [], "tests": []})
    write_json(unavailable_dir / "test-plan.json", {"schemaVersion": 2, "baseUrl": "http://127.0.0.1:9527", "scenarios": []})
    unavailable_calls: list[list[str]] = []

    def fake_unavailable_run_command(command: list[str], cwd: Path) -> dict[str, Any]:
        unavailable_calls.append(command)
        return {"command": command, "cwd": str(cwd), "exit_code": 0, "stdout": "", "stderr": ""}

    try:
        module.run_command = fake_unavailable_run_command
        sys.argv = [
            "qa_agent_loop.py",
            "--run-dir",
            str(unavailable_dir),
            "--max-iterations",
            "1",
            "--apply-existing-next-probes",
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            unavailable_exit = module.main()
    finally:
        module.run_command = original_run_command
        sys.argv = original_argv

    unavailable_summary = load_json(unavailable_dir / "qa-agent-summary.json")
    unavailable_action = unavailable_summary.get("next_action") or {}
    unavailable_control = unavailable_summary.get("loop_control") or {}
    assert_true(unavailable_exit == 1, "agent loop should stop when --apply-existing-next-probes is explicit but next-probes.json is unavailable.")
    assert_true(unavailable_calls == [], "agent loop must not start a cycle when explicit next-probe application cannot find next-probes.json.")
    assert_true(unavailable_summary.get("stop_reason") == "next_probes_unavailable", "unavailable existing next-probes should produce a specific stop reason.")
    assert_true(unavailable_action.get("action") == "repreview_next_probes", "unavailable existing next-probes should ask for repreview.")
    assert_true(unavailable_action.get("input_artifact_errors", [{}])[0].get("error") == "missing", "unavailable existing next-probes should expose the missing artifact error.")
    assert_true(unavailable_control.get("input_artifact_errors", [{}])[0].get("error") == "missing", "loop_control should carry unavailable next-probes artifact errors.")
    assert_true(unavailable_control.get("stop_before_cycle") == "next_probes_unavailable", "loop_control should expose the unavailable next-probes pre-cycle stop.")


def run_agent_product_defect_handoff_fixture(script_dir: Path, tmp_path: Path) -> None:
    module = load_qa_agent_loop_module(script_dir)
    run_dir = tmp_path / "agent-product-defect-handoff"
    run_dir.mkdir(parents=True, exist_ok=True)
    write_json(run_dir / "test-matrix.json", {"schemaVersion": 2, "requirements": [], "tests": []})
    write_json(run_dir / "test-plan.json", {"schemaVersion": 2, "baseUrl": "http://127.0.0.1:9527", "scenarios": []})

    calls: list[str] = []
    original_argv = sys.argv[:]
    original_run_command = module.run_command

    def fake_run_command(command: list[str], cwd: Path) -> dict[str, Any]:
        joined = " ".join(str(item) for item in command)
        now = datetime_now_for_fixture()
        started_at_epoch = time.time() - 1.0
        if "run_qa_cycle.py" in joined:
            calls.append("cycle")
            write_json(
                run_dir / "qa-run-summary.json",
                {
                    "schema_version": 1,
                    "status": "failed",
                    "started_at": now,
                    "finished_at": now,
                    "steps": [{"name": "generate_verdict", "exit_code": 0}],
                },
            )
            write_json(
                run_dir / "qa-verdict.json",
                {
                    "schema_version": 1,
                    "generated_at": now,
                    "verdict": "failed",
                    "can_claim_pass": False,
                    "reasons": [{"code": "defects_present"}],
                },
            )
            write_json(
                run_dir / "results.json",
                {
                    "schemaVersion": 2,
                    "status": "failed",
                    "console": [{"type": "error", "text": "catalog pane crashed", "url": "http://127.0.0.1:9527/aibox"}],
                    "failedResponses": [{"status": 500, "url": "http://127.0.0.1:9527/api/v1/agents/catalog"}],
                    "requestFailures": [],
                },
            )
            write_json(
                run_dir / "defects.json",
                {
                    "schema_version": 1,
                    "summary": {"finding_count": 1, "severity_counts": {"P1": 1}},
                    "findings": [
                        {
                            "id": "D-fixture",
                            "title": "Session API returns 500",
                            "severity": "P1",
                            "confidence": "High",
                            "layers": ["api"],
                            "affected_tests": ["T-session"],
                            "affected_requirements": [{"id": "R-session", "text": "Session detail API returns messages."}],
                            "expected": "Session detail API returns 200 with persisted messages.",
                            "actual": "GET /api/v1/sessions/fixture returned HTTP 500.",
                            "evidence": [{"id": "runtime-failed_responses-1", "locator": str(run_dir / "results.json"), "status_code": 500}],
                        }
                    ],
                },
            )
            write_json(
                run_dir / "evidence-ledger.json",
                {
                    "schema_version": 2,
                    "runtime_summary": {
                        "probe_status": "failed",
                        "qa_run_id": "fixture-run",
                        "qa_marker": "QA_FIXTURE_MARKER",
                        "console_errors": 1,
                        "failed_responses": 1,
                        "request_failures": 0,
                    },
                    "requirements": [
                        {
                            "id": "R-session",
                            "source": "fixture",
                            "text": "Session detail API returns messages.",
                            "test_ids": ["T-session"],
                            "status": "Failed",
                            "evidence_ids": ["E1"],
                            "notes": "API returned HTTP 500.",
                        }
                    ],
                    "tests": [
                        {
                            "id": "T-session",
                            "requirement_ids": ["R-session"],
                            "type": "api",
                            "expected": "Session detail API returns 200 with persisted messages.",
                            "status": "Failed",
                            "evidence_ids": ["E1"],
                            "notes": "GET /api/v1/sessions/fixture returned HTTP 500.",
                        }
                    ],
                    "evidence": [
                        {
                            "id": "E1",
                            "type": "api_response",
                            "proves": "Session detail API returned HTTP 500.",
                            "current_run": True,
                            "status": "failed",
                            "status_code": 500,
                            "observed_url": "http://127.0.0.1:9527/api/v1/sessions/fixture",
                            "test_ids": ["T-session"],
                            "requirement_ids": ["R-session"],
                            "assertions": ["HTTP status observed: 500"],
                        }
                    ],
                },
            )
            write_json(
                run_dir / "audit-summary.json",
                {
                    "ledger": str(run_dir / "evidence-ledger.json"),
                    "results": str(run_dir / "results.json"),
                    "requirement_count": 1,
                    "test_count": 1,
                    "evidence_count": 1,
                    "status_counts": {"Passed": 0, "Failed": 1, "Blocked": 0, "Untested": 0, "Inconclusive": 0},
                    "passed": False,
                    "errors": ["Requirement R-session is Failed but has current-run API evidence for diagnosis."],
                    "warnings": [],
                    "input_artifact_errors": [],
                },
            )
            write_json(
                run_dir / "plan-audit-summary.json",
                {
                    "plan": str(run_dir / "test-plan.json"),
                    "matrix": str(run_dir / "test-matrix.json"),
                    "requirement_count": 2,
                    "test_count": 2,
                    "scenario_count": 1,
                    "step_count": 1,
                    "mapped_executable_test_count": 1,
                    "mapped_executable_requirement_count": 1,
                    "passed": True,
                    "errors": [],
                    "warnings": [],
                    "strategy_coverage": {
                        "schema_version": 1,
                        "dimension_order": ["ui", "api", "stream", "persistence"],
                        "dimensions": {
                            "api": {
                                "planned_count": 1,
                                "executable_count": 1,
                                "blocked_count": 0,
                                "untested_count": 0,
                                "inconclusive_count": 0,
                                "test_ids": ["T-session"],
                            },
                            "persistence": {
                                "planned_count": 1,
                                "executable_count": 0,
                                "blocked_count": 1,
                                "untested_count": 0,
                                "inconclusive_count": 0,
                                "test_ids": ["T-persist"],
                            },
                        },
                        "covered_dimensions": ["api"],
                        "gap_count": 1,
                        "gaps": [
                            {
                                "dimension": "persistence",
                                "reason": "no_executable_probe",
                                "planned_count": 1,
                                "blocked_count": 1,
                                "untested_count": 0,
                                "test_ids": ["T-persist"],
                            }
                        ],
                    },
                },
            )
            write_json(
                run_dir / "requirement-coverage.json",
                {
                    "schema_version": 1,
                    "requirement_unit_count": 2,
                    "matrix_requirement_count": 1,
                    "covered_count": 1,
                    "uncovered_count": 1,
                    "passed": False,
                    "coverage": [
                        {
                            "id": "S1",
                            "source": "line 1",
                            "text": "Session detail API returns messages.",
                            "covered": True,
                            "matches": [{"requirement_id": "R-session", "method": "text_contains", "score": 1.0}],
                        },
                        {
                            "id": "S2",
                            "source": "line 2",
                            "text": "Persisted turn should reach completed.",
                            "covered": False,
                            "matches": [],
                        },
                    ],
                    "errors": ["S2 (line 2) is not mapped to any matrix requirement: Persisted turn should reach completed."],
                    "warnings": [],
                    "input_artifact_errors": [],
                },
            )
            write_json(
                run_dir / "next-probes.json",
                {
                    "schema_version": 1,
                    "summary": {"recommendation_count": 2},
                    "recommendations": [
                        {"id": "NP-diagnose-after-defect", "layer": "api", "reason": "diagnose current API failure"},
                        {"id": "NP-live-stream-proof", "layer": "stream", "reason": "prove stream terminal status"},
                    ],
                },
            )
            return {
                "command": command,
                "cwd": str(cwd),
                "started_at": now,
                "started_at_epoch": started_at_epoch,
                "finished_at": now,
                "finished_at_epoch": time.time(),
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
            }
        if "apply_next_probes.py" in joined:
            calls.append("preview")
            write_json(
                run_dir / "next-probe-preview.json",
                {
                    "schema_version": 1,
                    "summary": {
                        "recommendation_count": 2,
                        "applied_count": 1,
                        "skipped_count": 1,
                        "applied_layer_counts": {"api": 1},
                        "skipped_reason_counts": {"live stream probes require --allow-live-stream": 1},
                    },
                    "applied_recommendations": [
                        {
                            "id": "NP-diagnose-after-defect",
                            "step_id": "diagnose-after-defect",
                            "layer": "api",
                            "test_ids": ["T-session"],
                            "requirement_ids": ["R-session"],
                        }
                    ],
                    "skipped_recommendations": [
                        {
                            "id": "NP-live-stream-proof",
                            "reason": "live stream probes require --allow-live-stream",
                            "layer": "stream",
                            "source_test_id": "T-persist",
                        }
                    ],
                },
            )
            return {
                "command": command,
                "cwd": str(cwd),
                "started_at": now,
                "started_at_epoch": started_at_epoch,
                "finished_at": now,
                "finished_at_epoch": time.time(),
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
            }
        return original_run_command(command, cwd)

    try:
        module.run_command = fake_run_command
        sys.argv = ["qa_agent_loop.py", "--run-dir", str(run_dir), "--max-iterations", "3"]
        with contextlib.redirect_stdout(io.StringIO()):
            exit_code = module.main()
    finally:
        module.run_command = original_run_command
        sys.argv = original_argv

    agent_summary = load_json(run_dir / "qa-agent-summary.json")
    next_action = agent_summary.get("next_action") or {}
    handoff_text = Path(str(agent_summary.get("handoff"))).read_text(encoding="utf-8")
    assert_true(exit_code == 0, "product defect handoff should be a completed QA cycle, not a tool failure.")
    assert_true(calls == ["cycle", "preview"], "product defects should preview once but must not auto-run a second cycle.")
    assert_true(len(agent_summary.get("iterations") or []) == 1, "product defect handoff should stop after the first iteration.")
    assert_true(agent_summary.get("status") == "failed", "agent summary should preserve the failed verdict.")
    assert_true(agent_summary.get("stop_reason") == "next_action_requires_handoff", "auto-continue policy should stop the main loop for product defects.")
    assert_true(next_action.get("action") == "report_product_defect", "product defect policy should expose report_product_defect.")
    assert_true(next_action.get("preview_applied_count") == 1, "product defect policy should retain the previewed safe follow-up count.")
    assert_true(next_action.get("failure_analysis", {}).get("category") == "product_defect", "product defect handoff should preserve product_defect analysis.")
    decision_summary = next_action.get("decision_summary") or {}
    defect_findings = decision_summary.get("defect_findings") or []
    assert_true(defect_findings and defect_findings[0].get("severity") == "P1", "product defect handoff should expose defect severity in decision_summary.")
    assert_true(defect_findings[0].get("title") == "Session API returns 500", "product defect handoff should expose the defect title in decision_summary.")
    assert_true(decision_summary.get("runtime_issue_counts", {}).get("failed_responses") == 1, "product defect handoff should summarize supporting failed response evidence.")
    evidence_layers = decision_summary.get("evidence_layer_summary") or {}
    assert_true(evidence_layers.get("requirement_status_counts", {}).get("Failed") == 1, "decision_summary should expose failed requirement counts from current audit/ledger evidence.")
    assert_true(evidence_layers.get("proof_layer_counts", {}).get("api") == 1, "decision_summary should expose API proof-layer evidence counts.")
    assert_true(evidence_layers.get("audit", {}).get("error_count") == 1, "decision_summary should summarize current audit errors for handoff.")
    strategy = decision_summary.get("strategy_coverage") or {}
    assert_true(strategy.get("gap_count") == 1, "decision_summary should expose plan strategy coverage gaps.")
    assert_true((strategy.get("gaps") or [{}])[0].get("dimension") == "persistence", "strategy gap summary should preserve the missing proof dimension.")
    source_coverage = decision_summary.get("source_coverage") or {}
    assert_true(source_coverage.get("uncovered_count") == 1, "decision_summary should expose unmapped requirement source units.")
    assert_true("Persisted turn should reach completed" in (source_coverage.get("uncovered_examples") or [{}])[0].get("text", ""), "source coverage summary should preserve the unmapped requirement text.")
    followups = decision_summary.get("follow_up_summary") or {}
    preview_followups = followups.get("preview") or {}
    assert_true(preview_followups.get("applied_count") == 1, "decision_summary should expose previewed safe follow-up counts.")
    assert_true((preview_followups.get("applied_examples") or [{}])[0].get("id") == "NP-diagnose-after-defect", "decision_summary should expose previewed follow-up ids.")
    assert_true(preview_followups.get("actionable_skipped_count") == 1, "decision_summary should expose actionable blocked follow-up counts.")
    assert_true("Auto-continue blocked" in handoff_text and "report_product_defect" in handoff_text, "handoff markdown should explain the product-defect stop.")
    assert_true("Decision Summary" in handoff_text and "Session API returns 500" in handoff_text, "handoff markdown should render reportable defect details.")
    assert_true("Follow-Up Probes" in handoff_text and "NP-diagnose-after-defect" in handoff_text, "handoff markdown should render concrete follow-up probe ids.")
    assert_true("Evidence Layers" in handoff_text and "Requirement statuses" in handoff_text, "handoff markdown should render evidence-layer status counts.")
    assert_true("Strategy Coverage" in handoff_text and "persistence" in handoff_text, "handoff markdown should render strategy coverage gaps.")
    assert_true("Requirement Source Coverage" in handoff_text and "Persisted turn should reach completed" in handoff_text, "handoff markdown should render source coverage gaps.")
    defect_control = agent_summary.get("loop_control") or {}
    assert_true(defect_control.get("terminal") is True, "product defect loop_control should be terminal for the current process.")
    assert_true(defect_control.get("handoff_required") is True, "product defect loop_control should require a defect handoff.")
    assert_true(defect_control.get("blocking_category") == "product_defect", "product defect loop_control should carry the failure category.")
    assert_true(defect_control.get("result_ready_to_report") is True, "product defect loop_control should mark the evidence-backed result as reportable.")
    control_decision_summary = defect_control.get("decision_summary") or {}
    assert_true((control_decision_summary.get("defect_findings") or [{}])[0].get("title") == "Session API returns 500", "product defect loop_control should expose compact defect findings.")
    assert_true(control_decision_summary.get("runtime_issue_counts", {}).get("failed_responses") == 1, "product defect loop_control should expose runtime issue counts.")
    assert_true(control_decision_summary.get("strategy_coverage", {}).get("gap_count") == 1, "product defect loop_control should expose strategy coverage gaps.")
    assert_true(control_decision_summary.get("source_coverage", {}).get("uncovered_count") == 1, "product defect loop_control should expose requirement source coverage gaps.")


def datetime_now_for_fixture() -> str:
    return datetime.now().isoformat(timespec="seconds")


def run_agent_initialization_failure_fixture(script_dir: Path, tmp_path: Path) -> None:
    summary_path = tmp_path / "agent-init-failure-summary.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "qa_agent_loop.py"),
            "--requirement-file",
            str(tmp_path / "missing-requirement.md"),
            "--out-dir",
            str(tmp_path / "agent-init-failure-out"),
            "--summary",
            str(summary_path),
            "--skip-adapter-context",
        ],
        cwd=str(tmp_path),
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "agent loop should exit non-zero when initialization fails.")
    assert_true(summary_path.exists(), "agent loop should write qa-agent-summary.json even when initialization fails before a run directory exists.")
    assert_true("Traceback" not in proc.stderr, "agent loop should not expose initialization failure as a raw traceback.")
    summary = load_json(summary_path)
    next_action = summary.get("next_action") if isinstance(summary.get("next_action"), dict) else {}
    failure_analysis = summary.get("failure_analysis") if isinstance(summary.get("failure_analysis"), dict) else {}
    handoff_path = Path(str(summary.get("handoff") or ""))
    run_dir = Path(str(summary.get("run_dir") or ""))
    assert_true(summary.get("status") == "failed", "initialization failure summary should be failed.")
    assert_true(summary.get("stop_reason") == "initialization_failed", "initialization failure summary should record stop_reason.")
    assert_true(handoff_path.exists(), "initialization failure should write a human-readable qa-agent-handoff.md.")
    handoff_text = handoff_path.read_text(encoding="utf-8")
    assert_true("fix_initialization_inputs" in handoff_text, "initialization failure handoff should name the corrective next_action.")
    assert_true("initialization_input_failure" in handoff_text, "initialization failure handoff should include the failure category.")
    assert_true(run_dir.exists(), "initialization failure summary should preserve the blocked initialization run directory when init created one.")
    init_error = load_json(run_dir / "qa-initialization-error.json")
    scaffold_summary = load_json(run_dir / "scaffold-summary.json")
    summary_errors = {item.get("name"): item.get("error") for item in summary.get("input_artifact_errors", []) if isinstance(item, dict)}
    action_errors = {item.get("name"): item.get("error") for item in next_action.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(init_error.get("input_artifact_errors", [{}])[0].get("name") == "requirement", "initialization error should name the unreadable requirement input.")
    assert_true(scaffold_summary.get("input_artifact_errors", [{}])[0].get("name") == "requirement", "scaffold summary should preserve initialization input errors.")
    assert_true(summary_errors.get("requirement") == "missing", "agent initialization summary should expose unreadable requirement input errors.")
    assert_true(action_errors.get("requirement") == "missing", "agent initialization next_action should expose unreadable requirement input errors.")
    assert_true((summary.get("init") or {}).get("exit_code") != 0, "initialization failure summary should preserve the failed init command result.")
    assert_true(next_action.get("action") == "fix_initialization_inputs", "initialization failure should expose a machine-readable corrective next_action.")
    assert_true(failure_analysis.get("blocking_layer") == "requirement_intake", "initialization failures should be classified at the requirement intake layer.")
    assert_true(next_action.get("failure_analysis", {}).get("category") == "initialization_input_failure", "initialization next_action should carry failure analysis.")
    init_control = summary.get("loop_control") or {}
    assert_true(init_control.get("terminal") is True, "initialization failure loop_control should be terminal.")
    assert_true(init_control.get("requires_input_repair") is True, "initialization failure loop_control should expose required input repair.")
    assert_true(init_control.get("handoff_required") is True, "initialization failure loop_control should require handoff.")


def run_scaffold_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "scaffold-input-errors"
    requirement_path = input_dir / "requirement-source.md"
    run_dir = input_dir / "run"
    requirement_path.mkdir(parents=True)

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(requirement_path),
            "--run-dir",
            str(run_dir),
            "--base-url",
            "http://127.0.0.1:9527",
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "scaffold_requirement should exit non-zero for unreadable requirement input.")
    assert_true((run_dir / "scaffold-summary.json").exists(), "scaffold_requirement should write scaffold-summary.json for unreadable requirement input.")
    summary = load_json(run_dir / "scaffold-summary.json")
    matrix = load_json(run_dir / "test-matrix.json")
    plan = load_json(run_dir / "test-plan.json")
    input_errors = {item.get("name"): item.get("error") for item in summary.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(input_errors.get("requirement") == "path_is_directory", "scaffold_requirement should classify directory-shaped requirement input.")
    assert_true(summary.get("status") == "blocked", "scaffold input errors should produce a blocked summary.")
    assert_true(matrix.get("requirements", [{}])[0].get("status") == "Blocked", "scaffold input errors should produce blocked matrix requirements.")
    assert_true(plan.get("scenarios", [{}])[0].get("steps") == [], "scaffold input errors should not synthesize product probes.")
    assert_true("Traceback" not in proc.stderr, "scaffold_requirement should report bad requirement input without a Python traceback.")


def run_init_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    out_dir = tmp_path / "init-input-errors"
    missing_requirement = tmp_path / "missing-init-requirement.md"
    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "init_qa_artifact.py"),
            "--requirement-file",
            str(missing_requirement),
            "--out-dir",
            str(out_dir),
            "--slug",
            "init-input-errors",
            "--base-url",
            "http://127.0.0.1:9527",
            "--skip-adapter-context",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "init_qa_artifact should exit non-zero for unreadable requirement input.")
    run_dir = last_path(proc.stdout)
    assert_true(run_dir.exists(), "init_qa_artifact should print and create a blocked initialization run directory.")
    init_error = load_json(run_dir / "qa-initialization-error.json")
    scaffold_summary = load_json(run_dir / "scaffold-summary.json")
    ledger = load_json(run_dir / "evidence-ledger.json")
    input_errors = {item.get("name"): item.get("error") for item in init_error.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(input_errors.get("requirement") == "missing", "init_qa_artifact should classify missing requirement input.")
    assert_true(scaffold_summary.get("status") == "blocked", "init input errors should write a blocked scaffold summary.")
    assert_true(ledger.get("requirements", [{}])[0].get("status") == "Blocked", "init input errors should seed a blocked evidence ledger.")
    assert_true("Traceback" not in proc.stderr, "init_qa_artifact should report bad requirement input without a Python traceback.")


def run_init_adapter_context_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    out_dir = tmp_path / "init-adapter-context-input-errors"
    requirement_path = tmp_path / "adapter-context-requirement.md"
    missing_root = tmp_path / "missing-project-root"
    requirement_path.write_text("- Verify the page at /aibox can be tested only after project context is valid.\n", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "init_qa_artifact.py"),
            "--requirement-file",
            str(requirement_path),
            "--project-root",
            str(missing_root),
            "--out-dir",
            str(out_dir),
            "--slug",
            "init-adapter-context-input-errors",
            "--base-url",
            "http://127.0.0.1:9527",
            "--no-http-probe",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "init_qa_artifact should exit non-zero for unreadable project-root adapter context.")
    run_dir = last_path(proc.stdout)
    assert_true(run_dir.exists(), "init_qa_artifact should create a blocked run directory for unreadable project roots.")
    init_error = load_json(run_dir / "qa-initialization-error.json")
    scaffold_summary = load_json(run_dir / "scaffold-summary.json")
    adapter_context = load_json(run_dir / "adapter-context.json")
    input_errors = {item.get("name"): item.get("error") for item in init_error.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(input_errors.get("project_root") == "missing", "init_qa_artifact should preserve project-root input errors from adapter context.")
    assert_true(adapter_context.get("project_root_status", {}).get("readable") is False, "adapter context should mark unreadable project-root status.")
    assert_true(scaffold_summary.get("status") == "blocked", "adapter context input errors should block initialization summary.")
    assert_true(scaffold_summary.get("planned_step_count", 0) >= 0, "adapter context input errors should still leave scaffold artifacts readable.")
    assert_true("Traceback" not in proc.stderr, "init_qa_artifact should report adapter context input errors without a Python traceback.")


def run_agent_snapshot_shape_fixture(script_dir: Path, tmp_path: Path) -> None:
    module = load_qa_agent_loop_module(script_dir)
    snapshot_dir = tmp_path / "agent-snapshot-shape"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    write_json(snapshot_dir / "adapter-context.json", {"schema_version": 1, "adapter": "fixture"})
    write_json(snapshot_dir / "adapter-probes.json", {"schema_version": 1, "summary": {"applied_count": 0}})
    write_json(snapshot_dir / "service-preflight.json", {"schema_version": 1, "summary": {"blocker_count": 0}})
    write_json(snapshot_dir / "service-runtime.json", {"schema_version": 1, "summary": {"ready_count": 0}})
    write_json(snapshot_dir / "results.json", {"schemaVersion": 2, "status": "passed"})
    cycle_error_source = snapshot_dir / "qa-cycle-error.json"
    cycle_error_source.mkdir()
    (cycle_error_source / "details.json").write_text('{"code":"fixture"}\n', encoding="utf-8")

    stale_file_target = snapshot_dir / "iterations" / "01" / "results.json"
    stale_file_target.mkdir(parents=True)
    (stale_file_target / "stale.txt").write_text("old directory shape", encoding="utf-8")
    stale_dir_target = snapshot_dir / "iterations" / "01" / "qa-cycle-error.json"
    write_json(stale_dir_target, {"code": "old-file-shape"})

    snapshot = module.snapshot_iteration(snapshot_dir, 1)
    assert_true(snapshot.get("errors") == [], "snapshot shape replacement should not record copy errors.")
    assert_true("adapter-context.json" in snapshot.get("copied", []), "snapshot should copy adapter context evidence.")
    assert_true("adapter-probes.json" in snapshot.get("copied", []), "snapshot should copy adapter probe evidence.")
    assert_true("service-preflight.json" in snapshot.get("copied", []), "snapshot should copy service preflight evidence.")
    assert_true("service-runtime.json" in snapshot.get("copied", []), "snapshot should copy service runtime evidence.")
    assert_true("results.json" in snapshot.get("copied", []), "snapshot should copy file artifacts after removing stale directory targets.")
    assert_true("qa-cycle-error.json" in snapshot.get("copied", []), "snapshot should copy directory artifacts after removing stale file targets.")
    assert_true((snapshot_dir / "iterations" / "01" / "adapter-context.json").is_file(), "snapshot should preserve adapter context artifacts.")
    assert_true((snapshot_dir / "iterations" / "01" / "service-runtime.json").is_file(), "snapshot should preserve service runtime artifacts.")
    assert_true((snapshot_dir / "iterations" / "01" / "results.json").is_file(), "snapshot should replace stale directory target with current file artifact.")
    assert_true((snapshot_dir / "iterations" / "01" / "qa-cycle-error.json").is_dir(), "snapshot should replace stale file target with current directory artifact.")
    assert_true(load_json(snapshot_dir / "iterations" / "01" / "results.json").get("status") == "passed", "snapshot file artifact should contain the current source JSON.")


def run_cycle_terminal_cleanup_fixture(script_dir: Path, tmp_path: Path) -> None:
    cleanup_dir = tmp_path / "cycle-terminal-cleanup"
    cleanup_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        cleanup_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "scenarios": [],
        },
    )
    write_json(
        cleanup_dir / "qa-verdict.json",
        {
            "schema_version": 1,
            "verdict": "passed",
            "can_claim_pass": True,
            "statement": "stale pass from an earlier run",
        },
    )
    (cleanup_dir / "report.md").write_text("# Stale pass report\n", encoding="utf-8")
    (cleanup_dir / "qa-cycle-error.json").mkdir()
    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(cleanup_dir),
        ],
        cwd=str(cleanup_dir),
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "cycle with a missing matrix should fail.")
    assert_true((cleanup_dir / "qa-verdict.json").is_file(), "run_qa_cycle should replace a stale verdict with a current non-pass handoff.")
    assert_true(not (cleanup_dir / "report.md").exists(), "run_qa_cycle should remove a stale report before a new cycle can fail early.")
    assert_true((cleanup_dir / "qa-cycle-error.json").is_file(), "run_qa_cycle should replace a stale cycle-error directory with a current error file.")
    summary = load_json(cleanup_dir / "qa-run-summary.json")
    cycle_error = load_json(cleanup_dir / "qa-cycle-error.json")
    verdict = load_json(cleanup_dir / "qa-verdict.json")
    cleared = {item.get("name"): item for item in summary.get("cleared_stale_outputs", [])}
    cleared_names = set(cleared)
    reason_codes = {reason.get("code") for reason in verdict.get("reasons", [])}
    assert_true(summary.get("status") != "passed", "early failed cycle should write a current non-pass qa-run-summary.json.")
    assert_true(cycle_error.get("code") == "missing_required_qa_artifact", "missing matrix should be recorded as a structured cycle error.")
    assert_true(cycle_error.get("phase") == "required_artifacts", "missing required artifacts should be reported with a dedicated phase.")
    assert_true(verdict.get("can_claim_pass") is False, "missing required artifacts must block pass claims.")
    assert_true("missing_required_qa_artifact" in reason_codes, "verdict should include the missing required artifact cycle-error code.")
    assert_true(summary.get("cycle_error", {}).get("code") == "missing_required_qa_artifact", "cycle summary should embed the structured missing artifact error.")
    assert_true({"verdict", "report", "cycle_error"}.issubset(cleared_names), "cycle summary should list cleared stale terminal artifacts.")
    assert_true(cleared.get("cycle_error", {}).get("kind") == "directory", "cycle summary should record stale terminal directory cleanup.")


def write_valid_skip_probe_plan(run_dir: Path) -> None:
    write_json(
        run_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-existing-results",
                    "source": "fixture",
                    "text": "Planning-only cycles must not trust unreadable existing results artifacts.",
                    "test_ids": ["T-existing-results"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-existing-results",
                    "requirement_ids": ["R-existing-results"],
                    "type": "api",
                    "steps": ["Use an existing results.json only when it is readable JSON."],
                    "expected": "Unreadable results artifacts become a structured QA cycle error.",
                    "required_evidence": ["qa-cycle-error.json", "qa-verdict.json"],
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        run_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(run_dir),
            "scenarios": [
                {
                    "id": "existing-results",
                    "steps": [
                        {
                            "action": "api",
                            "id": "T-existing-results-health",
                            "testIds": ["T-existing-results"],
                            "requirementIds": ["R-existing-results"],
                            "method": "GET",
                            "path": "/health",
                            "expectStatus": 200,
                            "evidenceType": "api",
                            "proves": "Existing results can only be reused when the results artifact is readable.",
                        }
                    ],
                }
            ],
        },
    )


def run_required_artifact_unreadable_fixture(script_dir: Path, tmp_path: Path) -> None:
    cases = (
        ("malformed-plan", "test-plan.json", "{not-json", "invalid_json"),
        ("non-object-plan", "test-plan.json", "[]", "json_root_not_object"),
        ("directory-matrix", "test-matrix.json", None, "path_is_directory"),
    )
    for name, artifact_name, replacement_text, expected_error in cases:
        case_dir = tmp_path / f"required-artifact-unreadable-{name}"
        case_dir.mkdir(parents=True, exist_ok=True)
        write_valid_skip_probe_plan(case_dir)
        artifact_path = case_dir / artifact_name
        if replacement_text is None:
            artifact_path.unlink()
            artifact_path.mkdir()
        else:
            artifact_path.write_text(replacement_text, encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable,
                str(script_dir / "run_qa_cycle.py"),
                "--run-dir",
                str(case_dir),
                "--skip-probe",
                "--skip-report",
            ],
            cwd=str(case_dir),
            text=True,
            capture_output=True,
        )
        assert_true(proc.returncode != 0, f"cycle with unreadable {name} artifact should fail.")
        assert_true("Traceback" not in proc.stderr, f"cycle with unreadable {name} artifact should not crash with a traceback.")
        cycle_summary = load_json(case_dir / "qa-run-summary.json")
        cycle_error = load_json(case_dir / "qa-cycle-error.json")
        cycle_verdict = load_json(case_dir / "qa-verdict.json")
        reason_codes = {reason.get("code") for reason in cycle_verdict.get("reasons", [])}
        step_names = {step.get("name") for step in cycle_summary.get("steps", [])}
        assert_true(cycle_error.get("code") == "invalid_required_qa_artifact", f"cycle error should identify invalid required artifact for {name}.")
        assert_true(cycle_error.get("phase") == "required_artifacts", "invalid required artifacts should be reported before helper execution.")
        assert_true(expected_error in str(cycle_error.get("message")), f"cycle error message should include {expected_error} for {name}.")
        assert_true(cycle_verdict.get("can_claim_pass") is False, "invalid required artifacts must block pass claims.")
        assert_true("invalid_required_qa_artifact" in reason_codes, "verdict should include the invalid required artifact cycle-error code.")
        assert_true("validate_plan" not in step_names, "invalid required artifacts should stop before plan validation.")
        assert_true(cycle_summary.get("cycle_error", {}).get("code") == "invalid_required_qa_artifact", "cycle summary should embed the structured invalid artifact error.")


def run_adapter_context_unreadable_fixture(script_dir: Path, tmp_path: Path) -> None:
    cases = (
        ("malformed-json", lambda path: path.write_text("{not-json", encoding="utf-8"), "invalid_json"),
        ("directory", lambda path: path.mkdir(), "path_is_directory"),
    )
    for name, make_bad_context, expected_error in cases:
        case_dir = tmp_path / f"adapter-context-unreadable-{name}"
        case_dir.mkdir(parents=True, exist_ok=True)
        write_valid_skip_probe_plan(case_dir)
        make_bad_context(case_dir / "adapter-context.json")
        proc = subprocess.run(
            [
                sys.executable,
                str(script_dir / "run_qa_cycle.py"),
                "--run-dir",
                str(case_dir),
                "--skip-probe",
                "--skip-report",
                "--runtime-mode",
                "test",
                "--data-boundary-status",
                "fixture data only; no production data",
            ],
            cwd=str(case_dir),
            text=True,
            capture_output=True,
        )
        assert_true(proc.returncode != 0, f"cycle with unreadable adapter context {name} should fail.")
        assert_true("Traceback" not in proc.stderr, f"cycle with unreadable adapter context {name} should not crash with a traceback.")
        cycle_summary = load_json(case_dir / "qa-run-summary.json")
        cycle_error = load_json(case_dir / "qa-cycle-error.json")
        cycle_verdict = load_json(case_dir / "qa-verdict.json")
        reason_codes = {reason.get("code") for reason in cycle_verdict.get("reasons", [])}
        step_names = {step.get("name") for step in cycle_summary.get("steps", [])}
        omitted = cycle_summary.get("omitted_stale_handoff_artifacts", [])
        omitted_reasons = {item.get("reason") for item in omitted if item.get("flag") == "--adapter-context"}
        assert_true(cycle_error.get("code") == "invalid_adapter_context", "cycle error should identify invalid adapter context.")
        assert_true(cycle_error.get("phase") == "adapter_context", "invalid adapter context should be reported in the adapter_context phase.")
        assert_true(expected_error in str(cycle_error.get("message")), f"cycle error message should include {expected_error}.")
        assert_true(cycle_verdict.get("can_claim_pass") is False, "invalid adapter context must block pass claims.")
        assert_true("invalid_adapter_context" in reason_codes, "verdict should include the invalid adapter context cycle-error code.")
        assert_true("validate_plan" not in step_names, "invalid adapter context should stop before plan validation.")
        assert_true(any(str(reason).startswith("unreadable_input:") for reason in omitted_reasons), "handoff should omit unreadable adapter context instead of passing it to verdict generation.")
        assert_true(cycle_summary.get("cycle_error", {}).get("code") == "invalid_adapter_context", "cycle summary should embed the structured adapter-context error.")


def run_skip_probe_unreadable_results_fixture(script_dir: Path, tmp_path: Path) -> None:
    for name, make_bad_results in (
        ("malformed-json", lambda path: path.write_text("{not-json", encoding="utf-8")),
        ("directory", lambda path: path.mkdir()),
    ):
        case_dir = tmp_path / f"skip-probe-unreadable-results-{name}"
        case_dir.mkdir(parents=True, exist_ok=True)
        write_valid_skip_probe_plan(case_dir)
        make_bad_results(case_dir / "results.json")
        proc = subprocess.run(
            [
                sys.executable,
                str(script_dir / "run_qa_cycle.py"),
                "--run-dir",
                str(case_dir),
                "--skip-probe",
                "--skip-report",
            ],
            cwd=str(case_dir),
            text=True,
            capture_output=True,
        )
        assert_true(proc.returncode != 0, f"skip-probe cycle with unreadable {name} results should fail.")
        assert_true("Traceback" not in proc.stderr, f"skip-probe cycle with unreadable {name} results should not crash with a traceback.")
        cycle_summary = load_json(case_dir / "qa-run-summary.json")
        cycle_error = load_json(case_dir / "qa-cycle-error.json")
        cycle_verdict = load_json(case_dir / "qa-verdict.json")
        reason_codes = {reason.get("code") for reason in cycle_verdict.get("reasons", [])}
        assert_true(cycle_error.get("code") == "skip_probe_results_unreadable", f"cycle error should identify unreadable {name} results.")
        assert_true(cycle_error.get("phase") == "probe", "unreadable existing results should be reported as a probe-phase handoff.")
        assert_true(cycle_verdict.get("can_claim_pass") is False, "unreadable existing results must block pass claims.")
        assert_true("skip_probe_results_unreadable" in reason_codes, "verdict should include the unreadable results cycle-error code.")
        assert_true(cycle_summary.get("cycle_error", {}).get("code") == "skip_probe_results_unreadable", "cycle summary should embed the structured cycle error.")


def run_preflight_blocker_handoff_fixture(script_dir: Path, tmp_path: Path) -> None:
    blocker_dir = tmp_path / "preflight-blocker-handoff"
    blocker_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        blocker_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-setup",
                    "source": "fixture",
                    "text": "Required service readiness must be checked before probes run.",
                    "test_ids": ["T-setup"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-setup",
                    "requirement_ids": ["R-setup"],
                    "type": "runtime",
                    "expected": "Preflight produces a setup blocker when a required service path is missing.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        blocker_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:65530",
            "artifactDir": str(blocker_dir),
            "scenarios": [],
        },
    )
    write_json(
        blocker_dir / "adapter-context.json",
        {
            "schema_version": 1,
            "adapter": "fixture",
            "project_root": str(blocker_dir),
            "base_url": "http://127.0.0.1:65530",
            "environment_boundary": {
                "runtime_mode": "test",
                "data_boundary_status": "fixture data only; no production data",
            },
            "services": [
                {
                    "id": "fixture-api",
                    "role": "api",
                    "path": "missing-fixture-service",
                    "path_exists": False,
                    "default_url": "http://127.0.0.1:65530",
                    "port": 65530,
                    "port_open": True,
                    "start_command": "python3 -m http.server 65530",
                }
            ],
        },
    )

    cycle_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(blocker_dir),
            "--preflight-runtime",
            "--required-service",
            "fixture-api",
            "--project-root",
            str(blocker_dir),
            "--runtime-mode",
            "test",
            "--data-boundary-status",
            "fixture data only; no production data",
        ],
        cwd=blocker_dir,
        text=True,
        capture_output=True,
    )
    assert_true(cycle_proc.returncode != 0, "preflight blocker cycle should exit non-zero.")
    cycle_summary = load_json(blocker_dir / "qa-run-summary.json")
    cycle_verdict = load_json(blocker_dir / "qa-verdict.json")
    cycle_codes = {reason.get("code") for reason in cycle_verdict.get("reasons", [])}
    assert_true(cycle_summary.get("status") == "blocked", "preflight blocker cycle summary should be blocked.")
    assert_true(cycle_verdict.get("verdict") == "blocked", "preflight blocker cycle should write a blocked verdict.")
    assert_true(cycle_verdict.get("can_claim_pass") is False, "preflight blocker verdict must not allow pass.")
    assert_true("preflight_blocked" in cycle_codes, "preflight blocker verdict should include preflight_blocked.")
    assert_true(cycle_summary.get("verdict", {}).get("verdict") == "blocked", "cycle summary should embed the early verdict.")

    loop_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "qa_agent_loop.py"),
            "--run-dir",
            str(blocker_dir),
            "--preflight-runtime",
            "--required-service",
            "fixture-api",
            "--project-root",
            str(blocker_dir),
            "--runtime-mode",
            "test",
            "--data-boundary-status",
            "fixture data only; no production data",
            "--max-iterations",
            "1",
        ],
        cwd=blocker_dir,
        text=True,
        capture_output=True,
    )
    assert_true(loop_proc.returncode != 0, "agent loop should keep non-zero exit when setup is blocked.")
    agent_summary = load_json(blocker_dir / "qa-agent-summary.json")
    assert_true(agent_summary.get("status") == "blocked", "agent loop should preserve blocked status from early verdict.")
    assert_true(agent_summary.get("stop_reason") == "cycle_stopped_with_verdict", "agent loop should distinguish verdict-backed cycle stop from generic failure.")
    assert_true((agent_summary.get("next_action") or {}).get("action") == "report_setup_blocker", "agent loop next_action should report setup blocker.")
    assert_true(agent_summary.get("failure_analysis", {}).get("category") == "setup_environment_blocker", "setup blocker should be classified separately from product defects.")
    assert_true((agent_summary.get("next_action") or {}).get("failure_analysis", {}).get("blocking_layer") == "runtime_setup", "setup next_action should expose the runtime setup blocking layer.")


def run_agent_service_start_next_action_fixture(script_dir: Path, tmp_path: Path) -> None:
    start_plan_dir = tmp_path / "agent-service-start-next-action"
    start_plan_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        start_plan_dir / "test-matrix.json",
        {"schemaVersion": 2, "requirements": [], "tests": []},
    )
    write_json(
        start_plan_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:65529",
            "artifactDir": str(start_plan_dir),
            "scenarios": [],
        },
    )
    write_json(
        start_plan_dir / "adapter-context.json",
        {
            "schema_version": 1,
            "adapter": "fixture",
            "project_root": str(start_plan_dir),
            "base_url": "http://127.0.0.1:65529",
            "environment_boundary": {
                "runtime_mode": "test",
                "data_boundary_status": "fixture data only; no production data",
            },
            "services": [
                {
                    "id": "fixture-api",
                    "role": "api",
                    "path": ".",
                    "path_exists": True,
                    "default_url": "http://127.0.0.1:65529",
                    "port": 65529,
                    "port_open": False,
                    "start_command": "python3 -m http.server 65529",
                }
            ],
        },
    )

    loop_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "qa_agent_loop.py"),
            "--run-dir",
            str(start_plan_dir),
            "--preflight-runtime",
            "--required-service",
            "fixture-api",
            "--project-root",
            str(start_plan_dir),
            "--runtime-mode",
            "test",
            "--data-boundary-status",
            "fixture data only; no production data",
            "--max-iterations",
            "1",
        ],
        cwd=start_plan_dir,
        text=True,
        capture_output=True,
    )
    assert_true(loop_proc.returncode != 0, "agent loop should stop non-zero when preflight needs service startup authorization.")
    preflight = load_json(start_plan_dir / "service-preflight.json")
    agent_summary = load_json(start_plan_dir / "qa-agent-summary.json")
    next_action = agent_summary.get("next_action") or {}
    handoff_path = Path(str(agent_summary.get("handoff") or ""))
    assert_true((preflight.get("start_plan") or [{}])[0].get("service") == "fixture-api", "preflight should expose a concrete service start_plan.")
    assert_true(next_action.get("action") == "retry_with_service_start", "agent loop should recommend a service-start retry when preflight has start_plan.")
    assert_true(next_action.get("requires_authorization") is True, "service-start retry should require explicit authorization.")
    assert_true(next_action.get("automatable_after_authorization") is True, "service-start retry should be machine-runnable after authorization.")
    assert_true("--start-missing-services" in next_action.get("recommended_flags", []), "service-start retry should name the required authorization flag.")
    assert_true((next_action.get("service_start_plan") or [{}])[0].get("service") == "fixture-api", "agent next_action should carry the compact start plan.")
    assert_true("--start-missing-services" in next_action.get("resume_command_args", []), "agent next_action should carry a runnable resume command.")
    assert_true(next_action.get("failure_analysis", {}).get("category") == "service_start_authorization_required", "service startup authorization should be its own agent failure category.")
    assert_true(agent_summary.get("failure_analysis", {}).get("blocking_layer") == "runtime_setup", "agent summary should mirror service-start runtime setup analysis.")
    start_control = agent_summary.get("loop_control") or {}
    assert_true(start_control.get("requires_authorization") is True, "service-start loop_control should expose authorization need.")
    assert_true(start_control.get("can_continue_after_authorization") is True, "service-start loop_control should expose authorized continuation.")
    assert_true(start_control.get("can_resume_with_command") is True, "service-start loop_control should expose the resume command.")
    assert_true("--start-missing-services" in start_control.get("resume_command_args", []), "service-start loop_control should preserve resume command args.")
    start_human = start_control.get("human_action_required") or {}
    assert_true(start_human.get("type") == "authorization", "service-start loop_control should expose service startup as an authorization request.")
    assert_true("--start-missing-services" in start_human.get("recommended_flags", []), "service-start human_action_required should name the authorization flag.")
    assert_true(start_human.get("can_continue_after_authorization") is True, "service-start human_action_required should expose authorized continuation.")
    start_health = start_control.get("evidence_health") or {}
    assert_true(start_health.get("status") == "blocked_authorization_or_boundary", "service-start evidence health should block on authorization.")
    assert_true("requires_authorization" in start_health.get("flags", []), "service-start evidence health should flag the authorization requirement.")
    assert_true(start_health.get("result_ready_to_report") is False, "service-start evidence health should not treat setup authorization as a product report.")
    assert_true(handoff_path.exists(), "agent loop should write a human-readable handoff markdown next to the summary.")
    handoff_text = handoff_path.read_text(encoding="utf-8")
    assert_true("retry_with_service_start" in handoff_text, "handoff markdown should name the service-start next_action.")
    assert_true("--start-missing-services" in handoff_text, "handoff markdown should include the required service-start authorization flag.")
    assert_true("service_start_authorization_required" in handoff_text, "handoff markdown should include the service-start failure category.")
    assert_true("## Human Action Required" in handoff_text and "authorization" in handoff_text, "handoff should render the structured service-start authorization request.")
    assert_true("## Evidence Health" in handoff_text and "blocked_authorization_or_boundary" in handoff_text, "handoff should render service-start evidence health.")


def run_agent_authorized_service_start_fixture(script_dir: Path, tmp_path: Path) -> None:
    start_dir = tmp_path / "agent-authorized-service-start"
    start_dir.mkdir(parents=True, exist_ok=True)
    (start_dir / "index.html").write_text("authorized service start fixture\n", encoding="utf-8")
    port = unused_tcp_port()
    base_url = f"http://127.0.0.1:{port}"
    write_json(
        start_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-service",
                    "source": "fixture",
                    "text": "The fixture API health endpoint is reachable after service startup.",
                    "test_ids": ["T-service"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-service",
                    "requirement_ids": ["R-service"],
                    "type": "api",
                    "expected": "GET / returns HTTP 200 from the started fixture service.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        start_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": base_url,
            "artifactDir": str(start_dir),
            "scenarios": [
                {
                    "id": "service-health",
                    "steps": [
                        {
                            "action": "api",
                            "id": "service-health-api",
                            "method": "GET",
                            "path": "/",
                            "expectStatus": 200,
                            "testIds": ["T-service"],
                            "requirementIds": ["R-service"],
                            "evidenceType": "api_response",
                            "proves": "The started fixture API responds on the current run.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        start_dir / "adapter-context.json",
        {
            "schema_version": 1,
            "adapter": "fixture",
            "project_root": str(start_dir),
            "base_url": base_url,
            "environment_boundary": {
                "runtime_mode": "test",
                "data_boundary_status": "fixture data only; no production data",
            },
            "services": [
                {
                    "id": "fixture-api",
                    "role": "api",
                    "path": ".",
                    "path_exists": True,
                    "default_url": base_url,
                    "port": port,
                    "port_open": False,
                    "start_command": f"python3 -m http.server {port} --bind 127.0.0.1",
                }
            ],
        },
    )

    try:
        loop_proc = subprocess.run(
            [
                sys.executable,
                str(script_dir / "qa_agent_loop.py"),
                "--run-dir",
                str(start_dir),
                "--preflight-runtime",
                "--start-missing-services",
                "--required-service",
                "fixture-api",
                "--project-root",
                str(start_dir),
                "--runtime-mode",
                "test",
                "--data-boundary-status",
                "fixture data only; no production data",
                "--service-start-timeout",
                "8",
                "--max-iterations",
                "1",
            ],
            cwd=start_dir,
            text=True,
            capture_output=True,
        )
        assert_true(loop_proc.returncode == 0, "authorized agent loop should continue after service startup instead of stopping at setup authorization.")
        runtime = load_json(start_dir / "service-runtime.json")
        preflight = load_json(start_dir / "service-preflight.json")
        results = load_json(start_dir / "results.json")
        ledger = load_json(start_dir / "evidence-ledger.json")
        audit = load_json(start_dir / "audit-summary.json")
        verdict = load_json(start_dir / "qa-verdict.json")
        run_summary = load_json(start_dir / "qa-run-summary.json")
        agent_summary = load_json(start_dir / "qa-agent-summary.json")
        runtime_summary = runtime.get("summary") or {}
        services_by_id = {item.get("id"): item for item in preflight.get("services", []) if isinstance(item, dict)}
        steps_by_name = {item.get("name"): item for item in run_summary.get("steps", []) if isinstance(item, dict)}
        next_action = agent_summary.get("next_action") or {}
        evidence_by_type = {item.get("type"): item for item in ledger.get("evidence", []) if isinstance(item, dict)}
        assert_true(runtime_summary.get("planned_count") == 1, "service runtime should attempt exactly one generated start candidate.")
        assert_true(runtime_summary.get("ready_count") == 1, "service runtime should record the started service as ready.")
        assert_true(steps_by_name.get("service_runtime_start", {}).get("exit_code") == 0, "cycle should record successful service runtime startup.")
        assert_true(steps_by_name.get("preflight_runtime_after_start", {}).get("exit_code") == 0, "cycle should re-run preflight successfully after startup.")
        assert_true(services_by_id.get("fixture-api", {}).get("required") is True, "post-start preflight should preserve the required custom service id.")
        assert_true(services_by_id.get("fixture-api", {}).get("port_open") is True, "post-start preflight should verify the preserved custom service port.")
        assert_true(results.get("status") == "passed", "authorized startup fixture should execute the API probe after service readiness.")
        assert_true((ledger.get("requirements") or [{}])[0].get("status") == "Passed", "service health requirement should pass from current-run API evidence.")
        assert_true((ledger.get("tests") or [{}])[0].get("status") == "Passed", "service health test should pass from current-run API evidence.")
        assert_true(evidence_by_type.get("api_response", {}).get("status_code") == 200, "service health evidence should capture the HTTP 200 response.")
        assert_true(evidence_by_type.get("api_response", {}).get("current_run") is True, "service health evidence should be marked current_run=true.")
        assert_true(audit.get("passed") is True, "generic current-run API evidence should pass audit without requiring marker echo.")
        assert_true(verdict.get("verdict") == "passed" and verdict.get("can_claim_pass") is True, "authorized startup fixture should produce a pass-claimable verdict.")
        assert_true(agent_summary.get("status") == "passed", "agent loop should stop with passed status after the service probe succeeds.")
        assert_true(agent_summary.get("stop_reason") == "verdict_passed", "agent loop should stop because the current verdict passed.")
        assert_true(next_action.get("action") != "retry_with_service_start", "authorized startup should not ask for service-start authorization again.")
        pass_control = agent_summary.get("loop_control") or {}
        assert_true(pass_control.get("pass_claim_allowed") is True, "authorized service startup loop_control should allow pass claims after audited success.")
        assert_true(pass_control.get("terminal") is True, "authorized service startup loop_control should be terminal after pass.")
        assert_true(pass_control.get("requires_authorization") is False, "authorized service startup loop_control should not keep asking for service authorization.")
    finally:
        runtime_path = start_dir / "service-runtime.json"
        if runtime_path.exists():
            subprocess.run(
                [
                    sys.executable,
                    str(script_dir / "service_runtime.py"),
                    "--run-dir",
                    str(start_dir),
                    "--runtime",
                    str(runtime_path),
                    "--out",
                    str(start_dir / "service-runtime-stop.json"),
                    "--stop",
                ],
                cwd=start_dir,
                text=True,
                capture_output=True,
            )


def run_agent_repeated_next_probe_stall_fixture(script_dir: Path, tmp_path: Path) -> None:
    module = load_qa_agent_loop_module(script_dir)
    run_dir = tmp_path / "agent-repeated-next-probe-stall"
    run_dir.mkdir(parents=True, exist_ok=True)
    write_json(run_dir / "test-matrix.json", {"schemaVersion": 2, "requirements": [], "tests": []})
    write_json(run_dir / "test-plan.json", {"schemaVersion": 2, "baseUrl": "http://127.0.0.1:9527", "scenarios": []})
    write_json(
        run_dir / "adapter-context.json",
        {
            "schema_version": 1,
            "adapter": "fixture",
            "generated_at": "2026-06-16T00:00:00",
            "project_root": str(run_dir),
            "environment_boundary": {
                "runtime_mode": "test",
                "data_boundary_status": "test database; no production data",
            },
            "services": [
                {
                    "id": "one_corpus_web",
                    "default_url": "http://127.0.0.1:9527",
                    "port_open": True,
                    "path_exists": True,
                },
                {
                    "id": "opc-bot",
                    "default_url": "http://127.0.0.1:8081",
                    "port_open": False,
                    "path_exists": True,
                },
            ],
        },
    )

    next_probe_payload = {
        "schema_version": 1,
        "summary": {"recommendation_count": 1},
        "recommendations": [
            {
                "id": "NP-repeat-runtime",
                "layer": "runtime",
                "reason": "The same runtime follow-up keeps being generated.",
            }
        ],
    }
    calls: list[str] = []
    state = {"cycles": 0, "previews": 0}
    original_argv = sys.argv[:]
    original_run_command = module.run_command

    def fake_result(command: list[str], cwd: Path, started_at_epoch: float) -> dict[str, Any]:
        now = datetime_now_for_fixture()
        return {
            "command": command,
            "cwd": str(cwd),
            "started_at": now,
            "started_at_epoch": started_at_epoch,
            "finished_at": now,
            "finished_at_epoch": time.time(),
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
        }

    def fake_run_command(command: list[str], cwd: Path) -> dict[str, Any]:
        joined = " ".join(str(item) for item in command)
        started_at_epoch = time.time() - 1.0
        if "run_qa_cycle.py" in joined:
            state["cycles"] += 1
            calls.append("cycle:apply" if "--apply-next-probes" in command else "cycle")
            now = datetime_now_for_fixture()
            steps = [
                {"name": "preflight_runtime", "exit_code": 0},
                {"name": "service_runtime_start", "exit_code": 0},
                {"name": "synthesize_adapter_probes", "exit_code": 0},
            ]
            if "--apply-next-probes" in command:
                steps.append({"name": "apply_next_probes", "exit_code": 0})
                write_json(
                    run_dir / "next-probe-application.json",
                    {
                        "schema_version": 1,
                        "summary": {"applied_count": 1, "skipped_count": 0},
                        "applied_recommendations": [{"id": "NP-repeat-runtime", "step_id": "next-repeat-runtime"}],
                    },
                )
            write_json(
                run_dir / "service-preflight.json",
                {
                    "schema_version": 1,
                    "generated_at": now,
                    "adapter": "fixture",
                    "runnable": True,
                    "required_services": ["one_corpus_web"],
                    "services": [
                        {
                            "id": "one_corpus_web",
                            "default_url": "http://127.0.0.1:9527",
                            "required": True,
                            "port_open": True,
                            "path_exists": True,
                        }
                    ],
                    "blockers": [],
                    "warnings": [],
                    "start_plan": [],
                    "input_artifact_errors": [],
                },
            )
            write_json(
                run_dir / "service-runtime.json",
                {
                    "schema_version": 1,
                    "generated_at": now,
                    "mode": "start",
                    "services": [
                        {
                            "service": "one_corpus_web",
                            "post_start_readiness": {"ready": True},
                        }
                    ],
                    "summary": {
                        "planned_count": 1,
                        "started_count": 1,
                        "ready_count": 1,
                        "failed_count": 0,
                        "dry_run_count": 0,
                    },
                    "safety": {"services_started": True},
                },
            )
            write_json(
                run_dir / "adapter-probes.json",
                {
                    "schema_version": 1,
                    "generated_at": now,
                    "summary": {
                        "stream_test_count": 1,
                        "session_api_test_count": 1,
                        "persistence_test_count": 1,
                        "proposed_step_count": 3,
                        "blocked_probe_count": 0,
                    },
                    "added_step_ids": ["adapter-stream", "adapter-session", "adapter-persistence"],
                    "proposed_step_ids": ["adapter-stream", "adapter-session", "adapter-persistence"],
                    "recommendations": [],
                    "blocked": [],
                    "input_artifact_errors": [],
                },
            )
            steps.append({"name": "generate_verdict", "exit_code": 0})
            write_json(
                run_dir / "qa-run-summary.json",
                {
                    "schema_version": 1,
                    "status": "blocked",
                    "started_at": now,
                    "finished_at": now,
                    "steps": steps,
                },
            )
            write_json(
                run_dir / "qa-verdict.json",
                {
                    "schema_version": 1,
                    "generated_at": now,
                    "verdict": "blocked",
                    "can_claim_pass": False,
                    "reasons": [{"code": "undispositioned_failed_responses"}],
                },
            )
            write_json(
                run_dir / "results.json",
                {
                    "schemaVersion": 2,
                    "status": "failed",
                    "failedResponses": [{"status": 500, "url": "http://127.0.0.1:9527/api/v1/repeat"}],
                    "console": [],
                    "requestFailures": [],
                },
            )
            return fake_result(command, cwd, started_at_epoch)
        if "apply_next_probes.py" in joined:
            state["previews"] += 1
            calls.append("preview")
            write_json(run_dir / "next-probes.json", next_probe_payload)
            write_json(
                run_dir / "next-probe-preview.json",
                {
                    "schema_version": 1,
                    "summary": {"recommendation_count": 1, "applied_count": 1, "skipped_count": 0},
                    "applied_recommendations": [
                        {
                            "id": "NP-repeat-runtime",
                            "step_id": "next-repeat-runtime",
                            "layer": "runtime",
                            "test_ids": ["T-repeat-runtime"],
                        }
                    ],
                },
            )
            return fake_result(command, cwd, started_at_epoch)
        return original_run_command(command, cwd)

    try:
        module.run_command = fake_run_command
        sys.argv = ["qa_agent_loop.py", "--run-dir", str(run_dir), "--max-iterations", "3"]
        with contextlib.redirect_stdout(io.StringIO()):
            exit_code = module.main()
    finally:
        module.run_command = original_run_command
        sys.argv = original_argv

    agent_summary = load_json(run_dir / "qa-agent-summary.json")
    iterations = agent_summary.get("iterations") or []
    first_action = (iterations[0].get("next_action") or {}) if len(iterations) > 0 else {}
    second_action = (iterations[1].get("next_action") or {}) if len(iterations) > 1 else {}
    control = agent_summary.get("loop_control") or {}
    repeated = second_action.get("repeated_next_probes") or {}
    repeated_hash = file_sha256(run_dir / "next-probes.json")
    repeated_evidence = control.get("evidence_artifacts") or []
    repeated_next_probes_entry = next((item for item in repeated_evidence if isinstance(item, dict) and item.get("name") == "next-probes.json"), {})
    artifact_entries = control.get("current_artifacts") or []
    artifact_by_name = {item.get("name"): item for item in artifact_entries if isinstance(item, dict)}
    artifact_status_summary = control.get("artifact_status_summary") or {}
    iteration_timeline = control.get("iteration_timeline") or []
    decision_summary = control.get("decision_summary") or {}
    environment_summary = decision_summary.get("environment_boundary") or {}
    service_preflight_summary = decision_summary.get("service_preflight") or {}
    service_runtime_summary = decision_summary.get("service_runtime") or {}
    adapter_probe_summary = decision_summary.get("adapter_probes") or {}
    evidence_health = control.get("evidence_health") or {}
    human_request = control.get("human_action_required") or {}
    orchestration = control.get("orchestration_state") or {}
    handoff_text = Path(str(agent_summary.get("handoff") or "")).read_text(encoding="utf-8")

    assert_route_model_consistent(control, "real repeated next-probes loop")
    assert_true(exit_code == 0, "repeated next-probes stall should be a controlled handoff, not a tool failure.")
    assert_true(calls == ["cycle", "preview", "cycle:apply", "preview"], "agent loop should stop before a third cycle when next-probes repeat.")
    assert_true(state["cycles"] == 2 and state["previews"] == 2, "repeated next-probes stall fixture should run exactly two cycles and two previews.")
    assert_true(len(iterations) == 2, "repeated next-probes stall should stop after the second iteration.")
    assert_true(first_action.get("action") == "continue_with_safe_next_probes", "first repeated-hash iteration should still continue once.")
    assert_true(second_action.get("action") == "report_no_new_progress", "second repeated-hash iteration should stop as no-new-progress.")
    assert_true(second_action.get("automatable") is False, "repeated-hash stop must not remain automatable.")
    assert_true(second_action.get("no_new_progress") is True, "repeated-hash stop should expose no_new_progress.")
    assert_true(repeated.get("sha256") == repeated_hash, "repeated-hash stop should preserve the repeated next-probes hash.")
    assert_true(repeated.get("previous_iteration") == 1, "repeated-hash stop should point back to the first previewed iteration.")
    assert_true(agent_summary.get("stop_reason") == "next_action_requires_handoff", "repeated next-probes stall should stop through next_action handoff.")
    assert_true(control.get("terminal") is True, "repeated next-probes loop_control should be terminal.")
    assert_true(control.get("can_continue_automatically") is False, "repeated next-probes loop_control should block automatic continuation.")
    assert_true(control.get("result_ready_to_report") is True, "repeated next-probes loop_control should be reportable.")
    assert_true(control.get("no_new_progress") is True, "repeated next-probes loop_control should expose no_new_progress.")
    assert_true(control.get("repeated_next_probes", {}).get("sha256") == repeated_hash, "loop_control should preserve repeated next-probes metadata.")
    assert_true(control.get("iteration_count") == 2 and len(iteration_timeline) == 2, "loop_control should expose a compact iteration timeline.")
    assert_true(iteration_timeline[0].get("next_action") == "continue_with_safe_next_probes", "iteration timeline should preserve the first continuation decision.")
    assert_true(iteration_timeline[1].get("next_action") == "report_no_new_progress", "iteration timeline should preserve the final no-new-progress decision.")
    assert_true(iteration_timeline[1].get("applied_next_before_cycle") is True, "iteration timeline should expose whether the preview was applied before the cycle.")
    assert_true(iteration_timeline[1].get("cycle_exit_code") == 0 and iteration_timeline[1].get("preview_exit_code") == 0, "iteration timeline should compact cycle and preview exit codes.")
    assert_true(iteration_timeline[1].get("preview_next_probes_sha256") == repeated_hash, "iteration timeline should carry the previewed next-probes hash.")
    assert_true(control.get("last_iteration", {}).get("next_action") == "report_no_new_progress", "loop_control should expose the last compact iteration.")
    assert_true("test-plan.json probe strategy" in human_request.get("manual_revision_targets", []), "real no-new-progress human handoff should name manual revision targets.")
    assert_true("test-plan.json probe strategy" in orchestration.get("manual_revision_targets", []), "real no-new-progress orchestration should name manual revision targets.")
    assert_true(environment_summary.get("runtime_mode") == "test", "decision_summary should expose the adapter-context runtime mode.")
    assert_true(environment_summary.get("data_boundary_confirmed") is True, "decision_summary should expose confirmed data-boundary state.")
    assert_true(environment_summary.get("needs_confirmation") is False, "decision_summary should avoid requiring boundary confirmation for explicit test data.")
    assert_true(environment_summary.get("reachable_service_count") == 1, "decision_summary should summarize reachable adapter-context services.")
    assert_true(environment_summary.get("unreachable_service_count") == 1, "decision_summary should summarize unreachable adapter-context services.")
    assert_true(service_preflight_summary.get("blocker_count") == 0, "decision_summary should expose service preflight blocker counts.")
    assert_true(service_preflight_summary.get("service_count") == 1, "decision_summary should expose service preflight service counts.")
    assert_true(service_runtime_summary.get("ready_count") == 1, "decision_summary should expose service runtime readiness counts.")
    assert_true(service_runtime_summary.get("failed_count") == 0, "decision_summary should expose service runtime failure counts.")
    assert_true(adapter_probe_summary.get("applied_count") == 3, "decision_summary should expose applied adapter probe counts.")
    assert_true(adapter_probe_summary.get("blocked_probe_count") == 0, "decision_summary should expose blocked adapter probe counts.")
    assert_true(evidence_health.get("environment_boundary_needs_confirmation") is False, "evidence_health should compact environment-boundary confirmation state.")
    assert_true(evidence_health.get("service_preflight_blocker_count") == 0, "evidence_health should compact service preflight blocker counts.")
    assert_true(evidence_health.get("service_runtime_failed_count") == 0, "evidence_health should compact service runtime failures.")
    assert_true(evidence_health.get("adapter_probe_blocker_count") == 0, "evidence_health should compact adapter probe blockers.")
    assert_true(artifact_status_summary.get("total", 0) >= 4, "loop_control should summarize current artifact status for machine handoff.")
    assert_true(artifact_by_name.get("qa-verdict.json", {}).get("current") is True, "loop_control current_artifacts should mark the current verdict artifact.")
    assert_true(artifact_by_name.get("qa-verdict.json", {}).get("sha256") == file_sha256(run_dir / "qa-verdict.json"), "loop_control current_artifacts should include verdict artifact hashes.")
    assert_true(artifact_by_name.get("results.json", {}).get("current") is True, "loop_control current_artifacts should mark current probe results.")
    assert_true(artifact_by_name.get("next-probe-preview.json", {}).get("current") is True, "loop_control current_artifacts should mark the current next-probe preview.")
    assert_true(artifact_by_name.get("service-preflight.json", {}).get("current") is True, "loop_control current_artifacts should mark current service preflight evidence.")
    assert_true(artifact_by_name.get("service-runtime.json", {}).get("current") is True, "loop_control current_artifacts should mark current service runtime evidence.")
    assert_true(artifact_by_name.get("adapter-probes.json", {}).get("current") is True, "loop_control current_artifacts should mark current adapter probe evidence.")
    assert_true(artifact_by_name.get("adapter-context.json", {}).get("stable_input_artifact") is True, "loop_control should expose adapter context as stable input context.")
    assert_true((run_dir / "iterations" / "02" / "service-runtime.json").is_file(), "iteration snapshots should preserve service runtime evidence.")
    assert_true((run_dir / "iterations" / "02" / "adapter-probes.json").is_file(), "iteration snapshots should preserve adapter probe evidence.")
    real_repeated_steps = control.get("recommended_next_steps") or []
    assert_true(real_repeated_steps and real_repeated_steps[0].get("id") == "report_no_new_progress", "real no-new-progress loop_control should put report/manual revision first.")
    assert_true(any(item.get("id") == "manual_revision_after_no_new_progress" for item in real_repeated_steps if isinstance(item, dict)), "real no-new-progress loop_control should include explicit manual revision.")
    assert_true(any(item.get("id") == "report_no_new_progress" for item in real_repeated_steps if isinstance(item, dict)), "real loop_control should include a no-new-progress recommended next step.")
    assert_true(any(item.get("name") == "next-probes.json" and Path(str(item.get("path"))).resolve() == (run_dir / "next-probes.json").resolve() for item in repeated_evidence if isinstance(item, dict)), "real loop_control should expose resolved evidence artifact paths.")
    assert_true(repeated_next_probes_entry.get("sha256") == repeated_hash, "real loop_control evidence artifacts should include the repeated next-probes hash.")
    assert_true(repeated_next_probes_entry.get("size_bytes") == (run_dir / "next-probes.json").stat().st_size, "real loop_control evidence artifacts should include the repeated next-probes file size.")
    assert_true(control.get("blocking_category") == "no_new_followup_progress", "repeated next-probes loop_control should classify the stall.")
    assert_true("### Environment Boundary" in handoff_text, "handoff should render compact environment-boundary context.")
    assert_true("### Service Readiness" in handoff_text, "handoff should render compact service readiness context.")
    assert_true("### Adapter Probes" in handoff_text, "handoff should render compact adapter probe context.")
    assert_true("## Agent Route Model" in handoff_text and "Human request type: `manual_plan_revision_or_report`" in handoff_text, "real repeated-hash handoff should render the route model contract.")
    assert_true(
        handoff_text.index("## Agent Route Model") < handoff_text.index("## Orchestration State"),
        "real repeated-hash handoff should show route model before orchestration projection.",
    )
    assert_true("## Orchestration State" in handoff_text and "Mode: `manual_revision_or_report`" in handoff_text, "real repeated-hash handoff should render orchestration mode.")
    assert_true("Manual revision targets" in handoff_text and "test-plan.json probe strategy" in handoff_text, "real repeated-hash handoff should render manual revision targets.")
    assert_true("No new progress: `true`" in handoff_text, "repeated next-probes handoff should make no-new-progress visible.")
    assert_true("## Repeated Next-Probes" in handoff_text and repeated_hash in handoff_text, "repeated next-probes handoff should show the repeated hash and stop reason.")
    assert_true("## Evidence To Read" in handoff_text and repeated_hash in handoff_text, "repeated next-probes handoff should include evidence artifact hashes.")
    assert_true("## Current Artifact Status" in handoff_text and file_sha256(run_dir / "qa-verdict.json") in handoff_text, "repeated next-probes handoff should render current artifact status and hashes.")
    assert_true("## Recommended Next Steps" in handoff_text and "report_no_new_progress" in handoff_text, "repeated next-probes handoff should show recommended next steps.")
    assert_true("## Iterations" in handoff_text and repeated_hash in handoff_text, "repeated next-probes handoff should render compact iteration timeline details.")


def run_agent_runtime_autorecovery_fixture(script_dir: Path, tmp_path: Path) -> None:
    run_dir = tmp_path / "agent-runtime-autorecovery"
    run_dir.mkdir(parents=True, exist_ok=True)
    state = {"visits": 0}

    class RuntimeRecoveryHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return
            if parsed.path != "/runtime-agent":
                self.send_response(404)
                self.end_headers()
                return
            state["visits"] += 1
            emit_error = state["visits"] == 1
            script = "<script>console.error('first iteration runtime fixture error')</script>" if emit_error else ""
            body = f"<!doctype html><html><body><main>Ready</main>{script}</body></html>".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    server = ThreadedHTTPServer(("127.0.0.1", 0), RuntimeRecoveryHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        write_json(
            run_dir / "adapter-context.json",
            {
                "schema_version": 1,
                "adapter": "runtime_autorecovery_fixture",
                "base_url": base_url,
                "environment_boundary": {
                    "runtime_mode": "local",
                    "data_boundary_status": "local deterministic fixture data; no production data",
                },
            },
        )
        write_json(
            run_dir / "test-matrix.json",
            {
                "schemaVersion": 2,
                "requirements": [
                    {
                        "id": "R-runtime-ui",
                        "source": "fixture",
                        "text": "The runtime fixture page reaches the Ready state.",
                        "test_ids": ["T-runtime-visible"],
                        "status": "Untested",
                    }
                ],
                "tests": [
                    {
                        "id": "T-runtime-visible",
                        "requirement_ids": ["R-runtime-ui"],
                        "type": "ui",
                        "expected": "The /runtime-agent page shows Ready.",
                        "status": "Untested",
                    }
                ],
            },
        )
        write_json(
            run_dir / "test-plan.json",
            {
                "schemaVersion": 2,
                "baseUrl": base_url,
                "artifactDir": str(run_dir),
                "headless": True,
                "scenarios": [
                    {
                        "id": "runtime-visible",
                        "steps": [
                            {
                                "action": "goto",
                                "id": "open-runtime-page",
                                "path": "/runtime-agent",
                                "testIds": ["T-runtime-visible"],
                                "requirementIds": ["R-runtime-ui"],
                                "evidenceType": "navigation",
                                "proves": "The runtime fixture page opened before the Ready assertion.",
                            },
                            {
                                "action": "expectText",
                                "id": "T-runtime-visible",
                                "text": "Ready",
                                "testIds": ["T-runtime-visible"],
                                "requirementIds": ["R-runtime-ui"],
                                "evidenceType": "ui_assertion",
                                "proves": "The runtime fixture page reached the Ready state.",
                            },
                        ],
                    }
                ],
            },
        )
        loop_proc = subprocess.run(
            [
                sys.executable,
                str(script_dir / "qa_agent_loop.py"),
                "--run-dir",
                str(run_dir),
                "--strict-runtime",
                "--max-iterations",
                "2",
            ],
            cwd=run_dir,
            text=True,
            capture_output=True,
        )
        assert_true(
            loop_proc.returncode == 0,
            "agent loop should auto-apply safe runtime follow-up probes and recover to pass.\n"
            + f"stdout={loop_proc.stdout[-2000:]}\nstderr={loop_proc.stderr[-2000:]}",
        )
        agent_summary = load_json(run_dir / "qa-agent-summary.json")
        results = load_json(run_dir / "results.json")
        ledger = load_json(run_dir / "evidence-ledger.json")
        application = load_json(run_dir / "next-probe-application.json")
        verdict = load_json(run_dir / "qa-verdict.json")
        iterations = agent_summary.get("iterations", [])
        first_action = ((iterations[0] or {}).get("next_action") or {}) if iterations else {}
        second_status = ((iterations[1] or {}).get("status") or {}) if len(iterations) > 1 else {}
        application_summary = second_status.get("application_summary") or {}
        req_statuses = {item.get("id"): item.get("status") for item in ledger.get("requirements", []) if isinstance(item, dict)}
        evidence_by_step = {item.get("step_id"): item for item in ledger.get("evidence", []) if isinstance(item, dict)}

        assert_true(state["visits"] >= 2, "runtime autorecovery fixture should be visited across two agent iterations.")
        assert_true(len(iterations) == 2, "agent loop should use two iterations for runtime autorecovery.")
        assert_true(first_action.get("action") == "continue_with_safe_next_probes", "first iteration should continue with safe runtime follow-up probes.")
        assert_true(first_action.get("automatable") is True, "runtime follow-up continuation should be automatable.")
        assert_true((iterations[1] or {}).get("applied_next_before_cycle") is True, "second iteration should apply the previewed follow-up before the cycle.")
        assert_true(application.get("summary", {}).get("applied_count") == 1, "runtime autorecovery should apply one console-disposition probe.")
        assert_true(application_summary.get("applied_count") == 1, "agent final status should expose the applied follow-up count from the current iteration.")
        assert_true(results.get("status") == "passed" and not results.get("console"), "second runtime run should have no console errors.")
        assert_true(req_statuses.get("R-runtime-ui") == "Passed", "original visible requirement should remain passed.")
        assert_true(req_statuses.get("R-runtime-issue-disposition") == "Passed", "auto-added runtime disposition requirement should pass.")
        assert_true(evidence_by_step.get("next-np1", {}).get("checked_console_errors") == 0, "runtime follow-up evidence should prove zero unignored console errors.")
        assert_true(verdict.get("verdict") == "passed" and verdict.get("can_claim_pass") is True, "runtime autorecovery should end with a pass-claimable verdict.")
        assert_true(agent_summary.get("status") == "passed", "agent loop summary should be passed after runtime autorecovery.")
        assert_true(agent_summary.get("stop_reason") == "verdict_passed", "agent loop should stop because the recovered verdict passed.")
    finally:
        server.shutdown()
        server.server_close()


def run_api_next_probe_path_reuse_fixture(script_dir: Path, tmp_path: Path) -> None:
    api_dir = tmp_path / "api-next-probe-path-reuse"
    api_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        api_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-api",
                    "source": "fixture",
                    "text": "The filtered item detail API returns HTTP 200.",
                    "test_ids": ["T-api"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-api",
                    "requirement_ids": ["R-api"],
                    "type": "api",
                    "expected": "GET /api/v1/items/42?filter=active&sort=desc returns HTTP 200.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        api_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(api_dir),
            "scenarios": [
                {
                    "id": "api",
                    "steps": [
                        {
                            "action": "api",
                            "id": "T-api",
                            "method": "GET",
                            "path": "/api/v1/items/42?filter=active&sort=desc",
                            "expectStatus": 200,
                            "testIds": ["T-api"],
                            "requirementIds": ["R-api"],
                            "evidenceType": "api_response",
                            "proves": "The filtered item detail API returns HTTP 200.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        api_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "attention",
            "artifactDir": str(api_dir),
            "baseUrl": "http://127.0.0.1:9527",
            "scenarios": [
                {
                    "id": "api",
                    "status": "failed",
                    "steps": [
                        {
                            "scenarioId": "api",
                            "stepId": "T-api",
                            "testIds": ["T-api"],
                            "requirementIds": ["R-api"],
                            "action": "api",
                            "status": "failed",
                            "evidenceType": "api_response",
                            "proves": "The filtered item detail API returns HTTP 200.",
                            "method": "GET",
                            "url": "http://127.0.0.1:9527/api/v1/items/42?filter=active&access_token=fixture-redacted&sort=desc",
                            "statusCode": 500,
                            "error": "Expected HTTP status 200, got 500",
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
            str(api_dir / "test-matrix.json"),
            "--results",
            str(api_dir / "results.json"),
            "--out",
            str(api_dir / "evidence-ledger.json"),
        ],
        cwd=api_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_defects.py"),
            "--ledger",
            str(api_dir / "evidence-ledger.json"),
            "--results",
            str(api_dir / "results.json"),
            "--matrix",
            str(api_dir / "test-matrix.json"),
            "--out",
            str(api_dir / "defects.json"),
        ],
        cwd=api_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_next_probes.py"),
            "--defects",
            str(api_dir / "defects.json"),
            "--results",
            str(api_dir / "results.json"),
            "--ledger",
            str(api_dir / "evidence-ledger.json"),
            "--out",
            str(api_dir / "next-probes.json"),
        ],
        cwd=api_dir,
    )
    next_probes = load_json(api_dir / "next-probes.json")
    api_recs = [rec for rec in next_probes.get("recommendations", []) if rec.get("layer") == "api"]
    assert_true(api_recs, "API failure should produce an API follow-up recommendation.")
    api_hint = api_recs[0].get("plan_step_hint") or {}
    assert_true(api_hint.get("path") == "/api/v1/items/42?filter=active&sort=desc", "API follow-up should reuse the failed response path and safe query parameters.")
    assert_true("access_token" not in api_hint.get("path", ""), "API follow-up should not preserve sensitive query parameters.")
    assert_true("failed API path" not in api_recs[0].get("required_inputs", []), "Observed API paths should not require manual failed-path input.")
    assert_true("auth token" not in api_recs[0].get("required_inputs", []), "Non-auth API failures should not require auth input by default.")

    run_cmd(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(api_dir),
            "--out",
            str(api_dir / "next-probe-preview.json"),
        ],
        cwd=api_dir,
    )
    preview = load_json(api_dir / "next-probe-preview.json")
    assert_true(preview.get("summary", {}).get("applied_count") == 1, "Diagnostic API follow-up should preview as applicable, not duplicate.")
    run_cmd(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(api_dir),
            "--apply",
        ],
        cwd=api_dir,
    )
    application = load_json(api_dir / "next-probe-application.json")
    plan = load_json(api_dir / "test-plan.json")
    followup_steps = [
        step
        for scenario in plan.get("scenarios", [])
        if scenario.get("id") == "next-probe-followups"
        for step in scenario.get("steps", [])
    ]
    assert_true(application.get("summary", {}).get("applied_count") == 1, "Diagnostic API follow-up should be applied.")
    assert_true(len(followup_steps) == 1, "Exactly one API diagnostic follow-up should be appended.")
    assert_true(followup_steps[0].get("path") == "/api/v1/items/42?filter=active&sort=desc", "Applied API diagnostic should keep the failed path and safe query.")
    assert_true(followup_steps[0].get("captureBody") is True, "Applied API diagnostic should capture the response body.")


def run_next_probe_scenario_step_binding_fixture(script_dir: Path, tmp_path: Path) -> None:
    binding_dir = tmp_path / "next-probe-scenario-step-binding"
    write_json(
        binding_dir / "defects.json",
        {
            "schema_version": 1,
            "summary": {"finding_count": 1},
            "findings": [
                {
                    "id": "D-shared-step",
                    "severity": "P1",
                    "layers": ["persistence"],
                    "expected": "The same failed session should be read back from persistence.",
                    "actual": "The failed scenario did not prove the terminal persistence state.",
                    "evidence": [
                        {
                            "id": "E-failed",
                            "type": "api_response",
                            "scenario_id": "failed-scenario",
                            "step_id": "T-shared",
                            "action": "api",
                            "test_ids": ["T-shared"],
                            "requirement_ids": ["R-shared"],
                            "error": "JSON path missing for failed scenario",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        binding_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "failed",
            "artifactDir": str(binding_dir),
            "scenarios": [
                {
                    "id": "other-scenario",
                    "steps": [
                        {
                            "scenarioId": "other-scenario",
                            "stepId": "T-shared",
                            "testIds": ["T-shared"],
                            "requirementIds": ["R-shared"],
                            "action": "api",
                            "status": "passed",
                            "extractedJson": {
                                "session_id": "wrong-session",
                                "turn_id": "wrong-turn",
                            },
                        }
                    ],
                },
                {
                    "id": "failed-scenario",
                    "steps": [
                        {
                            "scenarioId": "failed-scenario",
                            "stepId": "T-shared",
                            "testIds": ["T-shared"],
                            "requirementIds": ["R-shared"],
                            "action": "api",
                            "status": "failed",
                            "extractedJson": {
                                "session_id": "right-session",
                                "turn_id": "right-turn",
                            },
                        }
                    ],
                },
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    write_json(binding_dir / "evidence-ledger.json", {"schema_version": 1, "requirements": [], "tests": [], "evidence": []})
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_next_probes.py"),
            "--defects",
            str(binding_dir / "defects.json"),
            "--results",
            str(binding_dir / "results.json"),
            "--ledger",
            str(binding_dir / "evidence-ledger.json"),
            "--out",
            str(binding_dir / "next-probes.json"),
        ],
        cwd=binding_dir,
    )
    next_probes = load_json(binding_dir / "next-probes.json")
    serialized = json.dumps(next_probes, ensure_ascii=False)
    persistence_recs = [
        rec
        for rec in next_probes.get("recommendations", [])
        if rec.get("layer") == "persistence" and rec.get("suggested_probe_type") == "api"
    ]
    assert_true(persistence_recs, "Persistence findings should produce a same-object API diagnostic.")
    first_hint = persistence_recs[0].get("plan_step_hint") or {}
    correlated_vars = persistence_recs[0].get("correlated_vars") or {}
    assert_true(first_hint.get("path") == "/api/v1/sessions/right-session", "Next probes should bind extracted variables to the failed scenario, not a same-step sibling.")
    assert_true(correlated_vars.get("session_id") == "right-session", "Correlated vars should come from the matched failed scenario result step.")
    assert_true(correlated_vars.get("turn_id") == "right-turn", "Turn id should also come from the matched failed scenario result step.")
    assert_true("wrong-session" not in serialized and "wrong-turn" not in serialized, "Next probes should not leak variables from a sibling scenario sharing the same step id.")


def run_next_probe_lineage_gate_fixture(script_dir: Path, tmp_path: Path) -> None:
    gate_dir = tmp_path / "next-probe-lineage-gate"
    write_json(
        gate_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-api",
                    "source": "fixture",
                    "text": "The item detail follow-up should stay mapped to its requirement.",
                    "test_ids": ["T-api"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-api",
                    "requirement_ids": ["R-api"],
                    "type": "api",
                    "expected": "GET /api/v1/items/lineage returns HTTP 200.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        gate_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(gate_dir),
            "scenarios": [],
        },
    )
    write_json(gate_dir / "evidence-ledger.json", {"schema_version": 1, "requirements": [], "tests": [], "evidence": []})
    write_json(gate_dir / "defects.json", {"schema_version": 1, "summary": {"finding_count": 0}, "findings": []})
    write_json(gate_dir / "results.json", {"schemaVersion": 2, "status": "skipped", "scenarios": []})
    write_json(
        gate_dir / "next-probes.json",
        {
            "schema_version": 1,
              "generated_from": {
                  "defects": str(gate_dir / "defects.json"),
                  "results": str(gate_dir / "results.json"),
                  "ledger": str(gate_dir / "evidence-ledger.json"),
              },
              "generated_from_hashes": {
                  "defects_sha256": file_sha256(gate_dir / "defects.json"),
                  "results_sha256": file_sha256(gate_dir / "results.json"),
                  "ledger_sha256": file_sha256(gate_dir / "evidence-ledger.json"),
              },
              "summary": {"recommendation_count": 2},
            "recommendations": [
                {
                    "id": "NP-with-lineage",
                    "layer": "api",
                    "source_test_id": "T-api",
                    "requirement_ids": ["R-api"],
                    "objective": "Capture the mapped item detail body.",
                    "reason": "A mapped requirement still needs same-object API evidence.",
                    "suggested_probe_type": "api",
                    "required_inputs": ["baseUrl"],
                    "plan_step_hint": {
                        "action": "api",
                        "method": "GET",
                        "path": "/api/v1/items/lineage",
                        "expectStatus": 200,
                        "captureBody": True,
                    },
                },
                {
                    "id": "NP-no-lineage",
                    "layer": "api",
                    "objective": "Capture an orphan API body.",
                    "reason": "This recommendation is concrete but has no requirement or test lineage.",
                    "suggested_probe_type": "api",
                    "required_inputs": ["baseUrl"],
                    "plan_step_hint": {
                        "action": "api",
                        "method": "GET",
                        "path": "/api/v1/items/orphan",
                        "expectStatus": 200,
                        "captureBody": True,
                    },
                },
            ],
            "input_artifact_errors": [],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(gate_dir),
            "--out",
            str(gate_dir / "next-probe-preview.json"),
        ],
        cwd=gate_dir,
    )
    preview = load_json(gate_dir / "next-probe-preview.json")
    skipped = {item.get("id"): item.get("reason") for item in preview.get("skipped_recommendations", []) if isinstance(item, dict)}
    assert_true(preview.get("summary", {}).get("applied_count") == 1, "Only the recommendation with requirement/test lineage should preview as applicable.")
    assert_true(skipped.get("NP-no-lineage") == "recommendation has no requirement/test lineage", "Concrete but unlineaged next probes should be blocked from auto-application.")
    assert_true(preview.get("safety", {}).get("lineage_required_for_auto_apply") is True, "Preview safety metadata should disclose the lineage auto-apply gate.")

    run_cmd(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(gate_dir),
            "--apply",
        ],
        cwd=gate_dir,
    )
    plan = load_json(gate_dir / "test-plan.json")
    paths = [
        step.get("path")
        for scenario in plan.get("scenarios", [])
        if scenario.get("id") == "next-probe-followups"
        for step in scenario.get("steps", [])
    ]
    applied_step = [
        step
        for scenario in plan.get("scenarios", [])
        if scenario.get("id") == "next-probe-followups"
        for step in scenario.get("steps", [])
        if step.get("path") == "/api/v1/items/lineage"
    ][0]
    assert_true(paths == ["/api/v1/items/lineage"], "Auto-application should append only the lineage-bound next probe.")
    assert_true(applied_step.get("testIds") == ["T-api"], "Applied next probe should keep test lineage.")
    assert_true(applied_step.get("requirementIds") == ["R-api"], "Applied next probe should keep requirement lineage.")


def run_next_probe_generated_from_binding_fixture(script_dir: Path, tmp_path: Path) -> None:
    source_dir = tmp_path / "next-probe-generated-from-binding"
    other_dir = tmp_path / "other-next-probe-source"
    write_json(
        source_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [{"id": "R-api", "source": "fixture", "text": "Mapped API follow-up.", "test_ids": ["T-api"], "status": "Untested"}],
            "tests": [{"id": "T-api", "requirement_ids": ["R-api"], "type": "api", "expected": "GET /api/v1/current returns 200.", "status": "Untested"}],
        },
    )
    write_json(
        source_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(source_dir),
            "scenarios": [],
        },
    )
    write_json(source_dir / "evidence-ledger.json", {"schema_version": 1, "requirements": [], "tests": [], "evidence": []})
    write_json(source_dir / "defects.json", {"schema_version": 1, "summary": {"finding_count": 0}, "findings": []})
    write_json(source_dir / "results.json", {"schemaVersion": 2, "status": "skipped", "scenarios": []})
    write_json(
        source_dir / "next-probes.json",
        {
            "schema_version": 1,
            "generated_from": {
                "defects": str(other_dir / "defects.json"),
                "results": str(other_dir / "results.json"),
                "ledger": str(other_dir / "evidence-ledger.json"),
            },
            "summary": {"recommendation_count": 1},
            "recommendations": [
                {
                    "id": "NP-cross-run",
                    "layer": "api",
                    "source_test_id": "T-api",
                    "requirement_ids": ["R-api"],
                    "objective": "This recommendation came from another run and must not be applied here.",
                    "reason": "Cross-run next-probe fixture.",
                    "suggested_probe_type": "api",
                    "required_inputs": ["baseUrl"],
                    "plan_step_hint": {
                        "action": "api",
                        "method": "GET",
                        "path": "/api/v1/current",
                        "expectStatus": 200,
                        "captureBody": True,
                    },
                }
            ],
            "input_artifact_errors": [],
        },
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(source_dir),
            "--out",
            str(source_dir / "next-probe-preview.json"),
        ],
        cwd=str(source_dir),
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "cross-run next-probe generated_from paths should fail preview instead of applying.")
    preview = load_json(source_dir / "next-probe-preview.json")
    input_errors = preview.get("input_artifact_errors", [])
    names = {item.get("name") for item in input_errors if isinstance(item, dict)}
    errors = " ".join(str(item.get("error", "")) for item in input_errors if isinstance(item, dict))
    assert_true("next_probes.generated_from.defects" in names, "cross-run next-probes should name the mismatched defects source.")
    assert_true("next_probes.generated_from.results" in names, "cross-run next-probes should name the mismatched results source.")
    assert_true("next_probes.generated_from.ledger" in names, "cross-run next-probes should name the mismatched ledger source.")
    assert_true("source_mismatch" in errors, "cross-run next-probe source errors should use a stable source_mismatch code.")
    assert_true(preview.get("summary", {}).get("applied_count") == 0, "cross-run next-probes must not apply recommendations.")


def run_next_probe_missing_generated_from_fixture(script_dir: Path, tmp_path: Path) -> None:
    source_dir = tmp_path / "next-probe-missing-generated-from"
    write_json(
        source_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [{"id": "R-api", "source": "fixture", "text": "Mapped API follow-up.", "test_ids": ["T-api"], "status": "Untested"}],
            "tests": [{"id": "T-api", "requirement_ids": ["R-api"], "type": "api", "expected": "GET /api/v1/current returns 200.", "status": "Untested"}],
        },
    )
    write_json(
        source_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(source_dir),
            "scenarios": [],
        },
    )
    write_json(source_dir / "evidence-ledger.json", {"schema_version": 1, "requirements": [], "tests": [], "evidence": []})
    write_json(source_dir / "defects.json", {"schema_version": 1, "summary": {"finding_count": 0}, "findings": []})
    write_json(source_dir / "results.json", {"schemaVersion": 2, "status": "skipped", "scenarios": []})
    write_json(
        source_dir / "next-probes.json",
        {
            "schema_version": 1,
            "summary": {"recommendation_count": 1},
            "recommendations": [
                {
                    "id": "NP-missing-source-binding",
                    "layer": "api",
                    "source_test_id": "T-api",
                    "requirement_ids": ["R-api"],
                    "objective": "This safe-looking recommendation has no current-run provenance and must not be applied.",
                    "reason": "Missing generated_from fixture.",
                    "suggested_probe_type": "api",
                    "required_inputs": ["baseUrl"],
                    "plan_step_hint": {
                        "action": "api",
                        "method": "GET",
                        "path": "/api/v1/current",
                        "expectStatus": 200,
                        "captureBody": True,
                    },
                }
            ],
            "input_artifact_errors": [],
        },
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(source_dir),
            "--apply",
            "--out",
            str(source_dir / "next-probe-preview.json"),
        ],
        cwd=str(source_dir),
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "next-probes without generated_from should fail apply instead of using unbound recommendations.")
    preview = load_json(source_dir / "next-probe-preview.json")
    input_errors = preview.get("input_artifact_errors", [])
    names = {item.get("name") for item in input_errors if isinstance(item, dict)}
    errors = " ".join(str(item.get("error", "")) for item in input_errors if isinstance(item, dict))
    assert_true("next_probes.generated_from" in names, "missing next-probe provenance should name generated_from as the blocking input.")
    assert_true("missing_current_run_source_binding" in errors, "missing provenance should use a stable current-run source binding error.")
    assert_true(preview.get("summary", {}).get("applied_count") == 0, "unbound next-probe recommendations must not apply.")
    assert_true(preview.get("safety", {}).get("current_run_source_binding_required") is True, "preview safety metadata should disclose the source-binding gate.")
    plan = load_json(source_dir / "test-plan.json")
    followup_steps = [
        step
        for scenario in plan.get("scenarios", [])
        if scenario.get("id") == "next-probe-followups"
        for step in scenario.get("steps", [])
    ]
    assert_true(followup_steps == [], "unbound next-probe recommendations must leave the executable plan unchanged.")


def run_next_probe_generated_from_hash_fixture(script_dir: Path, tmp_path: Path) -> None:
    source_dir = tmp_path / "next-probe-generated-from-hash"
    write_json(
        source_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [{"id": "R-api", "source": "fixture", "text": "Mapped API follow-up.", "test_ids": ["T-api"], "status": "Untested"}],
            "tests": [{"id": "T-api", "requirement_ids": ["R-api"], "type": "api", "expected": "GET /api/v1/current returns 200.", "status": "Untested"}],
        },
    )
    write_json(
        source_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(source_dir),
            "scenarios": [],
        },
    )
    write_json(source_dir / "evidence-ledger.json", {"schema_version": 1, "requirements": [], "tests": [], "evidence": []})
    write_json(source_dir / "defects.json", {"schema_version": 1, "summary": {"finding_count": 0}, "findings": []})
    write_json(source_dir / "results.json", {"schemaVersion": 2, "status": "skipped", "scenarios": []})
    write_json(
        source_dir / "next-probes.json",
        {
            "schema_version": 1,
            "generated_from": {
                "defects": str(source_dir / "defects.json"),
                "results": str(source_dir / "results.json"),
                "ledger": str(source_dir / "evidence-ledger.json"),
            },
            "generated_from_hashes": {
                "defects_sha256": file_sha256(source_dir / "defects.json"),
                "results_sha256": file_sha256(source_dir / "results.json"),
                "ledger_sha256": file_sha256(source_dir / "evidence-ledger.json"),
            },
            "summary": {"recommendation_count": 1},
            "recommendations": [
                {
                    "id": "NP-source-hash-drift",
                    "layer": "api",
                    "source_test_id": "T-api",
                    "requirement_ids": ["R-api"],
                    "objective": "This recommendation must not be applied after its source defects artifact changes.",
                    "reason": "Source hash drift fixture.",
                    "suggested_probe_type": "api",
                    "required_inputs": ["baseUrl"],
                    "plan_step_hint": {
                        "action": "api",
                        "method": "GET",
                        "path": "/api/v1/current",
                        "expectStatus": 200,
                        "captureBody": True,
                    },
                }
            ],
            "input_artifact_errors": [],
        },
    )
    write_json(
        source_dir / "defects.json",
        {
            "schema_version": 1,
            "summary": {"finding_count": 1},
            "findings": [{"id": "D-drift", "severity": "P2", "layers": ["api"], "actual": "Source changed after next-probe generation."}],
        },
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(source_dir),
            "--apply",
            "--out",
            str(source_dir / "next-probe-preview.json"),
        ],
        cwd=str(source_dir),
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "next-probes with source hash drift should fail apply instead of using stale recommendations.")
    preview = load_json(source_dir / "next-probe-preview.json")
    input_errors = preview.get("input_artifact_errors", [])
    names = {item.get("name") for item in input_errors if isinstance(item, dict)}
    errors = " ".join(str(item.get("error", "")) for item in input_errors if isinstance(item, dict))
    assert_true("next_probes.generated_from_hashes.defects" in names, "source hash drift should name the changed defects artifact.")
    assert_true("source_hash_mismatch" in errors, "source hash drift should use a stable source_hash_mismatch error.")
    assert_true(preview.get("summary", {}).get("applied_count") == 0, "source hash drift must not apply recommendations.")
    assert_true(preview.get("safety", {}).get("current_run_source_hash_required") is True, "preview safety metadata should disclose the source hash gate.")
    plan = load_json(source_dir / "test-plan.json")
    followup_steps = [
        step
        for scenario in plan.get("scenarios", [])
        if scenario.get("id") == "next-probe-followups"
        for step in scenario.get("steps", [])
    ]
    assert_true(followup_steps == [], "source hash drift must leave the executable plan unchanged.")


def run_next_probe_embedded_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    embedded_dir = tmp_path / "next-probe-embedded-input-errors"
    write_json(
        embedded_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [{"id": "R-api", "source": "fixture", "text": "Mapped API follow-up.", "test_ids": ["T-api"], "status": "Untested"}],
            "tests": [{"id": "T-api", "requirement_ids": ["R-api"], "type": "api", "expected": "GET /api/v1/current returns 200.", "status": "Untested"}],
        },
    )
    write_json(
        embedded_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(embedded_dir),
            "scenarios": [],
        },
    )
    write_json(embedded_dir / "evidence-ledger.json", {"schema_version": 1, "requirements": [], "tests": [], "evidence": []})
    write_json(embedded_dir / "defects.json", {"schema_version": 1, "summary": {"finding_count": 0}, "findings": []})
    write_json(embedded_dir / "results.json", {"schemaVersion": 2, "status": "skipped", "scenarios": []})
    write_json(
        embedded_dir / "next-probes.json",
        {
            "schema_version": 1,
              "generated_from": {
                  "defects": str(embedded_dir / "defects.json"),
                  "results": str(embedded_dir / "results.json"),
                  "ledger": str(embedded_dir / "evidence-ledger.json"),
              },
              "generated_from_hashes": {
                  "defects_sha256": file_sha256(embedded_dir / "defects.json"),
                  "results_sha256": file_sha256(embedded_dir / "results.json"),
                  "ledger_sha256": file_sha256(embedded_dir / "evidence-ledger.json"),
              },
              "summary": {"recommendation_count": 1, "input_artifact_error_count": 1},
            "input_artifact_errors": [
                {
                    "name": "defects",
                    "path": str(embedded_dir / "defects.json"),
                    "error": "invalid_json: fixture",
                    "required": True,
                }
            ],
            "recommendations": [
                {
                    "id": "NP-embedded-input-error",
                    "layer": "api",
                    "source_test_id": "T-api",
                    "requirement_ids": ["R-api"],
                    "objective": "This safe-looking recommendation must not be applied because next-probes was generated from bad inputs.",
                    "reason": "Embedded input-artifact error fixture.",
                    "suggested_probe_type": "api",
                    "required_inputs": ["baseUrl"],
                    "plan_step_hint": {
                        "action": "api",
                        "method": "GET",
                        "path": "/api/v1/current",
                        "expectStatus": 200,
                        "captureBody": True,
                    },
                }
            ],
        },
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(embedded_dir),
            "--apply",
            "--out",
            str(embedded_dir / "next-probe-preview.json"),
        ],
        cwd=str(embedded_dir),
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "embedded next-probe input_artifact_errors should fail apply instead of applying safe-looking recommendations.")
    preview = load_json(embedded_dir / "next-probe-preview.json")
    input_errors = preview.get("input_artifact_errors", [])
    names = {item.get("name") for item in input_errors if isinstance(item, dict)}
    assert_true("next_probes.defects" in names, "embedded next-probe input errors should preserve the upstream bad artifact name.")
    assert_true(preview.get("summary", {}).get("applied_count") == 0, "embedded next-probe input errors must not apply recommendations.")
    assert_true(preview.get("applied_recommendations") == [], "embedded next-probe input errors should not report partial applications.")
    plan = load_json(embedded_dir / "test-plan.json")
    followup_steps = [
        step
        for scenario in plan.get("scenarios", [])
        if scenario.get("id") == "next-probe-followups"
        for step in scenario.get("steps", [])
    ]
    assert_true(followup_steps == [], "embedded next-probe input errors must leave the executable plan unchanged.")


def run_runtime_failed_response_auth_guard_fixture(script_dir: Path, tmp_path: Path) -> None:
    guard_dir = tmp_path / "runtime-failed-response-auth-guard"
    write_json(
        guard_dir / "defects.json",
        {
            "schema_version": 1,
            "summary": {"finding_count": 1},
            "findings": [
                {
                    "id": "D-runtime-403",
                    "severity": "P2",
                    "layers": ["runtime"],
                    "runtime_categories": ["failed_responses"],
                    "actual": "Undispositioned runtime issue category=failed_responses count=1; failed response: status=403 url=http://127.0.0.1:9527/api/v1/private?filter=mine&access_token=fixture-redacted",
                    "evidence": [
                        {
                            "id": "runtime-failed-403",
                            "type": "runtime",
                            "action": "response",
                            "status_code": 403,
                            "observed_url": "http://127.0.0.1:9527/api/v1/private?filter=mine&access_token=fixture-redacted",
                        }
                    ],
                }
            ],
        },
    )
    write_json(guard_dir / "results.json", {"schemaVersion": 2, "status": "attention", "console": [], "failedResponses": [], "requestFailures": []})
    write_json(guard_dir / "evidence-ledger.json", {"schema_version": 1, "requirements": [], "tests": [], "evidence": []})
    write_json(guard_dir / "test-plan.json", {"schemaVersion": 2, "baseUrl": "http://127.0.0.1:9527", "scenarios": []})
    write_json(guard_dir / "test-matrix.json", {"schemaVersion": 2, "requirements": [], "tests": []})
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_next_probes.py"),
            "--defects",
            str(guard_dir / "defects.json"),
            "--results",
            str(guard_dir / "results.json"),
            "--ledger",
            str(guard_dir / "evidence-ledger.json"),
            "--out",
            str(guard_dir / "next-probes.json"),
        ],
        cwd=guard_dir,
    )
    next_probes = load_json(guard_dir / "next-probes.json")
    api_recs = [rec for rec in next_probes.get("recommendations", []) if rec.get("suggested_probe_type") == "api"]
    assert_true(api_recs, "403 failed runtime responses should still produce a concrete API diagnostic recommendation.")
    assert_true(api_recs[0].get("plan_step_hint", {}).get("path") == "/api/v1/private?filter=mine", "403 API diagnostic should keep safe query parameters and strip sensitive ones.")
    assert_true("auth token" in api_recs[0].get("required_inputs", []), "403 API diagnostics should require explicit auth input before automatic application.")
    run_cmd(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(guard_dir),
            "--out",
            str(guard_dir / "next-probe-preview.json"),
        ],
        cwd=guard_dir,
    )
    preview = load_json(guard_dir / "next-probe-preview.json")
    skipped_api = [item for item in preview.get("skipped_recommendations", []) if item.get("id") == api_recs[0].get("id")]
    assert_true(skipped_api, "403 API diagnostic should not be auto-applied without auth input.")
    assert_true("auth" in skipped_api[0].get("reason", ""), "403 API diagnostic skip reason should name the missing auth input.")


def run_planning_blocker_handoff_fixture(script_dir: Path, tmp_path: Path) -> None:
    coverage_dir = tmp_path / "coverage-blocker-handoff"
    coverage_dir.mkdir(parents=True, exist_ok=True)
    (coverage_dir / "requirement.md").write_text(
        "# Coverage fixture\n\n- Alpha login button must be visible.\n- Invoice export must persist audit metadata.\n",
        encoding="utf-8",
    )
    write_json(
        coverage_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-alpha",
                    "source": "line 3",
                    "text": "Alpha login button must be visible.",
                    "test_ids": ["T-alpha"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-alpha",
                    "requirement_ids": ["R-alpha"],
                    "type": "ui",
                    "expected": "Alpha page opens.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        coverage_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(coverage_dir),
            "scenarios": [
                {
                    "id": "alpha",
                    "steps": [
                        {
                            "action": "goto",
                            "id": "alpha-open",
                            "path": "/alpha",
                            "testIds": ["T-alpha"],
                            "requirementIds": ["R-alpha"],
                            "evidenceType": "navigation",
                            "proves": "Alpha page opens.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        coverage_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "startedAt": "2000-01-01T00:00:00",
            "finishedAt": "2000-01-01T00:00:01",
            "scenarios": [],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    write_json(
        coverage_dir / "evidence-ledger.json",
        {
            "schema_version": 1,
            "requirements": [{"id": "R-stale", "status": "Passed"}],
            "tests": [{"id": "T-stale", "status": "Passed"}],
            "evidence": [{"id": "E-stale", "type": "api_response", "current_run": True}],
        },
    )
    write_json(
        coverage_dir / "audit-summary.json",
        {
            "schema_version": 1,
            "passed": True,
            "status_counts": {"Passed": 1, "Failed": 0, "Blocked": 0, "Untested": 0, "Inconclusive": 0},
        },
    )
    write_json(
        coverage_dir / "defects.json",
        {
            "schema_version": 1,
            "summary": {"finding_count": 1, "severity_counts": {"P1": 1}},
            "findings": [{"id": "D-stale", "severity": "P1", "title": "stale defect"}],
        },
    )
    coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(coverage_dir),
            "--skip-probe",
        ],
        cwd=coverage_dir,
        text=True,
        capture_output=True,
    )
    assert_true(coverage_proc.returncode != 0, "unmapped requirement coverage should stop the cycle.")
    coverage_summary = load_json(coverage_dir / "qa-run-summary.json")
    coverage_verdict = load_json(coverage_dir / "qa-verdict.json")
    coverage_codes = {reason.get("code") for reason in coverage_verdict.get("reasons", [])}
    assert_true(coverage_summary.get("status") == "blocked", "coverage handoff summary should be blocked.")
    assert_true(coverage_verdict.get("verdict") == "blocked", "coverage handoff verdict should be blocked.")
    assert_true("requirement_source_unmapped" in coverage_codes, "coverage handoff should include requirement_source_unmapped.")
    assert_true("defects_present" not in coverage_codes, "coverage handoff must not include stale defects from a previous execution.")
    coverage_inputs = coverage_verdict.get("inputs") or {}
    assert_true(coverage_inputs.get("results") is None, "coverage handoff must omit stale results.json.")
    assert_true(coverage_inputs.get("audit_summary") is None, "coverage handoff must omit stale audit-summary.json.")
    assert_true(coverage_inputs.get("defects") is None, "coverage handoff must omit stale defects.json.")
    omitted_flags = {item.get("flag") for item in coverage_summary.get("omitted_stale_handoff_artifacts", [])}
    assert_true({"--results", "--audit-summary", "--defects"}.issubset(omitted_flags), "cycle summary should name stale execution artifacts omitted from early handoff.")

    loop_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "qa_agent_loop.py"),
            "--run-dir",
            str(coverage_dir),
            "--skip-probe",
            "--max-iterations",
            "1",
        ],
        cwd=coverage_dir,
        text=True,
        capture_output=True,
    )
    assert_true(loop_proc.returncode != 0, "agent loop should stay non-zero for coverage planning blocker.")
    coverage_agent = load_json(coverage_dir / "qa-agent-summary.json")
    assert_true((coverage_agent.get("next_action") or {}).get("action") == "report_planning_blocker", "coverage blocker should become a planning next_action.")
    assert_true(coverage_agent.get("failure_analysis", {}).get("category") == "planning_coverage_blocker", "coverage blocker should be classified as planning coverage, not product behavior.")
    assert_true((coverage_agent.get("next_action") or {}).get("failure_analysis", {}).get("blocking_layer") == "requirement_plan", "planning blocker next_action should expose requirement_plan as the blocking layer.")

    plan_dir = tmp_path / "plan-validation-blocker-handoff"
    plan_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        plan_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-plan",
                    "source": "fixture",
                    "text": "Plan validation must block invalid probe plans.",
                    "test_ids": ["T-plan"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-plan",
                    "requirement_ids": ["R-plan"],
                    "type": "ui",
                    "expected": "A concrete probe exists.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        plan_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(plan_dir),
            "scenarios": [],
        },
    )
    plan_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(plan_dir),
            "--skip-probe",
        ],
        cwd=plan_dir,
        text=True,
        capture_output=True,
    )
    assert_true(plan_proc.returncode != 0, "invalid plan should stop the cycle.")
    plan_summary = load_json(plan_dir / "qa-run-summary.json")
    plan_verdict = load_json(plan_dir / "qa-verdict.json")
    plan_codes = {reason.get("code") for reason in plan_verdict.get("reasons", [])}
    assert_true(plan_summary.get("status") == "blocked", "plan validation handoff summary should be blocked.")
    assert_true(plan_verdict.get("verdict") == "blocked", "plan validation handoff verdict should be blocked.")
    assert_true("plan_validation_failed" in plan_codes, "plan validation handoff should include plan_validation_failed.")


def run_plan_validation_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "plan-validation-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    plan_path = input_dir / "test-plan.json"
    matrix_path = input_dir / "test-matrix.json"
    summary_path = input_dir / "nested" / "plan-audit-summary.json"
    plan_path.write_text("[]", encoding="utf-8")
    matrix_path.mkdir()

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(plan_path),
            "--matrix",
            str(matrix_path),
            "--summary",
            str(summary_path),
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "validate_plan should exit non-zero for unreadable plan/matrix input artifacts.")
    assert_true(summary_path.exists(), "validate_plan should write plan-audit-summary.json even when inputs are unreadable.")
    summary = load_json(summary_path)
    input_errors = {item.get("name"): item.get("error") for item in summary.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(summary.get("passed") is False, "bad validate_plan inputs must not pass.")
    assert_true(input_errors.get("plan") == "json_root_not_object", "validate_plan should classify non-object plan JSON.")
    assert_true(input_errors.get("matrix") == "path_is_directory", "validate_plan should classify directory-shaped matrix artifacts.")
    assert_true(summary.get("scenario_count") == 0 and summary.get("test_count") == 0, "bad validate_plan inputs should not synthesize coverage counts.")
    assert_true("Traceback" not in proc.stderr, "validate_plan should report bad inputs without a Python traceback.")


def run_storage_state_validation_fixture(script_dir: Path, tmp_path: Path) -> None:
    state_dir = tmp_path / "storage-state-validation"
    state_dir.mkdir(parents=True, exist_ok=True)
    valid_state = state_dir / "auth-state.json"
    valid_state.write_text(json.dumps({"cookies": [], "origins": []}, indent=2), encoding="utf-8")
    bad_state = state_dir / "bad-state.json"
    bad_state.write_text("{not-json", encoding="utf-8")
    dir_state = state_dir / "state-dir"
    dir_state.mkdir()

    matrix = {
        "requirements": [
            {
                "id": "R-auth",
                "text": "Authenticated browser checks must fail during planning when the storage state is unavailable.",
                "test_ids": ["T-auth"],
            }
        ],
        "tests": [
            {
                "id": "T-auth",
                "requirement_ids": ["R-auth"],
                "type": "permission",
                "expected": "Plan validation confirms auth storage state before browser execution.",
            }
        ],
    }

    def plan_with(storage_state: Any, *, context_options: bool = False) -> dict[str, Any]:
        plan: dict[str, Any] = {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "scenarios": [
                {
                    "id": "auth",
                    "steps": [
                        {
                            "action": "goto",
                            "id": "T-auth-open",
                            "testIds": ["T-auth"],
                            "requirementIds": ["R-auth"],
                            "path": "/",
                            "evidenceType": "ui_assertion",
                            "proves": "The authenticated entry point is reachable when login state exists.",
                        }
                    ],
                }
            ],
        }
        if context_options:
            plan["contextOptions"] = {"storageState": storage_state}
        else:
            plan["storageState"] = storage_state
        return plan

    def run_case(name: str, plan: dict[str, Any], *, env: dict[str, str] | None = None) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        case_dir = state_dir / name
        case_dir.mkdir(parents=True, exist_ok=True)
        write_json(case_dir / "test-plan.json", plan)
        write_json(case_dir / "test-matrix.json", matrix)
        proc = subprocess.run(
            [
                sys.executable,
                str(script_dir / "validate_plan.py"),
                "--plan",
                str(case_dir / "test-plan.json"),
                "--matrix",
                str(case_dir / "test-matrix.json"),
                "--summary",
                str(case_dir / "plan-audit-summary.json"),
            ],
            cwd=case_dir,
            env=env or os.environ.copy(),
            text=True,
            capture_output=True,
        )
        assert_true((case_dir / "plan-audit-summary.json").exists(), f"{name} should write plan-audit-summary.json.")
        return proc, load_json(case_dir / "plan-audit-summary.json")

    valid_proc, valid_summary = run_case("valid-file", plan_with(str(valid_state)))
    assert_true(valid_proc.returncode == 0, "validate_plan should accept an existing JSON storageState file.")
    assert_true(valid_summary.get("storage_state_check_count") == 1, "valid storageState file should be counted as checked.")

    env_proc, env_summary = run_case(
        "valid-env",
        plan_with({"env": "QA_STORAGE_STATE_PATH"}, context_options=True),
        env={**os.environ.copy(), "QA_STORAGE_STATE_PATH": str(valid_state)},
    )
    assert_true(env_proc.returncode == 0, "validate_plan should accept a storageState path supplied through an env reference.")
    assert_true(env_summary.get("storage_state_check_count") == 1, "env storageState should be counted as checked.")

    inline_cookie_proc, inline_cookie_summary = run_case(
        "inline-storage-state-cookie",
        plan_with(
            {
                "cookies": [
                    {
                        "name": "sid",
                        "value": "fixture-session",
                        "domain": "127.0.0.1",
                        "path": "/",
                    }
                ],
                "origins": [],
            }
        ),
    )
    assert_true(inline_cookie_proc.returncode != 0, "inline storageState cookies should block plan validation.")
    assert_true(any("storageState embeds cookies/origins directly" in error for error in inline_cookie_summary.get("errors", [])), "inline storageState cookies should produce a specific file-path requirement error.")

    inline_origin_proc, inline_origin_summary = run_case(
        "inline-storage-state-origin",
        plan_with(
            {
                "cookies": [],
                "origins": [
                    {
                        "origin": "http://127.0.0.1:9527",
                        "localStorage": [{"name": "oc_token", "value": "fixture-token"}],
                    }
                ],
            }
        ),
    )
    assert_true(inline_origin_proc.returncode != 0, "inline storageState origins should block plan validation.")
    assert_true(any("storageState embeds cookies/origins directly" in error for error in inline_origin_summary.get("errors", [])), "inline storageState origins should produce a specific file-path requirement error.")

    def plan_with_step(step: dict[str, Any]) -> dict[str, Any]:
        plan = plan_with(str(valid_state))
        plan["scenarios"][0]["steps"] = [step]
        return plan

    direct_local_storage_proc, direct_local_storage_summary = run_case(
        "direct-local-storage-token",
        plan_with_step(
            {
                "action": "setLocalStorage",
                "id": "T-auth-local-storage",
                "testIds": ["T-auth"],
                "requirementIds": ["R-auth"],
                "path": "/",
                "values": {"oc_token": "fixture-token"},
                "evidenceType": "auth_setup",
                "proves": "The browser receives auth setup.",
            }
        ),
    )
    assert_true(direct_local_storage_proc.returncode != 0, "direct auth-like localStorage values should block plan validation.")
    assert_true(any("setLocalStorage.oc_token writes auth-like material directly" in error for error in direct_local_storage_summary.get("errors", [])), "direct localStorage token should produce a specific auth-material error.")

    env_local_storage_proc, _ = run_case(
        "env-local-storage-token",
        plan_with_step(
            {
                "action": "setLocalStorage",
                "id": "T-auth-local-storage-env",
                "testIds": ["T-auth"],
                "requirementIds": ["R-auth"],
                "path": "/",
                "values": {"oc_token": {"env": "QA_DIRECT_TOKEN"}},
                "evidenceType": "auth_setup",
                "proves": "The browser receives auth setup through an environment reference.",
            }
        ),
        env={**os.environ.copy(), "QA_DIRECT_TOKEN": "fixture-token"},
    )
    assert_true(env_local_storage_proc.returncode == 0, "env-referenced localStorage auth setup should pass validation.")

    direct_default_header_plan = plan_with(str(valid_state))
    direct_default_header_plan["defaultHeaders"] = {"Authorization": "Bearer fixture-token"}
    direct_default_header_proc, direct_default_header_summary = run_case("direct-default-header", direct_default_header_plan)
    assert_true(direct_default_header_proc.returncode != 0, "direct auth-like default headers should block plan validation.")
    assert_true(any("plan.defaultHeaders.Authorization writes auth-like header material directly" in error for error in direct_default_header_summary.get("errors", [])), "direct Authorization header should produce a specific auth-material error.")

    env_default_header_plan = plan_with(str(valid_state))
    env_default_header_plan["defaultHeaders"] = {"Authorization": {"env": "QA_AUTH_HEADER", "prefix": "Bearer "}}
    env_default_header_proc, _ = run_case(
        "env-default-header",
        env_default_header_plan,
        env={**os.environ.copy(), "QA_AUTH_HEADER": "fixture-token"},
    )
    assert_true(env_default_header_proc.returncode == 0, "env-referenced auth-like default headers should pass validation.")

    direct_runtime_var_plan = plan_with(str(valid_state))
    direct_runtime_var_plan["runtimeVars"] = {"auth_token": "fixture-token"}
    direct_runtime_var_plan["scenarios"][0]["steps"] = [
        {
            "action": "api",
            "id": "T-auth-api-runtime-token",
            "testIds": ["T-auth"],
            "requirementIds": ["R-auth"],
            "method": "GET",
            "path": "/api/me",
            "headers": {"Authorization": {"var": "auth_token", "prefix": "Bearer "}},
            "evidenceType": "api_response",
            "proves": "The API request carries authenticated state from a runtime variable.",
        }
    ]
    direct_runtime_var_proc, direct_runtime_var_summary = run_case("direct-runtime-var-token", direct_runtime_var_plan)
    assert_true(direct_runtime_var_proc.returncode != 0, "direct auth-like runtime variables should block plan validation.")
    assert_true(any("plan.runtimeVars.auth_token writes auth-like runtime material directly" in error for error in direct_runtime_var_summary.get("errors", [])), "direct auth-like runtime var should produce a specific auth-material error.")

    env_runtime_var_plan = plan_with(str(valid_state))
    env_runtime_var_plan["runtimeVars"] = {"auth_token": {"env": "QA_RUNTIME_AUTH_TOKEN"}}
    env_runtime_var_plan["scenarios"][0]["steps"] = [
        {
            "action": "api",
            "id": "T-auth-api-runtime-token-env",
            "testIds": ["T-auth"],
            "requirementIds": ["R-auth"],
            "method": "GET",
            "path": "/api/me",
            "headers": {"Authorization": {"var": "auth_token", "prefix": "Bearer "}},
            "evidenceType": "api_response",
            "proves": "The API request carries authenticated state from an environment-backed runtime variable.",
        }
    ]
    env_runtime_var_proc, _ = run_case(
        "env-runtime-var-token",
        env_runtime_var_plan,
        env={**os.environ.copy(), "QA_RUNTIME_AUTH_TOKEN": "fixture-token"},
    )
    assert_true(env_runtime_var_proc.returncode == 0, "env-referenced auth-like runtime variables should pass validation.")

    direct_runtime_session_id_plan = plan_with(str(valid_state))
    direct_runtime_session_id_plan["runtimeVars"] = {"session_id": "fixture-session-id"}
    direct_runtime_session_id_plan["scenarios"][0]["steps"] = [
        {
            "action": "api",
            "id": "T-auth-api-session-id",
            "testIds": ["T-auth"],
            "requirementIds": ["R-auth"],
            "method": "GET",
            "pathTemplate": "/api/sessions/{session_id}",
            "evidenceType": "api_response",
            "proves": "The API probe can reuse a non-secret session object id.",
        }
    ]
    direct_runtime_session_id_proc, _ = run_case("direct-runtime-session-id", direct_runtime_session_id_plan)
    assert_true(direct_runtime_session_id_proc.returncode == 0, "direct non-secret session_id runtime variables should pass validation.")

    direct_api_json_secret_proc, direct_api_json_secret_summary = run_case(
        "direct-api-json-password",
        plan_with_step(
            {
                "action": "api",
                "id": "T-auth-api-json-password",
                "testIds": ["T-auth"],
                "requirementIds": ["R-auth"],
                "method": "POST",
                "path": "/api/login",
                "json": {"username": "qa-user", "password": "fixture-password"},
                "evidenceType": "api_response",
                "proves": "The API request submits login material.",
            }
        ),
    )
    assert_true(direct_api_json_secret_proc.returncode != 0, "direct auth-like API JSON values should block plan validation.")
    assert_true(any(".json.password writes auth-like material directly" in error for error in direct_api_json_secret_summary.get("errors", [])), "direct API JSON password should produce a specific auth-material error.")

    env_api_json_secret_proc, _ = run_case(
        "env-api-json-password",
        plan_with_step(
            {
                "action": "api",
                "id": "T-auth-api-json-password-env",
                "testIds": ["T-auth"],
                "requirementIds": ["R-auth"],
                "method": "POST",
                "path": "/api/login",
                "json": {"username": "qa-user", "password": {"env": "QA_API_PASSWORD"}},
                "evidenceType": "api_response",
                "proves": "The API request submits login material through an environment reference.",
            }
        ),
        env={**os.environ.copy(), "QA_API_PASSWORD": "fixture-password"},
    )
    assert_true(env_api_json_secret_proc.returncode == 0, "env-referenced auth-like API JSON values should pass validation.")

    direct_command_env_proc, direct_command_env_summary = run_case(
        "direct-command-env-api-key",
        plan_with_step(
            {
                "action": "command",
                "id": "T-auth-command-env",
                "testIds": ["T-auth"],
                "requirementIds": ["R-auth"],
                "command": ["python3", "-c", "print('ok')"],
                "env": {"API_KEY": "fixture-key"},
                "evidenceType": "command",
                "proves": "The command receives auth setup.",
            }
        ),
    )
    assert_true(direct_command_env_proc.returncode != 0, "direct auth-like command env values should block plan validation.")
    assert_true(any(".env.API_KEY writes auth-like material directly" in error for error in direct_command_env_summary.get("errors", [])), "direct command env API key should produce a specific auth-material error.")

    direct_step_header_proc, direct_step_header_summary = run_case(
        "direct-step-cookie-header",
        plan_with_step(
            {
                "action": "api",
                "id": "T-auth-api-cookie",
                "testIds": ["T-auth"],
                "requirementIds": ["R-auth"],
                "method": "GET",
                "path": "/api/me",
                "headers": {"Cookie": "sid=fixture-session"},
                "evidenceType": "api_response",
                "proves": "The API request carries authenticated state.",
            }
        ),
    )
    assert_true(direct_step_header_proc.returncode != 0, "direct auth-like step headers should block plan validation.")
    assert_true(any("headers.Cookie writes auth-like header material directly" in error for error in direct_step_header_summary.get("errors", [])), "direct Cookie step header should produce a specific auth-material error.")

    direct_cookie_proc, direct_cookie_summary = run_case(
        "direct-cookie",
        plan_with_step(
            {
                "action": "addCookies",
                "id": "T-auth-cookie",
                "testIds": ["T-auth"],
                "requirementIds": ["R-auth"],
                "cookies": [{"name": "sid", "value": "fixture-session", "domain": "127.0.0.1", "path": "/"}],
                "evidenceType": "auth_setup",
                "proves": "The browser receives a session cookie.",
            }
        ),
    )
    assert_true(direct_cookie_proc.returncode != 0, "direct session cookie values should block plan validation.")
    assert_true(any("addCookies cookie sid writes auth-like material directly" in error for error in direct_cookie_summary.get("errors", [])), "direct session cookie should produce a specific auth-material error.")

    missing_proc, missing_summary = run_case("missing-file", plan_with("missing-auth-state.json"))
    assert_true(missing_proc.returncode != 0, "missing storageState file should block plan validation.")
    assert_true(any("storageState file does not exist" in error for error in missing_summary.get("errors", [])), "missing storageState should produce a specific setup error.")

    dir_proc, dir_summary = run_case("directory", plan_with(str(dir_state)))
    assert_true(dir_proc.returncode != 0, "directory-shaped storageState should block plan validation.")
    assert_true(any("storageState path is a directory" in error for error in dir_summary.get("errors", [])), "directory storageState should be classified before Playwright execution.")

    bad_proc, bad_summary = run_case("bad-json", plan_with(str(bad_state)))
    assert_true(bad_proc.returncode != 0, "invalid JSON storageState should block plan validation.")
    assert_true(any("storageState file is not valid JSON" in error for error in bad_summary.get("errors", [])), "bad storageState JSON should be classified by validate_plan.")
    assert_true("Traceback" not in bad_proc.stderr, "bad storageState should report without a traceback.")

    cycle_dir = state_dir / "cycle-missing-file"
    cycle_dir.mkdir(parents=True, exist_ok=True)
    write_json(cycle_dir / "test-plan.json", plan_with("missing-auth-state.json"))
    write_json(cycle_dir / "test-matrix.json", matrix)
    cycle_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(cycle_dir),
            "--skip-probe",
        ],
        cwd=cycle_dir,
        text=True,
        capture_output=True,
    )
    assert_true(cycle_proc.returncode != 0, "missing storageState should stop the QA cycle before probe execution.")
    cycle_summary = load_json(cycle_dir / "qa-run-summary.json")
    cycle_verdict = load_json(cycle_dir / "qa-verdict.json")
    cycle_codes = {reason.get("code") for reason in cycle_verdict.get("reasons", [])}
    assert_true(cycle_summary.get("status") == "blocked", "missing storageState cycle summary should be blocked.")
    assert_true(cycle_verdict.get("verdict") == "blocked", "missing storageState cycle verdict should be blocked.")
    assert_true("plan_validation_failed" in cycle_codes, "missing storageState should surface through plan_validation_failed in the final handoff.")


def run_requirement_coverage_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "requirement-coverage-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    requirement_path = input_dir / "requirement.md"
    matrix_path = input_dir / "test-matrix.json"
    summary_path = input_dir / "nested" / "requirement-coverage.json"
    requirement_path.write_text("- The QA loop must stop before probes when matrix coverage cannot be audited.\n", encoding="utf-8")
    matrix_path.write_text("[]", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(requirement_path),
            "--matrix",
            str(matrix_path),
            "--out",
            str(summary_path),
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "audit_requirement_coverage should exit non-zero for unreadable matrix artifacts.")
    assert_true(summary_path.exists(), "audit_requirement_coverage should write requirement-coverage.json even when inputs are unreadable.")
    summary = load_json(summary_path)
    input_errors = {item.get("name"): item.get("error") for item in summary.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(summary.get("passed") is False, "bad requirement coverage inputs must not pass.")
    assert_true(input_errors.get("matrix") == "json_root_not_object", "audit_requirement_coverage should classify non-object matrix JSON.")
    assert_true(summary.get("matrix_requirement_count") == 0, "bad matrix input should not synthesize matrix requirements.")
    assert_true(summary.get("covered_count") == 0, "bad matrix input should not synthesize covered source units.")
    assert_true("Traceback" not in proc.stderr, "audit_requirement_coverage should report bad inputs without a Python traceback.")


def run_adapter_probe_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "adapter-probe-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    context_path = input_dir / "adapter-context.json"
    plan_path = input_dir / "test-plan.json"
    matrix_path = input_dir / "test-matrix.json"
    out_path = input_dir / "nested" / "adapter-probes.json"
    context_path.write_text("[]", encoding="utf-8")
    plan_path.mkdir()
    matrix_path.write_text("{not-json", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "synthesize_adapter_probes.py"),
            "--run-dir",
            str(input_dir),
            "--adapter-context",
            str(context_path),
            "--plan",
            str(plan_path),
            "--matrix",
            str(matrix_path),
            "--out",
            str(out_path),
            "--apply",
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "synthesize_adapter_probes should exit non-zero for unreadable input artifacts.")
    assert_true(out_path.exists(), "synthesize_adapter_probes should write adapter-probes.json even when inputs are unreadable.")
    report = load_json(out_path)
    input_errors = {item.get("name"): item.get("error") for item in report.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(input_errors.get("adapter_context") == "json_root_not_object", "synthesize_adapter_probes should classify non-object adapter contexts.")
    assert_true(input_errors.get("plan") == "path_is_directory", "synthesize_adapter_probes should classify directory-shaped plans.")
    assert_true(str(input_errors.get("matrix", "")).startswith("invalid_json"), "synthesize_adapter_probes should classify malformed matrices.")
    assert_true(report.get("summary", {}).get("input_artifact_error_count") == 3, "adapter-probes summary should count unreadable inputs.")
    assert_true(report.get("proposed_step_ids") == [] and report.get("added_step_ids") == [], "bad adapter-probe inputs should not synthesize or apply steps.")
    assert_true("Traceback" not in proc.stderr, "synthesize_adapter_probes should report bad inputs without a Python traceback.")


def run_preflight_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "preflight-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    context_path = input_dir / "adapter-context.json"
    plan_path = input_dir / "test-plan.json"
    out_path = input_dir / "nested" / "service-preflight.json"
    context_path.write_text("[]", encoding="utf-8")
    plan_path.mkdir()

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "preflight_runtime.py"),
            "--run-dir",
            str(input_dir),
            "--adapter-context",
            str(context_path),
            "--plan",
            str(plan_path),
            "--out",
            str(out_path),
            "--fail-on-blockers",
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "preflight_runtime should exit non-zero for unreadable input artifacts.")
    assert_true(out_path.exists(), "preflight_runtime should write service-preflight.json even when inputs are unreadable.")
    report = load_json(out_path)
    input_errors = {item.get("name"): item.get("error") for item in report.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(report.get("runnable") is False, "bad preflight inputs must not be runnable.")
    assert_true(input_errors.get("adapter_context") == "json_root_not_object", "preflight_runtime should classify non-object adapter contexts.")
    assert_true(input_errors.get("plan") == "path_is_directory", "preflight_runtime should classify directory-shaped plans.")
    assert_true(report.get("start_plan") == [], "bad preflight inputs should not synthesize a service start plan.")
    assert_true("Traceback" not in proc.stderr, "preflight_runtime should report bad inputs without a Python traceback.")


def run_preflight_missing_required_service_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "preflight-missing-required-service"
    input_dir.mkdir(parents=True, exist_ok=True)
    context_path = input_dir / "adapter-context.json"
    plan_path = input_dir / "test-plan.json"
    out_path = input_dir / "service-preflight.json"
    write_json(
        context_path,
        {
            "schema_version": 1,
            "adapter": "fixture",
            "project_root": str(input_dir),
            "base_url": "http://127.0.0.1:65527",
            "environment_boundary": {
                "runtime_mode": "test",
                "data_boundary_status": "fixture data only; no production data",
            },
            "services": [],
        },
    )
    write_json(
        plan_path,
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:65527",
            "artifactDir": str(input_dir),
            "scenarios": [],
        },
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "preflight_runtime.py"),
            "--run-dir",
            str(input_dir),
            "--adapter-context",
            str(context_path),
            "--plan",
            str(plan_path),
            "--out",
            str(out_path),
            "--required-service",
            "missing-api",
            "--fail-on-blockers",
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "preflight_runtime should block when an explicit required service id is absent from adapter context.")
    report = load_json(out_path)
    blockers = {(item.get("service"), item.get("reason")) for item in report.get("blockers", []) if isinstance(item, dict)}
    assert_true(report.get("runnable") is False, "missing explicit required services must not be runnable.")
    assert_true(("missing-api", "required service is not present in adapter context") in blockers, "preflight should name the missing required service id.")
    assert_true(report.get("start_plan") == [], "missing service definitions should not synthesize a start plan.")
    assert_true("Traceback" not in proc.stderr, "missing required services should report without a Python traceback.")


def run_service_runtime_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "service-runtime-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    preflight_path = input_dir / "service-preflight.json"
    runtime_path = input_dir / "service-runtime.json"
    start_out = input_dir / "nested" / "service-runtime.json"
    stop_out = input_dir / "nested" / "service-runtime-stop.json"
    preflight_path.write_text("[]", encoding="utf-8")
    runtime_path.mkdir()

    start_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "service_runtime.py"),
            "--run-dir",
            str(input_dir),
            "--preflight",
            str(preflight_path),
            "--out",
            str(start_out),
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(start_proc.returncode != 0, "service_runtime dry-run should exit non-zero for unreadable preflight artifacts.")
    assert_true(start_out.exists(), "service_runtime should write service-runtime.json even when preflight is unreadable.")
    start_report = load_json(start_out)
    start_errors = {item.get("name"): item.get("error") for item in start_report.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(start_errors.get("preflight") == "json_root_not_object", "service_runtime should classify non-object preflight artifacts.")
    assert_true(start_report.get("summary", {}).get("started_count") == 0, "bad preflight input should not start services.")
    assert_true("Traceback" not in start_proc.stderr, "service_runtime dry-run should report bad inputs without a Python traceback.")

    stop_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "service_runtime.py"),
            "--run-dir",
            str(input_dir),
            "--runtime",
            str(runtime_path),
            "--out",
            str(stop_out),
            "--stop",
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(stop_proc.returncode != 0, "service_runtime stop should exit non-zero for unreadable runtime artifacts.")
    assert_true(stop_out.exists(), "service_runtime should write service-runtime-stop.json even when runtime input is unreadable.")
    stop_report = load_json(stop_out)
    stop_errors = {item.get("name"): item.get("error") for item in stop_report.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(stop_errors.get("runtime") == "path_is_directory", "service_runtime should classify directory-shaped runtime artifacts.")
    assert_true(stop_report.get("summary", {}).get("stopped_count") == 0, "bad runtime input should not stop services.")
    assert_true("Traceback" not in stop_proc.stderr, "service_runtime stop should report bad inputs without a Python traceback.")


def run_discover_project_context_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "discover-context-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    missing_root = input_dir / "missing-project-root"
    out_path = input_dir / "nested" / "adapter-context.json"

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "discover_project_context.py"),
            "--project-root",
            str(missing_root),
            "--out",
            str(out_path),
            "--no-http-probe",
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "discover_project_context should exit non-zero for unreadable project roots.")
    assert_true(out_path.exists(), "discover_project_context should write adapter-context.json even when project-root is unreadable.")
    context = load_json(out_path)
    input_errors = {item.get("name"): item.get("error") for item in context.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(input_errors.get("project_root") == "missing", "discover_project_context should classify missing project roots.")
    assert_true(context.get("project_root_status", {}).get("readable") is False, "adapter context should mark unreadable project roots.")
    assert_true(context.get("services") == [], "bad project roots should not synthesize service candidates.")
    assert_true("Traceback" not in proc.stderr, "discover_project_context should report bad project roots without a Python traceback.")


def run_preflight_project_root_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "preflight-project-root-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    file_root = input_dir / "not-a-project-root.txt"
    file_root.write_text("not a directory\n", encoding="utf-8")
    out_path = input_dir / "nested" / "service-preflight.json"

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "preflight_runtime.py"),
            "--run-dir",
            str(input_dir),
            "--project-root",
            str(file_root),
            "--refresh-context",
            "--no-http-probe",
            "--out",
            str(out_path),
            "--fail-on-blockers",
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "preflight_runtime should exit non-zero for unreadable discovered project roots.")
    assert_true(out_path.exists(), "preflight_runtime should write service-preflight.json for unreadable project roots.")
    report = load_json(out_path)
    input_errors = {item.get("name"): item.get("error") for item in report.get("input_artifact_errors", []) if isinstance(item, dict)}
    blocker_errors = {item.get("artifact"): item.get("error") for item in report.get("blockers", []) if isinstance(item, dict)}
    assert_true(report.get("runnable") is False, "preflight with unreadable project root must not be runnable.")
    assert_true(input_errors.get("project_root") == "path_is_not_directory", "preflight should preserve project-root input errors from discovery.")
    assert_true(blocker_errors.get("project_root") == "path_is_not_directory", "preflight blockers should name the project-root error.")
    assert_true(report.get("start_plan") == [], "bad project roots should not synthesize service start plans.")
    assert_true("Traceback" not in proc.stderr, "preflight_runtime should report bad discovered project roots without a Python traceback.")


def run_audit_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "audit-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = input_dir / "evidence-ledger.json"
    matrix_path = input_dir / "test-matrix.json"
    results_path = input_dir / "results.json"
    summary_path = input_dir / "nested" / "audit-summary.json"
    ledger_path.write_text("[]", encoding="utf-8")
    matrix_path.mkdir()
    results_path.write_text("{not-json", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--ledger",
            str(ledger_path),
            "--matrix",
            str(matrix_path),
            "--results",
            str(results_path),
            "--summary",
            str(summary_path),
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "audit_evidence should exit non-zero for unreadable input artifacts.")
    assert_true(summary_path.exists(), "audit_evidence should write audit-summary.json even when inputs are unreadable.")
    summary = load_json(summary_path)
    input_errors = {item.get("name"): item.get("error") for item in summary.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(summary.get("passed") is False, "bad audit_evidence inputs must not pass.")
    assert_true(input_errors.get("ledger") == "json_root_not_object", "audit_evidence should classify non-object ledgers.")
    assert_true(input_errors.get("matrix") == "path_is_directory", "audit_evidence should classify directory-shaped matrices.")
    assert_true(str(input_errors.get("results", "")).startswith("invalid_json"), "audit_evidence should classify malformed results JSON.")
    assert_true(summary.get("requirement_count") == 0 and summary.get("evidence_count") == 0, "bad audit_evidence inputs should not synthesize evidence counts.")
    assert_true(summary.get("passed_evidence_current_run_checked") is False, "bad audit_evidence inputs should not claim current-run evidence was checked.")
    assert_true("Traceback" not in proc.stderr, "audit_evidence should report bad inputs without a Python traceback.")


def run_defect_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "defect-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = input_dir / "evidence-ledger.json"
    matrix_path = input_dir / "test-matrix.json"
    results_path = input_dir / "results.json"
    defects_path = input_dir / "nested" / "defects.json"
    ledger_path.write_text("[]", encoding="utf-8")
    matrix_path.mkdir()
    results_path.write_text("{not-json", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "generate_defects.py"),
            "--ledger",
            str(ledger_path),
            "--results",
            str(results_path),
            "--matrix",
            str(matrix_path),
            "--out",
            str(defects_path),
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "generate_defects should exit non-zero for unreadable input artifacts.")
    assert_true(defects_path.exists(), "generate_defects should write defects.json even when inputs are unreadable.")
    defects = load_json(defects_path)
    input_errors = {item.get("name"): item.get("error") for item in defects.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(defects.get("summary", {}).get("finding_count") == 0, "bad defect inputs should not synthesize findings.")
    assert_true(input_errors.get("ledger") == "json_root_not_object", "generate_defects should classify non-object ledgers.")
    assert_true(input_errors.get("matrix") == "path_is_directory", "generate_defects should classify directory-shaped matrices.")
    assert_true(str(input_errors.get("results", "")).startswith("invalid_json"), "generate_defects should classify malformed results JSON.")
    assert_true(defects.get("summary", {}).get("input_artifact_error_count") == 3, "defects summary should count unreadable inputs.")
    assert_true("Traceback" not in proc.stderr, "generate_defects should report bad inputs without a Python traceback.")


def run_next_probe_generation_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "next-probe-generation-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    defects_path = input_dir / "defects.json"
    results_path = input_dir / "results.json"
    ledger_path = input_dir / "evidence-ledger.json"
    next_path = input_dir / "nested" / "next-probes.json"
    defects_path.write_text("[]", encoding="utf-8")
    results_path.mkdir()
    ledger_path.write_text("{not-json", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "generate_next_probes.py"),
            "--defects",
            str(defects_path),
            "--results",
            str(results_path),
            "--ledger",
            str(ledger_path),
            "--out",
            str(next_path),
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "generate_next_probes should exit non-zero for unreadable input artifacts.")
    assert_true(next_path.exists(), "generate_next_probes should write next-probes.json even when inputs are unreadable.")
    next_probes = load_json(next_path)
    input_errors = {item.get("name"): item.get("error") for item in next_probes.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(next_probes.get("summary", {}).get("recommendation_count") == 0, "bad next-probe inputs should not synthesize recommendations.")
    assert_true(input_errors.get("defects") == "json_root_not_object", "generate_next_probes should classify non-object defects.")
    assert_true(input_errors.get("results") == "path_is_directory", "generate_next_probes should classify directory-shaped results.")
    assert_true(str(input_errors.get("ledger", "")).startswith("invalid_json"), "generate_next_probes should classify malformed ledgers.")
    assert_true(next_probes.get("summary", {}).get("input_artifact_error_count") == 3, "next-probes summary should count unreadable inputs.")
    assert_true("Traceback" not in proc.stderr, "generate_next_probes should report bad inputs without a Python traceback.")


def run_ledger_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "ledger-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    matrix_path = input_dir / "test-matrix.json"
    results_path = input_dir / "results.json"
    ledger_path = input_dir / "nested" / "evidence-ledger.json"
    matrix_path.write_text("[]", encoding="utf-8")
    results_path.write_text("{not-json", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "ledger_from_probe.py"),
            "--matrix",
            str(matrix_path),
            "--results",
            str(results_path),
            "--out",
            str(ledger_path),
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "ledger_from_probe should exit non-zero for unreadable input artifacts.")
    assert_true(ledger_path.exists(), "ledger_from_probe should write evidence-ledger.json even when inputs are unreadable.")
    ledger = load_json(ledger_path)
    input_errors = {item.get("name"): item.get("error") for item in ledger.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(ledger.get("requirements") == [] and ledger.get("tests") == [] and ledger.get("evidence") == [], "bad ledger inputs should not synthesize evidence.")
    assert_true(input_errors.get("matrix") == "json_root_not_object", "ledger_from_probe should classify non-object matrices.")
    assert_true(str(input_errors.get("results", "")).startswith("invalid_json"), "ledger_from_probe should classify malformed results JSON.")
    assert_true(ledger.get("runtime_summary", {}).get("input_artifact_error_count") == 2, "ledger runtime summary should count unreadable inputs.")
    assert_true("Traceback" not in proc.stderr, "ledger_from_probe should report bad inputs without a Python traceback.")


def run_audit_failure_handoff_fixture(script_dir: Path, tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit-failure-handoff"
    audit_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        audit_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-shot",
                    "source": "fixture",
                    "text": "A visible result must be backed by a current screenshot artifact.",
                    "test_ids": ["T-shot"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-shot",
                    "requirement_ids": ["R-shot"],
                    "type": "ui",
                    "expected": "The screenshot artifact exists and is readable.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        audit_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(audit_dir),
            "scenarios": [
                {
                    "id": "shot-proof",
                    "steps": [
                        {
                            "action": "screenshot",
                            "id": "shot-proof-step",
                            "testIds": ["T-shot"],
                            "requirementIds": ["R-shot"],
                            "evidenceType": "screenshot",
                            "proves": "A visible result is captured in a screenshot artifact.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        audit_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "startedAt": "2026-06-15T00:00:00+00:00",
            "finishedAt": "2026-06-15T00:00:01+00:00",
            "scenarios": [
                {
                    "id": "shot-proof",
                    "steps": [
                        {
                            "stepId": "shot-proof-step",
                            "action": "screenshot",
                            "status": "passed",
                            "screenshot": "screenshots/missing.png",
                            "testIds": ["T-shot"],
                            "requirementIds": ["R-shot"],
                            "evidenceType": "screenshot",
                            "proves": "A visible result is captured in a screenshot artifact.",
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    cycle_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(audit_dir),
            "--skip-probe",
            "--skip-report",
        ],
        cwd=audit_dir,
        text=True,
        capture_output=True,
    )
    assert_true(cycle_proc.returncode != 0, "audit failure cycle should exit non-zero.")
    cycle_summary = load_json(audit_dir / "qa-run-summary.json")
    cycle_verdict = load_json(audit_dir / "qa-verdict.json")
    cycle_codes = {reason.get("code") for reason in cycle_verdict.get("reasons", [])}
    audit_summary = load_json(audit_dir / "audit-summary.json")
    assert_true(audit_summary.get("passed") is False, "fixture audit should fail before verdict handoff.")
    assert_true(cycle_summary.get("status") == "inconclusive", "audit failure summary should use the structured verdict status.")
    assert_true(cycle_verdict.get("verdict") == "inconclusive", "audit failure handoff verdict should be inconclusive.")
    assert_true(cycle_verdict.get("can_claim_pass") is False, "audit failure handoff must not allow pass.")
    assert_true("audit_failed" in cycle_codes, "audit failure handoff should include audit_failed.")
    assert_true(cycle_summary.get("verdict", {}).get("verdict") == "inconclusive", "cycle summary should embed the audit failure verdict.")

    loop_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "qa_agent_loop.py"),
            "--run-dir",
            str(audit_dir),
            "--skip-probe",
            "--skip-report",
            "--max-iterations",
            "1",
        ],
        cwd=audit_dir,
        text=True,
        capture_output=True,
    )
    assert_true(loop_proc.returncode != 0, "agent loop should stay non-zero for audit failure handoff.")
    agent_summary = load_json(audit_dir / "qa-agent-summary.json")
    assert_true(agent_summary.get("status") == "inconclusive", "agent loop should preserve audit failure verdict status.")
    assert_true(agent_summary.get("stop_reason") == "cycle_stopped_with_verdict", "agent loop should distinguish audit verdict handoff from generic failure.")
    assert_true((agent_summary.get("next_action") or {}).get("action") == "repair_evidence_pipeline", "audit failure should request evidence-pipeline repair.")


def run_helper_failure_handoff_fixture(script_dir: Path, tmp_path: Path) -> None:
    helper_dir = tmp_path / "helper-failure-handoff"
    helper_dir.mkdir(parents=True, exist_ok=True)
    (helper_dir / "screenshots").mkdir(parents=True, exist_ok=True)
    (helper_dir / "screenshots" / "actual.png").write_bytes(VALID_PNG_1X1)
    write_json(
        helper_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-shot",
                    "source": "fixture",
                    "text": "A visible result must be backed by a current screenshot artifact.",
                    "test_ids": ["T-shot"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-shot",
                    "requirement_ids": ["R-shot"],
                    "type": "ui",
                    "expected": "The screenshot artifact exists and is readable.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        helper_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(helper_dir),
            "scenarios": [
                {
                    "id": "shot-proof",
                    "steps": [
                        {
                            "action": "screenshot",
                            "id": "shot-proof-step",
                            "testIds": ["T-shot"],
                            "requirementIds": ["R-shot"],
                            "evidenceType": "screenshot",
                            "proves": "A visible result is captured in a screenshot artifact.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        helper_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "startedAt": "2000-01-01T00:00:00+00:00",
            "finishedAt": "2000-01-01T00:00:01+00:00",
            "scenarios": [
                {
                    "id": "shot-proof",
                    "steps": [
                        {
                            "stepId": "shot-proof-step",
                            "action": "screenshot",
                            "status": "passed",
                            "screenshot": "screenshots/actual.png",
                            "testIds": ["T-shot"],
                            "requirementIds": ["R-shot"],
                            "evidenceType": "screenshot",
                            "proves": "A visible result is captured in a screenshot artifact.",
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    (helper_dir / "defects.json").mkdir()
    cycle_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(helper_dir),
            "--skip-probe",
            "--skip-report",
        ],
        cwd=helper_dir,
        text=True,
        capture_output=True,
    )
    assert_true(cycle_proc.returncode != 0, "helper failure cycle should exit non-zero.")
    cycle_summary = load_json(helper_dir / "qa-run-summary.json")
    cycle_error = load_json(helper_dir / "qa-cycle-error.json")
    cycle_verdict = load_json(helper_dir / "qa-verdict.json")
    cycle_codes = {reason.get("code") for reason in cycle_verdict.get("reasons", [])}
    assert_true(cycle_error.get("phase") == "generate_defects", "cycle error should name the failed helper phase.")
    assert_true(cycle_summary.get("status") == "inconclusive", "helper failure summary should use the structured verdict status.")
    assert_true(cycle_verdict.get("verdict") == "inconclusive", "helper failure handoff verdict should be inconclusive.")
    assert_true(cycle_verdict.get("can_claim_pass") is False, "helper failure handoff must not allow pass.")
    assert_true("cycle_helper_failed" in cycle_codes, "helper failure handoff should include cycle_helper_failed.")
    assert_true(cycle_verdict.get("gates", {}).get("cycle_completed") is False, "helper failure verdict should mark the cycle incomplete.")

    loop_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "qa_agent_loop.py"),
            "--run-dir",
            str(helper_dir),
            "--skip-probe",
            "--skip-report",
            "--max-iterations",
            "1",
        ],
        cwd=helper_dir,
        text=True,
        capture_output=True,
    )
    assert_true(loop_proc.returncode != 0, "agent loop should stay non-zero for helper failure handoff.")
    agent_summary = load_json(helper_dir / "qa-agent-summary.json")
    assert_true(agent_summary.get("status") == "inconclusive", "agent loop should preserve helper failure verdict status.")
    assert_true(agent_summary.get("stop_reason") == "cycle_stopped_with_verdict", "agent loop should distinguish helper verdict handoff from generic failure.")
    assert_true((agent_summary.get("next_action") or {}).get("action") == "repair_evidence_pipeline", "helper failure should request evidence-pipeline repair.")


def run_helper_output_unreadable_fixture(script_dir: Path, tmp_path: Path) -> None:
    shim_dir = tmp_path / "helper-output-unreadable-shim"
    shim_dir.mkdir(parents=True, exist_ok=True)
    for source in script_dir.iterdir():
        if source.is_file() and source.suffix in {".py", ".mjs"}:
            shutil.copy2(source, shim_dir / source.name)

    preflight_shim_dir = tmp_path / "helper-output-missing-preflight-shim"
    preflight_shim_dir.mkdir(parents=True, exist_ok=True)
    for source in script_dir.iterdir():
        if source.is_file() and source.suffix in {".py", ".mjs"}:
            shutil.copy2(source, preflight_shim_dir / source.name)
    (preflight_shim_dir / "preflight_runtime.py").write_text(
        """#!/usr/bin/env python3
raise SystemExit(0)
""",
        encoding="utf-8",
    )
    (shim_dir / "generate_defects.py").write_text(
        """#!/usr/bin/env python3
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--ledger")
parser.add_argument("--results")
parser.add_argument("--matrix")
parser.add_argument("--out", required=True)
args = parser.parse_args()
Path(args.out).write_text("{not-json", encoding="utf-8")
print(args.out)
raise SystemExit(0)
""",
        encoding="utf-8",
    )

    missing_preflight_dir = tmp_path / "helper-output-missing-preflight"
    missing_preflight_dir.mkdir(parents=True, exist_ok=True)
    write_valid_skip_probe_plan(missing_preflight_dir)
    preflight_proc = subprocess.run(
        [
            sys.executable,
            str(preflight_shim_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(missing_preflight_dir),
            "--preflight-runtime",
            "--skip-probe",
            "--skip-report",
        ],
        cwd=missing_preflight_dir,
        text=True,
        capture_output=True,
    )
    assert_true(preflight_proc.returncode != 0, "cycle should exit non-zero when preflight exits zero without service-preflight.json.")
    assert_true("Traceback" not in preflight_proc.stderr, "missing preflight output should not crash run_qa_cycle with a traceback.")
    preflight_error = load_json(missing_preflight_dir / "qa-cycle-error.json")
    preflight_verdict = load_json(missing_preflight_dir / "qa-verdict.json")
    preflight_codes = {reason.get("code") for reason in preflight_verdict.get("reasons", [])}
    assert_true(preflight_error.get("code") == "helper_output_unreadable", "missing preflight output should be classified as unreadable helper output.")
    assert_true(preflight_error.get("phase") == "preflight_runtime", "missing preflight output should name the preflight phase.")
    assert_true("missing_output" in str(preflight_error.get("message")), "missing preflight output should preserve the missing_output load error.")
    assert_true("helper_output_unreadable" in preflight_codes, "preflight verdict should include helper_output_unreadable.")

    case_dir = tmp_path / "helper-output-unreadable"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "screenshots").mkdir(parents=True, exist_ok=True)
    (case_dir / "screenshots" / "actual.png").write_bytes(VALID_PNG_1X1)
    write_json(
        case_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-output",
                    "source": "fixture",
                    "text": "A helper that exits zero must still produce readable JSON.",
                    "test_ids": ["T-output"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-output",
                    "requirement_ids": ["R-output"],
                    "type": "ui",
                    "expected": "The screenshot artifact exists and is readable.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        case_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(case_dir),
            "scenarios": [
                {
                    "id": "output-proof",
                    "steps": [
                        {
                            "action": "screenshot",
                            "id": "output-proof-step",
                            "testIds": ["T-output"],
                            "requirementIds": ["R-output"],
                            "evidenceType": "screenshot",
                            "proves": "A visible result is captured in a screenshot artifact.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        case_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "startedAt": "2000-01-01T00:00:00+00:00",
            "finishedAt": "2000-01-01T00:00:01+00:00",
            "scenarios": [
                {
                    "id": "output-proof",
                    "steps": [
                        {
                            "stepId": "output-proof-step",
                            "action": "screenshot",
                            "status": "passed",
                            "screenshot": "screenshots/actual.png",
                            "testIds": ["T-output"],
                            "requirementIds": ["R-output"],
                            "evidenceType": "screenshot",
                            "proves": "A visible result is captured in a screenshot artifact.",
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    cycle_proc = subprocess.run(
        [
            sys.executable,
            str(shim_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(case_dir),
            "--skip-probe",
            "--skip-report",
        ],
        cwd=case_dir,
        text=True,
        capture_output=True,
    )
    assert_true(cycle_proc.returncode != 0, "cycle should exit non-zero when a zero-exit helper writes unreadable JSON.")
    assert_true("Traceback" not in cycle_proc.stderr, "unreadable helper output should not crash run_qa_cycle with a traceback.")
    cycle_summary = load_json(case_dir / "qa-run-summary.json")
    cycle_error = load_json(case_dir / "qa-cycle-error.json")
    cycle_verdict = load_json(case_dir / "qa-verdict.json")
    cycle_codes = {reason.get("code") for reason in cycle_verdict.get("reasons", [])}
    assert_true(cycle_error.get("code") == "helper_output_unreadable", "cycle error should classify zero-exit unreadable helper output.")
    assert_true(cycle_error.get("phase") == "generate_defects", "cycle error should name the helper phase with unreadable output.")
    assert_true("invalid_json" in str(cycle_error.get("message")), "cycle error should preserve the JSON load error.")
    assert_true(cycle_verdict.get("can_claim_pass") is False, "unreadable helper output must block pass claims.")
    assert_true("helper_output_unreadable" in cycle_codes, "verdict should include helper_output_unreadable.")
    assert_true(cycle_summary.get("cycle_error", {}).get("code") == "helper_output_unreadable", "cycle summary should embed the unreadable helper output error.")


def run_browser_hit_test_fixture(script_dir: Path, tmp_path: Path) -> None:
    browser_dir = tmp_path / "browser-hit-test"
    browser_dir.mkdir(parents=True, exist_ok=True)
    html_path = browser_dir / "page.html"
    html_path.write_text(
        """<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Hit Test Fixture</title>
    <style>
      body { font-family: sans-serif; padding: 40px; }
      .stack { position: relative; width: 240px; height: 80px; margin-top: 24px; }
      .blocked-button { position: absolute; left: 0; top: 0; width: 200px; height: 48px; }
      .blocking-overlay { position: absolute; left: 0; top: 0; width: 200px; height: 48px; background: rgba(200, 0, 0, 0.3); z-index: 2; }
    </style>
  </head>
  <body>
    <button id="ok">Save</button>
    <div class="stack">
      <button id="blocked" class="blocked-button">Delete</button>
      <div class="blocking-overlay" data-onboarding="blocking-overlay">Blocking overlay</div>
    </div>
  </body>
</html>
""",
        encoding="utf-8",
    )
    write_json(
        browser_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {"id": "R-open", "source": "fixture", "text": "Fixture page opens.", "test_ids": ["T-open"], "status": "Untested"},
                {"id": "R-save", "source": "fixture", "text": "Save button is clickable.", "test_ids": ["T-save"], "status": "Untested"},
                {"id": "R-delete", "source": "fixture", "text": "Delete button is clickable.", "test_ids": ["T-delete"], "status": "Untested"},
                {"id": "R-skipped", "source": "fixture", "text": "A planned assertion after a failure must not silently pass.", "test_ids": ["T-skipped"], "status": "Untested"},
            ],
            "tests": [
                {"id": "T-open", "requirement_ids": ["R-open"], "type": "ui", "expected": "Fixture opens.", "status": "Untested"},
                {"id": "T-save", "requirement_ids": ["R-save"], "type": "interaction", "expected": "Save receives pointer events.", "status": "Untested"},
                {"id": "T-delete", "requirement_ids": ["R-delete"], "type": "interaction", "expected": "Delete receives pointer events.", "status": "Untested"},
                {"id": "T-skipped", "requirement_ids": ["R-skipped"], "type": "ui", "expected": "Both planned assertions execute before a pass is possible.", "status": "Untested"},
            ],
        },
    )
    write_json(
        browser_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "",
            "artifactDir": str(browser_dir),
            "headless": True,
            "scenarios": [
                {
                    "id": "hit-test",
                    "continueOnFailure": True,
                    "steps": [
                        {
                            "action": "goto",
                            "id": "open",
                            "url": html_path.resolve().as_uri(),
                            "testIds": ["T-open"],
                            "requirementIds": ["R-open"],
                            "evidenceType": "navigation",
                            "proves": "Fixture page opens.",
                        },
                        {
                            "action": "expectClickable",
                            "id": "save-clickable",
                            "role": "button",
                            "name": "Save",
                            "testIds": ["T-save"],
                            "requirementIds": ["R-save"],
                            "evidenceType": "ui_interaction",
                            "proves": "Save button receives pointer events.",
                        },
                        {
                            "action": "expectClickable",
                            "id": "delete-clickable",
                            "role": "button",
                            "name": "Delete",
                            "testIds": ["T-delete"],
                            "requirementIds": ["R-delete"],
                            "evidenceType": "ui_interaction",
                            "proves": "Delete button receives pointer events.",
                        },
                    ],
                },
                {
                    "id": "skipped-after-failure",
                    "steps": [
                        {
                            "action": "goto",
                            "id": "skipped-open",
                            "url": html_path.resolve().as_uri(),
                            "testIds": ["T-skipped"],
                            "requirementIds": ["R-skipped"],
                            "evidenceType": "navigation",
                            "proves": "The skipped-step scenario opens the fixture page independently.",
                        },
                        {
                            "action": "expectText",
                            "id": "skipped-setup-visible",
                            "text": "Save",
                            "testIds": ["T-skipped"],
                            "requirementIds": ["R-skipped"],
                            "evidenceType": "ui_assertion",
                            "proves": "The fixture page was still visible before the later failure.",
                        },
                        {
                            "action": "expectText",
                            "id": "skipped-trigger-failure",
                            "text": "Text that is intentionally absent",
                            "testIds": ["T-delete"],
                            "requirementIds": ["R-delete"],
                            "evidenceType": "ui_assertion",
                            "proves": "An intentional failure stops normal follow-up steps.",
                        },
                        {
                            "action": "expectText",
                            "id": "skipped-critical-assertion",
                            "text": "Save",
                            "testIds": ["T-skipped"],
                            "requirementIds": ["R-skipped"],
                            "evidenceType": "ui_assertion",
                            "proves": "This critical planned assertion must be recorded as skipped, not silently omitted.",
                        },
                    ],
                }
            ],
        },
    )
    run_cmd(["node", str(script_dir / "playwright_probe.mjs"), "--plan", str(browser_dir / "test-plan.json")], cwd=browser_dir)
    results = load_json(browser_dir / "results.json")
    failed_step = results["scenarios"][0]["steps"][2]
    skipped_scenario = next(scenario for scenario in results.get("scenarios", []) if scenario.get("id") == "skipped-after-failure")
    skipped_step = next(step for step in skipped_scenario.get("steps", []) if step.get("stepId") == "skipped-critical-assertion")
    assert_true(results.get("status") == "attention", "browser hit-test fixture should produce attention status.")
    assert_true(failed_step.get("status") == "failed", "blocked Delete button should fail expectClickable.")
    assert_true((failed_step.get("hitTest") or {}).get("blocker", {}).get("dataOnboarding") == "blocking-overlay", "blocked hit-test should preserve blocker details.")
    assert_true(skipped_step.get("status") == "skipped", "runner should record planned steps skipped after an earlier failure.")
    assert_true(skipped_step.get("testIds") == ["T-skipped"], "skipped step should preserve test lineage.")
    run_cmd(
        [
            sys.executable,
            str(script_dir / "ledger_from_probe.py"),
            "--matrix",
            str(browser_dir / "test-matrix.json"),
            "--results",
            str(browser_dir / "results.json"),
            "--out",
            str(browser_dir / "evidence-ledger.json"),
        ],
        cwd=browser_dir,
    )
    browser_ledger = load_json(browser_dir / "evidence-ledger.json")
    skipped_test = next(test for test in browser_ledger.get("tests", []) if test.get("id") == "T-skipped")
    skipped_requirement = next(req for req in browser_ledger.get("requirements", []) if req.get("id") == "R-skipped")
    assert_true(skipped_test.get("status") == "Inconclusive", "a test with skipped planned assertions must not be marked Passed.")
    assert_true(skipped_requirement.get("status") == "Inconclusive", "a requirement with skipped planned assertions must not be marked Passed.")
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(browser_dir / "test-matrix.json"),
            "--results",
            str(browser_dir / "results.json"),
            "--ledger",
            str(browser_dir / "evidence-ledger.json"),
            "--summary",
            str(browser_dir / "audit-summary.json"),
        ],
        cwd=browser_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_defects.py"),
            "--ledger",
            str(browser_dir / "evidence-ledger.json"),
            "--results",
            str(browser_dir / "results.json"),
            "--matrix",
            str(browser_dir / "test-matrix.json"),
            "--out",
            str(browser_dir / "defects.json"),
        ],
        cwd=browser_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(browser_dir / "test-plan.json"),
            "--results",
            str(browser_dir / "results.json"),
            "--ledger",
            str(browser_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(browser_dir / "audit-summary.json"),
            "--defects",
            str(browser_dir / "defects.json"),
            "--out",
            str(browser_dir / "report.md"),
        ],
        cwd=browser_dir,
    )
    ledger = load_json(browser_dir / "evidence-ledger.json")
    defects = load_json(browser_dir / "defects.json")
    report = (browser_dir / "report.md").read_text(encoding="utf-8")
    failed_evidence = next(item for item in ledger.get("evidence", []) if item.get("step_id") == "delete-clickable")
    assert_true(failed_evidence.get("hit_test", {}).get("blocker", {}).get("dataOnboarding") == "blocking-overlay", "ledger should retain hit-test blocker details.")
    assert_true(defects.get("summary", {}).get("finding_count") == 1, "blocked clickability should generate one defect.")
    assert_true("Hit test:" in report and "blocking-overlay" in report, "report should render hit-test blocker details.")


def run_probe_redaction_fixture(script_dir: Path, tmp_path: Path) -> None:
    redaction_dir = tmp_path / "probe-redaction"
    redaction_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        redaction_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "artifactDir": str(redaction_dir),
            "headless": True,
            "scenarios": [
                {
                    "id": "redaction",
                    "steps": [
                        {
                            "action": "command",
                            "id": "T-redact-command",
                            "testIds": ["T-redact"],
                            "requirementIds": ["R-redact"],
                            "command": [
                                "python3",
                                "-c",
                                "import sys; print('password=fixture-password'); print('https://example.test/callback?password=fixture-password&ok=1'); print('Cookie: sid=fixture-session; theme=light', file=sys.stderr); print('Authorization: Basic fixture-basic', file=sys.stderr)",
                            ],
                            "captureStdout": True,
                            "captureStderr": True,
                            "evidenceType": "command",
                            "proves": "Runner evidence redacts secret-like stdout and stderr values.",
                        }
                    ],
                }
            ],
        },
    )
    run_cmd(["node", str(script_dir / "playwright_probe.mjs"), "--plan", str(redaction_dir / "test-plan.json")], cwd=redaction_dir)
    results = load_json(redaction_dir / "results.json")
    step = results.get("scenarios", [{}])[0].get("steps", [{}])[0]
    stdout_text = Path(step.get("stdoutPath")).read_text(encoding="utf-8")
    stderr_text = Path(step.get("stderrPath")).read_text(encoding="utf-8")
    combined = json.dumps(step, ensure_ascii=False) + "\n" + stdout_text + "\n" + stderr_text
    assert_true("fixture-password" not in combined, "Runner output should redact password-like values from previews and evidence files.")
    assert_true("fixture-session" not in combined, "Runner output should redact cookie values from previews and evidence files.")
    assert_true("fixture-basic" not in combined, "Runner output should redact authorization values from previews and evidence files.")
    assert_true("password=[REDACTED]" in combined, "Runner output should preserve password field shape with a redacted value.")
    assert_true("Cookie: [REDACTED]" in combined, "Runner output should preserve cookie header shape with a redacted value.")
    assert_true("Authorization: [REDACTED]" in combined, "Runner output should preserve authorization header shape with a redacted value.")


def run_evidence_layer_gate_fixture(script_dir: Path, tmp_path: Path) -> None:
    layer_dir = tmp_path / "evidence-layer-gate"
    layer_dir.mkdir(parents=True, exist_ok=True)
    (layer_dir / "screenshots").mkdir(parents=True, exist_ok=True)
    (layer_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (layer_dir / "screenshots" / "fallback.png").write_bytes(b"fake-png-placeholder")
    (layer_dir / "evidence" / "stream-messages.txt").write_text('{"type":"answer_done","answer":"QA_LAYER_MARKER"}\n', encoding="utf-8")
    (layer_dir / "evidence" / "session-response.json").write_text('{"answer":"QA_LAYER_MARKER"}\n', encoding="utf-8")
    (layer_dir / "evidence" / "persistence-stdout.json").write_text('{"status":"completed"}\n', encoding="utf-8")

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-stream",
                "source": "fixture",
                "text": "The stream emits answer_done and returns the current-run marker.",
                "test_ids": ["T-stream"],
                "status": "Untested",
            },
            {
                "id": "R-api",
                "source": "fixture",
                "text": "The session API returns the current-run marker.",
                "test_ids": ["T-api"],
                "status": "Untested",
            },
            {
                "id": "R-persist",
                "source": "fixture",
                "text": "The persisted turn reaches completed.",
                "test_ids": ["T-persist"],
                "status": "Untested",
            },
        ],
        "tests": [
            {
                "id": "T-stream",
                "requirement_ids": ["R-stream"],
                "type": "stream",
                "expected": "WebSocket returns the current-run marker QA_LAYER_MARKER and answer_done.",
                "status": "Untested",
            },
            {
                "id": "T-api",
                "requirement_ids": ["R-api"],
                "type": "api",
                "expected": "Session detail API response contains the current-run marker QA_LAYER_MARKER.",
                "status": "Untested",
            },
            {
                "id": "T-persist",
                "requirement_ids": ["R-persist"],
                "type": "persistence",
                "expected": "Read-only persistence helper observes completed.",
                "status": "Untested",
            },
        ],
    }
    write_json(layer_dir / "test-matrix.json", matrix)

    weak_ledger = {
        "schema_version": 2,
        "requirements": [
            {"id": "R-stream", "source": "fixture", "text": matrix["requirements"][0]["text"], "test_ids": ["T-stream"], "status": "Passed", "evidence_ids": ["E-ui"]},
            {"id": "R-api", "source": "fixture", "text": matrix["requirements"][1]["text"], "test_ids": ["T-api"], "status": "Passed", "evidence_ids": ["E-ui"]},
            {"id": "R-persist", "source": "fixture", "text": matrix["requirements"][2]["text"], "test_ids": ["T-persist"], "status": "Passed", "evidence_ids": ["E-ui"]},
        ],
        "tests": [
            {"id": "T-stream", "requirement_ids": ["R-stream"], "type": "stream", "expected": matrix["tests"][0]["expected"], "status": "Passed", "evidence_ids": ["E-ui"]},
            {"id": "T-api", "requirement_ids": ["R-api"], "type": "api", "expected": matrix["tests"][1]["expected"], "status": "Passed", "evidence_ids": ["E-ui"]},
            {"id": "T-persist", "requirement_ids": ["R-persist"], "type": "persistence", "expected": matrix["tests"][2]["expected"], "status": "Passed", "evidence_ids": ["E-ui"]},
        ],
        "evidence": [
            {
                "id": "E-ui",
                "type": "screenshot",
                "path": "screenshots/fallback.png",
                "current_run": True,
                "assertions": ["Fallback text is visible in the UI."],
                "proves": "The UI shows fallback text containing a user prompt marker.",
            }
        ],
    }
    write_json(layer_dir / "weak-ledger.json", weak_ledger)
    weak_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(layer_dir / "test-matrix.json"),
            "--ledger",
            str(layer_dir / "weak-ledger.json"),
            "--summary",
            str(layer_dir / "weak-audit-summary.json"),
        ],
        cwd=str(layer_dir),
        text=True,
        capture_output=True,
    )
    assert_true(weak_proc.returncode != 0, "Weak UI/fallback evidence must not pass stream/API/persistence layer audit.")
    weak_audit = load_json(layer_dir / "weak-audit-summary.json")
    weak_errors = "\n".join(weak_audit.get("errors", []))
    assert_true("no WebSocket/SSE evidence" in weak_errors, "Stream tests should require WebSocket/SSE evidence.")
    assert_true("returned marker evidence" in weak_errors, "Current-run marker claims should require returned marker evidence.")
    assert_true("no persistence/log/API evidence" in weak_errors, "Persistence tests should require persistence/log/API evidence.")

    weak_stream_message_matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-stream-message",
                "source": "fixture",
                "text": "The WebSocket stream emits an assistant message.",
                "test_ids": ["T-stream-message"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-stream-message",
                "requirement_ids": ["R-stream-message"],
                "type": "stream",
                "expected": "WebSocket evidence captures at least one assistant message.",
                "status": "Untested",
            }
        ],
    }
    write_json(layer_dir / "weak-stream-message-matrix.json", weak_stream_message_matrix)
    weak_stream_message_ledger = {
        "schema_version": 2,
        "requirements": [
            {"id": "R-stream-message", "source": "fixture", "text": weak_stream_message_matrix["requirements"][0]["text"], "test_ids": ["T-stream-message"], "status": "Passed", "evidence_ids": ["E-stream-assertion-only"]}
        ],
        "tests": [
            {"id": "T-stream-message", "requirement_ids": ["R-stream-message"], "type": "stream", "expected": weak_stream_message_matrix["tests"][0]["expected"], "status": "Passed", "evidence_ids": ["E-stream-assertion-only"]}
        ],
        "evidence": [
            {
                "id": "E-stream-assertion-only",
                "type": "websocket",
                "current_run": True,
                "messages_seen": 0,
                "assertions": ["The stream emitted an assistant message."],
                "requirement_ids": ["R-stream-message"],
                "test_ids": ["T-stream-message"],
                "proves": "A WebSocket assistant message was observed.",
            }
        ],
    }
    write_json(layer_dir / "weak-stream-message-ledger.json", weak_stream_message_ledger)
    weak_stream_message_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(layer_dir / "weak-stream-message-matrix.json"),
            "--ledger",
            str(layer_dir / "weak-stream-message-ledger.json"),
            "--summary",
            str(layer_dir / "weak-stream-message-audit-summary.json"),
        ],
        cwd=str(layer_dir),
        text=True,
        capture_output=True,
    )
    assert_true(weak_stream_message_proc.returncode != 0, "Stream pass claims must not pass from zero messages plus hand-written assertions.")
    weak_stream_message_audit = load_json(layer_dir / "weak-stream-message-audit-summary.json")
    assert_true("lacks captured stream message evidence" in "\n".join(weak_stream_message_audit.get("errors", [])), "Stream message audit should reject zero-message/assertion-only WebSocket evidence.")

    missing_stream_message_path_ledger = {
        "schema_version": 2,
        "requirements": [
            {"id": "R-stream-message", "source": "fixture", "text": weak_stream_message_matrix["requirements"][0]["text"], "test_ids": ["T-stream-message"], "status": "Passed", "evidence_ids": ["E-stream-missing-message-path"]}
        ],
        "tests": [
            {"id": "T-stream-message", "requirement_ids": ["R-stream-message"], "type": "stream", "expected": weak_stream_message_matrix["tests"][0]["expected"], "status": "Passed", "evidence_ids": ["E-stream-missing-message-path"]}
        ],
        "evidence": [
            {
                "id": "E-stream-missing-message-path",
                "type": "websocket",
                "url": "ws://fixture/stream",
                "messages_path": "evidence/missing-stream-messages.ndjson",
                "current_run": True,
                "assertions": ["The stream emitted an assistant message."],
                "requirement_ids": ["R-stream-message"],
                "test_ids": ["T-stream-message"],
                "proves": "A WebSocket assistant message was observed.",
            }
        ],
    }
    write_json(layer_dir / "missing-stream-message-path-ledger.json", missing_stream_message_path_ledger)
    missing_stream_message_path_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(layer_dir / "weak-stream-message-matrix.json"),
            "--ledger",
            str(layer_dir / "missing-stream-message-path-ledger.json"),
            "--summary",
            str(layer_dir / "missing-stream-message-path-audit-summary.json"),
        ],
        cwd=str(layer_dir),
        text=True,
        capture_output=True,
    )
    assert_true(missing_stream_message_path_proc.returncode != 0, "Stream pass claims must not pass from a missing messages_path artifact.")
    missing_stream_message_path_audit = load_json(layer_dir / "missing-stream-message-path-audit-summary.json")
    missing_stream_message_path_errors = "\n".join(missing_stream_message_path_audit.get("errors", []))
    assert_true("messages_path is missing" in missing_stream_message_path_errors, "Stream message audit should name missing messages_path artifacts.")
    assert_true("lacks captured stream message evidence" in missing_stream_message_path_errors, "Missing messages_path should not count as captured stream message evidence.")

    weak_json_matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-api-marker",
                "source": "fixture",
                "text": "The API returns the current-run marker.",
                "test_ids": ["T-api-marker"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-api-marker",
                "requirement_ids": ["R-api-marker"],
                "type": "api",
                "expected": "API response contains QA_JSON_MARKER.",
                "status": "Untested",
            }
        ],
    }
    write_json(layer_dir / "weak-json-matrix.json", weak_json_matrix)
    weak_json_ledger = {
        "schema_version": 2,
        "runtime_summary": {"qa_marker": "QA_JSON_MARKER"},
        "requirements": [
            {"id": "R-api-marker", "source": "fixture", "text": weak_json_matrix["requirements"][0]["text"], "test_ids": ["T-api-marker"], "status": "Passed", "evidence_ids": ["E-api-json"]}
        ],
        "tests": [
            {"id": "T-api-marker", "requirement_ids": ["R-api-marker"], "type": "api", "expected": weak_json_matrix["tests"][0]["expected"], "status": "Passed", "evidence_ids": ["E-api-json"]}
        ],
        "evidence": [
            {
                "id": "E-api-json",
                "type": "api_response",
                "url": "/api/v1/echo",
                "current_run": True,
                "status_code": 200,
                "checked_json": {"ok": True},
                "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
                "requirement_ids": ["R-api-marker"],
                "test_ids": ["T-api-marker"],
                "proves": "The API returned the current-run marker.",
            }
        ],
    }
    write_json(layer_dir / "weak-json-ledger.json", weak_json_ledger)
    weak_json_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(layer_dir / "weak-json-matrix.json"),
            "--ledger",
            str(layer_dir / "weak-json-ledger.json"),
            "--summary",
            str(layer_dir / "weak-json-audit-summary.json"),
        ],
        cwd=str(layer_dir),
        text=True,
        capture_output=True,
    )
    assert_true(weak_json_proc.returncode != 0, "Non-marker checked_json must not satisfy marker-return claims.")
    weak_json_audit = load_json(layer_dir / "weak-json-audit-summary.json")
    assert_true("returned marker evidence" in "\n".join(weak_json_audit.get("errors", [])), "Marker-return audit should reject checked_json that lacks the runtime marker.")

    self_proving_json_ledger = {
        "schema_version": 2,
        "runtime_summary": {"qa_marker": "QA_JSON_MARKER"},
        "requirements": [
            {"id": "R-api-marker", "source": "fixture", "text": weak_json_matrix["requirements"][0]["text"], "test_ids": ["T-api-marker"], "status": "Passed", "evidence_ids": ["E-api-json-self-proof"]}
        ],
        "tests": [
            {"id": "T-api-marker", "requirement_ids": ["R-api-marker"], "type": "api", "expected": "API response contains QA_JSON_MARKER and completed.", "status": "Passed", "evidence_ids": ["E-api-json-self-proof"]}
        ],
        "evidence": [
            {
                "id": "E-api-json-self-proof",
                "type": "api_response",
                "url": "/api/v1/echo",
                "current_run": True,
                "status_code": 200,
                "checked_json": {"answer": "QA_JSON_MARKER", "status": "completed"},
                "assertions": [
                    "HTTP status observed: 200",
                    "JSON answer matched observed value QA_JSON_MARKER",
                    "JSON status matched observed value completed",
                ],
                "requirement_ids": ["R-api-marker"],
                "test_ids": ["T-api-marker"],
                "proves": "The API returned the current-run marker and completed terminal state.",
            }
        ],
    }
    write_json(layer_dir / "self-proving-json-ledger.json", self_proving_json_ledger)
    self_proving_json_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(layer_dir / "weak-json-matrix.json"),
            "--ledger",
            str(layer_dir / "self-proving-json-ledger.json"),
            "--summary",
            str(layer_dir / "self-proving-json-audit-summary.json"),
        ],
        cwd=str(layer_dir),
        text=True,
        capture_output=True,
    )
    assert_true(self_proving_json_proc.returncode != 0, "checked_json marker/terminal claims must not pass without a source response artifact.")
    self_proving_json_audit = load_json(layer_dir / "self-proving-json-audit-summary.json")
    assert_true("no referenced checked JSON artifact path" in "\n".join(self_proving_json_audit.get("errors", [])), "JSON audit should reject checked_json self-proof without a source artifact path.")

    weak_terminal_matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-stream-terminal",
                "source": "fixture",
                "text": "The stream emits answer_done.",
                "test_ids": ["T-stream-terminal"],
                "status": "Untested",
            },
            {
                "id": "R-persist-terminal",
                "source": "fixture",
                "text": "The persisted turn reaches completed.",
                "test_ids": ["T-persist-terminal"],
                "status": "Untested",
            },
            {
                "id": "R-api-terminal",
                "source": "fixture",
                "text": "The same-session API read reaches completed.",
                "test_ids": ["T-api-terminal"],
                "status": "Untested",
            },
            {
                "id": "R-ui-api-terminal",
                "source": "fixture",
                "text": "The click-triggered API response reaches completed.",
                "test_ids": ["T-ui-api-terminal"],
                "status": "Untested",
            },
        ],
        "tests": [
            {
                "id": "T-stream-terminal",
                "requirement_ids": ["R-stream-terminal"],
                "type": "stream",
                "expected": "WebSocket evidence includes answer_done.",
                "status": "Untested",
            },
            {
                "id": "T-persist-terminal",
                "requirement_ids": ["R-persist-terminal"],
                "type": "persistence",
                "expected": "Read-only persistence evidence shows completed.",
                "status": "Untested",
            },
            {
                "id": "T-api-terminal",
                "requirement_ids": ["R-api-terminal"],
                "type": "api",
                "expected": "API response JSON shows completed.",
                "status": "Untested",
            },
            {
                "id": "T-ui-api-terminal",
                "requirement_ids": ["R-ui-api-terminal"],
                "type": "ui_to_api",
                "expected": "Click-to-response evidence shows completed.",
                "status": "Untested",
            },
        ],
    }
    write_json(layer_dir / "weak-terminal-matrix.json", weak_terminal_matrix)
    weak_terminal_ledger = {
        "schema_version": 2,
        "requirements": [
            {"id": "R-stream-terminal", "source": "fixture", "text": weak_terminal_matrix["requirements"][0]["text"], "test_ids": ["T-stream-terminal"], "status": "Passed", "evidence_ids": ["E-stream-terminal"]},
            {"id": "R-persist-terminal", "source": "fixture", "text": weak_terminal_matrix["requirements"][1]["text"], "test_ids": ["T-persist-terminal"], "status": "Passed", "evidence_ids": ["E-persist-terminal"]},
            {"id": "R-api-terminal", "source": "fixture", "text": weak_terminal_matrix["requirements"][2]["text"], "test_ids": ["T-api-terminal"], "status": "Passed", "evidence_ids": ["E-api-terminal"]},
            {"id": "R-ui-api-terminal", "source": "fixture", "text": weak_terminal_matrix["requirements"][3]["text"], "test_ids": ["T-ui-api-terminal"], "status": "Passed", "evidence_ids": ["E-ui-api-terminal"]},
        ],
        "tests": [
            {"id": "T-stream-terminal", "requirement_ids": ["R-stream-terminal"], "type": "stream", "expected": weak_terminal_matrix["tests"][0]["expected"], "status": "Passed", "evidence_ids": ["E-stream-terminal"]},
            {"id": "T-persist-terminal", "requirement_ids": ["R-persist-terminal"], "type": "persistence", "expected": weak_terminal_matrix["tests"][1]["expected"], "status": "Passed", "evidence_ids": ["E-persist-terminal"]},
            {"id": "T-api-terminal", "requirement_ids": ["R-api-terminal"], "type": "api", "expected": weak_terminal_matrix["tests"][2]["expected"], "status": "Passed", "evidence_ids": ["E-api-terminal"]},
            {"id": "T-ui-api-terminal", "requirement_ids": ["R-ui-api-terminal"], "type": "ui_to_api", "expected": weak_terminal_matrix["tests"][3]["expected"], "status": "Passed", "evidence_ids": ["E-ui-api-terminal"]},
        ],
        "evidence": [
            {
                "id": "E-stream-terminal",
                "type": "websocket",
                "current_run": True,
                "messages_seen": 1,
                "assertions": ["The stream returned answer_done."],
                "proves": "The stream reached answer_done terminal status.",
            },
            {
                "id": "E-persist-terminal",
                "type": "command",
                "current_run": True,
                "exit_code": 0,
                "assertions": ["The persistence helper saw completed."],
                "proves": "The persisted turn reached completed terminal status.",
            },
            {
                "id": "E-api-terminal",
                "type": "api_response",
                "current_run": True,
                "status_code": 200,
                "assertions": ["HTTP status observed: 200"],
                "requirement_ids": ["R-api-terminal"],
                "test_ids": ["T-api-terminal"],
                "proves": "The same-session API returned completed terminal status.",
            },
            {
                "id": "E-ui-api-terminal",
                "type": "ui_to_api",
                "current_run": True,
                "status_code": 200,
                "assertions": ["Click response status observed: 200"],
                "requirement_ids": ["R-ui-api-terminal"],
                "test_ids": ["T-ui-api-terminal"],
                "proves": "The click-triggered API returned completed terminal status.",
            },
        ],
    }
    write_json(layer_dir / "weak-terminal-ledger.json", weak_terminal_ledger)
    weak_terminal_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(layer_dir / "weak-terminal-matrix.json"),
            "--ledger",
            str(layer_dir / "weak-terminal-ledger.json"),
            "--summary",
            str(layer_dir / "weak-terminal-audit-summary.json"),
        ],
        cwd=str(layer_dir),
        text=True,
        capture_output=True,
    )
    assert_true(weak_terminal_proc.returncode != 0, "Terminal/completed claims must not pass from hand-written proves/assertions alone.")
    weak_terminal_audit = load_json(layer_dir / "weak-terminal-audit-summary.json")
    terminal_errors = "\n".join(weak_terminal_audit.get("errors", []))
    assert_true(terminal_errors.count("terminal-status evidence") >= 4, "Terminal audit should require returned/output terminal-status evidence for stream, API, UI-to-API, and persistence claims.")

    good_ledger = {
        "schema_version": 2,
        "requirements": [
            {"id": "R-stream", "source": "fixture", "text": matrix["requirements"][0]["text"], "test_ids": ["T-stream"], "status": "Passed", "evidence_ids": ["E-stream"]},
            {"id": "R-api", "source": "fixture", "text": matrix["requirements"][1]["text"], "test_ids": ["T-api"], "status": "Passed", "evidence_ids": ["E-api"]},
            {"id": "R-persist", "source": "fixture", "text": matrix["requirements"][2]["text"], "test_ids": ["T-persist"], "status": "Passed", "evidence_ids": ["E-persist"]},
        ],
        "tests": [
            {"id": "T-stream", "requirement_ids": ["R-stream"], "type": "stream", "expected": matrix["tests"][0]["expected"], "status": "Passed", "evidence_ids": ["E-stream"]},
            {"id": "T-api", "requirement_ids": ["R-api"], "type": "api", "expected": matrix["tests"][1]["expected"], "status": "Passed", "evidence_ids": ["E-api"]},
            {"id": "T-persist", "requirement_ids": ["R-persist"], "type": "persistence", "expected": matrix["tests"][2]["expected"], "status": "Passed", "evidence_ids": ["E-persist"]},
        ],
        "evidence": [
            {
                "id": "E-stream",
                "type": "websocket",
                "path": "evidence/stream-messages.txt",
                "current_run": True,
                "messages_seen": 2,
                "message_text_contains_matched": "QA_LAYER_MARKER",
                "checked_json": {"type": "answer_done"},
                "assertions": [
                    "WebSocket messages observed: 2",
                    "WebSocket message text contained expected text: QA_LAYER_MARKER",
                    "JSON type matched observed value answer_done",
                ],
                "proves": "The stream emitted answer_done and returned the current-run marker.",
            },
            {
                "id": "E-api",
                "type": "api_response",
                "url": "/api/v1/sessions/session-1",
                "body_path": "evidence/session-response.json",
                "current_run": True,
                "status_code": 200,
                "response_text_contains_matched": "QA_LAYER_MARKER",
                "assertions": ["HTTP status observed: 200", "Response text contained expected text: QA_LAYER_MARKER"],
                "proves": "The session API returned the current-run marker.",
            },
            {
                "id": "E-persist",
                "type": "command",
                "value": "exit_code=0",
                "stdout_path": "evidence/persistence-stdout.json",
                "current_run": True,
                "exit_code": 0,
                "stdout_contains_matched": "completed",
                "assertions": ["Command exit code observed: 0", "Stdout contained expected text: completed"],
                "proves": "The read-only persistence helper observed completed terminal status.",
            },
        ],
    }
    write_json(layer_dir / "good-ledger.json", good_ledger)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(layer_dir / "test-matrix.json"),
            "--ledger",
            str(layer_dir / "good-ledger.json"),
            "--summary",
            str(layer_dir / "good-audit-summary.json"),
        ],
        cwd=layer_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(layer_dir / "good-ledger.json"),
            "--audit-summary",
            str(layer_dir / "good-audit-summary.json"),
            "--out",
            str(layer_dir / "good-verdict.json"),
            "--fail-on-not-pass",
        ],
        cwd=layer_dir,
    )
    good_verdict = load_json(layer_dir / "good-verdict.json")
    assert_true(good_verdict.get("can_claim_pass") is True, "Strong stream/API/persistence evidence should allow a pass verdict.")


def run_evidence_freshness_fixture(script_dir: Path, tmp_path: Path) -> None:
    fresh_dir = tmp_path / "evidence-freshness"
    fresh_dir.mkdir(parents=True, exist_ok=True)
    (fresh_dir / "screenshots").mkdir(parents=True, exist_ok=True)
    stale_file = fresh_dir / "screenshots" / "stale.png"
    fresh_file = fresh_dir / "screenshots" / "fresh.png"
    stale_file.write_bytes(b"old-image")
    fresh_file.write_bytes(VALID_PNG_1X1)
    os.utime(stale_file, (1577836800, 1577836800))

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-fresh",
                "source": "fixture",
                "text": "The report must use a fresh screenshot artifact.",
                "test_ids": ["T-fresh"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-fresh",
                "requirement_ids": ["R-fresh"],
                "type": "ui",
                "expected": "A fresh screenshot artifact proves the visible result.",
                "status": "Untested",
            }
        ],
    }
    write_json(fresh_dir / "test-matrix.json", matrix)
    write_json(
        fresh_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "startedAt": "2020-01-02T00:00:00+00:00",
            "finishedAt": "2020-01-02T00:00:01+00:00",
            "scenarios": [],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )

    def ledger_for(path_name: str) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-fresh",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-fresh"],
                    "status": "Passed",
                    "evidence_ids": ["E-shot"],
                }
            ],
            "tests": [
                {
                    "id": "T-fresh",
                    "requirement_ids": ["R-fresh"],
                    "type": "ui",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-shot"],
                }
            ],
            "evidence": [
                {
                    "id": "E-shot",
                    "type": "screenshot",
                    "path": f"screenshots/{path_name}",
                    "current_run": True,
                    "assertions": ["Fresh screenshot artifact shows the visible result."],
                    "proves": "The visible result is shown in a fresh screenshot artifact.",
                }
            ],
        }

    write_json(fresh_dir / "stale-ledger.json", ledger_for("stale.png"))
    stale_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(fresh_dir / "test-matrix.json"),
            "--results",
            str(fresh_dir / "results.json"),
            "--ledger",
            str(fresh_dir / "stale-ledger.json"),
            "--summary",
            str(fresh_dir / "stale-audit-summary.json"),
        ],
        cwd=str(fresh_dir),
        text=True,
        capture_output=True,
    )
    assert_true(stale_proc.returncode != 0, "Stale current-run file evidence must fail audit.")
    stale_audit = load_json(fresh_dir / "stale-audit-summary.json")
    assert_true("predates results.startedAt" in "\n".join(stale_audit.get("errors", [])), "Freshness audit should name stale file evidence.")

    write_json(fresh_dir / "fresh-ledger.json", ledger_for("fresh.png"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(fresh_dir / "test-matrix.json"),
            "--results",
            str(fresh_dir / "results.json"),
            "--ledger",
            str(fresh_dir / "fresh-ledger.json"),
            "--summary",
            str(fresh_dir / "fresh-audit-summary.json"),
        ],
        cwd=fresh_dir,
    )


def run_screenshot_integrity_fixture(script_dir: Path, tmp_path: Path) -> None:
    screenshot_dir = tmp_path / "screenshot-integrity"
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    (screenshot_dir / "screenshots").mkdir(parents=True, exist_ok=True)
    bad_file = screenshot_dir / "screenshots" / "placeholder.png"
    good_file = screenshot_dir / "screenshots" / "actual.png"
    bad_file.write_bytes(b"fake-png-placeholder")
    good_file.write_bytes(VALID_PNG_1X1)

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-shot",
                "source": "fixture",
                "text": "The report must cite a readable screenshot artifact.",
                "test_ids": ["T-shot"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-shot",
                "requirement_ids": ["R-shot"],
                "type": "ui",
                "expected": "A readable screenshot artifact proves the visible result.",
                "status": "Untested",
            }
        ],
    }
    write_json(screenshot_dir / "test-matrix.json", matrix)

    def ledger_for(path_name: str) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-shot",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-shot"],
                    "status": "Passed",
                    "evidence_ids": ["E-shot"],
                }
            ],
            "tests": [
                {
                    "id": "T-shot",
                    "requirement_ids": ["R-shot"],
                    "type": "ui",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-shot"],
                }
            ],
            "evidence": [
                {
                    "id": "E-shot",
                    "type": "screenshot",
                    "path": f"screenshots/{path_name}",
                    "current_run": True,
                    "assertions": ["Screenshot artifact shows the visible result."],
                    "proves": "The visible result is shown in a readable screenshot artifact.",
                }
            ],
        }

    write_json(screenshot_dir / "bad-ledger.json", ledger_for("placeholder.png"))
    bad_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(screenshot_dir / "test-matrix.json"),
            "--ledger",
            str(screenshot_dir / "bad-ledger.json"),
            "--summary",
            str(screenshot_dir / "bad-audit-summary.json"),
        ],
        cwd=str(screenshot_dir),
        text=True,
        capture_output=True,
    )
    assert_true(bad_proc.returncode != 0, "Placeholder screenshot bytes must fail screenshot integrity audit.")
    bad_audit = load_json(screenshot_dir / "bad-audit-summary.json")
    bad_errors = "\n".join(bad_audit.get("errors", []))
    assert_true("not a readable PNG/JPEG" in bad_errors, "Screenshot integrity audit should name unreadable images.")
    assert_true(bad_audit.get("screenshot_evidence_checked") == 1, "Screenshot integrity audit should count checked screenshot evidence.")

    write_json(screenshot_dir / "good-ledger.json", ledger_for("actual.png"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(screenshot_dir / "test-matrix.json"),
            "--ledger",
            str(screenshot_dir / "good-ledger.json"),
            "--summary",
            str(screenshot_dir / "good-audit-summary.json"),
        ],
        cwd=screenshot_dir,
    )
    good_audit = load_json(screenshot_dir / "good-audit-summary.json")
    assert_true(good_audit.get("screenshot_evidence_checked") == 1, "Readable screenshots should be counted by the audit.")


def run_text_artifact_assertion_fixture(script_dir: Path, tmp_path: Path) -> None:
    text_dir = tmp_path / "text-artifact-assertions"
    text_dir.mkdir(parents=True, exist_ok=True)
    (text_dir / "evidence").mkdir(parents=True, exist_ok=True)
    good_messages = text_dir / "evidence" / "messages-good.txt"
    bad_messages = text_dir / "evidence" / "messages-bad.txt"
    good_messages.write_text('{"type":"answer_done","answer":"QA_TEXT_MARKER"}\n', encoding="utf-8")
    bad_messages.write_text('{"type":"answer_done","answer":"stale fallback text"}\n', encoding="utf-8")

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-text",
                "source": "fixture",
                "text": "The stream evidence file must contain the returned current-run marker.",
                "test_ids": ["T-text"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-text",
                "requirement_ids": ["R-text"],
                "type": "stream",
                "expected": "WebSocket evidence returns QA_TEXT_MARKER and answer_done.",
                "status": "Untested",
            }
        ],
    }
    write_json(text_dir / "test-matrix.json", matrix)

    def ledger_for(path_name: str) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-text",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-text"],
                    "status": "Passed",
                    "evidence_ids": ["E-stream"],
                }
            ],
            "tests": [
                {
                    "id": "T-text",
                    "requirement_ids": ["R-text"],
                    "type": "stream",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-stream"],
                }
            ],
            "evidence": [
                {
                    "id": "E-stream",
                    "type": "websocket",
                    "path": f"evidence/{path_name}",
                    "messages_path": f"evidence/{path_name}",
                    "current_run": True,
                    "messages_seen": 1,
                    "message_text_contains_matched": "QA_TEXT_MARKER",
                    "checked_json": {"type": "answer_done"},
                    "assertions": [
                        "WebSocket messages observed: 1",
                        "WebSocket message text contained expected text: QA_TEXT_MARKER",
                        "JSON type matched observed value answer_done",
                    ],
                    "proves": "The stream returned the current-run marker and answer_done terminal event.",
                }
            ],
        }

    write_json(text_dir / "bad-ledger.json", ledger_for("messages-bad.txt"))
    bad_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(text_dir / "test-matrix.json"),
            "--ledger",
            str(text_dir / "bad-ledger.json"),
            "--summary",
            str(text_dir / "bad-audit-summary.json"),
        ],
        cwd=str(text_dir),
        text=True,
        capture_output=True,
    )
    assert_true(bad_proc.returncode != 0, "Ledger text marker claims must fail when the artifact file does not contain the marker.")
    bad_audit = load_json(text_dir / "bad-audit-summary.json")
    assert_true("message_text_contains_matched" in "\n".join(bad_audit.get("errors", [])), "Text artifact audit should name the missing marker field.")
    assert_true(bad_audit.get("text_artifact_assertions_checked") == 1, "Text artifact audit should count checked text assertions.")

    write_json(text_dir / "good-ledger.json", ledger_for("messages-good.txt"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(text_dir / "test-matrix.json"),
            "--ledger",
            str(text_dir / "good-ledger.json"),
            "--summary",
            str(text_dir / "good-audit-summary.json"),
        ],
        cwd=text_dir,
    )
    good_audit = load_json(text_dir / "good-audit-summary.json")
    assert_true(good_audit.get("text_artifact_assertions_checked") == 1, "Matching text artifacts should be counted by the audit.")


def run_json_artifact_assertion_fixture(script_dir: Path, tmp_path: Path) -> None:
    json_dir = tmp_path / "json-artifact-assertions"
    json_dir.mkdir(parents=True, exist_ok=True)
    (json_dir / "evidence").mkdir(parents=True, exist_ok=True)
    good_body = json_dir / "evidence" / "response-good.json"
    bad_body = json_dir / "evidence" / "response-bad.json"
    good_body.write_text('{"reply":"QA_JSON_MARKER","status":"completed"}\n', encoding="utf-8")
    bad_body.write_text('{"reply":"stale fallback","status":"completed"}\n', encoding="utf-8")

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-json",
                "source": "fixture",
                "text": "The API body artifact must contain the checked current-run marker JSON.",
                "test_ids": ["T-json"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-json",
                "requirement_ids": ["R-json"],
                "type": "api",
                "expected": "API response JSON includes QA_JSON_MARKER.",
                "status": "Untested",
            }
        ],
    }
    write_json(json_dir / "test-matrix.json", matrix)

    def ledger_for(path_name: str) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-json",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-json"],
                    "status": "Passed",
                    "evidence_ids": ["E-api"],
                }
            ],
            "tests": [
                {
                    "id": "T-json",
                    "requirement_ids": ["R-json"],
                    "type": "api",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-api"],
                }
            ],
            "evidence": [
                {
                    "id": "E-api",
                    "type": "api_response",
                    "path": f"evidence/{path_name}",
                    "body_path": f"evidence/{path_name}",
                    "current_run": True,
                    "status_code": 200,
                    "checked_json": {"reply": "QA_JSON_MARKER", "status": "completed"},
                    "assertions": [
                        "HTTP status observed: 200",
                        "JSON reply matched observed value QA_JSON_MARKER",
                        "JSON status matched observed value completed",
                    ],
                    "proves": "The API response returned the current-run marker and completed status.",
                }
            ],
        }

    write_json(json_dir / "bad-ledger.json", ledger_for("response-bad.json"))
    bad_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(json_dir / "test-matrix.json"),
            "--ledger",
            str(json_dir / "bad-ledger.json"),
            "--summary",
            str(json_dir / "bad-audit-summary.json"),
        ],
        cwd=str(json_dir),
        text=True,
        capture_output=True,
    )
    assert_true(bad_proc.returncode != 0, "Ledger checked_json claims must fail when the artifact JSON disagrees.")
    bad_audit = load_json(json_dir / "bad-audit-summary.json")
    assert_true("checked_json" in "\n".join(bad_audit.get("errors", [])), "JSON artifact audit should name the checked_json field.")
    assert_true(bad_audit.get("json_artifact_assertions_checked") == 1, "JSON artifact audit should count checked JSON assertions.")

    write_json(json_dir / "good-ledger.json", ledger_for("response-good.json"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(json_dir / "test-matrix.json"),
            "--ledger",
            str(json_dir / "good-ledger.json"),
            "--summary",
            str(json_dir / "good-audit-summary.json"),
        ],
        cwd=json_dir,
    )
    good_audit = load_json(json_dir / "good-audit-summary.json")
    assert_true(good_audit.get("json_artifact_assertions_checked") == 1, "Matching JSON artifacts should be counted by the audit.")


def run_api_body_defect_evidence_fixture(script_dir: Path, tmp_path: Path) -> None:
    body_dir = tmp_path / "api-body-defect-evidence"
    body_dir.mkdir(parents=True, exist_ok=True)
    body_path = body_dir / "evidence" / "api-body.txt"
    body_path.parent.mkdir(parents=True, exist_ok=True)
    response_body = '{"error":"fixture backend exploded","trace_id":"trace-fixture-1","access_token":"fixture-redacted"}'
    body_path.write_text(response_body, encoding="utf-8")
    write_json(
        body_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-api-body",
                    "source": "fixture",
                    "text": "API failures must preserve captured response body evidence.",
                    "test_ids": ["T-api-body"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-api-body",
                    "requirement_ids": ["R-api-body"],
                    "type": "api",
                    "expected": "GET /api/v1/body-fixture returns HTTP 200.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        body_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "failed",
            "artifactDir": str(body_dir),
            "baseUrl": "http://127.0.0.1:9527",
            "scenarios": [
                {
                    "id": "api-body",
                    "status": "failed",
                    "steps": [
                        {
                            "scenarioId": "api-body",
                            "stepId": "T-api-body",
                            "testIds": ["T-api-body"],
                            "requirementIds": ["R-api-body"],
                            "action": "api",
                            "status": "failed",
                            "evidenceType": "api_response",
                            "proves": "The failed API response body is captured for root-cause evidence.",
                            "url": "http://127.0.0.1:9527/api/v1/body-fixture",
                            "method": "GET",
                            "statusCode": 500,
                            "bodyPreview": '{"error":"fixture backend exploded","trace_id":"trace-fixture-1","access_token":"[REDACTED]"}',
                            "bodyPath": str(body_path),
                            "error": "Expected status 200, got 500",
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    write_json(
        body_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(body_dir),
            "scenarios": [],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "ledger_from_probe.py"),
            "--matrix",
            str(body_dir / "test-matrix.json"),
            "--results",
            str(body_dir / "results.json"),
            "--out",
            str(body_dir / "evidence-ledger.json"),
        ],
        cwd=body_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_defects.py"),
            "--ledger",
            str(body_dir / "evidence-ledger.json"),
            "--results",
            str(body_dir / "results.json"),
            "--matrix",
            str(body_dir / "test-matrix.json"),
            "--out",
            str(body_dir / "defects.json"),
        ],
        cwd=body_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_next_probes.py"),
            "--defects",
            str(body_dir / "defects.json"),
            "--results",
            str(body_dir / "results.json"),
            "--ledger",
            str(body_dir / "evidence-ledger.json"),
            "--out",
            str(body_dir / "next-probes.json"),
        ],
        cwd=body_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(body_dir),
            "--out",
            str(body_dir / "next-probe-preview.json"),
        ],
        cwd=body_dir,
    )
    ledger = load_json(body_dir / "evidence-ledger.json")
    defects = load_json(body_dir / "defects.json")
    next_probes = load_json(body_dir / "next-probes.json")
    preview = load_json(body_dir / "next-probe-preview.json")
    evidence = ledger.get("evidence", [{}])[0]
    finding = defects.get("findings", [{}])[0]
    finding_ref = finding.get("evidence", [{}])[0]
    log_recs = [rec for rec in next_probes.get("recommendations", []) if rec.get("objective") == "Correlate the captured trace/request id against local service logs."]
    assert_true(evidence.get("body_preview") and "fixture backend exploded" in evidence.get("body_preview", ""), "ledger should preserve captured API response body preview.")
    assert_true(evidence.get("body_path") == "evidence/api-body.txt", "ledger should preserve response body artifact path relative to the run dir.")
    assert_true(any("Response body preview observed" in item for item in evidence.get("assertions", [])), "ledger assertions should name response body preview evidence.")
    assert_true("response body: " in finding.get("actual", "") and "fixture backend exploded" in finding.get("actual", ""), "defect actual should include a bounded response body preview.")
    assert_true(finding_ref.get("body_path") == "evidence/api-body.txt", "defect evidence ref should keep the response body artifact path.")
    assert_true("access_token\":\"[REDACTED]" in finding_ref.get("body_preview", ""), "defect evidence ref should keep redacted body preview, not raw secret-like values.")
    assert_true(log_recs, "captured response-body trace_id should generate a log-correlation next-probe recommendation.")
    assert_true(log_recs[0].get("plan_step_hint", {}).get("env", {}).get("QA_TRACE_ID") == "trace-fixture-1", "log-correlation recommendation should pass the extracted trace id through env.")
    skipped_log = [item for item in preview.get("skipped_recommendations", []) if item.get("id") == log_recs[0].get("id")]
    assert_true(skipped_log and skipped_log[0].get("reason") == "command probe requires --allow-command-probes", "log-correlation command probes should remain behind the command safety gate by default.")


def run_extraction_artifact_assertion_fixture(script_dir: Path, tmp_path: Path) -> None:
    extract_dir = tmp_path / "extraction-artifact-assertions"
    extract_dir.mkdir(parents=True, exist_ok=True)
    (extract_dir / "evidence").mkdir(parents=True, exist_ok=True)
    good_stdout = extract_dir / "evidence" / "stdout-good.json"
    bad_stdout = extract_dir / "evidence" / "stdout-bad.json"
    good_stdout.write_text('{"turn_id":"turn-1","status":"completed"}\n', encoding="utf-8")
    bad_stdout.write_text('{"turn_id":"turn-2","status":"completed"}\n', encoding="utf-8")

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-extract",
                "source": "fixture",
                "text": "The extracted turn id must come from the stdout JSON artifact.",
                "test_ids": ["T-extract"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-extract",
                "requirement_ids": ["R-extract"],
                "type": "persistence",
                "expected": "stdout JSON extraction records turn_id=turn-1 from the artifact.",
                "status": "Untested",
            }
        ],
    }
    write_json(extract_dir / "test-matrix.json", matrix)

    def ledger_for(path_name: str) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-extract",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-extract"],
                    "status": "Passed",
                    "evidence_ids": ["E-command"],
                }
            ],
            "tests": [
                {
                    "id": "T-extract",
                    "requirement_ids": ["R-extract"],
                    "type": "persistence",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-command"],
                }
            ],
            "evidence": [
                {
                    "id": "E-command",
                    "type": "command",
                    "path": f"evidence/{path_name}",
                    "stdout_path": f"evidence/{path_name}",
                    "current_run": True,
                    "exit_code": 0,
                    "checked_stdout_json": {"status": "completed"},
                    "extracted_stdout_json": {"turn_id": "turn-1"},
                    "extracted_stdout_json_paths": {"turn_id": "turn_id"},
                    "assertions": [
                        "Command exit code observed: 0",
                        "stdout JSON status matched observed value completed",
                        "Extracted stdout runtime variables: turn_id",
                    ],
                    "proves": "The read-only helper extracted turn_id from stdout JSON.",
                }
            ],
        }

    write_json(extract_dir / "bad-ledger.json", ledger_for("stdout-bad.json"))
    bad_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(extract_dir / "test-matrix.json"),
            "--ledger",
            str(extract_dir / "bad-ledger.json"),
            "--summary",
            str(extract_dir / "bad-audit-summary.json"),
        ],
        cwd=str(extract_dir),
        text=True,
        capture_output=True,
    )
    assert_true(bad_proc.returncode != 0, "Extracted stdout JSON must fail when the source artifact disagrees.")
    bad_audit = load_json(extract_dir / "bad-audit-summary.json")
    assert_true("extracted_stdout_json.turn_id" in "\n".join(bad_audit.get("errors", [])), "Extraction audit should name the mismatched extracted variable.")
    assert_true(bad_audit.get("extraction_artifact_assertions_checked") == 1, "Extraction artifact audit should count checked extractions.")

    write_json(extract_dir / "good-ledger.json", ledger_for("stdout-good.json"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(extract_dir / "test-matrix.json"),
            "--ledger",
            str(extract_dir / "good-ledger.json"),
            "--summary",
            str(extract_dir / "good-audit-summary.json"),
        ],
        cwd=extract_dir,
    )
    good_audit = load_json(extract_dir / "good-audit-summary.json")
    assert_true(good_audit.get("extraction_artifact_assertions_checked") == 1, "Matching extraction artifacts should be counted by the audit.")


def run_response_header_consistency_fixture(script_dir: Path, tmp_path: Path) -> None:
    header_dir = tmp_path / "response-header-consistency"
    header_dir.mkdir(parents=True, exist_ok=True)
    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-header",
                "source": "fixture",
                "text": "The checked and extracted trace header must match the captured response headers.",
                "test_ids": ["T-header"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-header",
                "requirement_ids": ["R-header"],
                "type": "api",
                "expected": "Captured response headers contain x-trace-id=trace-good.",
                "status": "Untested",
            }
        ],
    }
    write_json(header_dir / "test-matrix.json", matrix)

    def ledger_for(claimed_trace: str, *, include_response_headers: bool = True) -> dict[str, Any]:
        evidence = {
            "id": "E-header",
            "type": "api_response",
            "url": "/api/v1/trace",
            "current_run": True,
            "status_code": 200,
            "checked_response_headers": {"x-trace-id": claimed_trace},
            "extracted_response_headers": {"trace_id": claimed_trace},
            "extracted_response_header_names": {"trace_id": "x-trace-id"},
            "assertions": ["HTTP status observed: 200", "Response header x-trace-id matched observed value"],
            "proves": "The API response exposes a trace header.",
        }
        if include_response_headers:
            evidence["response_headers"] = {"content-type": "application/json", "x-trace-id": "trace-good"}
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-header",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-header"],
                    "status": "Passed",
                    "evidence_ids": ["E-header"],
                }
            ],
            "tests": [
                {
                    "id": "T-header",
                    "requirement_ids": ["R-header"],
                    "type": "api",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-header"],
                }
            ],
            "evidence": [evidence],
        }

    write_json(header_dir / "self-proving-ledger.json", ledger_for("trace-good", include_response_headers=False))
    self_proving_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(header_dir / "test-matrix.json"),
            "--ledger",
            str(header_dir / "self-proving-ledger.json"),
            "--summary",
            str(header_dir / "self-proving-audit-summary.json"),
        ],
        cwd=str(header_dir),
        text=True,
        capture_output=True,
    )
    assert_true(self_proving_proc.returncode != 0, "Header claims must not pass without captured response_headers.")
    self_proving_audit = load_json(header_dir / "self-proving-audit-summary.json")
    assert_true("lacks captured response_headers" in "\n".join(self_proving_audit.get("errors", [])), "Header audit should reject response-header self-proof without captured headers.")

    write_json(header_dir / "bad-ledger.json", ledger_for("trace-bad"))
    bad_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(header_dir / "test-matrix.json"),
            "--ledger",
            str(header_dir / "bad-ledger.json"),
            "--summary",
            str(header_dir / "bad-audit-summary.json"),
        ],
        cwd=str(header_dir),
        text=True,
        capture_output=True,
    )
    assert_true(bad_proc.returncode != 0, "Checked/extracted response headers must fail when captured response_headers disagrees.")
    bad_audit = load_json(header_dir / "bad-audit-summary.json")
    assert_true("checked_response_headers.x-trace-id" in "\n".join(bad_audit.get("errors", [])), "Header audit should name checked response header mismatch.")
    assert_true(bad_audit.get("response_header_consistency_checked") == 2, "Header audit should count checked and extracted header consistency.")

    write_json(header_dir / "good-ledger.json", ledger_for("trace-good"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(header_dir / "test-matrix.json"),
            "--ledger",
            str(header_dir / "good-ledger.json"),
            "--summary",
            str(header_dir / "good-audit-summary.json"),
        ],
        cwd=header_dir,
    )
    good_audit = load_json(header_dir / "good-audit-summary.json")
    assert_true(good_audit.get("response_header_consistency_checked") == 2, "Matching header evidence should be counted by the audit.")


def run_strategy_coverage_fixture(script_dir: Path, tmp_path: Path) -> None:
    strategy_dir = tmp_path / "strategy-coverage"
    strategy_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        strategy_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-ui",
                    "source": "fixture",
                    "text": "The settings page is visible.",
                    "test_ids": ["T-ui"],
                    "status": "Untested",
                },
                {
                    "id": "R-permission",
                    "source": "fixture",
                    "text": "Only admins can save restricted settings.",
                    "test_ids": ["T-permission"],
                    "status": "Blocked",
                    "notes": "Admin and non-admin auth states are not available in this fixture.",
                },
                {
                    "id": "R-permission-ui-only",
                    "source": "fixture",
                    "text": "Non-admin users cannot save restricted settings, not just open the settings page.",
                    "test_ids": ["T-permission-ui-only"],
                    "status": "Untested",
                },
                {
                    "id": "R-runtime-disposition",
                    "source": "fixture",
                    "text": "Runtime diagnostics must prove no failed HTTP responses or request failures remain in results.json.",
                    "test_ids": ["T-runtime-disposition"],
                    "status": "Untested",
                },
            ],
            "tests": [
                {
                    "id": "T-ui",
                    "requirement_ids": ["R-ui"],
                    "type": "ui",
                    "expected": "Settings page is visible.",
                    "status": "Untested",
                },
                {
                    "id": "T-permission",
                    "requirement_ids": ["R-permission"],
                    "type": "permission",
                    "expected": "Admin is allowed and non-admin is denied.",
                    "status": "Blocked",
                    "notes": "Missing auth states for role coverage.",
                },
                {
                    "id": "T-permission-ui-only",
                    "requirement_ids": ["R-permission-ui-only"],
                    "type": "permission",
                    "expected": "Non-admin save denial must be proven by role-aware denial evidence.",
                    "status": "Untested",
                },
                {
                    "id": "T-runtime-disposition",
                    "requirement_ids": ["R-runtime-disposition"],
                    "type": "runtime",
                    "steps": ["Check failed response and request failure runtime arrays."],
                    "expected": "No failed HTTP responses or request failures remain in results.json runtime arrays.",
                    "required_evidence": ["runtime disposition probe", "results.json runtime arrays"],
                    "status": "Untested",
                },
            ],
        },
    )
    write_json(
        strategy_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(strategy_dir),
            "scenarios": [
                {
                    "id": "ui-only",
                    "steps": [
                        {
                            "action": "goto",
                            "id": "T-ui-open",
                            "testIds": ["T-ui"],
                            "requirementIds": ["R-ui"],
                            "path": "/settings",
                            "evidenceType": "navigation",
                            "proves": "The settings page entry path opens.",
                        },
                        {
                            "action": "goto",
                            "id": "T-permission-ui-only-open",
                            "testIds": ["T-permission-ui-only"],
                            "requirementIds": ["R-permission-ui-only"],
                            "path": "/settings/restricted",
                            "evidenceType": "navigation",
                            "proves": "The restricted settings page opens.",
                        }
                    ],
                },
                {
                    "id": "runtime-only",
                    "steps": [
                        {
                            "action": "expectNoFailedResponses",
                            "id": "T-runtime-disposition",
                            "testIds": ["T-runtime-disposition"],
                            "requirementIds": ["R-runtime-disposition"],
                            "evidenceType": "runtime",
                            "proves": "No failed runtime responses remain in the current run.",
                        }
                    ],
                }
            ],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(strategy_dir / "test-plan.json"),
            "--matrix",
            str(strategy_dir / "test-matrix.json"),
            "--summary",
            str(strategy_dir / "plan-audit-summary.json"),
        ],
        cwd=strategy_dir,
    )
    plan_audit = load_json(strategy_dir / "plan-audit-summary.json")
    strategy = plan_audit.get("strategy_coverage") or {}
    assert_true(plan_audit.get("passed") is True, "blocked strategy dimensions should not make the plan structurally invalid.")
    assert_true("ui" in strategy.get("covered_dimensions", []), "strategy coverage should mark UI as executable.")
    assert_true("ui" in strategy.get("observed_dimensions", []), "strategy coverage should separately expose observed executable UI probes.")
    dimensions = strategy.get("dimensions") or {}
    permission_dim = dimensions.get("permission") or {}
    assert_true(permission_dim.get("executable_count") == 0, "UI-only probes must not count as executable permission coverage.")
    assert_true("T-permission-ui-only" in permission_dim.get("test_ids", []), "UI-only permission test should remain a planned permission dimension.")
    assert_true("T-permission-ui-only" not in permission_dim.get("executable_test_ids", []), "UI-only permission test should not appear in permission executable_test_ids.")
    ui_dim = dimensions.get("ui") or {}
    assert_true(ui_dim.get("incidental_executable_count", 0) >= 1, "UI-only probes for non-UI requirements should be counted as incidental UI execution.")
    assert_true("T-permission-ui-only" in ui_dim.get("observed_test_ids", []), "UI-only permission probe should be visible as observed UI execution.")
    runtime_dim = dimensions.get("runtime") or {}
    assert_true("T-runtime-disposition" in runtime_dim.get("executable_test_ids", []), "runtime disposition tests should stay executable runtime coverage.")
    api_dim = dimensions.get("api") or {}
    assert_true("T-runtime-disposition" not in api_dim.get("test_ids", []), "runtime disposition wording about failed responses must not create a false API strategy requirement.")
    gaps = strategy.get("gaps") or []
    assert_true(any(item.get("dimension") == "permission" for item in gaps), "strategy coverage should expose permission as a non-executable planned dimension.")
    assert_true(not any(item.get("dimension") == "api" and "T-runtime-disposition" in item.get("test_ids", []) for item in gaps), "runtime disposition tests should not produce false API strategy gaps.")

    write_json(
        strategy_dir / "evidence-ledger.json",
        {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-ui",
                    "source": "fixture",
                    "text": "The settings page is visible.",
                    "test_ids": ["T-ui"],
                    "status": "Passed",
                    "evidence_ids": ["E-ui"],
                },
                {
                    "id": "R-permission",
                    "source": "fixture",
                    "text": "Only admins can save restricted settings.",
                    "test_ids": ["T-permission"],
                    "status": "Blocked",
                    "evidence_ids": [],
                    "notes": "Admin and non-admin auth states are not available in this fixture.",
                },
                {
                    "id": "R-permission-ui-only",
                    "source": "fixture",
                    "text": "Non-admin users cannot save restricted settings, not just open the settings page.",
                    "test_ids": ["T-permission-ui-only"],
                    "status": "Passed",
                    "evidence_ids": ["E-ui-only"],
                },
                {
                    "id": "R-runtime-disposition",
                    "source": "fixture",
                    "text": "Runtime diagnostics must prove no failed HTTP responses or request failures remain in results.json.",
                    "test_ids": ["T-runtime-disposition"],
                    "status": "Passed",
                    "evidence_ids": ["E-runtime"],
                },
            ],
            "tests": [
                {
                    "id": "T-ui",
                    "requirement_ids": ["R-ui"],
                    "type": "ui",
                    "expected": "Settings page is visible.",
                    "status": "Passed",
                    "evidence_ids": ["E-ui"],
                },
                {
                    "id": "T-permission",
                    "requirement_ids": ["R-permission"],
                    "type": "permission",
                    "expected": "Admin is allowed and non-admin is denied.",
                    "status": "Blocked",
                    "evidence_ids": [],
                    "notes": "Missing auth states for role coverage.",
                },
                {
                    "id": "T-permission-ui-only",
                    "requirement_ids": ["R-permission-ui-only"],
                    "type": "permission",
                    "expected": "Non-admin save denial must be proven by role-aware denial evidence.",
                    "status": "Passed",
                    "evidence_ids": ["E-ui-only"],
                },
                {
                    "id": "T-runtime-disposition",
                    "requirement_ids": ["R-runtime-disposition"],
                    "type": "runtime",
                    "expected": "No failed HTTP responses or request failures remain in results.json runtime arrays.",
                    "status": "Passed",
                    "evidence_ids": ["E-runtime"],
                },
            ],
            "evidence": [
                {
                    "id": "E-ui",
                    "type": "ui_assertion",
                    "value": "settings page visible",
                    "current_run": True,
                    "assertions": ["The settings page opened."],
                    "proves": "The settings page is visible.",
                },
                {
                    "id": "E-ui-only",
                    "type": "ui_assertion",
                    "value": "restricted settings page opened",
                    "current_run": True,
                    "assertions": ["The restricted settings page opened."],
                    "proves": "The restricted settings page is reachable.",
                },
                {
                    "id": "E-runtime",
                    "type": "runtime",
                    "value": "failed_responses=0 request_failures=0",
                    "current_run": True,
                    "assertions": ["No failed responses remain.", "No request failures remain."],
                    "proves": "Runtime failed response and request failure arrays are empty.",
                }
            ],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(strategy_dir / "test-matrix.json"),
            "--ledger",
            str(strategy_dir / "evidence-ledger.json"),
            "--summary",
            str(strategy_dir / "audit-summary.json"),
        ],
        cwd=strategy_dir,
    )
    verdict_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(strategy_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(strategy_dir / "audit-summary.json"),
            "--plan-audit-summary",
            str(strategy_dir / "plan-audit-summary.json"),
            "--out",
            str(strategy_dir / "qa-verdict.json"),
        ],
        cwd=strategy_dir,
        text=True,
        capture_output=True,
    )
    assert_true(verdict_proc.returncode == 0, "strategy coverage verdict generation should complete and write qa-verdict.json.")
    verdict = load_json(strategy_dir / "qa-verdict.json")
    reason_codes = {item.get("code") for item in verdict.get("reasons", []) if isinstance(item, dict)}
    assert_true("strategy_dimension_gap" in reason_codes, "verdict should expose non-executable strategy dimensions as a pass-blocking reason.")
    assert_true(verdict.get("can_claim_pass") is False, "strategy dimension gaps should block final pass claims.")


def run_current_run_required_fixture(script_dir: Path, tmp_path: Path) -> None:
    current_dir = tmp_path / "current-run-required"
    current_dir.mkdir(parents=True, exist_ok=True)
    (current_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (current_dir / "evidence" / "current-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-current",
                "source": "fixture",
                "text": "Passed requirements must use current-run evidence.",
                "test_ids": ["T-current"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-current",
                "requirement_ids": ["R-current"],
                "type": "api",
                "expected": "A current-run API response proves the requirement.",
                "status": "Untested",
            }
        ],
    }
    write_json(current_dir / "test-matrix.json", matrix)

    def ledger_for(current_value: Any = None, include_field: bool = True) -> dict[str, Any]:
        evidence = {
            "id": "E-api",
            "type": "api_response",
            "url": "/api/v1/current",
            "body_path": "evidence/current-response.json",
            "status_code": 200,
            "checked_json": {"ok": True},
            "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
            "proves": "The API response proves the requirement.",
        }
        if include_field:
            evidence["current_run"] = current_value
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-current",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-current"],
                    "status": "Passed",
                    "evidence_ids": ["E-api"],
                }
            ],
            "tests": [
                {
                    "id": "T-current",
                    "requirement_ids": ["R-current"],
                    "type": "api",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-api"],
                }
            ],
            "evidence": [evidence],
        }

    for name, ledger in (
        ("missing-current-run", ledger_for(include_field=False)),
        ("false-current-run", ledger_for(False)),
    ):
        ledger_path = current_dir / f"{name}.json"
        summary_path = current_dir / f"{name}-audit-summary.json"
        write_json(ledger_path, ledger)
        proc = subprocess.run(
            [
                sys.executable,
                str(script_dir / "audit_evidence.py"),
                "--matrix",
                str(current_dir / "test-matrix.json"),
                "--ledger",
                str(ledger_path),
                "--summary",
                str(summary_path),
            ],
            cwd=str(current_dir),
            text=True,
            capture_output=True,
        )
        assert_true(proc.returncode != 0, f"{name} should fail current-run evidence audit.")
        audit = load_json(summary_path)
        assert_true("current_run=true" in "\n".join(audit.get("errors", [])), f"{name} audit should name current_run requirement.")

    write_json(current_dir / "good-ledger.json", ledger_for(True))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(current_dir / "test-matrix.json"),
            "--ledger",
            str(current_dir / "good-ledger.json"),
            "--summary",
            str(current_dir / "good-audit-summary.json"),
        ],
        cwd=current_dir,
    )


def run_secret_like_ledger_audit_fixture(script_dir: Path, tmp_path: Path) -> None:
    secret_dir = tmp_path / "secret-like-ledger-audit"
    secret_dir.mkdir(parents=True, exist_ok=True)
    (secret_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (secret_dir / "evidence" / "redacted-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    write_json(
        secret_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-secret-audit",
                    "source": "fixture",
                    "text": "Final evidence audit must reject raw credential material before reporting.",
                    "test_ids": ["T-secret-audit"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-secret-audit",
                    "requirement_ids": ["R-secret-audit"],
                    "type": "api",
                    "steps": ["Audit a passed ledger that includes API evidence."],
                    "expected": "Raw password, Cookie, or Authorization material is blocked before report generation.",
                    "required_evidence": ["audit error", "secret-like field location"],
                    "status": "Untested",
                }
            ],
        },
    )

    def ledger_with(url_value: str, assertion_value: str, proves_value: str) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-secret-audit",
                    "source": "fixture",
                    "text": "Final evidence audit must reject raw credential material before reporting.",
                    "test_ids": ["T-secret-audit"],
                    "status": "Passed",
                    "evidence_ids": ["E-secret-audit"],
                }
            ],
            "tests": [
                {
                    "id": "T-secret-audit",
                    "requirement_ids": ["R-secret-audit"],
                    "type": "api",
                    "expected": "Raw password, Cookie, or Authorization material is blocked before report generation.",
                    "status": "Passed",
                    "evidence_ids": ["E-secret-audit"],
                }
            ],
            "evidence": [
                {
                    "id": "E-secret-audit",
                    "type": "api_response",
                    "current_run": True,
                    "url": url_value,
                    "body_path": "evidence/redacted-response.json",
                    "status_code": 200,
                    "checked_json": {"ok": True},
                    "assertions": [assertion_value, "HTTP status observed: 200", "JSON ok matched observed value true"],
                    "proves": proves_value,
                }
            ],
        }

    raw_ledger = secret_dir / "raw-secret-ledger.json"
    write_json(
        raw_ledger,
        ledger_with(
            "https://example.test/callback?password=fixture-password&ok=1",
            "Authorization: Basic fixture-basic",
            "Cookie: sid=fixture-session; theme=light",
        ),
    )
    raw_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(secret_dir / "test-matrix.json"),
            "--ledger",
            str(raw_ledger),
            "--summary",
            str(secret_dir / "raw-secret-audit-summary.json"),
        ],
        cwd=str(secret_dir),
        text=True,
        capture_output=True,
    )
    assert_true(raw_proc.returncode != 0, "raw password/cookie/authorization material should fail evidence audit.")
    raw_audit = load_json(secret_dir / "raw-secret-audit-summary.json")
    raw_errors = "\n".join(raw_audit.get("errors", []))
    assert_true("Secret-like value found in ledger" in raw_errors, "raw secret audit should name secret-like ledger values.")
    assert_true("evidence[0].url" in raw_errors, "raw secret audit should identify URL/query secret location.")
    assert_true("evidence[0].assertions[0]" in raw_errors, "raw secret audit should identify Authorization assertion location.")
    assert_true("evidence[0].proves" in raw_errors, "raw secret audit should identify Cookie proof location.")

    write_json(
        secret_dir / "redacted-ledger.json",
        ledger_with(
            "https://example.test/callback?password=[REDACTED]&ok=1",
            "Authorization: [REDACTED]",
            "Cookie: [REDACTED]",
        ),
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(secret_dir / "test-matrix.json"),
            "--ledger",
            str(secret_dir / "redacted-ledger.json"),
            "--summary",
            str(secret_dir / "redacted-audit-summary.json"),
        ],
        cwd=secret_dir,
    )


def run_evidence_disposition_gate_fixture(script_dir: Path, tmp_path: Path) -> None:
    disposition_dir = tmp_path / "evidence-disposition-gate"
    disposition_dir.mkdir(parents=True, exist_ok=True)
    (disposition_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (disposition_dir / "evidence" / "disposition-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    write_json(
        disposition_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-disposition",
                    "source": "fixture",
                    "text": "A passed requirement cannot be proven by skipped or blocked evidence.",
                    "test_ids": ["T-disposition"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-disposition",
                    "requirement_ids": ["R-disposition"],
                    "type": "api",
                    "steps": ["Audit evidence disposition before allowing pass."],
                    "expected": "Only pass-disposition current-run evidence can support a passed test.",
                    "required_evidence": ["current-run API evidence", "pass-disposition status"],
                    "status": "Untested",
                }
            ],
        },
    )

    def ledger_with(evidence_status: str, *, skipped: bool = False) -> dict[str, Any]:
        evidence = {
            "id": "E-disposition",
            "type": "api_response",
            "current_run": True,
            "status": evidence_status,
            "url": "/api/v1/disposition",
            "body_path": "evidence/disposition-response.json",
            "status_code": 200,
            "checked_json": {"ok": True},
            "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
            "proves": "The API response proves the requirement.",
            "test_ids": ["T-disposition"],
            "requirement_ids": ["R-disposition"],
        }
        if skipped:
            evidence["skipped"] = True
            evidence["skip_reason"] = "Skipped because an earlier setup step failed."
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-disposition",
                    "source": "fixture",
                    "text": "A passed requirement cannot be proven by skipped or blocked evidence.",
                    "test_ids": ["T-disposition"],
                    "status": "Passed",
                    "evidence_ids": ["E-disposition"],
                }
            ],
            "tests": [
                {
                    "id": "T-disposition",
                    "requirement_ids": ["R-disposition"],
                    "type": "api",
                    "expected": "Only pass-disposition current-run evidence can support a passed test.",
                    "status": "Passed",
                    "evidence_ids": ["E-disposition"],
                }
            ],
            "evidence": [evidence],
        }

    write_json(disposition_dir / "skipped-ledger.json", ledger_with("skipped", skipped=True))
    skipped_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(disposition_dir / "test-matrix.json"),
            "--ledger",
            str(disposition_dir / "skipped-ledger.json"),
            "--summary",
            str(disposition_dir / "skipped-audit-summary.json"),
        ],
        cwd=str(disposition_dir),
        text=True,
        capture_output=True,
    )
    assert_true(skipped_proc.returncode != 0, "Passed ledger must fail when it cites skipped evidence.")
    skipped_audit = load_json(disposition_dir / "skipped-audit-summary.json")
    skipped_errors = "\n".join(skipped_audit.get("errors", []))
    assert_true("non-pass evidence E-disposition" in skipped_errors, "Audit should name non-pass evidence disposition.")
    assert_true("Requirement R-disposition" in skipped_errors, "Audit should block passed requirement with skipped evidence.")
    assert_true("Test T-disposition" in skipped_errors, "Audit should block passed test with skipped evidence.")

    write_json(disposition_dir / "passed-ledger.json", ledger_with("passed"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(disposition_dir / "test-matrix.json"),
            "--ledger",
            str(disposition_dir / "passed-ledger.json"),
            "--summary",
            str(disposition_dir / "passed-audit-summary.json"),
        ],
        cwd=disposition_dir,
    )


def run_evidence_lineage_fixture(script_dir: Path, tmp_path: Path) -> None:
    lineage_dir = tmp_path / "evidence-lineage"
    lineage_dir.mkdir(parents=True, exist_ok=True)
    (lineage_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (lineage_dir / "evidence" / "lineage-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-a",
                "source": "fixture",
                "text": "Requirement A must be proven by test A evidence.",
                "test_ids": ["T-a"],
                "status": "Untested",
            },
            {
                "id": "R-b",
                "source": "fixture",
                "text": "Requirement B must be proven by test B evidence.",
                "test_ids": ["T-b"],
                "status": "Untested",
            },
        ],
        "tests": [
            {
                "id": "T-a",
                "requirement_ids": ["R-a"],
                "type": "api",
                "expected": "API response A returns ok=true.",
                "status": "Untested",
            },
            {
                "id": "T-b",
                "requirement_ids": ["R-b"],
                "type": "api",
                "expected": "API response B returns ok=true.",
                "status": "Untested",
            },
        ],
    }
    write_json(lineage_dir / "test-matrix.json", matrix)

    def ledger_for(evidence_id: str, ev_req_id: str, ev_test_id: str, *, include_lineage: bool = True, generated_by: str = "ledger_from_probe.py") -> dict[str, Any]:
        evidence = {
            "id": evidence_id,
            "type": "api_response",
            "url": f"/api/{ev_test_id}",
            "body_path": "evidence/lineage-response.json",
            "generated_by": generated_by,
            "current_run": True,
            "status_code": 200,
            "checked_json": {"ok": True},
            "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
            "proves": f"Evidence for {ev_req_id}/{ev_test_id} returned ok=true.",
        }
        if include_lineage:
            evidence["test_ids"] = [ev_test_id]
            evidence["requirement_ids"] = [ev_req_id]
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-a",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-a"],
                    "status": "Passed",
                    "evidence_ids": [evidence_id],
                },
                {
                    "id": "R-b",
                    "source": "fixture",
                    "text": matrix["requirements"][1]["text"],
                    "test_ids": ["T-b"],
                    "status": "Untested",
                    "evidence_ids": [],
                    "notes": "Not part of this fixture pass claim.",
                },
            ],
            "tests": [
                {
                    "id": "T-a",
                    "requirement_ids": ["R-a"],
                    "type": "api",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": [evidence_id],
                },
                {
                    "id": "T-b",
                    "requirement_ids": ["R-b"],
                    "type": "api",
                    "expected": matrix["tests"][1]["expected"],
                    "status": "Untested",
                    "evidence_ids": [],
                    "notes": "Not part of this fixture pass claim.",
                },
            ],
            "evidence": [evidence],
        }

    write_json(lineage_dir / "bad-ledger.json", ledger_for("E-b", "R-b", "T-b"))
    bad_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(lineage_dir / "test-matrix.json"),
            "--ledger",
            str(lineage_dir / "bad-ledger.json"),
            "--summary",
            str(lineage_dir / "bad-audit-summary.json"),
        ],
        cwd=str(lineage_dir),
        text=True,
        capture_output=True,
    )
    assert_true(bad_proc.returncode != 0, "Mismatched evidence lineage must fail the audit.")
    bad_audit = load_json(lineage_dir / "bad-audit-summary.json")
    bad_errors = "\n".join(bad_audit.get("errors", []))
    assert_true("Passed requirement R-a references evidence E-b" in bad_errors, "Lineage audit should name the wrong requirement citation.")
    assert_true("Passed test T-a references evidence E-b" in bad_errors, "Lineage audit should name the wrong test citation.")
    assert_true(bad_audit.get("evidence_lineage_checked") == 2, "Lineage audit should count checked passed citations.")

    write_json(lineage_dir / "missing-runner-lineage-ledger.json", ledger_for("E-a", "R-a", "T-a", include_lineage=False))
    missing_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(lineage_dir / "test-matrix.json"),
            "--ledger",
            str(lineage_dir / "missing-runner-lineage-ledger.json"),
            "--summary",
            str(lineage_dir / "missing-runner-lineage-audit-summary.json"),
        ],
        cwd=str(lineage_dir),
        text=True,
        capture_output=True,
    )
    assert_true(missing_proc.returncode != 0, "Bundled-runner evidence without lineage must fail the audit.")
    missing_audit = load_json(lineage_dir / "missing-runner-lineage-audit-summary.json")
    missing_errors = "\n".join(missing_audit.get("errors", []))
    assert_true("bundled-runner evidence E-a without test_ids/requirement_ids lineage" in missing_errors, "Audit should name missing bundled-runner lineage.")

    write_json(lineage_dir / "manual-no-lineage-ledger.json", ledger_for("E-manual", "R-a", "T-a", include_lineage=False, generated_by="manual"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(lineage_dir / "test-matrix.json"),
            "--ledger",
            str(lineage_dir / "manual-no-lineage-ledger.json"),
            "--summary",
            str(lineage_dir / "manual-no-lineage-audit-summary.json"),
        ],
        cwd=lineage_dir,
    )
    manual_audit = load_json(lineage_dir / "manual-no-lineage-audit-summary.json")
    assert_true(manual_audit.get("evidence_lineage_warning_count") == 2, "Manual evidence without lineage should remain a warning, not a hard failure.")

    write_json(lineage_dir / "good-ledger.json", ledger_for("E-a", "R-a", "T-a"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(lineage_dir / "test-matrix.json"),
            "--ledger",
            str(lineage_dir / "good-ledger.json"),
            "--summary",
            str(lineage_dir / "good-audit-summary.json"),
        ],
        cwd=lineage_dir,
    )
    good_audit = load_json(lineage_dir / "good-audit-summary.json")
    assert_true(good_audit.get("evidence_lineage_checked") == 2, "Matching evidence lineage should be counted by the audit.")


def run_runner_result_binding_fixture(script_dir: Path, tmp_path: Path) -> None:
    binding_dir = tmp_path / "runner-result-binding"
    binding_dir.mkdir(parents=True, exist_ok=True)
    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-ui",
                "source": "fixture",
                "text": "Ready text must be visible in the current runner results.",
                "test_ids": ["T-ui"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-ui",
                "requirement_ids": ["R-ui"],
                "type": "ui",
                "expected": "Ready text is visible.",
                "status": "Untested",
            }
        ],
    }

    def ledger_for(*, scenario_id: str = "ui", status: str = "passed") -> dict[str, Any]:
        return {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-ui",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-ui"],
                    "status": "Passed",
                    "evidence_ids": ["E-runner"],
                }
            ],
            "tests": [
                {
                    "id": "T-ui",
                    "requirement_ids": ["R-ui"],
                    "type": "ui",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-runner"],
                }
            ],
            "evidence": [
                {
                    "id": "E-runner",
                    "type": "ui_assertion",
                    "current_run": True,
                    "generated_by": "ledger_from_probe.py",
                    "scenario_id": scenario_id,
                    "step_id": "T-ui",
                    "action": "expectText",
                    "status": status,
                    "test_ids": ["T-ui"],
                    "requirement_ids": ["R-ui"],
                    "proves": "Ready text was visible.",
                    "value": "Ready",
                    "count": 1,
                }
            ],
        }

    good_results = {
        "schemaVersion": 2,
        "status": "passed",
        "artifactDir": str(binding_dir),
        "scenarios": [
            {
                "id": "ui",
                "status": "passed",
                "steps": [
                    {
                        "scenarioId": "ui",
                        "stepId": "T-ui",
                        "testIds": ["T-ui"],
                        "requirementIds": ["R-ui"],
                        "action": "expectText",
                        "status": "passed",
                        "evidenceType": "ui_assertion",
                        "count": 1,
                        "proves": "Ready text was visible.",
                    }
                ],
            }
        ],
        "console": [],
        "failedResponses": [],
        "requestFailures": [],
    }
    write_json(binding_dir / "test-matrix.json", matrix)
    write_json(binding_dir / "good-results.json", good_results)
    write_json(binding_dir / "good-ledger.json", ledger_for())
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(binding_dir / "test-matrix.json"),
            "--ledger",
            str(binding_dir / "good-ledger.json"),
            "--results",
            str(binding_dir / "good-results.json"),
            "--summary",
            str(binding_dir / "good-audit-summary.json"),
        ],
        cwd=binding_dir,
    )
    good_audit = load_json(binding_dir / "good-audit-summary.json")
    assert_true(good_audit.get("runner_result_binding_checked") == 1, "Runner evidence should be bound to one matching results step.")

    write_json(binding_dir / "missing-step-results.json", {**good_results, "scenarios": []})
    missing_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(binding_dir / "test-matrix.json"),
            "--ledger",
            str(binding_dir / "good-ledger.json"),
            "--results",
            str(binding_dir / "missing-step-results.json"),
            "--summary",
            str(binding_dir / "missing-step-audit-summary.json"),
        ],
        cwd=binding_dir,
        text=True,
        capture_output=True,
    )
    assert_true(missing_proc.returncode != 0, "Runner evidence without a matching results step must fail audit.")
    missing_audit = load_json(binding_dir / "missing-step-audit-summary.json")
    missing_errors = "\n".join(missing_audit.get("errors", []))
    assert_true("Runner-generated evidence E-runner has no matching results.json step" in missing_errors, "Audit should name the missing runner step binding.")

    write_json(binding_dir / "failed-step-results.json", {**good_results, "scenarios": [{**good_results["scenarios"][0], "steps": [{**good_results["scenarios"][0]["steps"][0], "status": "failed", "error": "Ready text missing"}]}]})
    status_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(binding_dir / "test-matrix.json"),
            "--ledger",
            str(binding_dir / "good-ledger.json"),
            "--results",
            str(binding_dir / "failed-step-results.json"),
            "--summary",
            str(binding_dir / "status-mismatch-audit-summary.json"),
        ],
        cwd=binding_dir,
        text=True,
        capture_output=True,
    )
    assert_true(status_proc.returncode != 0, "Runner evidence status must match the bound results step status.")
    status_audit = load_json(binding_dir / "status-mismatch-audit-summary.json")
    status_errors = "\n".join(status_audit.get("errors", []))
    assert_true("does not match results.json step status" in status_errors, "Audit should name runner evidence status mismatches.")

    api_field_dir = tmp_path / "runner-result-field-binding"
    (api_field_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (api_field_dir / "evidence" / "api-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    api_matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-api",
                "source": "fixture",
                "text": "API evidence copied from runner results must not be hand-mutated.",
                "test_ids": ["T-api"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-api",
                "requirement_ids": ["R-api"],
                "type": "api",
                "expected": "API response is 200 and ok=true.",
                "status": "Untested",
            }
        ],
    }
    api_ledger = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-api",
                "source": "fixture",
                "text": api_matrix["requirements"][0]["text"],
                "test_ids": ["T-api"],
                "status": "Passed",
                "evidence_ids": ["E-api"],
            }
        ],
        "tests": [
            {
                "id": "T-api",
                "requirement_ids": ["R-api"],
                "type": "api",
                "expected": api_matrix["tests"][0]["expected"],
                "status": "Passed",
                "evidence_ids": ["E-api"],
            }
        ],
        "evidence": [
            {
                "id": "E-api",
                "type": "api_response",
                "current_run": True,
                "generated_by": "ledger_from_probe.py",
                "scenario_id": "api",
                "step_id": "T-api",
                "action": "api",
                "status": "passed",
                "test_ids": ["T-api"],
                "requirement_ids": ["R-api"],
                "proves": "API returned ok=true.",
                "url": "/api/v1/fixture",
                "body_path": "evidence/api-response.json",
                "status_code": 200,
                "checked_json": {"ok": True},
                "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
            }
        ],
    }
    api_results = {
        "schemaVersion": 2,
        "status": "passed",
        "artifactDir": str(api_field_dir),
        "scenarios": [
            {
                "id": "api",
                "status": "passed",
                "steps": [
                    {
                        "scenarioId": "api",
                        "stepId": "T-api",
                        "testIds": ["T-api"],
                        "requirementIds": ["R-api"],
                        "action": "api",
                        "status": "passed",
                        "evidenceType": "api_response",
                        "url": "/api/v1/fixture",
                        "bodyPath": "evidence/api-response.json",
                        "statusCode": 204,
                        "checkedJson": {"ok": False},
                        "proves": "API runner step intentionally disagrees with ledger evidence.",
                    }
                ],
            }
        ],
        "console": [],
        "failedResponses": [],
        "requestFailures": [],
    }
    write_json(api_field_dir / "test-matrix.json", api_matrix)
    write_json(api_field_dir / "evidence-ledger.json", api_ledger)
    write_json(api_field_dir / "results.json", api_results)
    field_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(api_field_dir / "test-matrix.json"),
            "--ledger",
            str(api_field_dir / "evidence-ledger.json"),
            "--results",
            str(api_field_dir / "results.json"),
            "--summary",
            str(api_field_dir / "field-mismatch-audit-summary.json"),
        ],
        cwd=api_field_dir,
        text=True,
        capture_output=True,
    )
    assert_true(field_proc.returncode != 0, "Runner evidence fields must match the bound results step fields.")
    field_audit = load_json(api_field_dir / "field-mismatch-audit-summary.json")
    field_errors = "\n".join(field_audit.get("errors", []))
    assert_true("does not match bound results.json step fields" in field_errors, "Audit should name runner evidence field mismatches.")

    deleted_field_dir = tmp_path / "runner-result-deleted-field-binding"
    (deleted_field_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (deleted_field_dir / "evidence" / "api-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    deleted_field_ledger = json.loads(json.dumps(api_ledger))
    deleted_evidence = deleted_field_ledger["evidence"][0]
    deleted_evidence.pop("body_path", None)
    deleted_evidence.pop("status_code", None)
    deleted_evidence.pop("checked_json", None)
    deleted_evidence["path"] = "evidence/api-response.json"
    deleted_field_results = json.loads(json.dumps(api_results))
    deleted_step = deleted_field_results["scenarios"][0]["steps"][0]
    deleted_step["statusCode"] = 200
    deleted_step["checkedJson"] = {"ok": True}
    deleted_step["proves"] = "API returned ok=true."
    write_json(deleted_field_dir / "test-matrix.json", api_matrix)
    write_json(deleted_field_dir / "evidence-ledger.json", deleted_field_ledger)
    write_json(deleted_field_dir / "results.json", deleted_field_results)
    deleted_field_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(deleted_field_dir / "test-matrix.json"),
            "--ledger",
            str(deleted_field_dir / "evidence-ledger.json"),
            "--results",
            str(deleted_field_dir / "results.json"),
            "--summary",
            str(deleted_field_dir / "deleted-field-audit-summary.json"),
        ],
        cwd=deleted_field_dir,
        text=True,
        capture_output=True,
    )
    assert_true(deleted_field_proc.returncode != 0, "Runner evidence must preserve copied fields from the bound results step.")
    deleted_field_audit = load_json(deleted_field_dir / "deleted-field-audit-summary.json")
    deleted_field_errors = "\n".join(deleted_field_audit.get("errors", []))
    assert_true("status_code is missing from ledger" in deleted_field_errors, "Audit should reject removed runner status_code fields.")
    assert_true("checked_json is missing from ledger" in deleted_field_errors, "Audit should reject removed runner checked_json fields.")

    verdict_dir = tmp_path / "runner-result-binding-verdict"
    write_json(verdict_dir / "test-matrix.json", matrix)
    write_json(verdict_dir / "evidence-ledger.json", ledger_for())
    write_json(verdict_dir / "results.json", {**good_results, "scenarios": []})
    write_synthetic_passing_audit_summary(verdict_dir)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(verdict_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(verdict_dir / "audit-summary.json"),
            "--results",
            str(verdict_dir / "results.json"),
            "--out",
            str(verdict_dir / "qa-verdict.json"),
        ],
        cwd=verdict_dir,
    )
    verdict = load_json(verdict_dir / "qa-verdict.json")
    codes = {reason.get("code") for reason in verdict.get("reasons", [])}
    assert_true(verdict.get("can_claim_pass") is False, "verdict should reject unbound runner evidence even if audit input claims passed.")
    assert_true("runner_evidence_unbound" in codes, "verdict should independently flag unbound runner evidence.")

    verdict_field_dir = tmp_path / "runner-result-field-binding-verdict"
    write_json(verdict_field_dir / "test-matrix.json", api_matrix)
    write_json(verdict_field_dir / "evidence-ledger.json", api_ledger)
    write_json(verdict_field_dir / "results.json", api_results)
    write_synthetic_passing_audit_summary(verdict_field_dir)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(verdict_field_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(verdict_field_dir / "audit-summary.json"),
            "--results",
            str(verdict_field_dir / "results.json"),
            "--out",
            str(verdict_field_dir / "qa-verdict.json"),
        ],
        cwd=verdict_field_dir,
    )
    field_verdict = load_json(verdict_field_dir / "qa-verdict.json")
    field_codes = {reason.get("code") for reason in field_verdict.get("reasons", [])}
    assert_true(field_verdict.get("can_claim_pass") is False, "verdict should reject runner evidence whose copied fields disagree with results.")
    assert_true("runner_evidence_unbound" in field_codes, "verdict should independently flag runner evidence field mismatches.")

    verdict_deleted_field_dir = tmp_path / "runner-result-deleted-field-binding-verdict"
    write_json(verdict_deleted_field_dir / "test-matrix.json", api_matrix)
    write_json(verdict_deleted_field_dir / "evidence-ledger.json", deleted_field_ledger)
    write_json(verdict_deleted_field_dir / "results.json", deleted_field_results)
    write_synthetic_passing_audit_summary(verdict_deleted_field_dir)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(verdict_deleted_field_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(verdict_deleted_field_dir / "audit-summary.json"),
            "--results",
            str(verdict_deleted_field_dir / "results.json"),
            "--out",
            str(verdict_deleted_field_dir / "qa-verdict.json"),
        ],
        cwd=verdict_deleted_field_dir,
    )
    deleted_field_verdict = load_json(verdict_deleted_field_dir / "qa-verdict.json")
    deleted_field_codes = {reason.get("code") for reason in deleted_field_verdict.get("reasons", [])}
    assert_true(deleted_field_verdict.get("can_claim_pass") is False, "verdict should reject runner evidence with deleted copied fields.")
    assert_true("runner_evidence_unbound" in deleted_field_codes, "verdict should independently flag deleted runner evidence fields.")


def run_requirement_status_consistency_fixture(script_dir: Path, tmp_path: Path) -> None:
    status_dir = tmp_path / "requirement-status-consistency"
    status_dir.mkdir(parents=True, exist_ok=True)
    (status_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (status_dir / "evidence" / "status-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-status",
                "source": "fixture",
                "text": "A requirement cannot pass while one mapped test is still failed.",
                "test_ids": ["T-pass", "T-second"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-pass",
                "requirement_ids": ["R-status"],
                "type": "api",
                "expected": "First API proof returns ok=true.",
                "status": "Untested",
            },
            {
                "id": "T-second",
                "requirement_ids": ["R-status"],
                "type": "api",
                "expected": "Second API proof returns ok=true.",
                "status": "Untested",
            },
        ],
    }
    write_json(status_dir / "test-matrix.json", matrix)

    def evidence_item(evidence_id: str, test_id: str) -> dict[str, Any]:
        return {
            "id": evidence_id,
            "type": "api_response",
            "url": f"/api/{test_id}",
            "body_path": "evidence/status-response.json",
            "generated_by": "ledger_from_probe.py",
            "current_run": True,
            "status_code": 200,
            "checked_json": {"ok": True},
            "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
            "test_ids": [test_id],
            "requirement_ids": ["R-status"],
            "proves": f"{test_id} returned ok=true.",
        }

    def ledger_for(second_status: str) -> dict[str, Any]:
        second_passed = second_status == "Passed"
        second_test = {
            "id": "T-second",
            "requirement_ids": ["R-status"],
            "type": "api",
            "expected": matrix["tests"][1]["expected"],
            "status": second_status,
            "evidence_ids": ["E-second"] if second_passed else [],
        }
        if not second_passed:
            second_test["notes"] = "Second proof failed in the current run."
        evidence = [evidence_item("E-pass", "T-pass")]
        if second_passed:
            evidence.append(evidence_item("E-second", "T-second"))
        return {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-status",
                    "source": "fixture",
                    "text": matrix["requirements"][0]["text"],
                    "test_ids": ["T-pass", "T-second"],
                    "status": "Passed",
                    "evidence_ids": ["E-pass"] + (["E-second"] if second_passed else []),
                }
            ],
            "tests": [
                {
                    "id": "T-pass",
                    "requirement_ids": ["R-status"],
                    "type": "api",
                    "expected": matrix["tests"][0]["expected"],
                    "status": "Passed",
                    "evidence_ids": ["E-pass"],
                },
                second_test,
            ],
            "evidence": evidence,
        }

    write_json(status_dir / "bad-ledger.json", ledger_for("Failed"))
    bad_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(status_dir / "test-matrix.json"),
            "--ledger",
            str(status_dir / "bad-ledger.json"),
            "--summary",
            str(status_dir / "bad-audit-summary.json"),
        ],
        cwd=str(status_dir),
        text=True,
        capture_output=True,
    )
    assert_true(bad_proc.returncode != 0, "A Passed requirement with a failed mapped test must fail audit.")
    bad_audit = load_json(status_dir / "bad-audit-summary.json")
    assert_true("Requirement R-status is Passed but mapped test T-second has status 'Failed'." in "\n".join(bad_audit.get("errors", [])), "Status consistency audit should name the contradictory mapped test.")
    assert_true(bad_audit.get("requirement_status_consistency_checked") == 2, "Status consistency audit should count mapped tests on passed requirements.")

    write_json(status_dir / "good-ledger.json", ledger_for("Passed"))
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(status_dir / "test-matrix.json"),
            "--ledger",
            str(status_dir / "good-ledger.json"),
            "--summary",
            str(status_dir / "good-audit-summary.json"),
        ],
        cwd=status_dir,
    )
    good_audit = load_json(status_dir / "good-audit-summary.json")
    assert_true(good_audit.get("requirement_status_consistency_checked") == 2, "Passing mapped tests should satisfy requirement status consistency.")


def run_verdict_artifact_binding_fixture(script_dir: Path, tmp_path: Path) -> None:
    binding_root = tmp_path / "verdict-artifact-binding"
    binding_root.mkdir(parents=True, exist_ok=True)

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-binding",
                "source": "fixture",
                "text": "Final verdict must be generated from the same audited ledger and results.",
                "test_ids": ["T-binding"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-binding",
                "requirement_ids": ["R-binding"],
                "type": "api",
                "expected": "API response returns ok=true.",
                "status": "Untested",
            }
        ],
    }
    good_ledger = {
        "schema_version": 2,
        "requirements": [
            {
                "id": "R-binding",
                "source": "fixture",
                "text": matrix["requirements"][0]["text"],
                "test_ids": ["T-binding"],
                "status": "Passed",
                "evidence_ids": ["E-binding"],
            }
        ],
        "tests": [
            {
                "id": "T-binding",
                "requirement_ids": ["R-binding"],
                "type": "api",
                "expected": matrix["tests"][0]["expected"],
                "status": "Passed",
                "evidence_ids": ["E-binding"],
            }
        ],
        "evidence": [
            {
                "id": "E-binding",
                "type": "api_response",
                "url": "/api/v1/binding",
                "body_path": "evidence/binding-response.json",
                "generated_by": "ledger_from_probe.py",
                "current_run": True,
                "status_code": 200,
                "checked_json": {"ok": True},
                "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
                "test_ids": ["T-binding"],
                "requirement_ids": ["R-binding"],
                "proves": "The API response returned ok=true.",
            }
        ],
    }
    good_results = {
        "status": "passed",
        "startedAt": "2026-06-15T00:00:00+00:00",
        "scenarios": [
            {
                "id": "binding",
                "status": "passed",
                "steps": [
                    {
                        "scenarioId": "binding",
                        "stepId": "T-binding",
                        "testIds": ["T-binding"],
                        "requirementIds": ["R-binding"],
                        "action": "api",
                        "status": "passed",
                        "evidenceType": "api_response",
                        "statusCode": 200,
                        "bodyPath": "evidence/binding-response.json",
                        "checkedJson": {"ok": True},
                        "proves": "The API response returned ok=true.",
                    }
                ],
            }
        ],
        "console": [],
        "failedResponses": [],
        "requestFailures": [],
    }
    defects = {"summary": {"finding_count": 0, "severity_counts": {}}}

    def prepare_case(case_dir: Path) -> None:
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "evidence").mkdir(parents=True, exist_ok=True)
        (case_dir / "evidence" / "binding-response.json").write_text('{"ok":true}\n', encoding="utf-8")
        write_json(case_dir / "test-matrix.json", matrix)
        write_json(case_dir / "evidence-ledger.json", good_ledger)
        write_json(case_dir / "results.json", good_results)
        write_json(case_dir / "defects.json", defects)
        run_cmd(
            [
                sys.executable,
                str(script_dir / "audit_evidence.py"),
                "--matrix",
                str(case_dir / "test-matrix.json"),
                "--results",
                str(case_dir / "results.json"),
                "--ledger",
                str(case_dir / "evidence-ledger.json"),
                "--summary",
                str(case_dir / "audit-summary.json"),
            ],
            cwd=case_dir,
        )

    def generate_case_verdict(
        case_dir: Path,
        name: str,
        fail_on_not_pass: bool = False,
        include_results: bool = True,
        include_defects: bool = True,
        include_requirement_coverage: bool = False,
    ) -> dict[str, Any]:
        cmd = [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(case_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(case_dir / "audit-summary.json"),
            "--out",
            str(case_dir / f"{name}-verdict.json"),
        ]
        if include_results:
            cmd.extend(["--results", str(case_dir / "results.json")])
        if include_defects:
            cmd.extend(["--defects", str(case_dir / "defects.json")])
        if include_requirement_coverage:
            cmd.extend(["--requirement-coverage", str(case_dir / "requirement-coverage.json")])
        if fail_on_not_pass:
            cmd.append("--fail-on-not-pass")
        run_cmd(cmd, cwd=case_dir)
        return load_json(case_dir / f"{name}-verdict.json")

    good_dir = binding_root / "good"
    prepare_case(good_dir)
    good_verdict = generate_case_verdict(good_dir, "good", fail_on_not_pass=True)
    assert_true(good_verdict.get("can_claim_pass") is True, "Matching audit, ledger, and results should allow a clean pass verdict.")
    assert_true(good_verdict.get("gates", {}).get("audit_artifacts_bound") is True, "Verdict should expose a passing artifact binding gate.")

    inconsistent_defects_dir = binding_root / "inconsistent-defects"
    prepare_case(inconsistent_defects_dir)
    write_json(
        inconsistent_defects_dir / "defects.json",
        {
            "summary": {"finding_count": 0, "severity_counts": {}},
            "findings": [{"id": "D-hidden", "severity": "P1", "title": "Hidden defect despite zero summary count."}],
        },
    )
    inconsistent_defects_verdict = generate_case_verdict(inconsistent_defects_dir, "inconsistent-defects")
    inconsistent_defects_codes = {reason.get("code") for reason in inconsistent_defects_verdict.get("reasons", [])}
    assert_true(inconsistent_defects_verdict.get("can_claim_pass") is False, "Defect findings must block pass even when summary.finding_count is stale or wrong.")
    assert_true("defects_present" in inconsistent_defects_codes, "Verdict should treat defects.findings as authoritative evidence of defects.")
    assert_true("defects_summary_mismatch" in inconsistent_defects_codes, "Verdict should expose mismatched defects summary counts.")
    assert_true(inconsistent_defects_verdict.get("gates", {}).get("defect_free") is False, "Mismatched defect findings should mark defect_free=false.")

    cross_run_defects_dir = binding_root / "cross-run-defects"
    prepare_case(cross_run_defects_dir)
    clean_artifact_dir = binding_root / "clean-artifact-source"
    clean_artifact_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        cross_run_defects_dir / "defects.json",
        {"summary": {"finding_count": 1, "severity_counts": {"P1": 1}}, "findings": [{"id": "D-current", "severity": "P1"}]},
    )
    write_json(clean_artifact_dir / "defects.json", defects)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(cross_run_defects_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(cross_run_defects_dir / "audit-summary.json"),
            "--results",
            str(cross_run_defects_dir / "results.json"),
            "--defects",
            str(clean_artifact_dir / "defects.json"),
            "--out",
            str(cross_run_defects_dir / "cross-run-defects-verdict.json"),
        ],
        cwd=cross_run_defects_dir,
    )
    cross_run_defects_verdict = load_json(cross_run_defects_dir / "cross-run-defects-verdict.json")
    cross_run_defects_codes = {reason.get("code") for reason in cross_run_defects_verdict.get("reasons", [])}
    assert_true(cross_run_defects_verdict.get("can_claim_pass") is False, "A clean defects artifact from another run must not hide current sibling defects.json.")
    assert_true("defects_sibling_path_mismatch" in cross_run_defects_codes, "Verdict should report cross-run defects artifact path mismatch.")

    artifact_dir_mismatch_dir = binding_root / "results-artifact-dir-mismatch"
    prepare_case(artifact_dir_mismatch_dir)
    external_artifact_dir = binding_root / "external-results-artifacts"
    external_artifact_dir.mkdir(parents=True, exist_ok=True)
    changed_results = json.loads(json.dumps(good_results))
    changed_results["artifactDir"] = str(external_artifact_dir)
    write_json(artifact_dir_mismatch_dir / "results.json", changed_results)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(artifact_dir_mismatch_dir / "test-matrix.json"),
            "--results",
            str(artifact_dir_mismatch_dir / "results.json"),
            "--ledger",
            str(artifact_dir_mismatch_dir / "evidence-ledger.json"),
            "--summary",
            str(artifact_dir_mismatch_dir / "audit-summary.json"),
        ],
        cwd=artifact_dir_mismatch_dir,
    )
    artifact_dir_mismatch_verdict = generate_case_verdict(artifact_dir_mismatch_dir, "results-artifact-dir-mismatch")
    artifact_dir_mismatch_codes = {reason.get("code") for reason in artifact_dir_mismatch_verdict.get("reasons", [])}
    assert_true(artifact_dir_mismatch_verdict.get("can_claim_pass") is False, "A results.json artifactDir from another run must block final pass.")
    assert_true("results_artifact_dir_mismatch" in artifact_dir_mismatch_codes, "Verdict should report artifactDir mismatch against the current run directory.")
    assert_true("results_artifact_dir_not_results_parent" in artifact_dir_mismatch_codes, "Verdict should report artifactDir mismatch against results.json parent.")

    artifact_changed_dir = binding_root / "evidence-artifact-changed"
    prepare_case(artifact_changed_dir)
    (artifact_changed_dir / "evidence" / "binding-response.json").write_text('{"ok":false}\n', encoding="utf-8")
    artifact_changed_verdict = generate_case_verdict(artifact_changed_dir, "evidence-artifact-changed")
    artifact_changed_codes = {reason.get("code") for reason in artifact_changed_verdict.get("reasons", [])}
    assert_true(artifact_changed_verdict.get("can_claim_pass") is False, "An evidence artifact changed after audit must block final pass.")
    assert_true("audit_evidence_artifact_hash_mismatch" in artifact_changed_codes, "Verdict should report evidence artifact hash mismatch after audit.")

    malformed_optional_dir = binding_root / "malformed-optional-input"
    prepare_case(malformed_optional_dir)
    (malformed_optional_dir / "adapter-context.json").write_text("{not-json", encoding="utf-8")
    malformed_cmd = [
        sys.executable,
        str(script_dir / "generate_verdict.py"),
        "--ledger",
        str(malformed_optional_dir / "evidence-ledger.json"),
        "--audit-summary",
        str(malformed_optional_dir / "audit-summary.json"),
        "--results",
        str(malformed_optional_dir / "results.json"),
        "--defects",
        str(malformed_optional_dir / "defects.json"),
        "--adapter-context",
        str(malformed_optional_dir / "adapter-context.json"),
        "--require-environment-boundary",
        "--out",
        str(malformed_optional_dir / "malformed-optional-verdict.json"),
        "--fail-on-not-pass",
    ]
    malformed_proc = subprocess.run(malformed_cmd, cwd=str(malformed_optional_dir), text=True, capture_output=True)
    assert_true(malformed_proc.returncode != 0, "fail-on-not-pass should exit non-zero for unreadable optional verdict inputs.")
    assert_true("Traceback" not in malformed_proc.stderr, "generate_verdict should not crash on malformed optional artifact JSON.")
    malformed_optional_verdict = load_json(malformed_optional_dir / "malformed-optional-verdict.json")
    malformed_optional_codes = {reason.get("code") for reason in malformed_optional_verdict.get("reasons", [])}
    malformed_input_names = {item.get("name") for item in malformed_optional_verdict.get("input_artifact_errors", [])}
    assert_true(malformed_optional_verdict.get("can_claim_pass") is False, "Unreadable optional verdict inputs must block pass claims.")
    assert_true("input_artifact_unreadable" in malformed_optional_codes, "Verdict should report unreadable input artifacts instead of crashing.")
    assert_true("adapter_context" in malformed_input_names, "Verdict should name the unreadable adapter context input.")

    unreadable_results_dir = binding_root / "unreadable-results-input"
    prepare_case(unreadable_results_dir)
    (unreadable_results_dir / "results.json").unlink()
    (unreadable_results_dir / "results.json").mkdir()
    unreadable_results_verdict = generate_case_verdict(unreadable_results_dir, "unreadable-results")
    unreadable_results_codes = {reason.get("code") for reason in unreadable_results_verdict.get("reasons", [])}
    unreadable_input_names = {item.get("name") for item in unreadable_results_verdict.get("input_artifact_errors", [])}
    assert_true(unreadable_results_verdict.get("can_claim_pass") is False, "Directory-shaped results input must block pass claims.")
    assert_true("input_artifact_unreadable" in unreadable_results_codes, "Verdict should report directory-shaped results as unreadable input.")
    assert_true("audit_results_unreadable" in unreadable_results_codes, "Verdict should report that audit-bound results cannot be hash-verified.")
    assert_true("results" in unreadable_input_names, "Verdict should name the unreadable results input.")

    unbound_matrix_dir = binding_root / "unbound-matrix"
    unbound_matrix_dir.mkdir(parents=True, exist_ok=True)
    (unbound_matrix_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (unbound_matrix_dir / "evidence" / "binding-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    write_json(unbound_matrix_dir / "test-matrix.json", matrix)
    write_json(unbound_matrix_dir / "evidence-ledger.json", good_ledger)
    write_json(unbound_matrix_dir / "results.json", good_results)
    write_json(unbound_matrix_dir / "defects.json", defects)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--results",
            str(unbound_matrix_dir / "results.json"),
            "--ledger",
            str(unbound_matrix_dir / "evidence-ledger.json"),
            "--summary",
            str(unbound_matrix_dir / "audit-summary.json"),
        ],
        cwd=unbound_matrix_dir,
    )
    unbound_matrix_verdict = generate_case_verdict(unbound_matrix_dir, "unbound-matrix")
    unbound_matrix_codes = {reason.get("code") for reason in unbound_matrix_verdict.get("reasons", [])}
    assert_true(unbound_matrix_verdict.get("can_claim_pass") is False, "A verdict whose audit omitted test-matrix.json must not claim pass.")
    assert_true("audit_matrix_unbound" in unbound_matrix_codes, "Verdict should report unbound matrix when audit omitted --matrix.")

    omitted_results_verdict = generate_case_verdict(good_dir, "omitted-results", include_results=False)
    omitted_results_codes = {reason.get("code") for reason in omitted_results_verdict.get("reasons", [])}
    assert_true(omitted_results_verdict.get("can_claim_pass") is False, "A verdict that omits audit-bound results.json must not claim pass.")
    assert_true("audit_results_omitted" in omitted_results_codes, "Verdict should report omitted results when audit was generated with results.json.")

    omitted_defects_dir = binding_root / "omitted-defects"
    prepare_case(omitted_defects_dir)
    write_json(
        omitted_defects_dir / "defects.json",
        {"summary": {"finding_count": 1, "severity_counts": {"P1": 1}}, "findings": [{"id": "D-hidden", "severity": "P1"}]},
    )
    omitted_defects_verdict = generate_case_verdict(omitted_defects_dir, "omitted-defects", include_defects=False)
    omitted_defects_codes = {reason.get("code") for reason in omitted_defects_verdict.get("reasons", [])}
    assert_true(omitted_defects_verdict.get("can_claim_pass") is False, "A verdict that omits sibling defects.json must not claim pass.")
    assert_true("defects_omitted" in omitted_defects_codes, "Verdict should report omitted defects when defects.json exists beside the ledger.")

    omitted_coverage_dir = binding_root / "omitted-coverage"
    prepare_case(omitted_coverage_dir)
    write_json(
        omitted_coverage_dir / "requirement-coverage.json",
        {
            "passed": False,
            "uncovered_count": 1,
            "coverage": [{"id": "SRC-hidden", "source": "fixture", "covered": False}],
        },
    )
    omitted_coverage_verdict = generate_case_verdict(omitted_coverage_dir, "omitted-coverage")
    omitted_coverage_codes = {reason.get("code") for reason in omitted_coverage_verdict.get("reasons", [])}
    assert_true(omitted_coverage_verdict.get("can_claim_pass") is False, "A verdict that omits sibling requirement-coverage.json must not claim pass.")
    assert_true("requirement_coverage_omitted" in omitted_coverage_codes, "Verdict should report omitted requirement coverage when requirement-coverage.json exists beside the ledger.")

    omitted_setup_adapter_dir = binding_root / "omitted-setup-adapter"
    prepare_case(omitted_setup_adapter_dir)
    write_json(
        omitted_setup_adapter_dir / "service-preflight.json",
        {"blockers": [{"service": "api", "reason": "synthetic service unavailable"}]},
    )
    write_json(
        omitted_setup_adapter_dir / "service-runtime.json",
        {
            "mode": "start",
            "summary": {"planned_count": 1, "ready_count": 0, "failed_count": 1},
            "services": [{"service": "api", "status": "failed"}],
        },
    )
    write_json(
        omitted_setup_adapter_dir / "adapter-probes.json",
        {"blocked": [{"layer": "stream", "reason": "synthetic stream endpoint missing"}]},
    )
    write_json(
        omitted_setup_adapter_dir / "adapter-context.json",
        {"environment_boundary": {"runtime_mode": "unconfirmed", "data_boundary_status": "unconfirmed"}},
    )
    omitted_setup_adapter_verdict = generate_case_verdict(omitted_setup_adapter_dir, "omitted-setup-adapter")
    omitted_setup_adapter_codes = {reason.get("code") for reason in omitted_setup_adapter_verdict.get("reasons", [])}
    expected_setup_adapter_codes = {
        "service_preflight_omitted",
        "service_runtime_omitted",
        "adapter_probes_omitted",
        "adapter_context_omitted",
    }
    assert_true(omitted_setup_adapter_verdict.get("can_claim_pass") is False, "A verdict that omits sibling setup/adapter artifacts must not claim pass.")
    assert_true(expected_setup_adapter_codes <= omitted_setup_adapter_codes, "Verdict should report every omitted setup/adapter sibling artifact.")

    omitted_cycle_error_dir = binding_root / "omitted-cycle-error"
    prepare_case(omitted_cycle_error_dir)
    write_json(
        omitted_cycle_error_dir / "qa-cycle-error.json",
        {
            "schema_version": 1,
            "code": "cycle_helper_failed",
            "phase": "generate_report",
            "message": "Synthetic report generation failure after audit.",
        },
    )
    omitted_cycle_error_verdict = generate_case_verdict(omitted_cycle_error_dir, "omitted-cycle-error")
    omitted_cycle_error_codes = {reason.get("code") for reason in omitted_cycle_error_verdict.get("reasons", [])}
    assert_true(omitted_cycle_error_verdict.get("can_claim_pass") is False, "A verdict that omits sibling qa-cycle-error.json must not claim pass.")
    assert_true("cycle_error_omitted" in omitted_cycle_error_codes, "Verdict should report omitted cycle error when qa-cycle-error.json exists beside the ledger.")
    assert_true(omitted_cycle_error_verdict.get("gates", {}).get("cycle_completed") is False, "Omitted cycle errors should mark the cycle incomplete.")

    matrix_changed_dir = binding_root / "matrix-changed"
    prepare_case(matrix_changed_dir)
    changed_matrix = json.loads(json.dumps(matrix))
    changed_matrix["requirements"].append(
        {
            "id": "R-new-after-audit",
            "source": "fixture",
            "text": "Synthetic requirement added after audit.",
            "test_ids": ["T-new-after-audit"],
            "status": "Untested",
        }
    )
    changed_matrix["tests"].append(
        {
            "id": "T-new-after-audit",
            "requirement_ids": ["R-new-after-audit"],
            "type": "api",
            "expected": "Synthetic test added after audit.",
            "status": "Untested",
        }
    )
    write_json(matrix_changed_dir / "test-matrix.json", changed_matrix)
    matrix_changed_verdict = generate_case_verdict(matrix_changed_dir, "matrix-changed")
    matrix_changed_codes = {reason.get("code") for reason in matrix_changed_verdict.get("reasons", [])}
    assert_true(matrix_changed_verdict.get("can_claim_pass") is False, "A matrix changed after audit must block final pass.")
    assert_true("audit_matrix_hash_mismatch" in matrix_changed_codes, "Verdict should report matrix hash mismatch after audit.")

    ledger_changed_dir = binding_root / "ledger-changed"
    prepare_case(ledger_changed_dir)
    changed_ledger = json.loads(json.dumps(good_ledger))
    changed_ledger["requirements"][0]["status"] = "Failed"
    changed_ledger["requirements"][0]["notes"] = "Synthetic contradiction after audit."
    changed_ledger["tests"][0]["status"] = "Failed"
    changed_ledger["tests"][0]["notes"] = "Synthetic contradiction after audit."
    write_json(ledger_changed_dir / "evidence-ledger.json", changed_ledger)
    ledger_changed_verdict = generate_case_verdict(ledger_changed_dir, "ledger-changed")
    ledger_changed_codes = {reason.get("code") for reason in ledger_changed_verdict.get("reasons", [])}
    assert_true(ledger_changed_verdict.get("can_claim_pass") is False, "A ledger changed after audit must block final pass.")
    assert_true("audit_ledger_hash_mismatch" in ledger_changed_codes, "Verdict should report ledger hash mismatch after audit.")
    assert_true("audit_status_counts_mismatch" in ledger_changed_codes, "Verdict should report status count mismatch after ledger mutation.")
    assert_true("requirement_failed" in ledger_changed_codes, "Verdict should count requirement status from the current ledger, not stale audit summary.")

    results_changed_dir = binding_root / "results-changed"
    prepare_case(results_changed_dir)
    changed_results = json.loads(json.dumps(good_results))
    changed_results["console"] = [{"type": "error", "text": "synthetic runtime error after audit"}]
    write_json(results_changed_dir / "results.json", changed_results)
    results_changed_verdict = generate_case_verdict(results_changed_dir, "results-changed")
    results_changed_codes = {reason.get("code") for reason in results_changed_verdict.get("reasons", [])}
    assert_true(results_changed_verdict.get("can_claim_pass") is False, "Results changed after audit must block final pass.")
    assert_true("audit_results_hash_mismatch" in results_changed_codes, "Verdict should report results hash mismatch after audit.")
    assert_true("undispositioned_console_errors" in results_changed_codes, "Verdict should still inspect current results runtime errors.")


def run_report_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    report_dir = tmp_path / "report-input-errors"
    report_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        report_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(report_dir),
            "scenarios": [
                {
                    "id": "report-fixture",
                    "title": "Report fixture",
                    "steps": [],
                }
            ],
        },
    )
    good_results = {
        "schemaVersion": 2,
        "status": "passed",
        "artifactDir": str(report_dir),
        "startedAt": "2026-06-15T00:00:00+00:00",
        "finishedAt": "2026-06-15T00:00:01+00:00",
        "scenarios": [{"id": "report-fixture", "title": "Report fixture", "status": "passed", "steps": []}],
        "console": [],
        "failedResponses": [],
        "requestFailures": [],
    }

    required_bad_dir = report_dir / "required-results"
    required_bad_dir.mkdir(parents=True, exist_ok=True)
    write_json(required_bad_dir / "test-plan.json", load_json(report_dir / "test-plan.json"))
    (required_bad_dir / "results.json").write_text("{not-json", encoding="utf-8")
    required_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(required_bad_dir / "test-plan.json"),
            "--results",
            str(required_bad_dir / "results.json"),
            "--out",
            str(required_bad_dir / "report.md"),
        ],
        cwd=required_bad_dir,
        text=True,
        capture_output=True,
    )
    assert_true(required_proc.returncode != 0, "Report generation should exit non-zero when required results.json is unreadable.")
    assert_true("Traceback" not in required_proc.stderr, "Report generation should not expose unreadable required inputs as a traceback.")
    required_report = (required_bad_dir / "report.md").read_text(encoding="utf-8")
    assert_true("Report Input Errors" in required_report, "Partial report should include an explicit input error section.")
    assert_true("results" in required_report and "invalid_json" in required_report, "Partial report should name unreadable required results input.")
    assert_true("Report completeness: PARTIAL" in required_report, "Partial report should block final pass/fail claims.")

    optional_bad_dir = report_dir / "optional-verdict"
    optional_bad_dir.mkdir(parents=True, exist_ok=True)
    write_json(optional_bad_dir / "test-plan.json", load_json(report_dir / "test-plan.json"))
    write_json(optional_bad_dir / "results.json", {**good_results, "artifactDir": str(optional_bad_dir)})
    (optional_bad_dir / "qa-verdict.json").write_text("{not-json", encoding="utf-8")
    optional_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(optional_bad_dir / "test-plan.json"),
            "--results",
            str(optional_bad_dir / "results.json"),
            "--verdict",
            str(optional_bad_dir / "qa-verdict.json"),
            "--out",
            str(optional_bad_dir / "report.md"),
        ],
        cwd=optional_bad_dir,
        text=True,
        capture_output=True,
    )
    assert_true(optional_proc.returncode != 0, "Report generation should exit non-zero when an explicit optional verdict input is unreadable.")
    assert_true("Traceback" not in optional_proc.stderr, "Report generation should not expose unreadable optional inputs as a traceback.")
    optional_report = (optional_bad_dir / "report.md").read_text(encoding="utf-8")
    assert_true("Report Input Errors" in optional_report, "Report should keep optional input errors visible.")
    assert_true("verdict" in optional_report and "invalid_json" in optional_report, "Report should name unreadable optional verdict input.")
    assert_true("Probe result: PASS" in optional_report, "Readable plan/results content should still render in a partial report.")

    verdict_blocked_dir = report_dir / "verdict-blocked-pass-claim"
    verdict_blocked_dir.mkdir(parents=True, exist_ok=True)
    write_json(verdict_blocked_dir / "test-plan.json", load_json(report_dir / "test-plan.json"))
    write_json(verdict_blocked_dir / "results.json", {**good_results, "artifactDir": str(verdict_blocked_dir)})
    write_json(
        verdict_blocked_dir / "evidence-ledger.json",
        {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R-report",
                    "source": "fixture",
                    "text": "Report should not claim final pass when verdict blocks pass.",
                    "test_ids": ["T-report"],
                    "status": "Passed",
                    "evidence_ids": ["E-report"],
                }
            ],
            "tests": [
                {
                    "id": "T-report",
                    "requirement_ids": ["R-report"],
                    "type": "api",
                    "expected": "The API fixture returns ok=true.",
                    "status": "Passed",
                    "evidence_ids": ["E-report"],
                }
            ],
            "evidence": [
                {
                    "id": "E-report",
                    "type": "api_response",
                    "current_run": True,
                    "url": "/api/v1/report-fixture",
                    "status_code": 200,
                    "checked_json": {"ok": True},
                    "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
                    "proves": "The API fixture returned ok=true.",
                }
            ],
        },
    )
    write_json(
        verdict_blocked_dir / "audit-summary.json",
        {
            "passed": True,
            "requirement_count": 1,
            "test_count": 1,
            "evidence_count": 1,
            "errors": [],
            "warnings": [],
        },
    )
    write_json(
        verdict_blocked_dir / "qa-verdict.json",
        {
            "verdict": "inconclusive",
            "can_claim_pass": False,
            "statement": "Do not claim pass: environment boundary is incomplete.",
            "gates": {"environment_boundary_confirmed": False},
            "reasons": [
                {
                    "code": "data_boundary_unconfirmed",
                    "category": "environment",
                    "severity": "gap",
                    "message": "Data boundary is unconfirmed.",
                    "refs": ["adapter-context.json"],
                }
            ],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(verdict_blocked_dir / "test-plan.json"),
            "--results",
            str(verdict_blocked_dir / "results.json"),
            "--ledger",
            str(verdict_blocked_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(verdict_blocked_dir / "audit-summary.json"),
            "--verdict",
            str(verdict_blocked_dir / "qa-verdict.json"),
            "--out",
            str(verdict_blocked_dir / "report.md"),
        ],
        cwd=verdict_blocked_dir,
    )
    blocked_report = (verdict_blocked_dir / "report.md").read_text(encoding="utf-8")
    assert_true("Pass claim: BLOCKED" in blocked_report, "Report should expose verdict-level pass claim blocking.")
    assert_true("Requirement pass/fail: LEDGER PASSED, FINAL PASS BLOCKED by qa-verdict.json." in blocked_report, "Report should separate ledger pass from final pass claim.")
    assert_true("Pass claim guard: DO NOT CLAIM PASS from this report." in blocked_report, "Final verdict section should carry an explicit no-pass guard.")
    assert_true("Requirement pass/fail: PASSED for the audited scope." not in blocked_report, "Report must not use final-pass wording when verdict blocks pass.")

    stale_pass_dir = report_dir / "stale-pass-verdict"
    stale_pass_dir.mkdir(parents=True, exist_ok=True)
    (stale_pass_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (stale_pass_dir / "evidence" / "report-body.json").write_text('{"ok":true}\n', encoding="utf-8")
    write_json(stale_pass_dir / "test-plan.json", {**load_json(report_dir / "test-plan.json"), "artifactDir": str(stale_pass_dir)})
    write_json(stale_pass_dir / "results.json", {**good_results, "artifactDir": str(stale_pass_dir)})
    write_json(
        stale_pass_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-stale-report",
                    "source": "fixture",
                    "text": "The report must not trust a stale pass verdict.",
                    "test_ids": ["T-stale-report"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-stale-report",
                    "requirement_ids": ["R-stale-report"],
                    "type": "api",
                    "expected": "The API fixture returns ok=true.",
                    "status": "Untested",
                }
            ],
        },
    )
    good_stale_ledger = {
        "schema_version": 2,
        "requirements": [
            {
                "id": "R-stale-report",
                "source": "fixture",
                "text": "The report must not trust a stale pass verdict.",
                "test_ids": ["T-stale-report"],
                "status": "Passed",
                "evidence_ids": ["E-stale-report"],
            }
        ],
        "tests": [
            {
                "id": "T-stale-report",
                "requirement_ids": ["R-stale-report"],
                "type": "api",
                "expected": "The API fixture returns ok=true.",
                "status": "Passed",
                "evidence_ids": ["E-stale-report"],
            }
        ],
        "evidence": [
            {
                "id": "E-stale-report",
                "type": "api_response",
                "current_run": True,
                "url": "/api/v1/report-fixture",
                "body_path": "evidence/report-body.json",
                "status_code": 200,
                "checked_json": {"ok": True},
                "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
                "proves": "The API fixture returned ok=true.",
            }
        ],
    }
    write_json(stale_pass_dir / "evidence-ledger.json", good_stale_ledger)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(stale_pass_dir / "test-matrix.json"),
            "--results",
            str(stale_pass_dir / "results.json"),
            "--ledger",
            str(stale_pass_dir / "evidence-ledger.json"),
            "--summary",
            str(stale_pass_dir / "audit-summary.json"),
        ],
        cwd=stale_pass_dir,
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(stale_pass_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(stale_pass_dir / "audit-summary.json"),
            "--results",
            str(stale_pass_dir / "results.json"),
            "--out",
            str(stale_pass_dir / "qa-verdict.json"),
            "--fail-on-not-pass",
        ],
        cwd=stale_pass_dir,
    )
    stale_verdict = load_json(stale_pass_dir / "qa-verdict.json")
    assert_true(stale_verdict.get("can_claim_pass") is True, "Stale-report fixture setup should first produce a pass verdict.")
    write_json(
        stale_pass_dir / "defects.json",
        {
            "summary": {"finding_count": 1, "severity_counts": {"P1": 1}},
            "findings": [{"id": "D-late-report", "severity": "P1"}],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(stale_pass_dir / "test-plan.json"),
            "--results",
            str(stale_pass_dir / "results.json"),
            "--ledger",
            str(stale_pass_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(stale_pass_dir / "audit-summary.json"),
            "--verdict",
            str(stale_pass_dir / "qa-verdict.json"),
            "--out",
            str(stale_pass_dir / "late-defects-report.md"),
        ],
        cwd=stale_pass_dir,
    )
    late_defects_report = (stale_pass_dir / "late-defects-report.md").read_text(encoding="utf-8")
    assert_true("Pass claim: ALLOWED" not in late_defects_report, "Report must not allow pass when defects.json appears after a pass verdict.")
    assert_true("Report verdict binding: BLOCKED" in late_defects_report, "Report should expose late defects as a verdict binding blocker.")
    assert_true("defects.json has finding_count=1" in late_defects_report, "Report should name late defect findings that block pass.")

    clean_report_artifact_dir = report_dir / "clean-report-artifact-source"
    clean_report_artifact_dir.mkdir(parents=True, exist_ok=True)
    write_json(clean_report_artifact_dir / "defects.json", {"summary": {"finding_count": 0, "severity_counts": {}}, "findings": []})
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(stale_pass_dir / "test-plan.json"),
            "--results",
            str(stale_pass_dir / "results.json"),
            "--ledger",
            str(stale_pass_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(stale_pass_dir / "audit-summary.json"),
            "--verdict",
            str(stale_pass_dir / "qa-verdict.json"),
            "--defects",
            str(clean_report_artifact_dir / "defects.json"),
            "--out",
            str(stale_pass_dir / "cross-run-defects-report.md"),
        ],
        cwd=stale_pass_dir,
    )
    cross_run_defects_report = (stale_pass_dir / "cross-run-defects-report.md").read_text(encoding="utf-8")
    assert_true("Pass claim: ALLOWED" not in cross_run_defects_report, "Report must not allow pass when an explicit clean defects artifact comes from another run.")
    assert_true("Report verdict binding: BLOCKED" in cross_run_defects_report, "Report should expose cross-run defects artifact path mismatch.")
    assert_true("defects.json exists in the current run" in cross_run_defects_report, "Report should name the current sibling defects artifact that was bypassed.")

    artifactdir_report_dir = report_dir / "results-artifactdir-report"
    external_report_artifact_dir = report_dir / "external-report-artifacts"
    artifactdir_report_dir.mkdir(parents=True, exist_ok=True)
    external_report_artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifactdir_report_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (artifactdir_report_dir / "evidence" / "report-body.json").write_text('{"ok":true}\n', encoding="utf-8")
    write_json(artifactdir_report_dir / "test-plan.json", {**load_json(report_dir / "test-plan.json"), "artifactDir": str(artifactdir_report_dir)})
    write_json(artifactdir_report_dir / "test-matrix.json", load_json(stale_pass_dir / "test-matrix.json"))
    write_json(artifactdir_report_dir / "evidence-ledger.json", good_stale_ledger)
    write_json(artifactdir_report_dir / "results.json", {**good_results, "artifactDir": str(external_report_artifact_dir)})
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(artifactdir_report_dir / "test-matrix.json"),
            "--results",
            str(artifactdir_report_dir / "results.json"),
            "--ledger",
            str(artifactdir_report_dir / "evidence-ledger.json"),
            "--summary",
            str(artifactdir_report_dir / "audit-summary.json"),
        ],
        cwd=artifactdir_report_dir,
    )
    write_json(
        artifactdir_report_dir / "qa-verdict.json",
        {
            "verdict": "passed",
            "can_claim_pass": True,
            "statement": "Synthetic legacy pass verdict before artifactDir guard.",
            "inputs": {
                "ledger": str(artifactdir_report_dir / "evidence-ledger.json"),
                "audit_summary": str(artifactdir_report_dir / "audit-summary.json"),
                "results": str(artifactdir_report_dir / "results.json"),
            },
            "reasons": [],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(artifactdir_report_dir / "test-plan.json"),
            "--results",
            str(artifactdir_report_dir / "results.json"),
            "--ledger",
            str(artifactdir_report_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(artifactdir_report_dir / "audit-summary.json"),
            "--verdict",
            str(artifactdir_report_dir / "qa-verdict.json"),
            "--out",
            str(artifactdir_report_dir / "report.md"),
        ],
        cwd=artifactdir_report_dir,
    )
    artifactdir_report = (artifactdir_report_dir / "report.md").read_text(encoding="utf-8")
    assert_true("Pass claim: ALLOWED" not in artifactdir_report, "Report must not allow a pass verdict when results.artifactDir points outside the current run.")
    assert_true("Report verdict binding: BLOCKED" in artifactdir_report, "Report should expose results artifactDir mismatch.")
    assert_true("results.json artifactDir=" in artifactdir_report and "does not match this report's current artifact directory" in artifactdir_report, "Report should name the artifactDir mismatch.")

    write_json(
        stale_pass_dir / "defects.json",
        {
            "summary": {"finding_count": 0, "severity_counts": {}},
            "findings": [{"id": "D-late-hidden", "severity": "P1"}],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(stale_pass_dir / "test-plan.json"),
            "--results",
            str(stale_pass_dir / "results.json"),
            "--ledger",
            str(stale_pass_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(stale_pass_dir / "audit-summary.json"),
            "--verdict",
            str(stale_pass_dir / "qa-verdict.json"),
            "--out",
            str(stale_pass_dir / "mismatched-defects-report.md"),
        ],
        cwd=stale_pass_dir,
    )
    mismatched_defects_report = (stale_pass_dir / "mismatched-defects-report.md").read_text(encoding="utf-8")
    assert_true("Pass claim: ALLOWED" not in mismatched_defects_report, "Report must not allow pass when defects.findings contradict a zero summary count.")
    assert_true("Report verdict binding: BLOCKED" in mismatched_defects_report, "Report should expose mismatched defects as a verdict binding blocker.")
    assert_true("defects.json has finding_count=1" in mismatched_defects_report, "Report should count defect findings even when summary.finding_count is stale.")
    assert_true("summary.finding_count=0 does not match findings length=1" in mismatched_defects_report, "Report should name the defects summary mismatch.")
    assert_true("Defect summary mismatch: summary=0, findings=1" in mismatched_defects_report, "Report summary should surface defects count inconsistency.")
    (stale_pass_dir / "defects.json").unlink()
    write_json(
        stale_pass_dir / "plan-audit-summary.json",
        {
            "passed": False,
            "errors": ["Synthetic weak probe after verdict."],
            "strategy_coverage": {
                "gap_count": 1,
                "gaps": [{"dimension": "persistence", "test_ids": ["T-stale-report"]}],
            },
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(stale_pass_dir / "test-plan.json"),
            "--results",
            str(stale_pass_dir / "results.json"),
            "--ledger",
            str(stale_pass_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(stale_pass_dir / "audit-summary.json"),
            "--verdict",
            str(stale_pass_dir / "qa-verdict.json"),
            "--out",
            str(stale_pass_dir / "late-plan-audit-report.md"),
        ],
        cwd=stale_pass_dir,
    )
    late_plan_report = (stale_pass_dir / "late-plan-audit-report.md").read_text(encoding="utf-8")
    assert_true("Pass claim: ALLOWED" not in late_plan_report, "Report must not allow pass when plan-audit-summary.json fails after a pass verdict.")
    assert_true("Report verdict binding: BLOCKED" in late_plan_report, "Report should expose late plan audit as a verdict binding blocker.")
    assert_true("plan-audit-summary.json is not passed" in late_plan_report, "Report should name failed plan validation that blocks pass.")
    (stale_pass_dir / "plan-audit-summary.json").unlink()
    changed_ledger = json.loads(json.dumps(good_stale_ledger))
    changed_ledger["requirements"][0]["status"] = "Failed"
    changed_ledger["requirements"][0]["notes"] = "Synthetic current contradiction after verdict."
    changed_ledger["tests"][0]["status"] = "Failed"
    changed_ledger["tests"][0]["notes"] = "Synthetic current contradiction after verdict."
    write_json(stale_pass_dir / "evidence-ledger.json", changed_ledger)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(stale_pass_dir / "test-plan.json"),
            "--results",
            str(stale_pass_dir / "results.json"),
            "--ledger",
            str(stale_pass_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(stale_pass_dir / "audit-summary.json"),
            "--verdict",
            str(stale_pass_dir / "qa-verdict.json"),
            "--out",
            str(stale_pass_dir / "report.md"),
        ],
        cwd=stale_pass_dir,
    )
    stale_report = (stale_pass_dir / "report.md").read_text(encoding="utf-8")
    assert_true("Pass claim: ALLOWED" not in stale_report, "Report must not allow pass when a pass verdict is stale relative to current artifacts.")
    assert_true("Report verdict binding: BLOCKED" in stale_report, "Report should expose stale verdict artifact binding blockers.")
    assert_true("ledger artifact hash differs from audit-summary.json" in stale_report, "Report should name the current ledger/audit hash mismatch.")


def run_next_probe_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    next_dir = tmp_path / "next-probe-input-errors"
    next_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        next_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(next_dir),
            "scenarios": [],
        },
    )
    write_json(
        next_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-next",
                    "source": "fixture",
                    "text": "Next-probe application should report malformed follow-up artifacts.",
                    "test_ids": ["T-next"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-next",
                    "requirement_ids": ["R-next"],
                    "type": "runtime",
                    "expected": "Malformed next-probe input produces a structured handoff.",
                    "status": "Untested",
                }
            ],
        },
    )

    (next_dir / "next-probes.json").write_text("{not-json", encoding="utf-8")
    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(next_dir),
            "--out",
            str(next_dir / "next-probe-preview.json"),
        ],
        cwd=next_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "apply_next_probes should exit non-zero when required next-probes.json is unreadable.")
    assert_true("Traceback" not in proc.stderr, "apply_next_probes should not expose unreadable required inputs as a traceback.")
    preview = load_json(next_dir / "next-probe-preview.json")
    input_errors = preview.get("input_artifact_errors") if isinstance(preview.get("input_artifact_errors"), list) else []
    input_names = {item.get("name") for item in input_errors if isinstance(item, dict)}
    assert_true("next_probes" in input_names, "next-probe preview should name the unreadable next_probes input.")
    assert_true(preview.get("summary", {}).get("applied_count") == 0, "unreadable next-probe inputs must not apply recommendations.")

    write_json(
        next_dir / "next-probes.json",
        {
            "schema_version": 1,
            "summary": {"recommendation_count": 0},
            "recommendations": [],
        },
    )
    (next_dir / "defects.json").write_text("{not-json", encoding="utf-8")
    optional_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "apply_next_probes.py"),
            "--run-dir",
            str(next_dir),
            "--defects",
            str(next_dir / "defects.json"),
            "--out",
            str(next_dir / "next-probe-preview-optional.json"),
        ],
        cwd=next_dir,
        text=True,
        capture_output=True,
    )
    assert_true(optional_proc.returncode != 0, "apply_next_probes should exit non-zero when an existing optional defects artifact is unreadable.")
    assert_true("Traceback" not in optional_proc.stderr, "apply_next_probes should not expose unreadable optional inputs as a traceback.")
    optional_preview = load_json(next_dir / "next-probe-preview-optional.json")
    optional_names = {item.get("name") for item in optional_preview.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true("defects" in optional_names, "next-probe preview should name unreadable optional defects input.")


def run_environment_boundary_fixture(script_dir: Path, tmp_path: Path) -> None:
    env_dir = tmp_path / "environment-boundary"
    env_dir.mkdir(parents=True, exist_ok=True)
    (env_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (env_dir / "evidence" / "env-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-env",
                "source": "fixture",
                "text": "A real backtest pass must have an explicit runtime and data boundary.",
                "test_ids": ["T-env"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T-env",
                "requirement_ids": ["R-env"],
                "type": "api",
                "expected": "A current-run API response passes in a declared test environment.",
                "status": "Untested",
            }
        ],
    }
    ledger = {
        "schema_version": 2,
        "requirements": [
            {
                "id": "R-env",
                "source": "fixture",
                "text": matrix["requirements"][0]["text"],
                "test_ids": ["T-env"],
                "status": "Passed",
                "evidence_ids": ["E-api"],
            }
        ],
        "tests": [
            {
                "id": "T-env",
                "requirement_ids": ["R-env"],
                "type": "api",
                "expected": matrix["tests"][0]["expected"],
                "status": "Passed",
                "evidence_ids": ["E-api"],
            }
        ],
        "evidence": [
            {
                "id": "E-api",
                "type": "api_response",
                "url": "/api/v1/env",
                "body_path": "evidence/env-response.json",
                "current_run": True,
                "status_code": 200,
                "checked_json": {"ok": True},
                "assertions": ["HTTP status observed: 200", "JSON ok matched observed value true"],
                "proves": "The API response proves the declared environment fixture.",
            }
        ],
    }
    defects = {"summary": {"finding_count": 0, "severity_counts": {}}}
    write_json(env_dir / "test-matrix.json", matrix)
    write_json(env_dir / "evidence-ledger.json", ledger)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--matrix",
            str(env_dir / "test-matrix.json"),
            "--ledger",
            str(env_dir / "evidence-ledger.json"),
            "--summary",
            str(env_dir / "audit-summary.json"),
        ],
        cwd=env_dir,
    )
    write_json(env_dir / "defects.json", defects)

    def verdict_for(name: str, adapter_context: dict[str, Any] | None, extra_args: list[str] | None = None) -> dict[str, Any]:
        context_path = env_dir / f"{name}-adapter-context.json"
        if adapter_context is not None:
            write_json(context_path, adapter_context)
        cmd = [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(env_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(env_dir / "audit-summary.json"),
            "--defects",
            str(env_dir / "defects.json"),
            "--out",
            str(env_dir / f"{name}-verdict.json"),
            "--require-environment-boundary",
        ]
        if adapter_context is not None:
            cmd.extend(["--adapter-context", str(context_path)])
        if extra_args:
            cmd.extend(extra_args)
        run_cmd(cmd, cwd=env_dir)
        return load_json(env_dir / f"{name}-verdict.json")

    missing = verdict_for("missing", None)
    assert_true(missing.get("can_claim_pass") is False, "Required environment boundary should block pass when adapter-context.json is missing.")
    assert_true("missing_environment_boundary" in {reason.get("code") for reason in missing.get("reasons", [])}, "Missing adapter context should produce a specific reason code.")

    unconfirmed_context = {
        "environment_boundary": {
            "runtime_mode": "unconfirmed",
            "data_boundary_status": "must be stated before pass/fail",
        }
    }
    unconfirmed = verdict_for("unconfirmed", unconfirmed_context)
    unconfirmed_codes = {reason.get("code") for reason in unconfirmed.get("reasons", [])}
    assert_true({"environment_unconfirmed", "data_boundary_unconfirmed"}.issubset(unconfirmed_codes), "Unconfirmed runtime/data boundary should block pass.")

    partial_context = {
        "environment_boundary": {
            "runtime_mode": "local",
            "data_boundary_status": "must be stated before pass/fail",
        }
    }
    partial = verdict_for("partial", partial_context)
    assert_true("data_boundary_unconfirmed" in {reason.get("code") for reason in partial.get("reasons", [])}, "Runtime-only boundary should still require data boundary.")

    confirmed_context = {
        "environment_boundary": {
            "runtime_mode": "local",
            "data_boundary_status": "test database with local seed data; no production data",
        }
    }
    confirmed = verdict_for("confirmed", confirmed_context)
    assert_true(confirmed.get("can_claim_pass") is True, "Confirmed runtime and data boundary should allow a clean pass verdict.")
    assert_true(confirmed.get("gates", {}).get("environment_boundary_confirmed") is True, "Verdict gates should expose confirmed environment boundary.")

    cycle_dir = tmp_path / "environment-boundary-cycle"
    (cycle_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (cycle_dir / "evidence" / "env-cycle-response.json").write_text('{"ok":true}\n', encoding="utf-8")
    write_json(cycle_dir / "test-matrix.json", matrix)
    write_json(
        cycle_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(cycle_dir),
            "scenarios": [
                {
                    "id": "env",
                    "steps": [
                        {
                            "action": "api",
                            "id": "T-env-api",
                            "testIds": ["T-env"],
                            "requirementIds": ["R-env"],
                            "path": "/api/v1/env",
                            "evidenceType": "api_response",
                            "proves": "The API response proves the declared environment fixture.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        cycle_dir / "results.json",
        {
            "schemaVersion": 2,
            "status": "passed",
            "artifactDir": str(cycle_dir),
            "baseUrl": "http://127.0.0.1:9527",
            "scenarios": [
                {
                    "id": "env",
                    "status": "passed",
                    "steps": [
                        {
                            "scenarioId": "env",
                            "stepId": "T-env-api",
                            "testIds": ["T-env"],
                            "requirementIds": ["R-env"],
                            "action": "api",
                            "status": "passed",
                            "evidenceType": "api_response",
                            "url": "http://127.0.0.1:9527/api/v1/env",
                            "statusCode": 200,
                            "bodyPath": str(cycle_dir / "evidence" / "env-cycle-response.json"),
                            "checkedJson": {"ok": True},
                            "proves": "The API response proves the declared environment fixture.",
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    write_json(cycle_dir / "adapter-context.json", unconfirmed_context)
    run_cmd(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(cycle_dir),
            "--skip-probe",
            "--strict-runtime",
            "--skip-report",
            "--require-environment-boundary",
            "--runtime-mode",
            "local",
            "--data-boundary-status",
            "test database with local seed data; no production data",
        ],
        cwd=cycle_dir,
    )
    cycle_verdict = load_json(cycle_dir / "qa-verdict.json")
    cycle_context = load_json(cycle_dir / "adapter-context.json")
    assert_true(cycle_verdict.get("can_claim_pass") is True, "run_qa_cycle should pass through confirmed environment boundary.")
    assert_true(cycle_context.get("environment_boundary", {}).get("runtime_mode") == "local", "run_qa_cycle should write runtime mode to adapter-context.json.")
    assert_true("test database" in cycle_context.get("environment_boundary", {}).get("data_boundary_status", ""), "run_qa_cycle should write data boundary to adapter-context.json.")


def read_exact(connection: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = connection.recv(remaining)
        if not chunk:
            raise ConnectionError("Unexpected EOF while reading WebSocket frame.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_ws_text(connection: Any) -> str:
    first = read_exact(connection, 2)
    opcode = first[0] & 0x0F
    length = first[1] & 0x7F
    masked = bool(first[1] & 0x80)
    if opcode == 8:
        return ""
    if length == 126:
        length = int.from_bytes(read_exact(connection, 2), "big")
    elif length == 127:
        length = int.from_bytes(read_exact(connection, 8), "big")
    mask = read_exact(connection, 4) if masked else b""
    payload = read_exact(connection, length) if length else b""
    if masked:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return payload.decode("utf-8")


def send_ws_text(connection: Any, text: str) -> None:
    payload = text.encode("utf-8")
    header = bytearray([0x81])
    if len(payload) < 126:
        header.append(len(payload))
    elif len(payload) < 65536:
        header.append(126)
        header.extend(len(payload).to_bytes(2, "big"))
    else:
        header.append(127)
        header.extend(len(payload).to_bytes(8, "big"))
    connection.sendall(bytes(header) + payload)


def run_live_backtest_fixture(script_dir: Path, tmp_path: Path) -> None:
    live_dir = tmp_path / "live-backtest-cycle"
    live_dir.mkdir(parents=True, exist_ok=True)
    store_path = live_dir / "live-store.json"
    marker = "QA_LIVE_STREAM_OK"
    session_id = "session-live-1"
    turn_id = "turn-live-1"
    state: dict[str, Any] = {
        "sessions": {},
        "received_payloads": [],
        "store_path": store_path,
    }

    class LiveFixtureHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def send_json(self, status: int, value: dict[str, Any]) -> None:
            body = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if path == "/api/v1/agents/ask/ws":
                self.handle_websocket()
                return
            if path == "/api/v1/agents/catalog":
                self.send_json(200, {"agents": [{"id": "agent-live", "name": "Live QA Agent"}]})
                return
            if path.startswith("/api/v1/sessions/"):
                wanted_session = path.rsplit("/", 1)[-1]
                session = state["sessions"].get(wanted_session)
                if session:
                    self.send_json(200, session)
                else:
                    self.send_json(404, {"error": "session_not_found", "id": wanted_session})
                return
            self.send_json(200, {"ok": True})

        def handle_websocket(self) -> None:
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()).decode("ascii")
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()

            raw_request = read_ws_text(self.connection)
            try:
                request_payload = json.loads(raw_request)
            except json.JSONDecodeError:
                request_payload = {"raw": raw_request}
            state["received_payloads"].append(request_payload)
            question = str(request_payload.get("question") or "")
            returned_marker = marker if marker in question else f"{marker}_MISSING_FROM_INPUT"
            answer = f"fixture answer contains {returned_marker}"
            session = {
                "id": session_id,
                "session_id": session_id,
                "status": "completed",
                "messages": [
                    {"role": "user", "content": question},
                    {"role": "assistant", "content": answer},
                ],
                "turns": [{"id": turn_id, "status": "completed", "answer": answer}],
            }
            state["sessions"][session_id] = session
            store_path.write_text(
                json.dumps(
                    {
                        "session_id": session_id,
                        "turn_id": turn_id,
                        "status": "completed",
                        "message_count": 2,
                        "answer": answer,
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            send_ws_text(self.connection, json.dumps({"type": "answer_chunk", "delta": answer}, ensure_ascii=False))
            send_ws_text(
                self.connection,
                json.dumps(
                    {
                        "type": "answer_done",
                        "session_id": session_id,
                        "turn_id": turn_id,
                        "status": "completed",
                        "answer": answer,
                    },
                    ensure_ascii=False,
                ),
            )
            self.connection.sendall(b"\x88\x00")

    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = ThreadedHTTPServer(("127.0.0.1", 0), LiveFixtureHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    helper_path = live_dir / "check_persistence.py"
    helper_path.write_text(
        """#!/usr/bin/env python3
import argparse
import json
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--store", required=True)
parser.add_argument("--turn-id", required=True)
args = parser.parse_args()
data = json.load(open(args.store, encoding="utf-8"))
if data.get("turn_id") != args.turn_id:
    print(json.dumps({"status": "wrong_turn", "expected": args.turn_id, "actual": data.get("turn_id")}))
    sys.exit(2)
print(json.dumps(data, ensure_ascii=False))
""",
        encoding="utf-8",
    )
    try:
        write_json(
            live_dir / "adapter-context.json",
            {
                "schema_version": 1,
                "adapter": "live_backtest_fixture",
                "base_url": base_url,
                "environment_boundary": {
                    "runtime_mode": "local",
                    "data_boundary_status": "local deterministic fixture data; no production data",
                    "data_boundaries": ["Local in-memory fixture only."],
                },
                "services": [
                    {
                        "id": "live-fixture",
                        "role": "local HTTP/WebSocket fixture",
                        "default_url": base_url,
                        "port": server.server_port,
                        "port_open": True,
                    }
                ],
                "evidence_layers": [
                    {"id": "real_stream_completion", "strong_signal": "answer_done plus marker returned from the WebSocket fixture."},
                    {"id": "persistence_terminal_state", "strong_signal": "Read-only helper observes completed for the same turn_id."},
                ],
            },
        )
        write_json(
            live_dir / "test-matrix.json",
            {
                "schemaVersion": 2,
                "requirements": [
                    {
                        "id": "R-stream",
                        "source": "live fixture",
                        "text": "The live WebSocket stream emits answer_done and returns the current-run marker.",
                        "test_ids": ["T-stream"],
                        "status": "Untested",
                    },
                    {
                        "id": "R-session-api",
                        "source": "live fixture",
                        "text": "The same session is readable through the session detail API and contains the marker.",
                        "test_ids": ["T-session-api"],
                        "status": "Untested",
                    },
                    {
                        "id": "R-persistence",
                        "source": "live fixture",
                        "text": "The same turn reaches completed in the persistence helper.",
                        "test_ids": ["T-persistence"],
                        "status": "Untested",
                    },
                ],
                "tests": [
                    {
                        "id": "T-stream",
                        "requirement_ids": ["R-stream"],
                        "type": "stream",
                        "expected": "WebSocket returns the current-run marker and answer_done.",
                        "status": "Untested",
                    },
                    {
                        "id": "T-session-api",
                        "requirement_ids": ["R-session-api"],
                        "type": "api",
                        "expected": "Session detail API returns the current-run marker for the same session_id.",
                        "status": "Untested",
                    },
                    {
                        "id": "T-persistence",
                        "requirement_ids": ["R-persistence"],
                        "type": "persistence",
                        "expected": "Read-only persistence helper returns completed for the same turn_id.",
                        "status": "Untested",
                    },
                ],
            },
        )
        write_json(
            live_dir / "test-plan.json",
            {
                "schemaVersion": 2,
                "baseUrl": base_url,
                "artifactDir": str(live_dir),
                "headless": True,
                "qaMarker": marker,
                "scenarios": [
                    {
                        "id": "live-stream-api-persistence",
                        "continueOnFailure": True,
                        "steps": [
                            {
                                "action": "websocket",
                                "id": "live-stream-answer-done",
                                "testIds": ["T-stream"],
                                "requirementIds": ["R-stream"],
                                "path": "/api/v1/agents/ask/ws",
                                "send": {"question": {"template": "live fixture question {qa_marker}"}},
                                "expectJson": {"type": "answer_done"},
                                "expectMessageTextContains": {"var": "qa_marker"},
                                "finishOnJsonTypes": ["answer_done"],
                                "captureMessages": True,
                                "extractJson": {
                                    "session_id": {"path": "session_id", "matchJson": {"session_id": {"op": "exists"}}},
                                    "turn_id": {"path": "turn_id", "from": "last"},
                                },
                                "evidenceType": "websocket",
                                "proves": "The live stream emits answer_done and returns the current-run marker.",
                            },
                            {
                                "action": "api",
                                "id": "live-session-detail",
                                "testIds": ["T-session-api"],
                                "requirementIds": ["R-session-api"],
                                "method": "GET",
                                "path": {"var": "session_id", "prefix": "/api/v1/sessions/"},
                                "expectStatus": 200,
                                "expectResponseTextContains": {"var": "qa_marker"},
                                "expectJson": {
                                    "id": {"var": "session_id"},
                                    "status": "completed",
                                    "messages[1].content": {"op": "contains", "value": {"var": "qa_marker"}},
                                },
                                "captureBody": True,
                                "evidenceType": "api_response",
                                "proves": "The same session is readable through the API and contains the current-run marker.",
                            },
                            {
                                "action": "command",
                                "id": "live-persistence-helper",
                                "testIds": ["T-persistence"],
                                "requirementIds": ["R-persistence"],
                                "command": [
                                    sys.executable,
                                    str(helper_path),
                                    "--store",
                                    str(store_path),
                                    "--turn-id",
                                    {"var": "turn_id"},
                                ],
                                "expectExitCode": 0,
                                "expectStdoutContains": "completed",
                                "expectStdoutJson": {
                                    "turn_id": {"var": "turn_id"},
                                    "status": "completed",
                                    "message_count": {"op": "gte", "value": 2},
                                    "answer": {"op": "contains", "value": {"var": "qa_marker"}},
                                },
                                "extractStdoutJson": {"session_id": "session_id", "turn_id_from_store": "turn_id"},
                                "captureStdout": True,
                                "captureStderr": True,
                                "evidenceType": "command",
                                "proves": "The read-only helper verifies the same turn reached completed persistence state.",
                            },
                        ],
                    }
                ],
            },
        )
        run_cmd(
            [
                sys.executable,
                str(script_dir / "run_qa_cycle.py"),
                "--run-dir",
                str(live_dir),
                "--strict-runtime",
                "--require-environment-boundary",
                "--skip-report",
            ],
            cwd=live_dir,
        )
        verdict = load_json(live_dir / "qa-verdict.json")
        ledger = load_json(live_dir / "evidence-ledger.json")
        audit = load_json(live_dir / "audit-summary.json")
        evidence_by_type = {item.get("type"): item for item in ledger.get("evidence", [])}
        assert_true(verdict.get("can_claim_pass") is True, "Live stream/API/persistence fixture should produce a pass verdict.")
        assert_true(audit.get("passed") is True, "Live fixture evidence audit should pass.")
        assert_true(evidence_by_type.get("websocket", {}).get("message_text_contains_matched") == marker, "Live stream evidence should preserve returned marker signal.")
        assert_true(evidence_by_type.get("api_response", {}).get("response_text_contains_matched") == marker, "Live API evidence should preserve returned marker signal.")
        assert_true(evidence_by_type.get("command", {}).get("checked_stdout_json", {}).get("status") == "completed", "Live persistence evidence should preserve completed status.")
        assert_true((store_path.exists() and marker in store_path.read_text(encoding="utf-8")), "Live fixture should write persisted marker state.")
    finally:
        server.shutdown()
        server.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run isolated self-regression checks for automated-qa-test helper scripts.")
    parser.add_argument("--keep", action="store_true", help="Keep the temporary regression directory.")
    parser.add_argument("--with-browser", action="store_true", help="Also launch Playwright/Chrome against a local hit-test fixture.")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="automated-qa-test-regression-", dir="/tmp") as tmp:
        tmp_path = Path(tmp)
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
        business_requirement_path = tmp_path / "business-requirement.md"
        business_requirement_path.write_text(BUSINESS_REQUIREMENT, encoding="utf-8")
        browser_hit_test_checked = False
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
        adapter_probe_input_errors_checked = False
        preflight_input_errors_checked = False
        preflight_missing_required_service_checked = False
        service_runtime_input_errors_checked = False
        discover_project_context_input_errors_checked = False
        preflight_project_root_input_errors_checked = False
        plan_validation_input_errors_checked = False
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
        semantic_report_checked = False
        semantic_artifact_refresh_checked = False
        semantic_report_guard_checked = False

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
        if args.with_browser:
            run_browser_hit_test_fixture(script_dir, tmp_path)
            browser_hit_test_checked = True
            skipped_step_recording_checked = True
            run_probe_redaction_fixture(script_dir, tmp_path)
            probe_redaction_checked = True
            run_live_backtest_fixture(script_dir, tmp_path)
            live_backtest_checked = True
        run_evidence_layer_gate_fixture(script_dir, tmp_path)
        evidence_layer_gate_checked = True
        run_evidence_freshness_fixture(script_dir, tmp_path)
        evidence_freshness_checked = True
        run_screenshot_integrity_fixture(script_dir, tmp_path)
        screenshot_integrity_checked = True
        run_text_artifact_assertion_fixture(script_dir, tmp_path)
        text_artifact_assertions_checked = True
        run_json_artifact_assertion_fixture(script_dir, tmp_path)
        json_artifact_assertions_checked = True
        run_api_body_defect_evidence_fixture(script_dir, tmp_path)
        api_body_defect_evidence_checked = True
        run_extraction_artifact_assertion_fixture(script_dir, tmp_path)
        extraction_artifact_assertions_checked = True
        run_response_header_consistency_fixture(script_dir, tmp_path)
        response_header_consistency_checked = True
        run_strategy_coverage_fixture(script_dir, tmp_path)
        strategy_coverage_checked = True
        run_current_run_required_fixture(script_dir, tmp_path)
        current_run_required_checked = True
        run_secret_like_ledger_audit_fixture(script_dir, tmp_path)
        secret_like_ledger_audit_checked = True
        run_evidence_disposition_gate_fixture(script_dir, tmp_path)
        evidence_disposition_gate_checked = True
        run_evidence_lineage_fixture(script_dir, tmp_path)
        evidence_lineage_checked = True
        run_runner_result_binding_fixture(script_dir, tmp_path)
        runner_result_binding_checked = True
        run_requirement_status_consistency_fixture(script_dir, tmp_path)
        requirement_status_consistency_checked = True
        run_verdict_artifact_binding_fixture(script_dir, tmp_path)
        verdict_artifact_binding_checked = True
        run_report_input_error_fixture(script_dir, tmp_path)
        report_input_errors_checked = True
        run_next_probe_input_error_fixture(script_dir, tmp_path)
        next_probe_input_errors_checked = True
        run_environment_boundary_fixture(script_dir, tmp_path)
        environment_boundary_checked = True
        run_agent_next_action_fixture(script_dir, tmp_path)
        agent_next_action_checked = True
        agent_loop_control_checked = True
        run_agent_preview_hash_binding_fixture(script_dir, tmp_path)
        agent_preview_hash_binding_checked = True
        run_agent_pass_skips_preview_fixture(script_dir, tmp_path)
        agent_pass_skips_preview_checked = True
        run_agent_product_defect_handoff_fixture(script_dir, tmp_path)
        agent_product_defect_handoff_checked = True
        run_agent_initialization_failure_fixture(script_dir, tmp_path)
        agent_initialization_failure_checked = True
        run_scaffold_input_error_fixture(script_dir, tmp_path)
        scaffold_input_errors_checked = True
        run_init_input_error_fixture(script_dir, tmp_path)
        init_input_errors_checked = True
        run_init_adapter_context_input_error_fixture(script_dir, tmp_path)
        init_adapter_context_input_errors_checked = True
        run_agent_snapshot_shape_fixture(script_dir, tmp_path)
        agent_snapshot_shape_checked = True
        run_cycle_terminal_cleanup_fixture(script_dir, tmp_path)
        cycle_terminal_cleanup_checked = True
        run_required_artifact_unreadable_fixture(script_dir, tmp_path)
        required_artifact_unreadable_checked = True
        run_adapter_context_unreadable_fixture(script_dir, tmp_path)
        adapter_context_unreadable_checked = True
        run_skip_probe_unreadable_results_fixture(script_dir, tmp_path)
        skip_probe_unreadable_results_checked = True
        run_preflight_blocker_handoff_fixture(script_dir, tmp_path)
        preflight_handoff_checked = True
        run_agent_service_start_next_action_fixture(script_dir, tmp_path)
        service_start_next_action_checked = True
        run_agent_authorized_service_start_fixture(script_dir, tmp_path)
        authorized_service_start_checked = True
        run_agent_repeated_next_probe_stall_fixture(script_dir, tmp_path)
        agent_repeated_next_probe_stall_checked = True
        run_agent_runtime_autorecovery_fixture(script_dir, tmp_path)
        agent_runtime_autorecovery_checked = True
        run_api_next_probe_path_reuse_fixture(script_dir, tmp_path)
        api_next_probe_path_reuse_checked = True
        run_next_probe_scenario_step_binding_fixture(script_dir, tmp_path)
        next_probe_scenario_step_binding_checked = True
        run_next_probe_lineage_gate_fixture(script_dir, tmp_path)
        next_probe_lineage_gate_checked = True
        run_next_probe_generated_from_binding_fixture(script_dir, tmp_path)
        next_probe_generated_from_binding_checked = True
        run_next_probe_missing_generated_from_fixture(script_dir, tmp_path)
        next_probe_missing_generated_from_checked = True
        run_next_probe_generated_from_hash_fixture(script_dir, tmp_path)
        next_probe_generated_from_hash_checked = True
        run_next_probe_embedded_input_error_fixture(script_dir, tmp_path)
        next_probe_embedded_input_errors_checked = True
        run_runtime_failed_response_auth_guard_fixture(script_dir, tmp_path)
        runtime_failed_response_auth_guard_checked = True
        run_planning_blocker_handoff_fixture(script_dir, tmp_path)
        planning_handoff_checked = True
        run_requirement_coverage_input_error_fixture(script_dir, tmp_path)
        requirement_coverage_input_errors_checked = True
        run_adapter_probe_input_error_fixture(script_dir, tmp_path)
        adapter_probe_input_errors_checked = True
        run_preflight_input_error_fixture(script_dir, tmp_path)
        preflight_input_errors_checked = True
        run_preflight_missing_required_service_fixture(script_dir, tmp_path)
        preflight_missing_required_service_checked = True
        run_service_runtime_input_error_fixture(script_dir, tmp_path)
        service_runtime_input_errors_checked = True
        run_discover_project_context_input_error_fixture(script_dir, tmp_path)
        discover_project_context_input_errors_checked = True
        run_preflight_project_root_input_error_fixture(script_dir, tmp_path)
        preflight_project_root_input_errors_checked = True
        run_plan_validation_input_error_fixture(script_dir, tmp_path)
        plan_validation_input_errors_checked = True
        run_storage_state_validation_fixture(script_dir, tmp_path)
        storage_state_validation_checked = True
        auth_material_validation_checked = True
        run_audit_input_error_fixture(script_dir, tmp_path)
        audit_input_errors_checked = True
        run_defect_input_error_fixture(script_dir, tmp_path)
        defect_input_errors_checked = True
        run_next_probe_generation_input_error_fixture(script_dir, tmp_path)
        next_probe_generation_input_errors_checked = True
        run_ledger_input_error_fixture(script_dir, tmp_path)
        ledger_input_errors_checked = True
        run_audit_failure_handoff_fixture(script_dir, tmp_path)
        audit_failure_handoff_checked = True
        run_helper_failure_handoff_fixture(script_dir, tmp_path)
        helper_failure_handoff_checked = True
        run_helper_output_unreadable_fixture(script_dir, tmp_path)
        helper_output_unreadable_checked = True

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

        if args.keep:
            kept = Path(tempfile.mkdtemp(prefix="automated-qa-test-regression-kept-", dir="/tmp"))
            for item in tmp_path.iterdir():
                target = kept / item.name
                if item.is_dir():
                    subprocess.run(["cp", "-R", str(item), str(target)], check=True)
                else:
                    target.write_bytes(item.read_bytes())
            print(kept)
        else:
            print(json.dumps({
                "status": "passed",
                "mapped_executable_requirement_count": plan_audit.get("mapped_executable_requirement_count"),
                "agent_loop_stop_reason": agent_summary.get("stop_reason"),
                "agent_loop_next_action": agent_next_action.get("action"),
                "browser_hit_test_checked": browser_hit_test_checked,
                "skipped_step_recording_checked": skipped_step_recording_checked,
                "probe_redaction_checked": probe_redaction_checked,
                "live_backtest_checked": live_backtest_checked,
                "evidence_layer_gate_checked": evidence_layer_gate_checked,
                "evidence_freshness_checked": evidence_freshness_checked,
                "screenshot_integrity_checked": screenshot_integrity_checked,
                "text_artifact_assertions_checked": text_artifact_assertions_checked,
                "json_artifact_assertions_checked": json_artifact_assertions_checked,
                "api_body_defect_evidence_checked": api_body_defect_evidence_checked,
                "extraction_artifact_assertions_checked": extraction_artifact_assertions_checked,
                "response_header_consistency_checked": response_header_consistency_checked,
                "strategy_coverage_checked": strategy_coverage_checked,
                "current_run_required_checked": current_run_required_checked,
                "secret_like_ledger_audit_checked": secret_like_ledger_audit_checked,
                "evidence_disposition_gate_checked": evidence_disposition_gate_checked,
                "evidence_lineage_checked": evidence_lineage_checked,
                "runner_result_binding_checked": runner_result_binding_checked,
                "requirement_status_consistency_checked": requirement_status_consistency_checked,
                "verdict_artifact_binding_checked": verdict_artifact_binding_checked,
                "report_input_errors_checked": report_input_errors_checked,
                "next_probe_input_errors_checked": next_probe_input_errors_checked,
                "environment_boundary_checked": environment_boundary_checked,
                "agent_next_action_checked": agent_next_action_checked,
                "agent_loop_control_checked": agent_loop_control_checked,
                "agent_preview_hash_binding_checked": agent_preview_hash_binding_checked,
                "agent_pass_skips_preview_checked": agent_pass_skips_preview_checked,
                "agent_product_defect_handoff_checked": agent_product_defect_handoff_checked,
                "agent_initialization_failure_checked": agent_initialization_failure_checked,
                "scaffold_input_errors_checked": scaffold_input_errors_checked,
                "init_input_errors_checked": init_input_errors_checked,
                "init_adapter_context_input_errors_checked": init_adapter_context_input_errors_checked,
                "agent_snapshot_shape_checked": agent_snapshot_shape_checked,
                "cycle_terminal_cleanup_checked": cycle_terminal_cleanup_checked,
                "required_artifact_unreadable_checked": required_artifact_unreadable_checked,
                "adapter_context_unreadable_checked": adapter_context_unreadable_checked,
                "skip_probe_unreadable_results_checked": skip_probe_unreadable_results_checked,
                "preflight_handoff_checked": preflight_handoff_checked,
                "service_start_next_action_checked": service_start_next_action_checked,
                "authorized_service_start_checked": authorized_service_start_checked,
                "agent_repeated_next_probe_stall_checked": agent_repeated_next_probe_stall_checked,
                "agent_runtime_autorecovery_checked": agent_runtime_autorecovery_checked,
                "api_next_probe_path_reuse_checked": api_next_probe_path_reuse_checked,
                "next_probe_scenario_step_binding_checked": next_probe_scenario_step_binding_checked,
                "next_probe_lineage_gate_checked": next_probe_lineage_gate_checked,
                "next_probe_generated_from_binding_checked": next_probe_generated_from_binding_checked,
                "next_probe_missing_generated_from_checked": next_probe_missing_generated_from_checked,
                "next_probe_generated_from_hash_checked": next_probe_generated_from_hash_checked,
                "next_probe_embedded_input_errors_checked": next_probe_embedded_input_errors_checked,
                "runtime_failed_response_auth_guard_checked": runtime_failed_response_auth_guard_checked,
                "planning_handoff_checked": planning_handoff_checked,
                "requirement_coverage_input_errors_checked": requirement_coverage_input_errors_checked,
                "adapter_probe_input_errors_checked": adapter_probe_input_errors_checked,
                "preflight_input_errors_checked": preflight_input_errors_checked,
                "preflight_missing_required_service_checked": preflight_missing_required_service_checked,
                "service_runtime_input_errors_checked": service_runtime_input_errors_checked,
                "discover_project_context_input_errors_checked": discover_project_context_input_errors_checked,
                "preflight_project_root_input_errors_checked": preflight_project_root_input_errors_checked,
                "plan_validation_input_errors_checked": plan_validation_input_errors_checked,
                "storage_state_validation_checked": storage_state_validation_checked,
                "auth_material_validation_checked": auth_material_validation_checked,
                "audit_input_errors_checked": audit_input_errors_checked,
                "defect_input_errors_checked": defect_input_errors_checked,
                "next_probe_generation_input_errors_checked": next_probe_generation_input_errors_checked,
                "ledger_input_errors_checked": ledger_input_errors_checked,
                "audit_failure_handoff_checked": audit_failure_handoff_checked,
                "helper_failure_handoff_checked": helper_failure_handoff_checked,
                "helper_output_unreadable_checked": helper_output_unreadable_checked,
                "business_model_checked": business_model_checked,
                "oracle_model_checked": oracle_model_checked,
                "qa_metrics_checked": qa_metrics_checked,
                "semantic_report_checked": semantic_report_checked,
                "semantic_artifact_refresh_checked": semantic_artifact_refresh_checked,
                "semantic_report_guard_checked": semantic_report_guard_checked,
                "validate_stdout": validate_proc.stdout.strip(),
            }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
