"""Agent、恢复与后续探针回归夹具。"""

import contextlib
import http.server
import io
import json
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any

from .agent_routes import run_agent_next_action_fixture
from .support import (
    assert_route_model_consistent,
    assert_true,
    file_sha256,
    last_path,
    load_json,
    load_qa_agent_loop_module,
    run_cmd,
    unused_tcp_port,
    write_json,
    write_valid_skip_probe_plan,
)

__all__ = ["run_agent_next_action_fixture"]


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
    (cleanup_dir / "qa-cycle-error.json" / "user-data.txt").write_text("preserve me\n", encoding="utf-8")
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
    assert_true(proc.returncode != 0, "cycle with a directory-shaped terminal output should fail before processing the missing matrix.")
    assert_true(not (cleanup_dir / "qa-verdict.json").exists(), "run_qa_cycle should remove the stale verdict but not synthesize a handoff after an unsafe output shape blocks the cycle.")
    assert_true(not (cleanup_dir / "report.md").exists(), "run_qa_cycle should remove a stale report before a new cycle can fail early.")
    assert_true((cleanup_dir / "qa-cycle-error.json").is_dir(), "run_qa_cycle must preserve a directory-shaped cycle-error target.")
    assert_true((cleanup_dir / "qa-cycle-error.json" / "user-data.txt").read_text(encoding="utf-8") == "preserve me\n", "directory-shaped output contents must remain untouched.")
    summary = load_json(cleanup_dir / "qa-run-summary.json")
    cleared = {item.get("name"): item for item in summary.get("cleared_stale_outputs", [])}
    cleared_names = set(cleared)
    blocked = {item.get("name"): item for item in summary.get("blocked_output_paths", [])}
    assert_true(summary.get("status") == "blocked", "unsafe terminal output shapes should write a blocked qa-run-summary.json.")
    assert_true({"verdict", "report"}.issubset(cleared_names), "cycle summary should list stale terminal files that were safely unlinked.")
    assert_true("cycle_error" not in cleared_names, "directory-shaped terminal outputs must never be reported as cleared.")
    assert_true(blocked.get("cycle_error", {}).get("reason") == "output_path_is_directory", "cycle summary should record the preserved directory blocker.")


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
    (start_dir / "requirement.md").write_text("- The fixture API health endpoint is reachable after service startup.\n", encoding="utf-8")
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
    (run_dir / "requirement.md").write_text("- The runtime fixture page reaches the Ready state.\n", encoding="utf-8")
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
            "artifactDir": str(coverage_dir),
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
