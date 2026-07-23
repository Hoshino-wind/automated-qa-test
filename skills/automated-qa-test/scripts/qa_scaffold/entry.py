"""脚手架产物编排入口。"""

from pathlib import Path
from typing import Any

from .intents import (
    has_explicit_runtime_acceptance,
    point_is_code_pr_file_context,
    point_is_code_pr_validation_context,
)
from .modeling import (
    append_code_pr_command_tests,
    build_business_model,
    build_closeout_candidates,
    build_oracle_model,
    build_qa_metrics,
    render_charter,
    scaffold_code_pr,
)
from .rules import (
    ScaffoldCursor,
    apply_advanced_point_rules,
    apply_authentication_point_rules,
    apply_foundation_point_rules,
    apply_integrity_point_rules,
    apply_interaction_point_rules,
    apply_resilience_point_rules,
    apply_transport_point_rules,
    build_scaffold_point,
    finalize_scaffold_point,
)
from .support import (
    extract_blocked_validation_commands,
    is_code_pr_requirement,
    split_requirement_points,
)


def scaffold(requirement: str, base_url: str, artifact_dir: Path, entry_path: str | None = None, persistence_command: str | None = None, allow_live_stream: bool = False, allow_mutating_api: bool = False) -> dict[str, Any]:
    code_pr_requirement = is_code_pr_requirement(requirement)
    hybrid_code_pr_runtime = code_pr_requirement and has_explicit_runtime_acceptance(requirement)
    if code_pr_requirement and not hybrid_code_pr_runtime:
        return scaffold_code_pr(requirement, base_url, artifact_dir)

    points = split_requirement_points(requirement)
    hybrid_code_pr_points: list[dict[str, Any]] = []
    if hybrid_code_pr_runtime:
        runtime_points: list[dict[str, Any]] = []
        for point in points:
            text = point["text"]
            if point_is_code_pr_file_context(text) or point_is_code_pr_validation_context(text):
                hybrid_code_pr_points.append(point)
            else:
                runtime_points.append(point)
        points = runtime_points
    requirements: list[dict[str, Any]] = []
    tests: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    gaps: list[str] = []
    hybrid_code_paths: list[str] = []
    hybrid_validation_commands: list[str] = []
    hybrid_blocked_validation_commands: list[str] = []
    test_index = 1
    default_entry_path = entry_path
    cursor = ScaffoldCursor(last_ui_context=entry_path)

    for req_index, point in enumerate(points, 1):
        context = build_scaffold_point(
            req_index,
            point,
            cursor=cursor,
            default_entry_path=default_entry_path,
        )
        test_index = apply_foundation_point_rules(
            point=context.point,
            req_id=context.req_id,
            text=context.text,
            tags=context.tags,
            tests=tests,
            req_tests=context.req_tests,
            gaps=gaps,
            test_index=test_index,
            shell_commands=context.shell_commands,
            page_path=context.page_path,
            paths=context.paths,
            method_path=context.method_path,
        )
        test_index = apply_resilience_point_rules(
            point=context.point,
            req_id=context.req_id,
            text=context.text,
            tags=context.tags,
            tests=tests,
            req_tests=context.req_tests,
            gaps=gaps,
            test_index=test_index,
            method_path=context.method_path,
            paths=context.paths,
            page_path=context.page_path,
            button_name=context.button_name,
            negative_request_intent=context.negative_request_intent,
            response_method=context.response_method,
            steps=steps,
        )
        test_index = apply_authentication_point_rules(
            point=context.point,
            req_id=context.req_id,
            text=context.text,
            tags=context.tags,
            tests=tests,
            req_tests=context.req_tests,
            gaps=gaps,
            test_index=test_index,
        )
        test_index = apply_integrity_point_rules(
            point=context.point,
            req_id=context.req_id,
            text=context.text,
            tags=context.tags,
            tests=tests,
            req_tests=context.req_tests,
            gaps=gaps,
            test_index=test_index,
        )
        test_index = apply_advanced_point_rules(
            point=context.point,
            req_id=context.req_id,
            text=context.text,
            tags=context.tags,
            tests=tests,
            req_tests=context.req_tests,
            gaps=gaps,
            test_index=test_index,
        )
        test_index = apply_interaction_point_rules(
            context=context,
            cursor=cursor,
            tests=tests,
            steps=steps,
            gaps=gaps,
            test_index=test_index,
            allow_mutating_api=allow_mutating_api,
        )
        test_index = apply_transport_point_rules(
            context=context,
            tests=tests,
            steps=steps,
            gaps=gaps,
            test_index=test_index,
            allow_live_stream=allow_live_stream,
            allow_mutating_api=allow_mutating_api,
            persistence_command=persistence_command,
        )
        finalize_scaffold_point(context, cursor, requirements)

    if hybrid_code_pr_runtime:
        hybrid_blocked_validation_commands = extract_blocked_validation_commands(requirement)
        gaps.extend(
            f"PR validation command `{command}` is blocked because it appears mutating or unsafe; provide a non-mutating check or explicit safe-environment authorization."
            for command in hybrid_blocked_validation_commands
        )
        _, test_index, hybrid_code_paths, hybrid_validation_commands = append_code_pr_command_tests(
            requirement,
            requirements,
            tests,
            steps,
            next_req_index=len(requirements) + 1,
            test_index=test_index,
            source_points=hybrid_code_pr_points,
        )

    plan = {
        "schemaVersion": 2,
        "baseUrl": base_url,
        "artifactDir": str(artifact_dir),
        "metadata": {
            "businessModel": "business-model.json",
            "oracleModel": "oracle-model.json",
            "qaMetrics": "qa-metrics.json",
            "closeoutCandidates": "closeout-candidates.json",
            **({"scaffoldMode": "hybrid_code_pr_runtime", "codeFilePaths": hybrid_code_paths} if hybrid_code_pr_runtime else {}),
        },
        "viewport": {"width": 1440, "height": 980},
        "headless": True,
        "captureWebSockets": True,
        "scenarios": [
            {
                "id": "scaffolded-requirement-probes",
                "title": "Scaffolded requirement probes",
                "continueOnFailure": True,
                "steps": steps,
            }
        ],
    }
    matrix = {
        "schemaVersion": 2,
        "requirements": requirements,
        "tests": tests,
    }
    business_model = build_business_model(requirement, requirements, tests, gaps)
    oracle_model = build_oracle_model(requirements, tests)
    qa_metrics = build_qa_metrics(requirements, tests, steps, gaps, business_model, oracle_model)
    closeout_candidates = build_closeout_candidates(business_model, oracle_model, gaps)
    charter = render_charter(requirement, requirements, tests, gaps, business_model, oracle_model)
    summary = {
        "schema_version": 1,
        "requirement_count": len(requirements),
        "test_count": len(tests),
        "planned_step_count": len(steps),
        "clickability_probe_count": len([step for step in steps if step.get("action") == "expectClickable"]),
        "blocked_clickability_test_count": len([test for test in tests if test.get("type") == "interaction" and test.get("status") == "Blocked"]),
        "click_response_probe_count": len([step for step in steps if step.get("action") == "clickAndWaitForResponse"]),
        "blocked_click_response_test_count": len([test for test in tests if test.get("type") == "ui_to_api" and test.get("status") == "Blocked"]),
        "followup_api_probe_count": len([step for step in steps if step.get("action") in {"api", "pollApi"} and step.get("pathTemplate")]),
        "poll_api_probe_count": len([step for step in steps if step.get("action") == "pollApi"]),
        "cleanup_api_probe_count": len([step for step in steps if step.get("action") == "cleanupApi"]),
        "blocked_followup_api_test_count": len([test for test in tests if test.get("type") == "api_followup" and test.get("status") == "Blocked"]),
        "blocked_cleanup_test_count": len([test for test in tests if test.get("type") == "cleanup" and test.get("status") == "Blocked"]),
        "blocked_test_count": len([test for test in tests if test.get("status") == "Blocked"]),
        "business_model": {
            "actor_count": len(business_model.get("actors", [])),
            "entity_count": len(business_model.get("entities", [])),
            "workflow_count": len(business_model.get("workflows", [])),
            "business_rule_count": len(business_model.get("business_rules", [])),
        },
        "oracle_model": oracle_model.get("summary", {}),
        "qa_metrics": "qa-metrics.json",
        "closeout_candidates": "closeout-candidates.json",
        "coverage_gaps": gaps,
        "input_artifact_errors": [],
        **({
            "scaffold_mode": "hybrid_code_pr_runtime",
            "code_file_path_count": len(hybrid_code_paths),
            "validation_command_count": len(hybrid_validation_commands),
            "validation_commands": hybrid_validation_commands,
            "blocked_validation_command_count": len(hybrid_blocked_validation_commands),
            "blocked_validation_commands": hybrid_blocked_validation_commands,
        } if hybrid_code_pr_runtime else {}),
    }
    return {
        "charter": charter,
        "matrix": matrix,
        "plan": plan,
        "summary": summary,
        "business_model": business_model,
        "oracle_model": oracle_model,
        "qa_metrics": qa_metrics,
        "closeout_candidates": closeout_candidates,
    }

def input_error_artifacts(base_url: str, artifact_dir: Path, input_errors: list[dict[str, str]]) -> dict[str, Any]:
    requirement = "Requirement source input is unreadable; QA planning is blocked until the input artifact is fixed."
    requirement_item = {
        "id": "R-input-1",
        "source": "requirement input",
        "text": requirement,
        "risk": "input_artifacts",
        "test_ids": ["T-input-1"],
        "status": "Blocked",
        "notes": "Generated because requirement input could not be read.",
    }
    test_item = {
        "id": "T-input-1",
        "requirement_ids": ["R-input-1"],
        "type": "input",
        "expected": "Requirement source file can be read before QA planning starts.",
        "status": "Blocked",
        "steps": ["Fix unreadable requirement input artifacts before generating probes."],
        "required_evidence": ["readable requirement source"],
        "notes": "No product probes were synthesized from unreadable requirement input.",
    }
    gaps = [f"{item['name']} input is unreadable: {item['error']} ({item['path']})" for item in input_errors]
    matrix = {
        "schemaVersion": 2,
        "requirements": [requirement_item],
        "tests": [test_item],
    }
    plan = {
        "schemaVersion": 2,
        "baseUrl": base_url,
        "artifactDir": str(artifact_dir),
        "metadata": {
            "businessModel": "business-model.json",
            "oracleModel": "oracle-model.json",
            "qaMetrics": "qa-metrics.json",
            "closeoutCandidates": "closeout-candidates.json",
        },
        "viewport": {"width": 1440, "height": 980},
        "headless": True,
        "captureWebSockets": True,
        "scenarios": [
            {
                "id": "scaffolded-requirement-probes",
                "title": "Scaffolded requirement probes",
                "continueOnFailure": True,
                "steps": [],
            }
        ],
    }
    summary = {
        "schema_version": 1,
        "status": "blocked",
        "requirement_count": 1,
        "test_count": 1,
        "planned_step_count": 0,
        "clickability_probe_count": 0,
        "blocked_clickability_test_count": 0,
        "click_response_probe_count": 0,
        "blocked_click_response_test_count": 0,
        "followup_api_probe_count": 0,
        "poll_api_probe_count": 0,
        "cleanup_api_probe_count": 0,
        "blocked_followup_api_test_count": 0,
        "blocked_cleanup_test_count": 0,
        "blocked_test_count": 1,
        "coverage_gaps": gaps,
        "input_artifact_errors": input_errors,
    }
    business_model = build_business_model(requirement, [requirement_item], [test_item], gaps)
    oracle_model = build_oracle_model([requirement_item], [test_item])
    qa_metrics = build_qa_metrics([requirement_item], [test_item], [], gaps, business_model, oracle_model)
    closeout_candidates = build_closeout_candidates(business_model, oracle_model, gaps)
    summary["business_model"] = {
        "actor_count": len(business_model.get("actors", [])),
        "entity_count": len(business_model.get("entities", [])),
        "workflow_count": len(business_model.get("workflows", [])),
        "business_rule_count": len(business_model.get("business_rules", [])),
    }
    summary["oracle_model"] = oracle_model.get("summary", {})
    summary["qa_metrics"] = "qa-metrics.json"
    summary["closeout_candidates"] = "closeout-candidates.json"
    return {
        "charter": render_charter(requirement, [requirement_item], [test_item], gaps, business_model, oracle_model),
        "matrix": matrix,
        "plan": plan,
        "summary": summary,
        "business_model": business_model,
        "oracle_model": oracle_model,
        "qa_metrics": qa_metrics,
        "closeout_candidates": closeout_candidates,
    }
