#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path
from typing import Any

from qa_common import atomic_write_json
from qa_core.contracts.schema import validate_artifact_schema

ALLOWED_STATUSES = {"Passed", "Failed", "Blocked", "Untested", "Inconclusive"}


def try_load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, "missing"
    if path.is_dir():
        return None, "path_is_directory"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, f"invalid_json: {exc.msg}"
    except OSError as exc:
        return None, f"read_error: {exc}"
    if not isinstance(value, dict):
        return None, "json_root_not_object"
    return value, None


def load_json(path: Path) -> dict[str, Any]:
    value, load_error = try_load_json(path)
    if load_error:
        raise SystemExit(f"Invalid JSON input {path}: {load_error}")
    assert value is not None
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write_json(path, value)


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def relpath(value: str | None, base_dir: Path) -> str | None:
    if not value:
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        return value
    try:
        return str(path.resolve().relative_to(base_dir.resolve()))
    except ValueError:
        return str(path)


def safe_observed_url(value: str | None) -> str | None:
    if not value:
        return None
    return re.sub(
        r"([?&](?:access_token|auth_token|token|session|cookie|key)=)[^&\s]+",
        r"\1",
        str(value),
        flags=re.IGNORECASE,
    )


def collect_steps(results: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for scenario in as_list(results.get("scenarios")):
        for step in as_list(scenario.get("steps")):
            merged = dict(step)
            merged.setdefault("scenarioId", scenario.get("id", ""))
            steps.append(merged)
    return steps


def infer_evidence_type(step: dict[str, Any]) -> str:
    if has_text(step.get("evidenceType")):
        return step["evidenceType"]
    action = step.get("action")
    if action == "screenshot" or step.get("screenshot"):
        return "screenshot"
    if action == "cleanupApi":
        return "cleanup"
    if action in {"api", "pollApi"}:
        return "api_response"
    if action == "websocket":
        return "websocket"
    if action == "sse":
        return "sse"
    if action == "command":
        return "command"
    if action == "clickAndWaitForResponse":
        return "ui_to_api"
    if action == "expectClickable":
        return "ui_interaction"
    if action in {"expectText", "expectAnyText", "expectVisible", "expectHidden", "expectLocatorCount", "expectUrlContains", "dismissIfPresent"}:
        return "ui_assertion"
    return "probe_step"


def evidence_locator(step: dict[str, Any], base_dir: Path) -> dict[str, Any]:
    for key in ("screenshot", "bodyPath", "requestBodyPath", "messagesPath", "stdoutPath", "stderrPath"):
        value = relpath(step.get(key), base_dir)
        if value:
            return {"path": value}
    if has_text(step.get("url")):
        return {"url": step["url"]}
    if step.get("exitCode") is not None:
        return {"value": f"exit_code={step.get('exitCode')}"}
    return {"value": f"{step.get('action', 'probe')}:{step.get('status', 'unknown')}"}


def evidence_assertions(step: dict[str, Any]) -> list[str]:
    assertions: list[str] = []
    if step.get("statusCode") is not None:
        assertions.append(f"HTTP status observed: {step.get('statusCode')}")
    if step.get("requestBodyCaptured") is not None:
        assertions.append(f"Request body captured: {step.get('requestBodyCaptured')}")
    if step.get("requestBodyPreview"):
        assertions.append(f"Request body preview observed: {json.dumps(step.get('requestBodyPreview'), ensure_ascii=False)}")
    if step.get("bodyPreview"):
        assertions.append(f"Response body preview observed: {json.dumps(step.get('bodyPreview'), ensure_ascii=False)}")
    if step.get("requestTextContainsMatched"):
        assertions.append(f"Request body contained expected text: {json.dumps(step.get('requestTextContainsMatched'), ensure_ascii=False)}")
    if step.get("requestTextNotContainsMatched"):
        assertions.append(f"Request body excluded forbidden text: {json.dumps(step.get('requestTextNotContainsMatched'), ensure_ascii=False)}")
    if step.get("responseTextContainsMatched"):
        assertions.append(f"Response text contained expected text: {json.dumps(step.get('responseTextContainsMatched'), ensure_ascii=False)}")
    if step.get("responseTextNotContainsMatched"):
        assertions.append(f"Response text excluded forbidden text: {json.dumps(step.get('responseTextNotContainsMatched'), ensure_ascii=False)}")
    if step.get("checkedRequestJson"):
        for key, value in step["checkedRequestJson"].items():
            assertions.append(f"Request JSON {key} matched observed value {json.dumps(value, ensure_ascii=False)}")
    if step.get("expectedStatusAny") is not None:
        assertions.append(f"Allowed HTTP statuses: {', '.join(str(item) for item in as_list(step.get('expectedStatusAny')))}")
    if step.get("checkedResponseHeaders"):
        for key, value in step["checkedResponseHeaders"].items():
            assertions.append(f"Response header {key} matched observed value {json.dumps(value, ensure_ascii=False)}")
    if step.get("extractedResponseHeaders"):
        assertions.append(f"Extracted response header variables: {', '.join(sorted(step['extractedResponseHeaders'].keys()))}")
    if step.get("cleanupAttempted") is not None:
        assertions.append(f"Cleanup request attempted: {step.get('cleanupAttempted')}")
    if step.get("skipped") is not None:
        assertions.append(f"Probe step skipped: {step.get('skipped')}")
    if step.get("skipReason"):
        assertions.append(f"Skip reason: {step.get('skipReason')}")
    if step.get("pollAttemptCount") is not None:
        assertions.append(f"API poll attempts observed: {step.get('pollAttemptCount')}")
    if step.get("pollMatched") is not None:
        assertions.append(f"API poll matched expectations: {step.get('pollMatched')}")
    if step.get("checkedJson"):
        for key, value in step["checkedJson"].items():
            assertions.append(f"JSON {key} matched observed value {json.dumps(value, ensure_ascii=False)}")
    if step.get("checkedJsonAlternativeIndex") is not None:
        assertions.append(f"JSON alternative matched: #{step.get('checkedJsonAlternativeIndex')}")
    if step.get("extractedJson"):
        assertions.append(f"Extracted runtime variables: {', '.join(sorted(step['extractedJson'].keys()))}")
    if step.get("count") is not None:
        assertions.append(f"Locator count observed: {step.get('count')}")
    if step.get("matchedText"):
        assertions.append(f"Matched visible text: {json.dumps(step.get('matchedText'), ensure_ascii=False)}")
    if step.get("dismissed") is not None:
        assertions.append(f"Dismissed optional UI element: {step.get('dismissed')}")
    if step.get("hitTest"):
        hit_test = step.get("hitTest") or {}
        assertions.append(f"Hit test target received pointer events: {hit_test.get('receivesPointerEvents')}")
        if hit_test.get("blocker"):
            blocker = hit_test.get("blocker") or {}
            assertions.append(f"Hit test blocker observed: {blocker.get('selector') or blocker.get('tag') or 'unknown'}")
        if hit_test.get("actionability"):
            assertions.append(f"Playwright actionability check: {hit_test.get('actionability')}")
    if step.get("responseAfterClick") is not None:
        assertions.append(f"Response captured after click: {step.get('responseAfterClick')}")
    if step.get("checkedConsoleErrors") is not None:
        assertions.append(f"Unignored console errors observed: {step.get('checkedConsoleErrors')}")
    if step.get("ignoredConsoleErrors") is not None:
        assertions.append(f"Ignored console errors: {step.get('ignoredConsoleErrors')}")
    if step.get("checkedRequestFailures") is not None:
        assertions.append(f"Unignored request failures observed: {step.get('checkedRequestFailures')}")
    if step.get("ignoredRequestFailures") is not None:
        assertions.append(f"Ignored request failures: {step.get('ignoredRequestFailures')}")
    if step.get("checkedNoRequest") is not None:
        target = step.get("checkedRequestTarget") or "<request>"
        method = step.get("checkedRequestMethod") or ""
        assertions.append(f"Forbidden request absent: {method} {target}".strip())
    if step.get("ignoredRequests") is not None:
        assertions.append(f"Ignored matching forbidden requests: {step.get('ignoredRequests')}")
    if step.get("checkedFailedResponses") is not None:
        assertions.append(f"Unignored failed HTTP responses observed: {step.get('checkedFailedResponses')}")
    if step.get("ignoredFailedResponses") is not None:
        assertions.append(f"Ignored failed HTTP responses: {step.get('ignoredFailedResponses')}")
    if step.get("exitCode") is not None:
        assertions.append(f"Command exit code observed: {step.get('exitCode')}")
    if step.get("checkedStdoutJson"):
        for key, value in step["checkedStdoutJson"].items():
            assertions.append(f"stdout JSON {key} matched observed value {json.dumps(value, ensure_ascii=False)}")
    if step.get("checkedStdoutJsonAlternativeIndex") is not None:
        assertions.append(f"stdout JSON alternative matched: #{step.get('checkedStdoutJsonAlternativeIndex')}")
    if step.get("extractedStdoutJson"):
        assertions.append(f"Extracted stdout runtime variables: {', '.join(sorted(step['extractedStdoutJson'].keys()))}")
    if step.get("stdoutContainsMatched"):
        assertions.append(f"Stdout contained expected text: {json.dumps(step.get('stdoutContainsMatched'), ensure_ascii=False)}")
    if step.get("stderrContainsMatched"):
        assertions.append(f"Stderr contained expected text: {json.dumps(step.get('stderrContainsMatched'), ensure_ascii=False)}")
    if step.get("opened") is not None:
        assertions.append(f"WebSocket opened: {step.get('opened')}")
    if step.get("messageCount") is not None:
        label = "SSE messages" if step.get("action") == "sse" else "WebSocket messages"
        assertions.append(f"{label} observed: {step.get('messageCount')}")
    if step.get("messageTextContainsMatched"):
        label = "SSE message text" if step.get("action") == "sse" else "WebSocket message text"
        assertions.append(f"{label} contained expected text: {json.dumps(step.get('messageTextContainsMatched'), ensure_ascii=False)}")
    if step.get("error"):
        assertions.append(f"Probe error observed: {step.get('error')}")
    if not assertions and step.get("status") == "passed":
        assertions.append(f"Step `{step.get('action')}` completed successfully.")
    return assertions


def step_matches_test(step: dict[str, Any], test: dict[str, Any]) -> bool:
    test_id = test.get("id")
    if has_text(step.get("stepId")) and step.get("stepId") == test_id:
        return True
    step_test_ids = as_list(step.get("testIds"))
    if step_test_ids:
        return test_id in step_test_ids
    test_reqs = set(as_list(test.get("requirement_ids")))
    step_reqs = set(as_list(step.get("requirementIds")))
    return bool(test_reqs and step_reqs and test_reqs.intersection(step_reqs))


def make_evidence(step: dict[str, Any], evidence_id: str, base_dir: Path) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": evidence_id,
        "type": infer_evidence_type(step),
        "proves": step.get("proves") or f"Probe step `{step.get('action')}` produced status `{step.get('status')}`.",
        "current_run": True,
        "generated_by": "ledger_from_probe.py",
        "scenario_id": step.get("scenarioId", ""),
        "step_id": step.get("stepId", ""),
        "action": step.get("action", ""),
        "status": step.get("status", ""),
        "test_ids": as_list(step.get("testIds")),
        "requirement_ids": as_list(step.get("requirementIds")),
        "assertions": evidence_assertions(step),
    }
    item.update(evidence_locator(step, base_dir))
    for source_key, dest_key in (
        ("bodyPath", "body_path"),
        ("requestBodyPath", "request_body_path"),
        ("messagesPath", "messages_path"),
        ("stdoutPath", "stdout_path"),
        ("stderrPath", "stderr_path"),
    ):
        if step.get(source_key) is not None:
            item[dest_key] = relpath(step.get(source_key), base_dir)
    for source_key, dest_key in (
        ("statusCode", "status_code"),
        ("pollAttemptCount", "poll_attempt_count"),
        ("pollIntervalMs", "poll_interval_ms"),
        ("pollTimeoutMs", "poll_timeout_ms"),
        ("pollMatched", "poll_matched"),
        ("pollAttempts", "poll_attempts"),
        ("expectedStatusAny", "expected_status_any"),
        ("method", "method"),
        ("url", "observed_url"),
        ("responseHeaders", "response_headers"),
        ("checkedResponseHeaders", "checked_response_headers"),
        ("extractedResponseHeaders", "extracted_response_headers"),
        ("extractedResponseHeaderNames", "extracted_response_header_names"),
        ("requestBodyCaptured", "request_body_captured"),
        ("requestBodyPreview", "request_body_preview"),
        ("bodyPreview", "body_preview"),
        ("requestTextContainsMatched", "request_text_contains_matched"),
        ("requestTextNotContainsMatched", "request_text_not_contains_matched"),
        ("responseTextContainsMatched", "response_text_contains_matched"),
        ("responseTextNotContainsMatched", "response_text_not_contains_matched"),
        ("checkedRequestJson", "checked_request_json"),
        ("checkedJson", "checked_json"),
        ("checkedJsonAlternativeIndex", "checked_json_alternative_index"),
        ("checkedJsonAlternative", "checked_json_alternative"),
        ("extractedJson", "extracted_json"),
        ("extractedJsonPaths", "extracted_json_paths"),
        ("messageCount", "messages_seen"),
        ("messageTextContainsMatched", "message_text_contains_matched"),
        ("exitCode", "exit_code"),
        ("checkedConsoleErrors", "checked_console_errors"),
        ("ignoredConsoleErrors", "ignored_console_errors"),
        ("checkedRequestFailures", "checked_request_failures"),
        ("ignoredRequestFailures", "ignored_request_failures"),
        ("checkedNoRequest", "checked_no_request"),
        ("ignoredRequests", "ignored_requests"),
        ("checkedRequestMethod", "checked_request_method"),
        ("checkedRequestTarget", "checked_request_target"),
        ("matchingRequests", "matching_requests"),
        ("checkedFailedResponses", "checked_failed_responses"),
        ("ignoredFailedResponses", "ignored_failed_responses"),
        ("stdoutPreview", "stdout_preview"),
        ("checkedStdoutJson", "checked_stdout_json"),
        ("checkedStdoutJsonAlternativeIndex", "checked_stdout_json_alternative_index"),
        ("checkedStdoutJsonAlternative", "checked_stdout_json_alternative"),
        ("extractedStdoutJson", "extracted_stdout_json"),
        ("extractedStdoutJsonPaths", "extracted_stdout_json_paths"),
        ("stdoutContainsMatched", "stdout_contains_matched"),
        ("stderrPreview", "stderr_preview"),
        ("stderrContainsMatched", "stderr_contains_matched"),
        ("hitTest", "hit_test"),
        ("responseAfterClick", "response_after_click"),
        ("pageUrl", "page_url"),
        ("cleanupAttempted", "cleanup_attempted"),
        ("skipped", "skipped"),
        ("skipReason", "skip_reason"),
        ("error", "error"),
    ):
        if step.get(source_key) is not None:
            item[dest_key] = safe_observed_url(step[source_key]) if dest_key == "observed_url" else step[source_key]
    return item


def final_status(statuses: list[str]) -> str:
    if not statuses:
        return "Untested"
    if any(status == "Failed" for status in statuses):
        return "Failed"
    if all(status == "Passed" for status in statuses):
        return "Passed"
    if any(status == "Inconclusive" for status in statuses):
        return "Inconclusive"
    if any(status == "Blocked" for status in statuses):
        return "Blocked"
    return "Untested"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an evidence ledger from a QA matrix and probe results.")
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--base-dir", help="Base directory for relative evidence paths. Defaults to results artifactDir or out directory.")
    args = parser.parse_args()

    matrix_path = Path(args.matrix).expanduser().resolve()
    results_path = Path(args.results).expanduser().resolve()
    out_path = Path(args.out).expanduser().resolve()
    input_artifact_errors: list[dict[str, str]] = []
    matrix, matrix_load_error = try_load_json(matrix_path)
    results, results_load_error = try_load_json(results_path)
    for name, path, load_error in (
        ("matrix", matrix_path, matrix_load_error),
        ("results", results_path, results_load_error),
    ):
        if load_error:
            input_artifact_errors.append({"name": name, "path": str(path), "error": load_error})
    if input_artifact_errors:
        ledger = {
            "schema_version": 2,
            "generated_from": {
                "matrix": str(matrix_path),
                "results": str(results_path),
            },
            "runtime_summary": {
                "probe_status": None,
                "qa_run_id": None,
                "qa_marker": None,
                "runtime_var_names": [],
                "console_errors": 0,
                "console_warnings": 0,
                "failed_responses": 0,
                "request_failures": 0,
                "input_artifact_error_count": len(input_artifact_errors),
            },
            "requirements": [],
            "tests": [],
            "evidence": [],
            "input_artifact_errors": input_artifact_errors,
        }
        write_json(out_path, ledger)
        print(json.dumps(ledger, indent=2, ensure_ascii=False))
        return 1
    assert matrix is not None
    assert results is not None
    schema_errors = validate_artifact_schema("matrix", matrix) + validate_artifact_schema("results", results)
    if schema_errors:
        ledger = {
            "schema_version": 2,
            "generated_from": {"matrix": str(matrix_path), "results": str(results_path)},
            "runtime_summary": {"probe_status": None, "input_artifact_error_count": len(schema_errors)},
            "requirements": [],
            "tests": [],
            "evidence": [],
            "input_artifact_errors": [
                {"name": "schema_contract", "path": str(matrix_path.parent), "error": error}
                for error in schema_errors
            ],
        }
        write_json(out_path, ledger)
        print(json.dumps(ledger, indent=2, ensure_ascii=False))
        return 1
    base_dir = Path(args.base_dir).expanduser().resolve() if args.base_dir else Path(results.get("artifactDir") or out_path.parent).expanduser().resolve()
    steps = collect_steps(results)

    evidence: list[dict[str, Any]] = []
    evidence_by_step_index: dict[int, str] = {}
    for index, step in enumerate(steps, 1):
        evidence_id = f"E{index}"
        evidence_by_step_index[index - 1] = evidence_id
        evidence.append(make_evidence(step, evidence_id, base_dir))

    tests: list[dict[str, Any]] = []
    for matrix_test in as_list(matrix.get("tests")):
        test_id = matrix_test.get("id")
        matrix_status = matrix_test.get("status")
        matched_steps = [step for step in steps if step_matches_test(step, matrix_test)]
        matched_indices = [idx for idx, step in enumerate(steps) if step_matches_test(step, matrix_test)]
        evidence_ids = [evidence_by_step_index[idx] for idx in matched_indices]
        if not matched_steps:
            status = matrix_status if matrix_status in {"Blocked", "Untested", "Inconclusive"} else "Untested"
            notes = matrix_test.get("notes") or "No executed probe step matched this test id or requirement mapping."
        elif any(step.get("status") == "failed" for step in matched_steps):
            status = "Failed"
            failed = [step.get("error") for step in matched_steps if step.get("status") == "failed" and step.get("error")]
            notes = "; ".join(failed)[:1000] or "At least one mapped probe step failed."
        elif any(step.get("status") == "skipped" for step in matched_steps):
            status = "Inconclusive"
            skipped = [step.get("skipReason") for step in matched_steps if step.get("status") == "skipped" and step.get("skipReason")]
            notes = "; ".join(skipped)[:1000] or "At least one mapped probe step was skipped."
        elif evidence_ids:
            status = "Passed"
            notes = ""
        else:
            status = "Inconclusive"
            notes = "Probe steps ran but produced no mappable evidence."
        item = {
            "id": test_id,
            "requirement_ids": as_list(matrix_test.get("requirement_ids")),
            "type": matrix_test.get("type", "probe"),
            "expected": matrix_test.get("expected", ""),
            "status": status,
            "evidence_ids": evidence_ids,
        }
        if notes:
            item["notes"] = notes
        tests.append(item)

    test_by_id = {test.get("id"): test for test in tests}
    requirements: list[dict[str, Any]] = []
    for matrix_req in as_list(matrix.get("requirements")):
        test_ids = [test_id for test_id in as_list(matrix_req.get("test_ids")) if has_text(test_id)]
        mapped_tests = [test_by_id[test_id] for test_id in test_ids if test_id in test_by_id]
        statuses = [test.get("status") for test in mapped_tests if test.get("status") in ALLOWED_STATUSES]
        req_status = final_status(statuses)
        evidence_ids = sorted({evidence_id for test in mapped_tests for evidence_id in as_list(test.get("evidence_ids"))})
        notes = ""
        if req_status != "Passed":
            notes = "; ".join(test.get("notes", "") for test in mapped_tests if test.get("notes")) or "Requirement was not fully proven by mapped tests."
        requirements.append(
            {
                "id": matrix_req.get("id"),
                "source": matrix_req.get("source", "test-matrix.json"),
                "text": matrix_req.get("text", ""),
                "test_ids": test_ids,
                "status": req_status,
                "evidence_ids": evidence_ids,
                **({"notes": notes[:1200]} if notes else {}),
            }
        )

    ledger = {
        "schema_version": 2,
        "generated_from": {
            "matrix": str(matrix_path),
            "results": str(results_path),
        },
        "runtime_summary": {
            "probe_status": results.get("status"),
            "qa_run_id": (results.get("run") or {}).get("qaRunId"),
            "qa_marker": (results.get("run") or {}).get("qaMarker"),
            "runtime_var_names": as_list((results.get("run") or {}).get("runtimeVarNames")),
            "console_errors": len([item for item in as_list(results.get("console")) if item.get("type") == "error"]),
            "console_warnings": len([item for item in as_list(results.get("console")) if item.get("type") == "warning"]),
            "failed_responses": len(as_list(results.get("failedResponses"))),
            "request_failures": len(as_list(results.get("requestFailures"))),
        },
        "requirements": requirements,
        "tests": tests,
        "evidence": evidence,
        "input_artifact_errors": input_artifact_errors,
    }

    write_json(out_path, ledger)
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
