"""证据路径、谱系和运行结果绑定的统一契约。"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Iterator

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

UNCONFIRMED_BOUNDARY_VALUES = frozenset(
    {
        "",
        "unconfirmed",
        "unknown",
        "unset",
        "todo",
        "tbd",
        "must be stated before pass/fail",
        "must be stated",
    }
)

RUNNER_STEP_FIELD_MAP = (
    ("status_code", "statusCode"),
    ("poll_attempt_count", "pollAttemptCount"),
    ("poll_interval_ms", "pollIntervalMs"),
    ("poll_timeout_ms", "pollTimeoutMs"),
    ("poll_matched", "pollMatched"),
    ("poll_attempts", "pollAttempts"),
    ("expected_status_any", "expectedStatusAny"),
    ("method", "method"),
    ("observed_url", "url"),
    ("response_headers", "responseHeaders"),
    ("checked_response_headers", "checkedResponseHeaders"),
    ("extracted_response_headers", "extractedResponseHeaders"),
    ("extracted_response_header_names", "extractedResponseHeaderNames"),
    ("request_body_captured", "requestBodyCaptured"),
    ("request_body_preview", "requestBodyPreview"),
    ("body_preview", "bodyPreview"),
    ("request_text_contains_matched", "requestTextContainsMatched"),
    ("request_text_not_contains_matched", "requestTextNotContainsMatched"),
    ("response_text_contains_matched", "responseTextContainsMatched"),
    ("response_text_not_contains_matched", "responseTextNotContainsMatched"),
    ("checked_request_json", "checkedRequestJson"),
    ("checked_json", "checkedJson"),
    ("checked_json_alternative_index", "checkedJsonAlternativeIndex"),
    ("checked_json_alternative", "checkedJsonAlternative"),
    ("extracted_json", "extractedJson"),
    ("extracted_json_paths", "extractedJsonPaths"),
    ("messages_seen", "messageCount"),
    ("message_text_contains_matched", "messageTextContainsMatched"),
    ("exit_code", "exitCode"),
    ("checked_console_errors", "checkedConsoleErrors"),
    ("ignored_console_errors", "ignoredConsoleErrors"),
    ("checked_request_failures", "checkedRequestFailures"),
    ("ignored_request_failures", "ignoredRequestFailures"),
    ("checked_no_request", "checkedNoRequest"),
    ("ignored_requests", "ignoredRequests"),
    ("checked_request_method", "checkedRequestMethod"),
    ("checked_request_target", "checkedRequestTarget"),
    ("matching_requests", "matchingRequests"),
    ("checked_failed_responses", "checkedFailedResponses"),
    ("ignored_failed_responses", "ignoredFailedResponses"),
    ("stdout_preview", "stdoutPreview"),
    ("checked_stdout_json", "checkedStdoutJson"),
    ("checked_stdout_json_alternative_index", "checkedStdoutJsonAlternativeIndex"),
    ("checked_stdout_json_alternative", "checkedStdoutJsonAlternative"),
    ("extracted_stdout_json", "extractedStdoutJson"),
    ("extracted_stdout_json_paths", "extractedStdoutJsonPaths"),
    ("stdout_contains_matched", "stdoutContainsMatched"),
    ("stderr_preview", "stderrPreview"),
    ("stderr_contains_matched", "stderrContainsMatched"),
    ("hit_test", "hitTest"),
    ("response_after_click", "responseAfterClick"),
    ("page_url", "pageUrl"),
    ("cleanup_attempted", "cleanupAttempted"),
    ("skipped", "skipped"),
    ("skip_reason", "skipReason"),
    ("error", "error"),
)

RUNNER_STEP_PATH_FIELD_MAP = (
    ("body_path", "bodyPath"),
    ("request_body_path", "requestBodyPath"),
    ("messages_path", "messagesPath"),
    ("stdout_path", "stdoutPath"),
    ("stderr_path", "stderrPath"),
)


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def id_set(value: Any) -> set[str]:
    items = value if isinstance(value, list) else [value]
    return {str(item).strip() for item in items if has_text(item)}


def nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def path_matches(recorded: Any, expected: Path | None) -> bool:
    if not recorded or expected is None:
        return False
    try:
        return Path(str(recorded)).expanduser().resolve() == expected.expanduser().resolve()
    except OSError:
        return False


def resolved_path(value: Any) -> Path | None:
    if not value:
        return None
    try:
        return Path(str(value)).expanduser().resolve()
    except OSError:
        return None


def resolve_artifact_path(base_dir: Path | None, value: str) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute() or base_dir is None:
        return path.resolve()
    return (base_dir / path).resolve()


def iter_path_values(value: Any) -> Iterator[str]:
    if has_text(value):
        yield str(value)
    elif isinstance(value, dict):
        for child in value.values():
            yield from iter_path_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_path_values(child)


def evidence_artifact_paths(evidence_or_ledger: Iterable[dict[str, Any]] | dict[str, Any] | None, base_dir: Path | None) -> list[Path]:
    if isinstance(evidence_or_ledger, dict):
        evidence = as_list(evidence_or_ledger.get("evidence"))
    else:
        evidence = list(evidence_or_ledger or [])
    paths: list[Path] = []
    seen: set[str] = set()
    for item in evidence:
        if not isinstance(item, dict):
            continue
        for field in EVIDENCE_ARTIFACT_PATH_FIELDS:
            for raw in iter_path_values(item.get(field)):
                path = resolve_artifact_path(base_dir, raw)
                key = str(path)
                if key not in seen:
                    seen.add(key)
                    paths.append(path)
    return paths


def collect_result_steps(results: dict[str, Any] | None) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for scenario in as_list((results or {}).get("scenarios")):
        if not isinstance(scenario, dict):
            continue
        for step in as_list(scenario.get("steps")):
            if isinstance(step, dict):
                merged = dict(step)
                merged.setdefault("scenarioId", scenario.get("id", ""))
                steps.append(merged)
    return steps


def result_step_lineage_match(evidence_item: dict[str, Any], step: dict[str, Any]) -> bool:
    evidence_req_ids = id_set(evidence_item.get("requirement_ids"))
    evidence_test_ids = id_set(evidence_item.get("test_ids"))
    step_req_ids = id_set(step.get("requirementIds"))
    step_test_ids = id_set(step.get("testIds"))
    if evidence_req_ids and step_req_ids and not evidence_req_ids.intersection(step_req_ids):
        return False
    if evidence_test_ids and step_test_ids and not evidence_test_ids.intersection(step_test_ids):
        return False
    return True


def _path_values_equal(base_dir: Path | None, evidence_value: Any, step_value: Any) -> bool:
    if not has_text(evidence_value) or not has_text(step_value):
        return evidence_value == step_value
    return resolve_artifact_path(base_dir, str(evidence_value)) == resolve_artifact_path(base_dir, str(step_value))


def runner_step_field_mismatches(evidence_item: dict[str, Any], step: dict[str, Any], base_dir: Path | None) -> list[str]:
    mismatches: list[str] = []
    for evidence_key, step_key in RUNNER_STEP_FIELD_MAP:
        step_present = step_key in step and step.get(step_key) is not None
        evidence_present = evidence_key in evidence_item
        if step_present and not evidence_present:
            mismatches.append(f"{evidence_key} is missing from ledger but results.{step_key} is present")
        elif evidence_present and not step_present:
            mismatches.append(f"{evidence_key} is present in ledger but results.{step_key} is absent")
        elif evidence_present and evidence_item.get(evidence_key) != step.get(step_key):
            mismatches.append(f"{evidence_key}={evidence_item.get(evidence_key)!r} does not match results.{step_key}={step.get(step_key)!r}")
    for evidence_key, step_key in RUNNER_STEP_PATH_FIELD_MAP:
        step_present = has_text(step.get(step_key))
        evidence_present = has_text(evidence_item.get(evidence_key))
        if step_present and not evidence_present:
            mismatches.append(f"{evidence_key} is missing from ledger but results.{step_key} is present")
        elif evidence_present and not step_present:
            mismatches.append(f"{evidence_key} is present in ledger but results.{step_key} is absent")
        elif evidence_present and not _path_values_equal(base_dir, evidence_item.get(evidence_key), step.get(step_key)):
            mismatches.append(f"{evidence_key}={evidence_item.get(evidence_key)!r} does not match results.{step_key}={step.get(step_key)!r}")
    return mismatches


def runner_result_binding_error(evidence_item: dict[str, Any], result_steps: list[dict[str, Any]], base_dir: Path | None) -> str | None:
    evidence_id = str(evidence_item.get("id") or "unknown")
    scenario_id = str(evidence_item.get("scenario_id") or "").strip()
    step_id = str(evidence_item.get("step_id") or "").strip()
    action = str(evidence_item.get("action") or "").strip()
    status = str(evidence_item.get("status") or "").strip()
    candidates = [
        step
        for step in result_steps
        if (not scenario_id or str(step.get("scenarioId") or "").strip() == scenario_id)
        and (not step_id or str(step.get("stepId") or "").strip() == step_id)
        and (not action or str(step.get("action") or "").strip() == action)
        and result_step_lineage_match(evidence_item, step)
    ]
    if not candidates:
        return (
            f"Runner-generated evidence {evidence_id} has no matching results.json step "
            f"(scenario_id={scenario_id or '<empty>'}, step_id={step_id or '<empty>'}, action={action or '<empty>'})."
        )
    status_candidates = [step for step in candidates if not status or str(step.get("status") or "").strip() == status]
    if not status_candidates:
        observed = sorted({str(step.get("status") or "<empty>") for step in candidates})
        return f"Runner-generated evidence {evidence_id} status={status!r} does not match results.json step status(es) {observed}."
    candidate_mismatches = [runner_step_field_mismatches(evidence_item, step, base_dir) for step in status_candidates]
    if candidate_mismatches and not any(not mismatches for mismatches in candidate_mismatches):
        return f"Runner-generated evidence {evidence_id} does not match bound results.json step fields: " + "; ".join(candidate_mismatches[0][:6]) + "."
    return None


def runner_result_binding_missing(evidence_item: dict[str, Any], result_steps: list[dict[str, Any]], base_dir: Path | None) -> bool:
    return runner_result_binding_error(evidence_item, result_steps, base_dir) is not None


def boundary_field_confirmed(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text not in UNCONFIRMED_BOUNDARY_VALUES


def defect_finding_summary(defects: dict[str, Any] | None) -> dict[str, Any]:
    if not defects:
        return {
            "finding_count": 0,
            "summary_count": None,
            "findings_count": 0,
            "invalid_summary_count": False,
            "severity_counts": {},
        }
    summary = defects.get("summary") if isinstance(defects.get("summary"), dict) else {}
    findings = defects.get("findings") if isinstance(defects.get("findings"), list) else []
    summary_declared = "finding_count" in summary
    summary_count = nonnegative_int(summary.get("finding_count")) if summary_declared else None
    findings_count = len(findings)
    severity_counts = summary.get("severity_counts") if isinstance(summary.get("severity_counts"), dict) else {}
    if findings and (not severity_counts or summary_count != findings_count):
        severity_counts = dict(sorted(Counter(str(item.get("severity") or "unknown") for item in findings if isinstance(item, dict)).items()))
    return {
        "finding_count": max(summary_count or 0, findings_count),
        "summary_count": summary_count,
        "findings_count": findings_count,
        "invalid_summary_count": summary_declared and summary_count is None,
        "severity_counts": severity_counts,
    }
