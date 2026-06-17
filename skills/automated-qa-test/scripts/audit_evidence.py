#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ALLOWED_STATUSES = {"Passed", "Failed", "Blocked", "Untested", "Inconclusive"}
PASSED = "Passed"
FILE_EVIDENCE_TYPES = {"screenshot", "file", "log_file", "trace", "video", "command", "websocket", "api_response"}
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
NON_PASS_EVIDENCE_STATUSES = {"failed", "error", "skipped", "blocked", "untested", "inconclusive", "cancelled", "canceled", "timeout", "timed_out"}
BUNDLED_LINEAGE_REQUIRED_GENERATORS = {"ledger_from_probe.py"}
SECRET_PATTERNS = [
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
    re.compile(r"\b(?:Authorization|Cookie|Set-Cookie)\s*:(?!\s*\[REDACTED\])\s*[^\r\n]+", re.IGNORECASE),
    re.compile(r"(?:[?&]?(?:access[_-]?token|auth[_-]?token|id[_-]?token|refresh[_-]?token|session[_-]?token|api[_-]?key|key|secret|password|passwd|pwd|cookie)=)(?!\s*\[REDACTED(?:_JWT)?\])\s*[^\s\"',}&]{4,}", re.IGNORECASE),
    re.compile(r"(?:authorization|access[_-]?token|auth[_-]?token|id[_-]?token|refresh[_-]?token|session[_-]?token|api[_-]?key|secret|password|passwd|pwd|jwt)\s*[:=](?!\s*[\"']?\[REDACTED(?:_JWT)?\])\s*[\"']?[^\s\"',}]{4,}", re.IGNORECASE),
]
STREAM_TEST_TYPES = {"stream", "websocket", "sse"}
STREAM_EVIDENCE_TYPES = {"websocket", "sse"}
API_TEST_TYPES = {"api", "api_followup"}
API_EVIDENCE_TYPES = {"api_response", "ui_to_api", "cleanup"}
UI_TO_API_TEST_TYPES = {"ui_to_api", "click_to_response"}
PERSISTENCE_TEST_TYPES = {"persistence", "database", "db"}
PERSISTENCE_EVIDENCE_TYPES = {"command", "log_file", "api_response"}
TERMINAL_STATUS_TEST_TYPES = STREAM_TEST_TYPES.union(API_TEST_TYPES, UI_TO_API_TEST_TYPES, PERSISTENCE_TEST_TYPES)
RETURN_MARKER_REQUIRED_TERMS = (
    "qa_marker",
    "marker",
    "unique marker",
    "stale",
    "not seed",
    "not fallback",
    "seed avoidance",
    "fallback avoidance",
    "without fallback",
    "唯一",
    "标记",
    "非种子",
    "不是种子",
    "非降级",
    "不是降级",
)
TERMINAL_TERMS = ("answer_done", "terminal", "completed", "completion", "done", "完成", "终态")
FRESHNESS_SKEW_SECONDS = 2.0
TEXT_ARTIFACT_MAX_BYTES = 2_000_000
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
JPEG_SOF_MARKERS = {
    0xC0,
    0xC1,
    0xC2,
    0xC3,
    0xC5,
    0xC6,
    0xC7,
    0xC9,
    0xCA,
    0xCB,
    0xCD,
    0xCE,
    0xCF,
}


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


def write_summary(path_arg: str | None, summary: dict[str, Any]) -> None:
    if path_arg:
        path = Path(path_arg).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_sha256_or_none(path: Path) -> str | None:
    if path.is_dir():
        return None
    try:
        return file_sha256(path)
    except OSError:
        return None


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def id_set(value: Any) -> set[str]:
    if isinstance(value, list):
        items = value
    else:
        items = [value]
    return {str(item).strip() for item in items if has_text(item)}


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def iter_strings(value: Any, prefix: str = ""):
    if isinstance(value, str):
        yield prefix, value
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            yield from iter_strings(item, f"{prefix}[{idx}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from iter_strings(item, f"{prefix}.{key}" if prefix else str(key))


def has_todo(value: Any) -> bool:
    return isinstance(value, str) and "TODO" in value.upper()


def has_locator(item: dict[str, Any]) -> bool:
    return any(has_text(item.get(key)) for key in ("path", "url", "file", "log_ref", "value", "messages_path"))


def has_assertion_signal(item: dict[str, Any]) -> bool:
    return bool(as_list(item.get("assertions"))) or any(
        item.get(key) is not None
        for key in ("status_code", "checked_json", "messages_seen", "exit_code", "observed", "value", "path", "url")
    )


def passed_evidence_disposition_error(subject_kind: str, subject_id: Any, evidence_id: Any, evidence_item: dict[str, Any]) -> str | None:
    if evidence_item.get("error"):
        return f"{subject_kind} {subject_id} is Passed but references failed/error evidence {evidence_id}."
    status = str(evidence_item.get("status") or "").strip().lower()
    if evidence_item.get("skipped") is True or status in NON_PASS_EVIDENCE_STATUSES:
        disposition = "skipped=true" if evidence_item.get("skipped") is True else f"status={evidence_item.get('status')!r}"
        return f"{subject_kind} {subject_id} is Passed but references non-pass evidence {evidence_id} ({disposition})."
    return None


def nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def runtime_disposition_status(
    evidence: list[dict[str, Any]],
    *,
    checked_field: str,
    ignored_field: str,
    observed_count: int,
    label: str,
) -> tuple[bool, list[str]]:
    findings: list[str] = []
    for item in evidence:
        if item.get("type") != "runtime":
            continue
        checked = nonnegative_int(item.get(checked_field))
        if checked is None:
            continue
        ignored = nonnegative_int(item.get(ignored_field))
        ignored_count = ignored if ignored is not None else 0
        if checked == 0 and ignored_count == observed_count:
            return True, []
        if checked == 0 and observed_count > ignored_count:
            evidence_id = str(item.get("id") or "unknown")
            findings.append(
                f"Runtime evidence {evidence_id} claims {checked_field}=0 but results contain "
                f"{observed_count} {label}; {ignored_field} accounts for {ignored_count}."
            )
    return False, findings


def is_current_run_evidence(item: dict[str, Any]) -> bool:
    return item.get("current_run") is True


def evidence_lineage(item: dict[str, Any]) -> tuple[set[str], set[str]]:
    return id_set(item.get("requirement_ids")), id_set(item.get("test_ids"))


def evidence_requires_lineage(item: dict[str, Any]) -> bool:
    return str(item.get("generated_by") or "").strip() in BUNDLED_LINEAGE_REQUIRED_GENERATORS


def collect_result_steps(results: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not results:
        return []
    steps: list[dict[str, Any]] = []
    for scenario in as_list(results.get("scenarios")):
        if not isinstance(scenario, dict):
            continue
        for step in as_list(scenario.get("steps")):
            if not isinstance(step, dict):
                continue
            merged = dict(step)
            merged.setdefault("scenarioId", scenario.get("id", ""))
            steps.append(merged)
    return steps


def result_step_lineage_match(evidence_item: dict[str, Any], step: dict[str, Any]) -> bool:
    evidence_req_ids, evidence_test_ids = evidence_lineage(evidence_item)
    step_req_ids = id_set(step.get("requirementIds"))
    step_test_ids = id_set(step.get("testIds"))
    if evidence_req_ids and step_req_ids and not evidence_req_ids.intersection(step_req_ids):
        return False
    if evidence_test_ids and step_test_ids and not evidence_test_ids.intersection(step_test_ids):
        return False
    return True


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


def values_equal(left: Any, right: Any) -> bool:
    return left == right


def path_values_equal(base_dir: Path, evidence_value: Any, step_value: Any) -> bool:
    if not has_text(evidence_value) or not has_text(step_value):
        return evidence_value == step_value
    return resolve_evidence_path(base_dir, str(evidence_value)).resolve() == resolve_evidence_path(base_dir, str(step_value)).resolve()


def runner_step_field_mismatches(evidence_item: dict[str, Any], step: dict[str, Any], base_dir: Path) -> list[str]:
    mismatches: list[str] = []
    for evidence_key, step_key in RUNNER_STEP_FIELD_MAP:
        if step_key not in step or step.get(step_key) is None:
            continue
        if evidence_key not in evidence_item:
            mismatches.append(f"{evidence_key} is missing from ledger but results.{step_key} is present")
        elif not values_equal(evidence_item.get(evidence_key), step.get(step_key)):
            mismatches.append(f"{evidence_key}={evidence_item.get(evidence_key)!r} does not match results.{step_key}={step.get(step_key)!r}")
    for evidence_key, step_key in RUNNER_STEP_PATH_FIELD_MAP:
        if not has_text(step.get(step_key)):
            continue
        if evidence_key not in evidence_item:
            mismatches.append(f"{evidence_key} is missing from ledger but results.{step_key} is present")
        elif not path_values_equal(base_dir, evidence_item.get(evidence_key), step.get(step_key)):
            mismatches.append(f"{evidence_key}={evidence_item.get(evidence_key)!r} does not match results.{step_key}={step.get(step_key)!r}")
    return mismatches


def runner_result_binding_error(evidence_item: dict[str, Any], result_steps: list[dict[str, Any]], base_dir: Path) -> str | None:
    if not evidence_requires_lineage(evidence_item):
        return None
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
    if status and not any(str(step.get("status") or "").strip() == status for step in candidates):
        observed = sorted({str(step.get("status") or "<empty>") for step in candidates})
        return f"Runner-generated evidence {evidence_id} status={status!r} does not match results.json step status(es) {observed}."
    status_candidates = [step for step in candidates if not status or str(step.get("status") or "").strip() == status]
    candidate_mismatches = [runner_step_field_mismatches(evidence_item, step, base_dir) for step in status_candidates]
    if candidate_mismatches and not any(not mismatches for mismatches in candidate_mismatches):
        return f"Runner-generated evidence {evidence_id} does not match bound results.json step fields: " + "; ".join(candidate_mismatches[0][:6]) + "."
    return None


def requirement_lineage_findings(req: dict[str, Any], evidence_item: dict[str, Any]) -> tuple[list[str], list[str], bool]:
    req_id = str(req.get("id") or "unknown")
    evidence_id = str(evidence_item.get("id") or "unknown")
    req_test_ids = id_set(req.get("test_ids"))
    evidence_req_ids, evidence_test_ids = evidence_lineage(evidence_item)
    has_lineage = bool(evidence_req_ids or evidence_test_ids)
    if not has_lineage:
        if evidence_requires_lineage(evidence_item):
            return [f"Passed requirement {req_id} references bundled-runner evidence {evidence_id} without test_ids/requirement_ids lineage."], [], False
        return [], [f"Passed requirement {req_id} references evidence {evidence_id} without test_ids/requirement_ids lineage; audit cannot verify mapping."], False

    req_match = req_id in evidence_req_ids
    test_overlap = bool(req_test_ids and evidence_test_ids and req_test_ids.intersection(evidence_test_ids))
    errors: list[str] = []
    if not (req_match or test_overlap):
        errors.append(
            f"Passed requirement {req_id} references evidence {evidence_id} whose test_ids {sorted(evidence_test_ids)} do not overlap requirement tests {sorted(req_test_ids)} and whose requirement_ids {sorted(evidence_req_ids)} do not include the requirement."
        )
    return errors, [], True


def test_lineage_findings(test: dict[str, Any], evidence_item: dict[str, Any]) -> tuple[list[str], list[str], bool]:
    test_id = str(test.get("id") or "unknown")
    evidence_id = str(evidence_item.get("id") or "unknown")
    test_requirement_ids = id_set(test.get("requirement_ids"))
    evidence_req_ids, evidence_test_ids = evidence_lineage(evidence_item)
    has_lineage = bool(evidence_req_ids or evidence_test_ids)
    if not has_lineage:
        if evidence_requires_lineage(evidence_item):
            return [f"Passed test {test_id} references bundled-runner evidence {evidence_id} without test_ids/requirement_ids lineage."], [], False
        return [], [f"Passed test {test_id} references evidence {evidence_id} without test_ids/requirement_ids lineage; audit cannot verify mapping."], False

    test_match = test_id in evidence_test_ids
    requirement_overlap = bool(test_requirement_ids and evidence_req_ids and test_requirement_ids.intersection(evidence_req_ids))
    errors: list[str] = []
    if not (test_match or requirement_overlap):
        errors.append(
            f"Passed test {test_id} references evidence {evidence_id} whose requirement_ids {sorted(evidence_req_ids)} do not overlap test requirements {sorted(test_requirement_ids)} and whose test_ids {sorted(evidence_test_ids)} do not include the test."
        )
    return errors, [], True


def requirement_status_consistency_errors(req: dict[str, Any], test_by_id: dict[str, dict[str, Any]]) -> tuple[list[str], int]:
    if req.get("status") != PASSED:
        return [], 0
    req_id = str(req.get("id") or "unknown")
    errors: list[str] = []
    checked_count = 0
    for test_id in [tid for tid in as_list(req.get("test_ids")) if has_text(tid)]:
        test = test_by_id.get(test_id)
        if not test:
            continue
        checked_count += 1
        test_status = test.get("status")
        if test_status != PASSED:
            errors.append(f"Requirement {req_id} is Passed but mapped test {test_id} has status {test_status!r}.")
    return errors, checked_count


def lower_blob(value: Any) -> str:
    if isinstance(value, str):
        return value.lower()
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True).lower()
    except TypeError:
        return str(value).lower()


def combined_text(*values: Any) -> str:
    return " ".join(lower_blob(value) for value in values if value is not None)


def test_claim_text(test: dict[str, Any], evidence_items: list[dict[str, Any]]) -> str:
    return combined_text(
        test.get("type"),
        test.get("expected"),
        test.get("notes"),
        [item.get("proves") for item in evidence_items],
        [item.get("assertions") for item in evidence_items],
    )


def has_evidence_type(evidence_items: list[dict[str, Any]], expected_types: set[str]) -> bool:
    return any(str(item.get("type") or "").lower() in expected_types for item in evidence_items)


def positive_count(value: Any) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, (int, float)):
        return value > 0
    if isinstance(value, str):
        try:
            return float(value.strip()) > 0
        except ValueError:
            return False
    return False


def artifact_path_has_content(base_dir: Path, raw_path: Any) -> bool:
    if not has_text(raw_path):
        return False
    resolved = resolve_evidence_path(base_dir, str(raw_path))
    if not resolved.exists() or resolved.is_dir():
        return False
    try:
        with resolved.open("rb") as handle:
            return bool(handle.read(1))
    except OSError:
        return False


def has_stream_message_signal(evidence_items: list[dict[str, Any]], base_dir: Path) -> bool:
    for item in evidence_items:
        if str(item.get("type") or "").lower() not in STREAM_EVIDENCE_TYPES:
            continue
        if positive_count(item.get("messages_seen")):
            return True
        if (
            artifact_path_has_content(base_dir, item.get("path"))
            or artifact_path_has_content(base_dir, item.get("file"))
            or artifact_path_has_content(base_dir, item.get("messages_path"))
        ):
            return True
        if has_text(item.get("message_text_contains_matched")) or bool(item.get("checked_json")) or bool(item.get("extracted_json")):
            return True
    return False


def value_contains_text(value: Any, needle: Any) -> bool:
    return has_text(needle) and str(needle).lower() in lower_blob(value)


def value_has_markerish_text(value: Any) -> bool:
    blob = lower_blob(value)
    return "marker" in blob or "qa_" in blob


def matched_return_text_has_signal(item: dict[str, Any], fields: tuple[str, ...], qa_marker: Any = None) -> bool:
    for field in fields:
        value = item.get(field)
        if not has_text(value):
            continue
        if has_text(qa_marker):
            if value_contains_text(value, qa_marker):
                return True
        else:
            return True
    return False


def checked_return_json_has_marker(item: dict[str, Any], fields: tuple[str, ...], qa_marker: Any = None) -> bool:
    for field in fields:
        value = item.get(field)
        if not value:
            continue
        if has_text(qa_marker):
            if value_contains_text(value, qa_marker):
                return True
        elif value_has_markerish_text(value):
            return True
    return False


def has_return_marker_signal(evidence_items: list[dict[str, Any]], qa_marker: Any = None) -> bool:
    for item in evidence_items:
        ev_type = str(item.get("type") or "").lower()
        if ev_type in {"websocket", "sse"} and matched_return_text_has_signal(item, ("message_text_contains_matched",), qa_marker):
            return True
        if ev_type in {"api_response", "ui_to_api"} and (
            matched_return_text_has_signal(item, ("response_text_contains_matched",), qa_marker)
            or checked_return_json_has_marker(item, ("checked_json",), qa_marker)
        ):
            return True
        if ev_type == "command" and (
            matched_return_text_has_signal(item, ("stdout_contains_matched", "stderr_contains_matched"), qa_marker)
            or checked_return_json_has_marker(item, ("checked_stdout_json",), qa_marker)
        ):
            return True
    return False


def has_terminal_signal(evidence_items: list[dict[str, Any]]) -> bool:
    for item in evidence_items:
        blob = combined_text(
            item.get("checked_json"),
            item.get("extracted_json"),
            item.get("checked_stdout_json"),
            item.get("extracted_stdout_json"),
            item.get("stdout_contains_matched"),
            item.get("message_text_contains_matched"),
            item.get("response_text_contains_matched"),
        )
        if any(term in blob for term in TERMINAL_TERMS):
            return True
    return False


def evidence_layer_errors(test: dict[str, Any], evidence_items: list[dict[str, Any]], base_dir: Path, qa_marker: Any = None) -> list[str]:
    test_id = test.get("id", "unknown")
    test_type = str(test.get("type") or "").lower()
    claim_text = test_claim_text(test, evidence_items)
    errors: list[str] = []

    if test_type in STREAM_TEST_TYPES:
        if not has_evidence_type(evidence_items, STREAM_EVIDENCE_TYPES):
            errors.append(f"Test {test_id} is Passed as {test_type} but has no WebSocket/SSE evidence.")
        elif not has_stream_message_signal(evidence_items, base_dir):
            errors.append(f"Test {test_id} is Passed as {test_type} but lacks captured stream message evidence.")

    if test_type in API_TEST_TYPES and not has_evidence_type(evidence_items, API_EVIDENCE_TYPES):
        errors.append(f"Test {test_id} is Passed as {test_type} but has no API response evidence.")

    if test_type in UI_TO_API_TEST_TYPES and not has_evidence_type(evidence_items, {"ui_to_api"}):
        errors.append(f"Test {test_id} is Passed as {test_type} but has no click-to-response evidence.")

    if test_type in PERSISTENCE_TEST_TYPES and not has_evidence_type(evidence_items, PERSISTENCE_EVIDENCE_TYPES):
        errors.append(f"Test {test_id} is Passed as {test_type} but has no persistence/log/API evidence.")

    if any(term in claim_text for term in RETURN_MARKER_REQUIRED_TERMS) and not has_return_marker_signal(evidence_items, qa_marker):
        errors.append(f"Test {test_id} is Passed with marker/stale-seed/fallback claims but lacks returned marker evidence.")

    if any(term in claim_text for term in TERMINAL_TERMS) and test_type in TERMINAL_STATUS_TEST_TYPES and not has_terminal_signal(evidence_items):
        errors.append(f"Test {test_id} is Passed with terminal/completed claims but lacks terminal-status evidence.")

    return errors


def resolve_evidence_path(base_dir: Path, raw_path: str) -> Path:
    p = Path(raw_path).expanduser()
    return p if p.is_absolute() else base_dir / p


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def file_mtime(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)


def stale_evidence_error(item_id: str, resolved: Path, run_started_at: datetime) -> str | None:
    observed = file_mtime(resolved)
    if observed.timestamp() + FRESHNESS_SKEW_SECONDS < run_started_at.timestamp():
        return (
            f"Evidence {item_id} file predates results.startedAt; possible stale artifact: "
            f"{resolved} mtime={observed.isoformat()} run_started_at={run_started_at.isoformat()}."
        )
    return None


def png_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) < 24 or not data.startswith(PNG_SIGNATURE) or data[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def jpeg_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return None
    offset = 2
    while offset < len(data):
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            return None
        marker = data[offset]
        offset += 1
        if marker in {0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7}:
            continue
        if marker == 0xDA or offset + 2 > len(data):
            return None
        segment_length = struct.unpack(">H", data[offset : offset + 2])[0]
        if segment_length < 2 or offset + segment_length > len(data):
            return None
        if marker in JPEG_SOF_MARKERS:
            if segment_length < 7:
                return None
            height = struct.unpack(">H", data[offset + 3 : offset + 5])[0]
            width = struct.unpack(">H", data[offset + 5 : offset + 7])[0]
            return width, height
        offset += segment_length
    return None


def image_dimensions(path: Path) -> tuple[str, int, int] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    dimensions = png_dimensions(data)
    if dimensions:
        return ("png", dimensions[0], dimensions[1])
    dimensions = jpeg_dimensions(data)
    if dimensions:
        return ("jpeg", dimensions[0], dimensions[1])
    return None


def screenshot_integrity_error(item_id: str, resolved: Path) -> str | None:
    dimensions = image_dimensions(resolved)
    if not dimensions:
        return f"Evidence {item_id} screenshot is not a readable PNG/JPEG image: {resolved}"
    image_format, width, height = dimensions
    if width <= 0 or height <= 0:
        return f"Evidence {item_id} screenshot has invalid {image_format.upper()} dimensions {width}x{height}: {resolved}"
    return None


def unique_resolved_paths(base_dir: Path, raw_values: list[Any]) -> list[Path]:
    paths: list[Path] = []
    seen: set[str] = set()
    for raw in raw_values:
        if not has_text(raw):
            continue
        resolved = resolve_evidence_path(base_dir, str(raw))
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        paths.append(resolved)
    return paths


def iter_path_values(value: Any):
    if has_text(value):
        yield str(value)
    elif isinstance(value, dict):
        for child in value.values():
            yield from iter_path_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_path_values(child)


def evidence_artifact_paths(evidence: list[dict[str, Any]], base_dir: Path) -> list[Path]:
    raw_values: list[Any] = []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        for field in EVIDENCE_ARTIFACT_PATH_FIELDS:
            raw_values.extend(iter_path_values(item.get(field)))
    return unique_resolved_paths(base_dir, raw_values)


def evidence_artifact_hashes(evidence: list[dict[str, Any]], base_dir: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in evidence_artifact_paths(evidence, base_dir):
        digest = file_sha256_or_none(path)
        if digest:
            hashes[str(path.resolve())] = digest
    return dict(sorted(hashes.items()))


def text_artifact_paths(
    item: dict[str, Any],
    base_dir: Path,
    explicit_keys: tuple[str, ...],
    *,
    include_generic: bool = True,
    exclude_keys: tuple[str, ...] = (),
) -> tuple[list[Path], list[str]]:
    item_id = str(item.get("id") or "unknown")
    explicit_raw = [item.get(key) for key in explicit_keys]
    paths = unique_resolved_paths(base_dir, explicit_raw)
    errors: list[str] = []
    for path in paths:
        if not path.exists():
            errors.append(f"Evidence {item_id} text artifact path is missing: {path}")
    paths = [path for path in paths if path.exists()]

    if paths or not include_generic:
        return paths, errors

    excluded = {str(path) for path in unique_resolved_paths(base_dir, [item.get(key) for key in exclude_keys])}
    generic_paths = unique_resolved_paths(base_dir, [item.get("path"), item.get("file")])
    for path in generic_paths:
        if str(path) in excluded:
            continue
        if path.exists():
            paths.append(path)
        else:
            errors.append(f"Evidence {item_id} text artifact path is missing: {path}")
    return paths, errors


def stream_message_artifact_errors(item: dict[str, Any], base_dir: Path, run_started_at: datetime | None) -> list[str]:
    if str(item.get("type") or "").lower() not in STREAM_EVIDENCE_TYPES or not has_text(item.get("messages_path")):
        return []
    item_id = str(item.get("id") or "unknown")
    resolved = resolve_evidence_path(base_dir, str(item.get("messages_path")))
    if not resolved.exists():
        return [f"Evidence {item_id} messages_path is missing: {resolved}"]
    if resolved.is_dir():
        return [f"Evidence {item_id} messages_path is a directory, not a stream message artifact: {resolved}"]
    try:
        with resolved.open("rb") as handle:
            has_content = bool(handle.read(1))
    except OSError as exc:
        return [f"Evidence {item_id} messages_path is unreadable: {resolved}: {exc}"]
    errors: list[str] = []
    if not has_content:
        errors.append(f"Evidence {item_id} messages_path is empty; no captured stream messages are present: {resolved}")
    if run_started_at and item.get("current_run") is True:
        freshness_error = stale_evidence_error(item_id, resolved, run_started_at)
        if freshness_error:
            errors.append(freshness_error)
    return errors


def read_text_artifact(path: Path) -> tuple[str | None, str | None]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, f"{path}: {exc}"
    if len(data) > TEXT_ARTIFACT_MAX_BYTES:
        data = data[:TEXT_ARTIFACT_MAX_BYTES]
    return data.decode("utf-8", errors="replace"), None


def text_assertion_artifact_errors(item: dict[str, Any], base_dir: Path) -> tuple[list[str], int]:
    item_id = str(item.get("id") or "unknown")
    specs = (
        ("message_text_contains_matched", True, ("messages_path",), (), "message text"),
        ("response_text_contains_matched", True, ("body_path", "response_body_path"), ("request_body_path",), "response text"),
        ("response_text_not_contains_matched", False, ("body_path", "response_body_path"), ("request_body_path",), "response text"),
        ("request_text_contains_matched", True, ("request_body_path",), ("body_path", "response_body_path"), "request body"),
        ("request_text_not_contains_matched", False, ("request_body_path",), ("body_path", "response_body_path"), "request body"),
        ("stdout_contains_matched", True, ("stdout_path",), ("stderr_path",), "stdout"),
        ("stderr_contains_matched", True, ("stderr_path",), ("stdout_path",), "stderr"),
    )
    errors: list[str] = []
    checked = 0
    for field, should_contain, explicit_keys, exclude_keys, label in specs:
        expected = item.get(field)
        if not has_text(expected):
            continue
        expected_text = str(expected)
        paths, path_errors = text_artifact_paths(
            item,
            base_dir,
            explicit_keys,
            include_generic=True,
            exclude_keys=exclude_keys,
        )
        errors.extend(path_errors)
        if not paths:
            if not path_errors:
                keys = ", ".join(explicit_keys)
                errors.append(f"Evidence {item_id} has {field} but no referenced {label} artifact path; add one of: {keys}.")
            continue
        checked += 1
        observed: list[tuple[Path, str]] = []
        for path in paths:
            text, read_error = read_text_artifact(path)
            if read_error:
                errors.append(f"Evidence {item_id} could not read {label} artifact for {field}: {read_error}")
                continue
            observed.append((path, text or ""))

        if should_contain:
            if not any(expected_text in text for _, text in observed):
                path_list = ", ".join(str(path) for path, _ in observed)
                errors.append(f"Evidence {item_id} {field}={expected_text!r} is not present in referenced {label} artifact(s): {path_list}")
        else:
            forbidden_hits = [path for path, text in observed if expected_text in text]
            if forbidden_hits:
                path_list = ", ".join(str(path) for path in forbidden_hits)
                errors.append(f"Evidence {item_id} {field}={expected_text!r} is still present in referenced {label} artifact(s): {path_list}")
    return errors, checked


def read_json_path(obj: Any, dotted_path: str) -> Any:
    value = obj
    for part in [item for item in str(dotted_path or "").split(".") if item]:
        if value is None:
            return None
        array_match = re.match(r"^(.+)\[(\d+)\]$", part)
        if array_match:
            if not isinstance(value, dict):
                return None
            parent = value.get(array_match.group(1))
            if not isinstance(parent, list):
                return None
            index = int(array_match.group(2))
            value = parent[index] if index < len(parent) else None
            continue
        if part.isdigit() and isinstance(value, list):
            index = int(part)
            value = value[index] if index < len(value) else None
            continue
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def parse_json_artifact(path: Path) -> tuple[list[Any], str | None]:
    text, read_error = read_text_artifact(path)
    if read_error:
        return [], read_error
    text = text or ""
    parsed_items: list[Any] = []
    try:
        parsed_items.append(json.loads(text))
    except json.JSONDecodeError:
        pass
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not any(json.dumps(existing, sort_keys=True, ensure_ascii=False) == json.dumps(item, sort_keys=True, ensure_ascii=False) for existing in parsed_items):
            parsed_items.append(item)
    return parsed_items, None


def checked_json_matches(items: list[Any], checked_json: dict[str, Any]) -> bool:
    for item in items:
        matched = True
        for json_path, expected_value in checked_json.items():
            actual_value = read_json_path(item, json_path)
            if actual_value != expected_value:
                matched = False
                break
        if matched:
            return True
    return False


def json_artifact_assertion_errors(item: dict[str, Any], base_dir: Path) -> tuple[list[str], int]:
    item_id = str(item.get("id") or "unknown")
    evidence_type = str(item.get("type") or "").lower()
    checked_json_keys = ("messages_path",) if evidence_type in STREAM_EVIDENCE_TYPES else ("body_path", "response_body_path")
    specs = (
        ("checked_json", checked_json_keys, ("request_body_path", "stdout_path", "stderr_path"), "checked JSON"),
        ("checked_request_json", ("request_body_path",), ("body_path", "response_body_path", "stdout_path", "stderr_path"), "checked request JSON"),
        ("checked_stdout_json", ("stdout_path",), ("body_path", "response_body_path", "request_body_path", "stderr_path"), "checked stdout JSON"),
    )
    errors: list[str] = []
    checked_count = 0
    for field, explicit_keys, exclude_keys, label in specs:
        checked_json = item.get(field)
        if not isinstance(checked_json, dict) or not checked_json:
            continue
        paths, path_errors = text_artifact_paths(
            item,
            base_dir,
            explicit_keys,
            include_generic=True,
            exclude_keys=exclude_keys,
        )
        errors.extend(path_errors)
        if not paths:
            if not path_errors:
                keys = ", ".join(explicit_keys)
                errors.append(f"Evidence {item_id} has {field} but no referenced {label} artifact path; add one of: {keys}.")
            continue
        checked_count += 1
        parsed_items: list[Any] = []
        artifact_errors: list[str] = []
        for path in paths:
            items, parse_error = parse_json_artifact(path)
            if parse_error:
                artifact_errors.append(f"{path}: {parse_error}")
            elif not items:
                artifact_errors.append(f"{path}: no parseable JSON object or line")
            parsed_items.extend(items)
        if artifact_errors:
            errors.append(f"Evidence {item_id} could not parse referenced artifact(s) for {field}: {'; '.join(artifact_errors)}")
            continue
        if not checked_json_matches(parsed_items, checked_json):
            path_list = ", ".join(str(path) for path in paths)
            errors.append(f"Evidence {item_id} {field} does not match referenced {label} artifact(s): {path_list}")
    return errors, checked_count


def extracted_json_artifact_errors(item: dict[str, Any], base_dir: Path) -> tuple[list[str], int]:
    item_id = str(item.get("id") or "unknown")
    evidence_type = str(item.get("type") or "").lower()
    extracted_json_keys = ("messages_path",) if evidence_type in STREAM_EVIDENCE_TYPES else ("body_path", "response_body_path")
    specs = (
        ("extracted_json", "extracted_json_paths", extracted_json_keys, ("request_body_path", "stdout_path", "stderr_path"), "extracted JSON"),
        ("extracted_stdout_json", "extracted_stdout_json_paths", ("stdout_path",), ("body_path", "response_body_path", "request_body_path", "stderr_path"), "extracted stdout JSON"),
    )
    errors: list[str] = []
    checked_count = 0
    for value_field, paths_field, explicit_keys, exclude_keys, label in specs:
        extracted = item.get(value_field)
        if not isinstance(extracted, dict) or not extracted:
            continue
        paths_map = item.get(paths_field)
        paths, path_errors = text_artifact_paths(
            item,
            base_dir,
            explicit_keys,
            include_generic=True,
            exclude_keys=exclude_keys,
        )
        errors.extend(path_errors)
        if not paths:
            continue
        checked_count += 1
        parsed_items: list[Any] = []
        artifact_errors: list[str] = []
        for path in paths:
            items, parse_error = parse_json_artifact(path)
            if parse_error:
                artifact_errors.append(f"{path}: {parse_error}")
            elif not items:
                artifact_errors.append(f"{path}: no parseable JSON object or line")
            parsed_items.extend(items)
        if artifact_errors:
            errors.append(f"Evidence {item_id} could not parse referenced artifact(s) for {value_field}: {'; '.join(artifact_errors)}")
            continue
        if not isinstance(paths_map, dict) or not paths_map:
            errors.append(f"Evidence {item_id} has {value_field} but lacks {paths_field} for source verification.")
            continue
        for name, expected_value in extracted.items():
            json_path = paths_map.get(name)
            if not has_text(json_path):
                errors.append(f"Evidence {item_id} has {value_field}.{name} but no source JSON path in {paths_field}.")
                continue
            if not any(read_json_path(parsed_item, str(json_path)) == expected_value for parsed_item in parsed_items):
                path_list = ", ".join(str(path) for path in paths)
                errors.append(f"Evidence {item_id} {value_field}.{name}={expected_value!r} does not match {json_path!r} in referenced {label} artifact(s): {path_list}")
    return errors, checked_count


def header_value(headers: dict[str, Any], name: str) -> Any:
    wanted = str(name or "").lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return value
    return None


def response_header_consistency_errors(item: dict[str, Any]) -> tuple[list[str], int]:
    item_id = str(item.get("id") or "unknown")
    headers = item.get("response_headers")
    errors: list[str] = []
    checked_count = 0

    checked_headers = item.get("checked_response_headers")
    if isinstance(checked_headers, dict) and checked_headers:
        if not isinstance(headers, dict) or not headers:
            return [f"Evidence {item_id} has checked_response_headers but lacks captured response_headers for source verification."], 0
        checked_count += 1
        for name, expected_value in checked_headers.items():
            actual_value = header_value(headers, str(name))
            if actual_value != expected_value:
                errors.append(f"Evidence {item_id} checked_response_headers.{name}={expected_value!r} does not match response_headers value {actual_value!r}.")

    extracted_headers = item.get("extracted_response_headers")
    extracted_names = item.get("extracted_response_header_names")
    if isinstance(extracted_headers, dict) and extracted_headers:
        if not isinstance(headers, dict) or not headers:
            return [f"Evidence {item_id} has extracted_response_headers but lacks captured response_headers for source verification."], checked_count
        checked_count += 1
        if not isinstance(extracted_names, dict) or not extracted_names:
            errors.append(f"Evidence {item_id} has extracted_response_headers but lacks extracted_response_header_names.")
        else:
            for var_name, expected_value in extracted_headers.items():
                header_name = extracted_names.get(var_name)
                if not has_text(header_name):
                    errors.append(f"Evidence {item_id} has extracted_response_headers.{var_name} but no header name in extracted_response_header_names.")
                    continue
                actual_value = header_value(headers, str(header_name))
                if actual_value != expected_value:
                    errors.append(f"Evidence {item_id} extracted_response_headers.{var_name}={expected_value!r} does not match response_headers[{header_name!r}] value {actual_value!r}.")
    return errors, checked_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a requirement-driven QA evidence ledger.")
    parser.add_argument("--ledger", required=True, help="Path to evidence-ledger.json")
    parser.add_argument("--matrix", help="Optional test-matrix.json to verify ledger completeness.")
    parser.add_argument("--results", help="Optional results.json to compare runtime issue disposition.")
    parser.add_argument("--base-dir", help="Base directory for relative evidence paths. Defaults to ledger directory.")
    parser.add_argument("--summary", help="Optional path to write audit-summary.json")
    parser.add_argument("--strict-runtime", action="store_true", help="Fail when probe runtime issues exist but all requirements are passed.")
    args = parser.parse_args()

    ledger_path = Path(args.ledger).expanduser().resolve()
    matrix_path = Path(args.matrix).expanduser().resolve() if args.matrix else None
    results_path = Path(args.results).expanduser().resolve() if args.results else None
    base_dir = Path(args.base_dir).expanduser().resolve() if args.base_dir else ledger_path.parent

    input_artifact_errors: list[dict[str, str]] = []
    ledger, ledger_load_error = try_load_json(ledger_path)
    matrix, matrix_load_error = try_load_json(matrix_path) if matrix_path else (None, None)
    results, results_load_error = try_load_json(results_path) if results_path else (None, None)
    for name, path, load_error in (
        ("ledger", ledger_path, ledger_load_error),
        ("matrix", matrix_path, matrix_load_error),
        ("results", results_path, results_load_error),
    ):
        if path and load_error:
            input_artifact_errors.append({"name": name, "path": str(path), "error": load_error})
    if input_artifact_errors:
        errors = [
            f"{item['name']} artifact is unreadable: {item['path']} ({item['error']})."
            for item in input_artifact_errors
        ]
        summary = {
            "ledger": str(ledger_path),
            "matrix": str(matrix_path) if matrix_path else None,
            "results": str(results_path) if results_path else None,
            "base_dir": str(base_dir),
            "artifact_hashes": {
                "ledger_sha256": None,
                "matrix_sha256": None,
                "results_sha256": None,
                "evidence_artifacts_sha256": {},
            },
            "requirement_count": 0,
            "test_count": 0,
            "evidence_count": 0,
            "evidence_freshness_checked": False,
            "passed_evidence_current_run_checked": False,
            "screenshot_integrity_checked": False,
            "screenshot_evidence_checked": 0,
            "text_artifact_assertions_checked": 0,
            "json_artifact_assertions_checked": 0,
            "extraction_artifact_assertions_checked": 0,
        "response_header_consistency_checked": 0,
        "evidence_lineage_checked": 0,
        "evidence_lineage_warning_count": 0,
        "runner_result_binding_checked": 0,
        "requirement_status_consistency_checked": 0,
            "status_counts": {status: 0 for status in sorted(ALLOWED_STATUSES)},
            "passed": False,
            "errors": errors,
            "warnings": [],
            "input_artifact_errors": input_artifact_errors,
        }
        write_summary(args.summary, summary)
        print(json.dumps(summary, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1
    assert ledger is not None
    run_started_at = parse_timestamp((results or {}).get("startedAt")) if results else None
    result_steps = collect_result_steps(results)

    requirements = as_list(ledger.get("requirements"))
    tests = as_list(ledger.get("tests"))
    evidence = as_list(ledger.get("evidence"))
    runtime_summary = ledger.get("runtime_summary") if isinstance(ledger.get("runtime_summary"), dict) else {}
    qa_marker = runtime_summary.get("qa_marker")

    errors: list[str] = []
    warnings: list[str] = []
    screenshot_evidence_checked = 0
    text_artifact_assertions_checked = 0
    json_artifact_assertions_checked = 0
    extraction_artifact_assertions_checked = 0
    response_header_consistency_checked = 0
    evidence_lineage_checked = 0
    evidence_lineage_warning_count = 0
    runner_result_binding_checked = 0
    requirement_status_consistency_checked = 0

    for location, text in iter_strings(ledger):
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            errors.append(f"Secret-like value found in ledger at {location}; redact before reporting.")

    if not requirements:
        errors.append("ledger.requirements is empty; cannot prove requirement coverage.")

    req_by_id = {}
    for req in requirements:
        req_id = req.get("id")
        if has_text(req_id):
            if req_id in req_by_id:
                errors.append(f"Duplicate requirement id: {req_id}")
            req_by_id[req_id] = req

    test_by_id = {}
    for item in tests:
        item_id = item.get("id")
        if not has_text(item_id):
            errors.append("A test entry is missing id.")
            continue
        if item_id in test_by_id:
            errors.append(f"Duplicate test id: {item_id}")
        test_by_id[item_id] = item

    evidence_by_id = {}
    for item in evidence:
        item_id = item.get("id")
        if not has_text(item_id):
            errors.append("An evidence entry is missing id.")
            continue
        if item_id in evidence_by_id:
            errors.append(f"Duplicate evidence id: {item_id}")
        evidence_by_id[item_id] = item

        evidence_type = item.get("type")
        if not has_text(evidence_type):
            errors.append(f"Evidence {item_id} is missing type.")
        if not has_text(item.get("proves")):
            errors.append(f"Evidence {item_id} is missing `proves` text.")
        elif has_todo(item.get("proves")):
            errors.append(f"Evidence {item_id} has TODO text in `proves`.")

        raw_path = item.get("path") or item.get("file")
        if has_text(raw_path):
            resolved = resolve_evidence_path(base_dir, raw_path)
            if not resolved.exists():
                errors.append(f"Evidence {item_id} points to missing file: {resolved}")
            else:
                if evidence_type == "screenshot":
                    screenshot_evidence_checked += 1
                    integrity_error = screenshot_integrity_error(item_id, resolved)
                    if integrity_error:
                        errors.append(integrity_error)
                if run_started_at and item.get("current_run") is True:
                    freshness_error = stale_evidence_error(item_id, resolved, run_started_at)
                    if freshness_error:
                        errors.append(freshness_error)
        elif evidence_type in {"screenshot", "file", "log_file", "trace", "video"}:
            errors.append(f"Evidence {item_id} type {evidence_type} requires path or file.")

        if not has_locator(item):
            errors.append(f"Evidence {item_id} needs one locator field: path, url, file, log_ref, or value.")
        if evidence_type in {"api_response", "cleanup"} and not (item.get("status_code") is not None or item.get("checked_json") or as_list(item.get("assertions"))):
            errors.append(f"Evidence {item_id} is {evidence_type} but lacks status_code, checked_json, or assertions.")
        if evidence_type in {"websocket", "sse"} and not (item.get("messages_seen") is not None or as_list(item.get("assertions")) or has_text(raw_path)):
            errors.append(f"Evidence {item_id} is {evidence_type} but lacks messages_seen, assertions, or captured message file.")
        if evidence_type == "command" and not (item.get("exit_code") is not None or as_list(item.get("assertions")) or has_text(raw_path)):
            errors.append(f"Evidence {item_id} is command but lacks exit_code, assertions, or captured output file.")
        errors.extend(stream_message_artifact_errors(item, base_dir, run_started_at))
        text_errors, text_checked = text_assertion_artifact_errors(item, base_dir)
        errors.extend(text_errors)
        text_artifact_assertions_checked += text_checked
        json_errors, json_checked = json_artifact_assertion_errors(item, base_dir)
        errors.extend(json_errors)
        json_artifact_assertions_checked += json_checked
        extraction_errors, extraction_checked = extracted_json_artifact_errors(item, base_dir)
        errors.extend(extraction_errors)
        extraction_artifact_assertions_checked += extraction_checked
        header_errors, header_checked = response_header_consistency_errors(item)
        errors.extend(header_errors)
        response_header_consistency_checked += header_checked
        if results and evidence_requires_lineage(item):
            runner_result_binding_checked += 1
            binding_error = runner_result_binding_error(item, result_steps, base_dir)
            if binding_error:
                errors.append(binding_error)

    for req in requirements:
        req_id = req.get("id")
        if not has_text(req_id):
            errors.append("A requirement entry is missing id.")
            continue
        if not has_text(req.get("source")):
            errors.append(f"Requirement {req_id} is missing source.")
        if not has_text(req.get("text")):
            errors.append(f"Requirement {req_id} is missing text.")
        elif has_todo(req.get("text")):
            errors.append(f"Requirement {req_id} still contains TODO text.")

        status = req.get("status")
        if status not in ALLOWED_STATUSES:
            errors.append(f"Requirement {req_id} has invalid status: {status!r}")

        test_ids = [tid for tid in as_list(req.get("test_ids")) if has_text(tid)]
        if not test_ids:
            errors.append(f"Requirement {req_id} has no mapped tests.")
        for test_id in test_ids:
            if test_id not in test_by_id:
                errors.append(f"Requirement {req_id} references missing test {test_id}.")

        status_errors, status_checked = requirement_status_consistency_errors(req, test_by_id)
        errors.extend(status_errors)
        requirement_status_consistency_checked += status_checked

        evidence_ids = [eid for eid in as_list(req.get("evidence_ids")) if has_text(eid)]
        if status == PASSED and not evidence_ids:
            errors.append(f"Requirement {req_id} is Passed without evidence.")
        if status != PASSED and not has_text(req.get("notes")):
            errors.append(f"Requirement {req_id} is {status} but has no explanatory notes.")
        for evidence_id in evidence_ids:
            if evidence_id not in evidence_by_id:
                errors.append(f"Requirement {req_id} references missing evidence {evidence_id}.")
            elif status == PASSED:
                ev = evidence_by_id[evidence_id]
                disposition_error = passed_evidence_disposition_error("Requirement", req_id, evidence_id, ev)
                if disposition_error:
                    errors.append(disposition_error)
                if not is_current_run_evidence(ev):
                    errors.append(f"Requirement {req_id} is Passed but evidence {evidence_id} is not marked current_run=true.")
                if not has_assertion_signal(ev):
                    errors.append(f"Requirement {req_id} is Passed but evidence {evidence_id} has no assertion signal.")
                lineage_errors, lineage_warnings, lineage_checked = requirement_lineage_findings(req, ev)
                errors.extend(lineage_errors)
                warnings.extend(lineage_warnings)
                evidence_lineage_warning_count += len(lineage_warnings)
                if lineage_checked:
                    evidence_lineage_checked += 1

    for test in tests:
        test_id = test.get("id")
        if not has_text(test_id):
            continue
        status = test.get("status")
        if status not in ALLOWED_STATUSES:
            errors.append(f"Test {test_id} has invalid status: {status!r}")
        requirement_ids = [rid for rid in as_list(test.get("requirement_ids")) if has_text(rid)]
        if not requirement_ids:
            errors.append(f"Test {test_id} maps to no requirements.")
        if not has_text(test.get("expected")):
            errors.append(f"Test {test_id} is missing expected behavior.")
        elif has_todo(test.get("expected")):
            errors.append(f"Test {test_id} expected behavior still contains TODO text.")

        evidence_ids = [eid for eid in as_list(test.get("evidence_ids")) if has_text(eid)]
        if status == PASSED and not evidence_ids:
            errors.append(f"Test {test_id} is Passed without evidence.")
        if status != PASSED and not has_text(test.get("notes")):
            errors.append(f"Test {test_id} is {status} but has no explanatory notes.")
        resolved_evidence_items: list[dict[str, Any]] = []
        for evidence_id in evidence_ids:
            if evidence_id not in evidence_by_id:
                errors.append(f"Test {test_id} references missing evidence {evidence_id}.")
            elif status == PASSED:
                ev = evidence_by_id[evidence_id]
                resolved_evidence_items.append(ev)
                disposition_error = passed_evidence_disposition_error("Test", test_id, evidence_id, ev)
                if disposition_error:
                    errors.append(disposition_error)
                if not is_current_run_evidence(ev):
                    errors.append(f"Test {test_id} is Passed but evidence {evidence_id} is not marked current_run=true.")
                if not has_assertion_signal(ev):
                    errors.append(f"Test {test_id} is Passed but evidence {evidence_id} has no assertion signal.")
                lineage_errors, lineage_warnings, lineage_checked = test_lineage_findings(test, ev)
                errors.extend(lineage_errors)
                warnings.extend(lineage_warnings)
                evidence_lineage_warning_count += len(lineage_warnings)
                if lineage_checked:
                    evidence_lineage_checked += 1
        if status == PASSED and resolved_evidence_items:
            errors.extend(evidence_layer_errors(test, resolved_evidence_items, base_dir, qa_marker))

    if matrix:
        matrix_req_ids = {item.get("id") for item in as_list(matrix.get("requirements")) if has_text(item.get("id"))}
        matrix_test_ids = {item.get("id") for item in as_list(matrix.get("tests")) if has_text(item.get("id"))}
        for req_id in sorted(matrix_req_ids):
            if req_id not in req_by_id:
                errors.append(f"Matrix requirement {req_id} is missing from evidence ledger.")
        for test_id in sorted(matrix_test_ids):
            if test_id not in test_by_id:
                errors.append(f"Matrix test {test_id} is missing from evidence ledger.")
        for req in as_list(matrix.get("requirements")):
            req_id = req.get("id")
            matrix_test_refs = {tid for tid in as_list(req.get("test_ids")) if has_text(tid)}
            ledger_test_refs = {tid for tid in as_list(req_by_id.get(req_id, {}).get("test_ids")) if has_text(tid)}
            missing_refs = matrix_test_refs - ledger_test_refs
            for test_id in sorted(missing_refs):
                errors.append(f"Ledger requirement {req_id} is missing matrix test mapping {test_id}.")

    if results:
        console_error_count = len([item for item in as_list(results.get("console")) if item.get("type") == "error"])
        failed_response_count = len(as_list(results.get("failedResponses")))
        request_failure_count = len(as_list(results.get("requestFailures")))
        runtime_issue_count = console_error_count + failed_response_count + request_failure_count
        if runtime_issue_count:
            message = f"Probe results contain {runtime_issue_count} runtime issue(s); final report must disposition them."
            undispositioned: list[str] = []
            runtime_disposition_errors: list[str] = []
            if console_error_count:
                disposed, disposition_errors = runtime_disposition_status(
                    evidence,
                    checked_field="checked_console_errors",
                    ignored_field="ignored_console_errors",
                    observed_count=console_error_count,
                    label="console error(s)",
                )
                runtime_disposition_errors.extend(disposition_errors)
                if not disposed:
                    undispositioned.append(f"console_errors={console_error_count}")
            if failed_response_count:
                disposed, disposition_errors = runtime_disposition_status(
                    evidence,
                    checked_field="checked_failed_responses",
                    ignored_field="ignored_failed_responses",
                    observed_count=failed_response_count,
                    label="failed HTTP response(s)",
                )
                runtime_disposition_errors.extend(disposition_errors)
                if not disposed:
                    undispositioned.append(f"failed_responses={failed_response_count}")
            if request_failure_count:
                disposed, disposition_errors = runtime_disposition_status(
                    evidence,
                    checked_field="checked_request_failures",
                    ignored_field="ignored_request_failures",
                    observed_count=request_failure_count,
                    label="request failure(s)",
                )
                runtime_disposition_errors.extend(disposition_errors)
                if not disposed:
                    undispositioned.append(f"request_failures={request_failure_count}")
            errors.extend(runtime_disposition_errors)
            if args.strict_runtime and all(req.get("status") == PASSED for req in requirements) and undispositioned:
                errors.append(message + " Missing runtime disposition for " + ", ".join(undispositioned) + ".")
            else:
                warnings.append(message)

    total = len(requirements)
    counts = {status: 0 for status in sorted(ALLOWED_STATUSES)}
    for req in requirements:
        status = req.get("status")
        if status in counts:
            counts[status] += 1

    summary = {
        "ledger": str(ledger_path),
        "matrix": str(matrix_path) if matrix_path else None,
        "results": str(results_path) if results_path else None,
        "base_dir": str(base_dir),
        "artifact_hashes": {
            "ledger_sha256": file_sha256(ledger_path),
            "matrix_sha256": file_sha256(matrix_path) if matrix_path else None,
            "results_sha256": file_sha256(results_path) if results_path else None,
            "evidence_artifacts_sha256": evidence_artifact_hashes(evidence, base_dir),
        },
        "requirement_count": total,
        "test_count": len(tests),
        "evidence_count": len(evidence),
        "evidence_freshness_checked": bool(run_started_at),
        "passed_evidence_current_run_checked": True,
        "screenshot_integrity_checked": True,
        "screenshot_evidence_checked": screenshot_evidence_checked,
        "text_artifact_assertions_checked": text_artifact_assertions_checked,
        "json_artifact_assertions_checked": json_artifact_assertions_checked,
        "extraction_artifact_assertions_checked": extraction_artifact_assertions_checked,
        "response_header_consistency_checked": response_header_consistency_checked,
        "evidence_lineage_checked": evidence_lineage_checked,
        "evidence_lineage_warning_count": evidence_lineage_warning_count,
        "runner_result_binding_checked": runner_result_binding_checked,
        "requirement_status_consistency_checked": requirement_status_consistency_checked,
        "status_counts": counts,
        "passed": not errors,
        "errors": errors,
        "warnings": warnings,
        "input_artifact_errors": input_artifact_errors,
    }

    write_summary(args.summary, summary)

    if errors:
        print(json.dumps(summary, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
