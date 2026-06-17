#!/usr/bin/env python3
import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


STATUSES = ("Passed", "Failed", "Blocked", "Untested", "Inconclusive")
UNCONFIRMED_BOUNDARY_VALUES = {
    "",
    "unconfirmed",
    "unknown",
    "unset",
    "todo",
    "tbd",
    "must be stated before pass/fail",
    "must be stated",
}
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


def try_load_json(path: Path | None) -> tuple[dict[str, Any] | None, str | None]:
    if not path or not path.exists():
        return None, None
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


def load_json(path: Path | None) -> dict[str, Any] | None:
    value, _ = try_load_json(path)
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def file_sha256(path: Path) -> str | None:
    if path.is_dir():
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def id_set(value: Any) -> set[str]:
    if isinstance(value, list):
        items = value
    else:
        items = [value]
    return {str(item).strip() for item in items if has_text(item)}


def ledger_status_counts(ledger: dict[str, Any] | None) -> dict[str, int]:
    counts = Counter()
    for item in as_list((ledger or {}).get("requirements")):
        if item.get("status") in STATUSES:
            counts[item["status"]] += 1
    return {status: counts.get(status, 0) for status in STATUSES}


def status_counts(ledger: dict[str, Any] | None, audit_summary: dict[str, Any] | None) -> dict[str, int]:
    if ledger:
        return ledger_status_counts(ledger)
    if audit_summary and isinstance(audit_summary.get("status_counts"), dict):
        return {status: int(audit_summary.get("status_counts", {}).get(status, 0) or 0) for status in STATUSES}
    return {status: 0 for status in STATUSES}


def runtime_issue_counts(results: dict[str, Any] | None) -> dict[str, int]:
    if not results:
        return {"console_errors": 0, "failed_responses": 0, "request_failures": 0, "total": 0}
    console_errors = len([item for item in as_list(results.get("console")) if item.get("type") == "error"])
    failed_responses = len(as_list(results.get("failedResponses")))
    request_failures = len(as_list(results.get("requestFailures")))
    return {
        "console_errors": console_errors,
        "failed_responses": failed_responses,
        "request_failures": request_failures,
        "total": console_errors + failed_responses + request_failures,
    }


def nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


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
    findings = as_list(defects.get("findings"))
    summary_declared = "finding_count" in summary
    summary_count = nonnegative_int(summary.get("finding_count")) if summary_declared else None
    findings_count = len(findings)
    effective_count = max(summary_count or 0, findings_count)
    severity_counts = summary.get("severity_counts") if isinstance(summary.get("severity_counts"), dict) else {}
    if findings and (not severity_counts or summary_count != findings_count):
        counted = Counter(str(item.get("severity") or "unknown") for item in findings if isinstance(item, dict))
        severity_counts = dict(sorted(counted.items()))
    return {
        "finding_count": effective_count,
        "summary_count": summary_count,
        "findings_count": findings_count,
        "invalid_summary_count": summary_declared and summary_count is None,
        "severity_counts": severity_counts,
    }


def runtime_issue_dispositioned(
    evidence: list[dict[str, Any]],
    *,
    checked_field: str,
    ignored_field: str,
    observed_count: int,
) -> bool:
    if observed_count <= 0:
        return True
    for item in evidence:
        if item.get("type") != "runtime":
            continue
        checked = nonnegative_int(item.get(checked_field))
        ignored = nonnegative_int(item.get(ignored_field))
        ignored_count = ignored if ignored is not None else 0
        if checked == 0 and ignored_count == observed_count:
            return True
    return False


def runtime_disposition(ledger: dict[str, Any] | None, runtime_counts: dict[str, int]) -> dict[str, bool]:
    evidence = as_list((ledger or {}).get("evidence"))
    return {
        "console_errors": runtime_issue_dispositioned(
            evidence,
            checked_field="checked_console_errors",
            ignored_field="ignored_console_errors",
            observed_count=runtime_counts.get("console_errors", 0),
        ),
        "failed_responses": runtime_issue_dispositioned(
            evidence,
            checked_field="checked_failed_responses",
            ignored_field="ignored_failed_responses",
            observed_count=runtime_counts.get("failed_responses", 0),
        ),
        "request_failures": runtime_issue_dispositioned(
            evidence,
            checked_field="checked_request_failures",
            ignored_field="ignored_request_failures",
            observed_count=runtime_counts.get("request_failures", 0),
        ),
    }


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
    evidence_req_ids = id_set(evidence_item.get("requirement_ids"))
    evidence_test_ids = id_set(evidence_item.get("test_ids"))
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


def resolve_artifact_path(base_dir: Path | None, value: str) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute() or base_dir is None:
        return path.resolve()
    return (base_dir / path).resolve()


def iter_path_values(value: Any):
    if has_text(value):
        yield str(value)
    elif isinstance(value, dict):
        for child in value.values():
            yield from iter_path_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_path_values(child)


def evidence_artifact_paths(evidence: list[dict[str, Any]], base_dir: Path | None) -> list[Path]:
    paths: list[Path] = []
    seen: set[str] = set()
    for item in evidence:
        if not isinstance(item, dict):
            continue
        for field in EVIDENCE_ARTIFACT_PATH_FIELDS:
            for raw in iter_path_values(item.get(field)):
                resolved = resolve_artifact_path(base_dir, raw)
                key = str(resolved)
                if key in seen:
                    continue
                seen.add(key)
                paths.append(resolved)
    return paths


def path_values_equal(base_dir: Path | None, evidence_value: Any, step_value: Any) -> bool:
    if not has_text(evidence_value) or not has_text(step_value):
        return evidence_value == step_value
    return resolve_artifact_path(base_dir, str(evidence_value)) == resolve_artifact_path(base_dir, str(step_value))


def runner_step_fields_match(evidence_item: dict[str, Any], step: dict[str, Any], base_dir: Path | None) -> bool:
    for evidence_key, step_key in RUNNER_STEP_FIELD_MAP:
        if step_key in step and step.get(step_key) is not None and evidence_key not in evidence_item:
            return False
        if evidence_key in evidence_item and (step_key not in step or evidence_item.get(evidence_key) != step.get(step_key)):
            return False
    for evidence_key, step_key in RUNNER_STEP_PATH_FIELD_MAP:
        if has_text(step.get(step_key)) and evidence_key not in evidence_item:
            return False
        if evidence_key in evidence_item and (step_key not in step or not path_values_equal(base_dir, evidence_item.get(evidence_key), step.get(step_key))):
            return False
    return True


def runner_result_binding_missing(evidence_item: dict[str, Any], result_steps: list[dict[str, Any]], base_dir: Path | None) -> bool:
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
        return True
    status_candidates = [step for step in candidates if not status or str(step.get("status") or "").strip() == status]
    if not status_candidates:
        return True
    return not any(runner_step_fields_match(evidence_item, step, base_dir) for step in status_candidates)


def unbound_runner_evidence_ids(ledger: dict[str, Any] | None, results: dict[str, Any] | None, results_path: Path | None, limit: int = 12) -> list[str]:
    if not ledger or not results:
        return []
    base_dir = Path(results.get("artifactDir")).expanduser().resolve() if has_text(results.get("artifactDir")) else (results_path.parent.resolve() if results_path else None)
    result_steps = collect_result_steps(results)
    refs: list[str] = []
    for item in as_list(ledger.get("evidence")):
        if str(item.get("generated_by") or "").strip() != "ledger_from_probe.py":
            continue
        if runner_result_binding_missing(item, result_steps, base_dir):
            refs.append(str(item.get("id") or "unknown"))
    return refs[:limit]


def normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def boundary_field_confirmed(value: Any) -> bool:
    text = normalize_text(value)
    return bool(text) and text not in UNCONFIRMED_BOUNDARY_VALUES


def environment_boundary_issues(adapter_context: dict[str, Any] | None, *, required: bool) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if not adapter_context:
        if required:
            issues.append(
                {
                    "code": "missing_environment_boundary",
                    "message": "Environment boundary was required but adapter-context.json was not provided.",
                    "refs": ["adapter-context.json"],
                }
            )
        return issues

    boundary = adapter_context.get("environment_boundary") or {}
    runtime_mode = boundary.get("runtime_mode")
    data_boundary_status = boundary.get("data_boundary_status")
    if not boundary_field_confirmed(runtime_mode):
        issues.append(
            {
                "code": "environment_unconfirmed",
                "message": "Runtime mode is unconfirmed; state local/test/staging/prod before final pass/fail.",
                "refs": ["adapter-context.json"],
            }
        )
    if required and not boundary_field_confirmed(data_boundary_status):
        issues.append(
            {
                "code": "data_boundary_unconfirmed",
                "message": "Data boundary is unconfirmed; state whether data is local seed, test, staging, production, mock, or real before final pass/fail.",
                "refs": ["adapter-context.json"],
            }
        )
    return issues


def add_reason(reasons: list[dict[str, Any]], code: str, category: str, severity: str, message: str, refs: list[str] | None = None) -> None:
    reasons.append(
        {
            "code": code,
            "category": category,
            "severity": severity,
            "message": message,
            "refs": refs or [],
        }
    )


def path_matches(recorded: Any, expected: Path | None) -> bool:
    if not recorded or not expected:
        return False
    try:
        return Path(str(recorded)).expanduser().resolve() == expected
    except OSError:
        return False


def resolved_path(value: Any) -> Path | None:
    if not value:
        return None
    try:
        return Path(str(value)).expanduser().resolve()
    except OSError:
        return None


def add_results_artifact_dir_reasons(
    reasons: list[dict[str, Any]],
    *,
    results: dict[str, Any] | None,
    results_path: Path | None,
    ledger_path: Path | None,
) -> None:
    if not results:
        return
    artifact_dir = resolved_path(results.get("artifactDir"))
    if not artifact_dir:
        return
    expected_dir = ledger_path.parent.resolve() if ledger_path else (results_path.parent.resolve() if results_path else None)
    if expected_dir and artifact_dir != expected_dir:
        add_reason(
            reasons,
            "results_artifact_dir_mismatch",
            "artifact",
            "gap",
            f"results.json artifactDir={artifact_dir} does not match the current run artifact directory {expected_dir}; rerun probes or regenerate results before claiming pass.",
            ["results.json", str(artifact_dir), str(expected_dir)],
        )
    if results_path and artifact_dir != results_path.parent.resolve():
        add_reason(
            reasons,
            "results_artifact_dir_not_results_parent",
            "artifact",
            "gap",
            f"results.json artifactDir={artifact_dir} does not match results.json parent {results_path.parent.resolve()}; relative runner artifacts may resolve to another run.",
            ["results.json", str(artifact_dir), str(results_path.parent.resolve())],
        )


def add_artifact_binding_reasons(
    reasons: list[dict[str, Any]],
    *,
    ledger: dict[str, Any] | None,
    ledger_path: Path | None,
    audit: dict[str, Any] | None,
    results_path: Path | None,
) -> None:
    if not audit:
        return
    audit_hashes = audit.get("artifact_hashes") if isinstance(audit.get("artifact_hashes"), dict) else {}
    if not audit.get("matrix"):
        add_reason(
            reasons,
            "audit_matrix_unbound",
            "artifact",
            "gap",
            "Audit summary does not declare the test-matrix.json it audited; rerun audit_evidence.py with --matrix before generating the final verdict.",
            ["audit-summary.json", "test-matrix.json"],
        )
    else:
        matrix_path = Path(str(audit.get("matrix"))).expanduser().resolve()
        matrix_hash = audit_hashes.get("matrix_sha256")
        if not matrix_hash:
            add_reason(
                reasons,
                "audit_matrix_hash_missing",
                "artifact",
                "gap",
                "Audit summary has no matrix content hash; rerun audit_evidence.py with --matrix before generating the final verdict.",
                ["audit-summary.json", "test-matrix.json"],
            )
        elif not matrix_path.exists():
            add_reason(
                reasons,
                "audit_matrix_missing",
                "artifact",
                "gap",
                "Audit summary references a test-matrix.json path that no longer exists.",
                ["audit-summary.json", "test-matrix.json"],
            )
        else:
            current_matrix_hash = file_sha256(matrix_path)
            if current_matrix_hash is None:
                add_reason(
                    reasons,
                    "audit_matrix_unreadable",
                    "artifact",
                    "gap",
                    "Audit summary references a test-matrix.json path that cannot be read for content-hash verification.",
                    ["audit-summary.json", "test-matrix.json"],
                )
            elif matrix_hash != current_matrix_hash:
                add_reason(
                    reasons,
                    "audit_matrix_hash_mismatch",
                    "artifact",
                    "gap",
                    "Audit summary hash does not match the current test-matrix.json; the matrix changed after audit.",
                    ["audit-summary.json", "test-matrix.json"],
                )
    if ledger_path:
        if not audit.get("ledger"):
            add_reason(
                reasons,
                "audit_ledger_unbound",
                "artifact",
                "gap",
                "Audit summary does not declare the ledger it audited; rerun audit_evidence.py for the current ledger.",
                ["audit-summary.json", "evidence-ledger.json"],
            )
        elif not path_matches(audit.get("ledger"), ledger_path):
            add_reason(
                reasons,
                "audit_ledger_path_mismatch",
                "artifact",
                "gap",
                "Audit summary was generated for a different evidence-ledger.json path.",
                ["audit-summary.json", "evidence-ledger.json"],
            )
        ledger_hash = audit_hashes.get("ledger_sha256")
        if not ledger_hash:
            add_reason(
                reasons,
                "audit_ledger_hash_missing",
                "artifact",
                "gap",
                "Audit summary has no ledger content hash; rerun audit_evidence.py before generating the final verdict.",
                ["audit-summary.json", "evidence-ledger.json"],
            )
        elif ledger_path.exists():
            current_ledger_hash = file_sha256(ledger_path)
            if current_ledger_hash is None:
                add_reason(
                    reasons,
                    "audit_ledger_unreadable",
                    "artifact",
                    "gap",
                    "Audit summary references an evidence-ledger.json path that cannot be read for content-hash verification.",
                    ["audit-summary.json", "evidence-ledger.json"],
                )
            elif ledger_hash != current_ledger_hash:
                add_reason(
                    reasons,
                    "audit_ledger_hash_mismatch",
                    "artifact",
                    "gap",
                    "Audit summary hash does not match the current evidence-ledger.json; the ledger changed after audit.",
                    ["audit-summary.json", "evidence-ledger.json"],
                )
    if results_path:
        if not audit.get("results"):
            add_reason(
                reasons,
                "audit_results_unbound",
                "artifact",
                "gap",
                "Probe results were provided to verdict generation, but the audit summary was not run against results.json.",
                ["audit-summary.json", "results.json"],
            )
        elif not path_matches(audit.get("results"), results_path):
            add_reason(
                reasons,
                "audit_results_path_mismatch",
                "artifact",
                "gap",
                "Audit summary was generated for a different results.json path.",
                ["audit-summary.json", "results.json"],
            )
        results_hash = audit_hashes.get("results_sha256")
        if not results_hash:
            add_reason(
                reasons,
                "audit_results_hash_missing",
                "artifact",
                "gap",
                "Audit summary has no results content hash; rerun audit_evidence.py with --results before generating the final verdict.",
                ["audit-summary.json", "results.json"],
            )
        elif results_path.exists():
            current_results_hash = file_sha256(results_path)
            if current_results_hash is None:
                add_reason(
                    reasons,
                    "audit_results_unreadable",
                    "artifact",
                    "gap",
                    "Audit summary references a results.json path that cannot be read for content-hash verification.",
                    ["audit-summary.json", "results.json"],
                )
            elif results_hash != current_results_hash:
                add_reason(
                    reasons,
                    "audit_results_hash_mismatch",
                    "artifact",
                    "gap",
                    "Audit summary hash does not match the current results.json; probe results changed after audit.",
                    ["audit-summary.json", "results.json"],
                )
    elif audit.get("results"):
        add_reason(
            reasons,
            "audit_results_omitted",
            "artifact",
            "gap",
            "Audit summary was generated with results.json, but verdict generation omitted --results; runtime evidence cannot be safely evaluated.",
            ["audit-summary.json", "results.json"],
        )
    if ledger and isinstance(audit.get("status_counts"), dict):
        current_counts = ledger_status_counts(ledger)
        audit_counts = {status: int(audit.get("status_counts", {}).get(status, 0) or 0) for status in STATUSES}
        if audit_counts != current_counts:
            add_reason(
                reasons,
                "audit_status_counts_mismatch",
                "artifact",
                "gap",
                "Audit summary status_counts do not match the current ledger requirement statuses.",
                ["audit-summary.json", "evidence-ledger.json"],
            )
    if ledger:
        evidence_artifact_hashes = audit_hashes.get("evidence_artifacts_sha256")
        current_artifact_paths = evidence_artifact_paths(
            as_list(ledger.get("evidence")),
            ledger_path.parent.resolve() if ledger_path else None,
        )
        if current_artifact_paths and not isinstance(evidence_artifact_hashes, dict):
            add_reason(
                reasons,
                "audit_evidence_artifact_hashes_missing",
                "artifact",
                "gap",
                "Audit summary has no evidence artifact content hashes; rerun audit_evidence.py before generating the final verdict.",
                ["audit-summary.json", "evidence artifacts"],
            )
        elif isinstance(evidence_artifact_hashes, dict):
            for artifact_path in current_artifact_paths:
                path_key = str(artifact_path.resolve())
                audit_hash = evidence_artifact_hashes.get(path_key)
                current_hash = file_sha256(artifact_path)
                if current_hash is None:
                    add_reason(
                        reasons,
                        "audit_evidence_artifact_unreadable",
                        "artifact",
                        "gap",
                        "Audit summary references an evidence artifact path that cannot be read for content-hash verification.",
                        ["audit-summary.json", path_key],
                    )
                elif not audit_hash:
                    add_reason(
                        reasons,
                        "audit_evidence_artifact_hash_missing",
                        "artifact",
                        "gap",
                        "Audit summary did not hash a current evidence artifact; rerun audit_evidence.py before generating the final verdict.",
                        ["audit-summary.json", path_key],
                    )
                elif audit_hash != current_hash:
                    add_reason(
                        reasons,
                        "audit_evidence_artifact_hash_mismatch",
                        "artifact",
                        "gap",
                        "Audit summary hash does not match a current evidence artifact; the evidence file changed after audit.",
                        ["audit-summary.json", path_key],
                    )
        expected_counts = {
            "requirement_count": len(as_list(ledger.get("requirements"))),
            "test_count": len(as_list(ledger.get("tests"))),
            "evidence_count": len(as_list(ledger.get("evidence"))),
        }
        for field, expected in expected_counts.items():
            if audit.get(field) is not None and int(audit.get(field) or 0) != expected:
                add_reason(
                    reasons,
                    f"audit_{field}_mismatch",
                    "artifact",
                    "gap",
                    f"Audit summary {field}={audit.get(field)!r} does not match the current ledger value {expected}.",
                    ["audit-summary.json", "evidence-ledger.json"],
                )


def sibling_artifact_path(ledger_path: Path | None, filename: str) -> Path | None:
    if not ledger_path:
        return None
    return ledger_path.parent / filename


SIBLING_VERDICT_ARTIFACTS = {
    "defects.json": (
        "defects_omitted",
        "defects_sibling_path_mismatch",
        "defects.json exists beside the current ledger but was omitted from verdict generation.",
    ),
    "requirement-coverage.json": (
        "requirement_coverage_omitted",
        "requirement_coverage_sibling_path_mismatch",
        "requirement-coverage.json exists beside the current ledger but was omitted from verdict generation.",
    ),
    "plan-audit-summary.json": (
        "plan_audit_omitted",
        "plan_audit_sibling_path_mismatch",
        "plan-audit-summary.json exists beside the current ledger but was omitted from verdict generation.",
    ),
    "service-preflight.json": (
        "service_preflight_omitted",
        "service_preflight_sibling_path_mismatch",
        "service-preflight.json exists beside the current ledger but was omitted from verdict generation.",
    ),
    "service-runtime.json": (
        "service_runtime_omitted",
        "service_runtime_sibling_path_mismatch",
        "service-runtime.json exists beside the current ledger but was omitted from verdict generation.",
    ),
    "adapter-probes.json": (
        "adapter_probes_omitted",
        "adapter_probes_sibling_path_mismatch",
        "adapter-probes.json exists beside the current ledger but was omitted from verdict generation.",
    ),
    "adapter-context.json": (
        "adapter_context_omitted",
        "adapter_context_sibling_path_mismatch",
        "adapter-context.json exists beside the current ledger but was omitted from verdict generation.",
    ),
    "qa-cycle-error.json": (
        "cycle_error_omitted",
        "cycle_error_sibling_path_mismatch",
        "qa-cycle-error.json exists beside the current ledger but was omitted from verdict generation.",
    ),
}


def add_sibling_artifact_reasons(
    reasons: list[dict[str, Any]],
    *,
    ledger_path: Path | None,
    provided_paths: dict[str, Path | None],
) -> None:
    for filename, (omitted_code, mismatch_code, omitted_message) in SIBLING_VERDICT_ARTIFACTS.items():
        sibling_path = sibling_artifact_path(ledger_path, filename)
        if not sibling_path or not sibling_path.exists():
            continue
        provided_path = provided_paths.get(filename)
        if not provided_path:
            add_reason(reasons, omitted_code, "artifact", "gap", omitted_message, [filename])
        elif not path_matches(provided_path, sibling_path):
            add_reason(
                reasons,
                mismatch_code,
                "artifact",
                "gap",
                f"{filename} exists beside the current ledger at {sibling_path}, but verdict generation used {provided_path}. Use the current run artifact before claiming pass.",
                [filename, str(sibling_path), str(provided_path)],
            )


def requirement_refs(ledger: dict[str, Any] | None, status: str, limit: int = 12) -> list[str]:
    refs = []
    for item in as_list((ledger or {}).get("requirements")):
        if item.get("status") == status and item.get("id"):
            refs.append(str(item["id"]))
    return refs[:limit]


def strategy_gap_refs(plan_audit: dict[str, Any] | None, limit: int = 12) -> list[str]:
    coverage = (plan_audit or {}).get("strategy_coverage")
    if not isinstance(coverage, dict):
        return []
    refs: list[str] = []
    for item in as_list(coverage.get("gaps")):
        if not isinstance(item, dict):
            continue
        label = str(item.get("dimension") or "strategy")
        test_ids = [str(test_id) for test_id in as_list(item.get("test_ids")) if test_id]
        if test_ids:
            label += ":" + ",".join(test_ids[:4])
        refs.append(label)
    return refs[:limit]


def decide_verdict(reasons: list[dict[str, Any]]) -> str:
    severities = {item.get("severity") for item in reasons}
    codes = {item.get("code") for item in reasons}
    if any(code in codes for code in ("requirement_failed", "defects_present")):
        return "failed"
    if any(code in codes for code in ("preflight_blocked", "service_runtime_failed", "service_runtime_not_all_ready", "requirement_blocked")):
        return "blocked"
    if "blocker" in severities:
        return "blocked"
    if reasons:
        return "inconclusive"
    return "passed"


def build_verdict(args: argparse.Namespace) -> dict[str, Any]:
    ledger_path = Path(args.ledger).expanduser().resolve() if args.ledger else None
    audit_path = Path(args.audit_summary).expanduser().resolve() if args.audit_summary else None
    results_path = Path(args.results).expanduser().resolve() if args.results else None
    preflight_path = Path(args.service_preflight).expanduser().resolve() if args.service_preflight else None
    service_runtime_path = Path(args.service_runtime).expanduser().resolve() if args.service_runtime else None
    plan_audit_path = Path(args.plan_audit_summary).expanduser().resolve() if args.plan_audit_summary else None
    defects_path = Path(args.defects).expanduser().resolve() if args.defects else None
    requirement_coverage_path = Path(args.requirement_coverage).expanduser().resolve() if args.requirement_coverage else None
    adapter_context_path = Path(args.adapter_context).expanduser().resolve() if args.adapter_context else None
    adapter_probes_path = Path(args.adapter_probes).expanduser().resolve() if args.adapter_probes else None
    cycle_error_path = Path(args.cycle_error).expanduser().resolve() if args.cycle_error else None

    artifact_paths = {
        "ledger": ledger_path,
        "audit_summary": audit_path,
        "results": results_path,
        "service_preflight": preflight_path,
        "service_runtime": service_runtime_path,
        "plan_audit_summary": plan_audit_path,
        "defects": defects_path,
        "requirement_coverage": requirement_coverage_path,
        "adapter_context": adapter_context_path,
        "adapter_probes": adapter_probes_path,
        "cycle_error": cycle_error_path,
    }
    loaded_artifacts: dict[str, dict[str, Any] | None] = {}
    input_artifact_errors: list[dict[str, str]] = []
    for name, path in artifact_paths.items():
        value, load_error = try_load_json(path)
        loaded_artifacts[name] = value
        if load_error and path:
            input_artifact_errors.append({"name": name, "path": str(path), "error": load_error})

    ledger = loaded_artifacts["ledger"]
    audit = loaded_artifacts["audit_summary"]
    results = loaded_artifacts["results"]
    preflight = loaded_artifacts["service_preflight"]
    service_runtime = loaded_artifacts["service_runtime"]
    plan_audit = loaded_artifacts["plan_audit_summary"]
    defects = loaded_artifacts["defects"]
    requirement_coverage = loaded_artifacts["requirement_coverage"]
    adapter_context = loaded_artifacts["adapter_context"]
    adapter_probes = loaded_artifacts["adapter_probes"]
    cycle_error = loaded_artifacts["cycle_error"]

    reasons: list[dict[str, Any]] = []
    counts = status_counts(ledger, audit)
    runtime_counts = runtime_issue_counts(results)
    runtime_ok = runtime_disposition(ledger, runtime_counts)

    for issue in input_artifact_errors:
        add_reason(
            reasons,
            "input_artifact_unreadable",
            "artifact",
            "gap",
            f"Input artifact {issue['name']} could not be read as a JSON object: {issue['error']}.",
            [issue["path"], issue["name"]],
        )

    if not ledger:
        add_reason(reasons, "missing_ledger", "artifact", "gap", "No evidence-ledger.json was provided; no final pass can be claimed.")
    add_sibling_artifact_reasons(
        reasons,
        ledger_path=ledger_path,
        provided_paths={
            "defects.json": defects_path,
            "requirement-coverage.json": requirement_coverage_path,
            "plan-audit-summary.json": plan_audit_path,
            "service-preflight.json": preflight_path,
            "service-runtime.json": service_runtime_path,
            "adapter-probes.json": adapter_probes_path,
            "adapter-context.json": adapter_context_path,
            "qa-cycle-error.json": cycle_error_path,
        },
    )
    if not audit:
        add_reason(reasons, "missing_audit", "artifact", "gap", "No audit-summary.json was provided; ledger integrity is unverified.")
    elif not audit.get("passed"):
        add_reason(
            reasons,
            "audit_failed",
            "evidence_integrity",
            "gap",
            f"Evidence audit failed with {len(as_list(audit.get('errors')))} error(s).",
            ["audit-summary.json"],
        )
    add_results_artifact_dir_reasons(reasons, results=results, results_path=results_path, ledger_path=ledger_path)
    add_artifact_binding_reasons(reasons, ledger=ledger, ledger_path=ledger_path, audit=audit, results_path=results_path)
    unbound_runner_refs = unbound_runner_evidence_ids(ledger, results, results_path)
    if unbound_runner_refs:
        add_reason(
            reasons,
            "runner_evidence_unbound",
            "evidence_integrity",
            "gap",
            f"{len(unbound_runner_refs)} runner-generated evidence item(s) are not bound to matching current results.json steps.",
            unbound_runner_refs,
        )

    if cycle_error:
        phase = cycle_error.get("phase") or cycle_error.get("step") or "qa_cycle"
        message = cycle_error.get("message") or "A QA cycle helper failed before the cycle could complete."
        add_reason(
            reasons,
            str(cycle_error.get("code") or "cycle_helper_failed"),
            "tooling",
            "gap",
            f"QA cycle helper failed during {phase}: {message}",
            ["qa-cycle-error.json", str(phase)],
        )

    if counts.get("Failed"):
        add_reason(
            reasons,
            "requirement_failed",
            "requirement",
            "fail",
            f"{counts['Failed']} requirement(s) failed.",
            requirement_refs(ledger, "Failed"),
        )
    if counts.get("Blocked"):
        add_reason(
            reasons,
            "requirement_blocked",
            "requirement",
            "blocker",
            f"{counts['Blocked']} requirement(s) are blocked.",
            requirement_refs(ledger, "Blocked"),
        )
    if counts.get("Untested"):
        add_reason(
            reasons,
            "requirement_untested",
            "requirement",
            "gap",
            f"{counts['Untested']} requirement(s) remain untested.",
            requirement_refs(ledger, "Untested"),
        )
    if counts.get("Inconclusive"):
        add_reason(
            reasons,
            "requirement_inconclusive",
            "requirement",
            "gap",
            f"{counts['Inconclusive']} requirement(s) have inconclusive evidence.",
            requirement_refs(ledger, "Inconclusive"),
        )
    if ledger and not any(counts.values()):
        add_reason(reasons, "no_requirements", "requirement", "gap", "The ledger contains no requirement statuses.")

    if preflight:
        blockers = as_list(preflight.get("blockers"))
        if blockers:
            refs = [str(item.get("service") or item.get("reason") or "preflight") for item in blockers[:12]]
            add_reason(reasons, "preflight_blocked", "runtime", "blocker", f"Runtime preflight has {len(blockers)} blocker(s).", refs)
    elif args.require_preflight:
        add_reason(reasons, "missing_preflight", "runtime", "gap", "Runtime preflight was required but service-preflight.json was not provided.")

    if service_runtime:
        summary = service_runtime.get("summary") or {}
        failed_count = int(summary.get("failed_count") or 0)
        planned_count = int(summary.get("planned_count") or 0)
        ready_count = int(summary.get("ready_count") or 0)
        if failed_count:
            refs = [str(item.get("service") or "service") for item in as_list(service_runtime.get("services")) if item.get("status") in {"failed_to_start", "unready", "blocked_by_safety", "failed"}]
            add_reason(reasons, "service_runtime_failed", "runtime", "blocker", f"Service runtime has {failed_count} failed/unready service(s).", refs[:12])
        if service_runtime.get("mode") == "start" and planned_count and ready_count < planned_count and not args.allow_partial_service_runtime:
            add_reason(reasons, "service_runtime_not_all_ready", "runtime", "blocker", f"Only {ready_count}/{planned_count} planned service(s) reached readiness.")
    elif args.require_service_runtime:
        add_reason(reasons, "missing_service_runtime", "runtime", "gap", "Service runtime artifact was required but service-runtime.json was not provided.")

    if plan_audit and not plan_audit.get("passed"):
        add_reason(
            reasons,
            "plan_validation_failed",
            "plan_validation",
            "blocker",
            f"Plan validation failed with {len(as_list(plan_audit.get('errors')))} error(s).",
            ["plan-audit-summary.json"],
        )
    strategy_refs = strategy_gap_refs(plan_audit)
    if strategy_refs:
        add_reason(
            reasons,
            "strategy_dimension_gap",
            "plan_strategy",
            "gap",
            f"{len(strategy_refs)} planned strategy dimension(s) have no executable probe coverage.",
            strategy_refs,
        )

    if runtime_counts["console_errors"] and not runtime_ok["console_errors"]:
        add_reason(reasons, "undispositioned_console_errors", "runtime", "gap", f"{runtime_counts['console_errors']} console error(s) were captured without zero-unignored runtime disposition.")
    if runtime_counts["failed_responses"] and not runtime_ok["failed_responses"]:
        add_reason(reasons, "undispositioned_failed_responses", "runtime", "gap", f"{runtime_counts['failed_responses']} failed HTTP response(s) were captured without zero-unignored runtime disposition.")
    if runtime_counts["request_failures"] and not runtime_ok["request_failures"]:
        add_reason(reasons, "undispositioned_request_failures", "runtime", "gap", f"{runtime_counts['request_failures']} request failure(s) were captured without zero-unignored runtime disposition.")

    defect_summary = defect_finding_summary(defects)
    if defects and defect_summary["invalid_summary_count"]:
        add_reason(
            reasons,
            "defects_summary_invalid",
            "defect",
            "gap",
            "defects.json summary.finding_count is not a non-negative integer; regenerate defects.json before a final pass claim.",
            ["defects.json"],
        )
    if defects and defect_summary["summary_count"] is not None and defect_summary["summary_count"] != defect_summary["findings_count"]:
        add_reason(
            reasons,
            "defects_summary_mismatch",
            "defect",
            "gap",
            f"defects.json summary.finding_count={defect_summary['summary_count']} does not match findings length={defect_summary['findings_count']}; findings are treated as authoritative.",
            ["defects.json"],
        )
    finding_count = int(defect_summary["finding_count"])
    if finding_count:
        severity_counts = defect_summary["severity_counts"]
        add_reason(reasons, "defects_present", "defect", "fail", f"{finding_count} defect finding(s) were generated: {json.dumps(severity_counts, ensure_ascii=False)}.", ["defects.json"])

    if requirement_coverage and not requirement_coverage.get("passed"):
        uncovered = int(requirement_coverage.get("uncovered_count") or 0)
        refs = [str(item.get("id") or item.get("source")) for item in as_list(requirement_coverage.get("coverage")) if not item.get("covered")]
        add_reason(reasons, "requirement_source_unmapped", "requirement_coverage", "blocker", f"{uncovered} requirement source unit(s) are not mapped to the test matrix.", refs[:12])

    blocked_adapter = len(as_list((adapter_probes or {}).get("blocked")))
    if blocked_adapter:
        add_reason(reasons, "adapter_probe_blocked", "adapter", "gap", f"{blocked_adapter} adapter probe layer(s) are blocked.", ["adapter-probes.json"])

    for issue in environment_boundary_issues(adapter_context, required=args.require_environment_boundary):
        add_reason(reasons, issue["code"], "environment", "gap", issue["message"], issue.get("refs"))

    cycle_error_unreadable = any(issue.get("name") == "cycle_error" for issue in input_artifact_errors)
    cycle_error_unresolved = bool(cycle_error) or cycle_error_unreadable or any(reason.get("code") == "cycle_error_omitted" for reason in reasons)
    verdict = decide_verdict(reasons)
    can_claim_pass = verdict == "passed"
    if can_claim_pass:
        statement = "All audited requirements passed with current-run evidence and no unresolved runtime/setup/defect blockers."
    elif verdict == "failed":
        statement = "Do not claim pass: at least one requirement or generated defect contradicts the expected behavior."
    elif verdict == "blocked":
        statement = "Do not claim pass: setup, service readiness, or blocked requirement evidence prevents execution/completion."
    else:
        statement = "Do not claim pass: evidence is incomplete, unaudited, undispositioned, or inconclusive."

    return {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "verdict": verdict,
        "can_claim_pass": can_claim_pass,
        "statement": statement,
        "status_counts": counts,
        "runtime_issue_counts": runtime_counts,
        "gates": {
            "ledger_present": bool(ledger),
            "audit_passed": bool(audit and audit.get("passed")),
            "audit_artifacts_bound": not any(str(reason.get("code", "")).startswith("audit_") for reason in reasons),
            "all_requirements_passed": bool(ledger and counts.get("Passed", 0) > 0 and not any(counts.get(status, 0) for status in ("Failed", "Blocked", "Untested", "Inconclusive"))),
            "runtime_issues_dispositioned": not any(reason.get("code", "").startswith("undispositioned_") for reason in reasons),
            "preflight_runnable": None if not preflight else not bool(preflight.get("blockers")),
            "service_runtime_ready": None if not service_runtime else not any(reason.get("code", "").startswith("service_runtime") for reason in reasons),
            "plan_validated": None if not plan_audit else bool(plan_audit.get("passed")),
            "defect_free": finding_count == 0,
            "requirement_source_covered": None if not requirement_coverage else bool(requirement_coverage.get("passed")),
            "environment_boundary_confirmed": not any(reason.get("code") in {"missing_environment_boundary", "environment_unconfirmed", "data_boundary_unconfirmed"} for reason in reasons),
            "cycle_completed": not cycle_error_unresolved,
        },
        "reasons": reasons,
        "inputs": {
            "ledger": str(ledger_path) if ledger_path else None,
            "audit_summary": str(audit_path) if audit_path else None,
            "results": str(results_path) if results_path else None,
            "service_preflight": str(preflight_path) if preflight_path else None,
            "service_runtime": str(service_runtime_path) if service_runtime_path else None,
            "plan_audit_summary": str(plan_audit_path) if plan_audit_path else None,
            "defects": str(defects_path) if defects_path else None,
            "requirement_coverage": str(requirement_coverage_path) if requirement_coverage_path else None,
            "adapter_context": str(adapter_context_path) if adapter_context_path else None,
            "adapter_probes": str(adapter_probes_path) if adapter_probes_path else None,
            "cycle_error": str(cycle_error_path) if cycle_error_path else None,
        },
        "input_artifact_errors": input_artifact_errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a strict final QA/backtest verdict from audited evidence artifacts.")
    parser.add_argument("--ledger")
    parser.add_argument("--audit-summary")
    parser.add_argument("--results")
    parser.add_argument("--service-preflight")
    parser.add_argument("--service-runtime")
    parser.add_argument("--plan-audit-summary")
    parser.add_argument("--defects")
    parser.add_argument("--requirement-coverage")
    parser.add_argument("--adapter-context")
    parser.add_argument("--adapter-probes")
    parser.add_argument("--cycle-error")
    parser.add_argument("--out", required=True)
    parser.add_argument("--require-preflight", action="store_true")
    parser.add_argument("--require-service-runtime", action="store_true")
    parser.add_argument("--require-environment-boundary", action="store_true", help="Require adapter-context.json plus confirmed runtime/data boundary before a pass can be claimed.")
    parser.add_argument("--allow-partial-service-runtime", action="store_true")
    parser.add_argument("--fail-on-not-pass", action="store_true")
    args = parser.parse_args()

    verdict = build_verdict(args)
    out_path = Path(args.out).expanduser().resolve()
    write_json(out_path, verdict)
    print(out_path)
    if args.fail_on_not_pass and not verdict.get("can_claim_pass"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
