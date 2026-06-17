#!/usr/bin/env python3
import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


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


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def defect_finding_summary(defects: dict | None) -> dict[str, Any]:
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


def iter_path_values(value: Any):
    if has_text(value):
        yield str(value)
    elif isinstance(value, dict):
        for child in value.values():
            yield from iter_path_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_path_values(child)


def evidence_artifact_paths(ledger: dict | None, base_dir: Path | None) -> list[Path]:
    paths: list[Path] = []
    seen: set[str] = set()
    for item in (ledger or {}).get("evidence", []):
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


def status_icon(status: str) -> str:
    value = str(status or "unknown")
    return {
        "passed": "PASS",
        "failed": "FAIL",
        "attention": "CHECK",
        "Passed": "PASS",
        "Failed": "FAIL",
        "Blocked": "BLOCKED",
        "Untested": "UNTESTED",
        "Inconclusive": "INCONCLUSIVE",
    }.get(value, value.upper())


def requirement_result(ledger: dict | None, audit_summary: dict | None) -> str:
    if not ledger:
        return "UNAUDITED"
    if audit_summary and not audit_summary.get("passed"):
        return "AUDIT_FAIL"
    statuses = [item.get("status") for item in ledger.get("requirements", [])]
    if not statuses:
        return "NO_REQUIREMENTS"
    if any(status == "Failed" for status in statuses):
        return "FAIL"
    if all(status == "Passed" for status in statuses):
        return "PASS"
    return "ATTENTION"


def requirement_status_counts(ledger: dict | None) -> dict[str, int]:
    counts = {status: 0 for status in ("Blocked", "Failed", "Inconclusive", "Passed", "Untested")}
    if not ledger:
        return counts
    for item in ledger.get("requirements", []):
        status = item.get("status")
        if status in counts:
            counts[status] += 1
    return counts


def runtime_disposition_rows(ledger: dict | None) -> list[dict]:
    if not ledger:
        return []
    rows = []
    for item in ledger.get("evidence", []):
        if item.get("type") != "runtime":
            continue
        signals = []
        for field, label in (
            ("checked_console_errors", "unignored console errors"),
            ("ignored_console_errors", "ignored console errors"),
            ("checked_request_failures", "unignored request failures"),
            ("ignored_request_failures", "ignored request failures"),
            ("checked_failed_responses", "unignored failed HTTP responses"),
            ("ignored_failed_responses", "ignored failed HTTP responses"),
        ):
            if item.get(field) is not None:
                signals.append(f"{label}: {item.get(field)}")
        if signals:
            rows.append({
                "id": item.get("id", ""),
                "proves": item.get("proves", ""),
                "signals": signals,
            })
    return rows


def service_probe_label(service: dict) -> str:
    parts = []
    if service.get("default_url"):
        parts.append(str(service.get("default_url")))
    if service.get("port") is not None:
        parts.append(f"port_open={service.get('port_open')}")
    probe = service.get("http_probe")
    if isinstance(probe, dict):
        if probe.get("status") is not None:
            parts.append(f"http={probe.get('status')}")
        elif probe.get("error"):
            parts.append(f"http_error={probe.get('error')}")
    return "; ".join(parts)


def preflight_service_label(service: dict) -> str:
    parts = []
    parts.append(f"required={service.get('required')}")
    if service.get("default_url"):
        parts.append(str(service.get("default_url")))
    if service.get("port_open") is not None:
        parts.append(f"port_open={service.get('port_open')}")
    start = service.get("start") or {}
    command_status = start.get("command_status") or {}
    if command_status:
        parts.append(f"cmd_found={command_status.get('found')}")
        if command_status.get("substitute"):
            parts.append(f"substitute={command_status.get('substitute')}")
    npm_status = start.get("npm_script_status")
    if isinstance(npm_status, dict):
        parts.append(f"npm_script={npm_status.get('script')}:{npm_status.get('found')}")
    return "; ".join(parts)


def service_runtime_label(service: dict) -> str:
    parts = [f"status={service.get('status')}"]
    if service.get("pid"):
        parts.append(f"pid={service.get('pid')}")
    if service.get("exit_code") is not None:
        parts.append(f"exit_code={service.get('exit_code')}")
    readiness = service.get("post_start_readiness") or service.get("pre_start_readiness")
    if isinstance(readiness, dict):
        if readiness.get("ready") is not None:
            parts.append(f"ready={readiness.get('ready')}")
        if readiness.get("check"):
            parts.append(f"check={readiness.get('check')}")
        if readiness.get("port"):
            parts.append(f"port={readiness.get('port')}")
    if service.get("error"):
        parts.append(f"error={service.get('error')}")
    if service.get("would_start"):
        parts.append("would_start=True")
    return "; ".join(parts)


def verdict_label(verdict: dict | None) -> str:
    if not verdict:
        return "NOT_GENERATED"
    value = str(verdict.get("verdict") or "unknown").upper()
    can_claim = verdict.get("can_claim_pass")
    return f"{value} (can_claim_pass={can_claim})"


def pass_claim_label(verdict: dict | None, report_guard_errors: list[str] | None = None) -> str:
    guard_errors = report_guard_errors or []
    if verdict and verdict.get("can_claim_pass") is True and not guard_errors:
        return "ALLOWED: qa-verdict.json permits a final pass claim."
    if verdict and verdict.get("can_claim_pass") is True and guard_errors:
        return "BLOCKED: qa-verdict.json permits pass, but report artifact binding checks failed. Regenerate verdict/report from current artifacts."
    if verdict:
        return "BLOCKED: qa-verdict.json has can_claim_pass=false. Do not phrase this report as a successful backtest."
    return "BLOCKED: qa-verdict.json is missing or unreadable. Do not claim pass from report, ledger, or raw results alone."


def is_unconfirmed_boundary_value(value: Any) -> bool:
    return str(value or "").strip().lower() in UNCONFIRMED_BOUNDARY_VALUES


def conclusion_artifact_errors(
    *,
    plan_audit_summary: dict | None,
    defects: dict | None,
    requirement_coverage: dict | None,
    adapter_context: dict | None,
    adapter_probes: dict | None,
    service_preflight: dict | None,
    service_runtime: dict | None,
) -> list[str]:
    errors: list[str] = []
    if plan_audit_summary and not plan_audit_summary.get("passed"):
        error_count = len(plan_audit_summary.get("errors") or [])
        coverage = plan_audit_summary.get("strategy_coverage") if isinstance(plan_audit_summary.get("strategy_coverage"), dict) else {}
        gap_count = int(coverage.get("gap_count") or 0)
        errors.append(f"plan-audit-summary.json is not passed (errors={error_count}, strategy_gap_count={gap_count}); do not claim pass.")
    elif plan_audit_summary:
        coverage = plan_audit_summary.get("strategy_coverage") if isinstance(plan_audit_summary.get("strategy_coverage"), dict) else {}
        gap_count = int(coverage.get("gap_count") or 0)
        if gap_count:
            errors.append(f"plan-audit-summary.json has strategy_gap_count={gap_count}; regenerate verdict/report before claiming pass.")
    defect_summary = defect_finding_summary(defects)
    if defects and defect_summary["invalid_summary_count"]:
        errors.append("defects.json summary.finding_count is not a non-negative integer; regenerate defects.json before claiming pass.")
    if defects and defect_summary["summary_count"] is not None and defect_summary["summary_count"] != defect_summary["findings_count"]:
        errors.append(
            f"defects.json summary.finding_count={defect_summary['summary_count']} does not match findings length={defect_summary['findings_count']}; regenerate verdict/report before claiming pass."
        )
    finding_count = int(defect_summary["finding_count"])
    if finding_count:
        errors.append(f"defects.json has finding_count={finding_count}; regenerate verdict/report before claiming pass.")
    if requirement_coverage and not requirement_coverage.get("passed"):
        uncovered = int(requirement_coverage.get("uncovered_count") or 0)
        errors.append(f"requirement-coverage.json is not passed (uncovered_count={uncovered}); do not claim pass.")
    if adapter_context:
        boundary = adapter_context.get("environment_boundary") if isinstance(adapter_context.get("environment_boundary"), dict) else {}
        if is_unconfirmed_boundary_value(boundary.get("runtime_mode")) or is_unconfirmed_boundary_value(boundary.get("data_boundary_status")):
            errors.append("adapter-context.json has unconfirmed runtime/data boundary; do not claim pass.")
    blocked_adapter_count = len((adapter_probes or {}).get("blocked") or [])
    if blocked_adapter_count:
        errors.append(f"adapter-probes.json has {blocked_adapter_count} blocked adapter probe(s); regenerate verdict/report before claiming pass.")
    preflight_blockers = len((service_preflight or {}).get("blockers") or [])
    if preflight_blockers:
        errors.append(f"service-preflight.json has {preflight_blockers} blocker(s); do not claim pass.")
    if service_runtime:
        summary = service_runtime.get("summary") if isinstance(service_runtime.get("summary"), dict) else {}
        failed_count = int(summary.get("failed_count") or 0)
        planned_count = int(summary.get("planned_count") or 0)
        ready_count = int(summary.get("ready_count") or 0)
        if failed_count:
            errors.append(f"service-runtime.json has failed_count={failed_count}; do not claim pass.")
        if service_runtime.get("mode") == "start" and planned_count and ready_count < planned_count:
            errors.append(f"service-runtime.json readiness is incomplete ({ready_count}/{planned_count}); do not claim pass.")
    return errors


REPORT_SIBLING_ARTIFACTS = {
    "plan_audit_summary": ("plan-audit-summary.json", "plan-audit-summary.json"),
    "defects": ("defects.json", "defects.json"),
    "requirement_coverage": ("requirement-coverage.json", "requirement-coverage.json"),
    "adapter_context": ("adapter-context.json", "adapter-context.json"),
    "adapter_probes": ("adapter-probes.json", "adapter-probes.json"),
    "service_preflight": ("service-preflight.json", "service-preflight.json"),
    "service_runtime": ("service-runtime.json", "service-runtime.json"),
}


def conclusion_artifact_path_errors(artifact_dirs: list[Path], paths: dict[str, Path | None]) -> list[str]:
    if not artifact_dirs:
        return []
    errors: list[str] = []
    seen: set[str] = set()
    for artifact_dir in artifact_dirs:
        for name, (filename, label) in REPORT_SIBLING_ARTIFACTS.items():
            sibling_path = artifact_dir / filename
            if not sibling_path.exists():
                continue
            loaded_path = paths.get(name)
            key = f"{name}:{sibling_path.resolve()}:{loaded_path.resolve() if loaded_path else ''}"
            if key in seen:
                continue
            seen.add(key)
            if loaded_path and not path_matches(loaded_path, sibling_path):
                errors.append(f"{label} exists in the current run at {sibling_path}, but this report loaded {loaded_path}; do not claim pass from cross-run artifacts.")
    return errors


def verdict_report_guard_errors(
    verdict: dict | None,
    *,
    artifact_dirs: list[Path],
    results: dict | None,
    ledger: dict | None,
    ledger_path: Path | None,
    audit_summary: dict | None,
    audit_summary_path: Path | None,
    results_path: Path | None,
    plan_audit_summary: dict | None,
    plan_audit_summary_path: Path | None,
    defects: dict | None,
    defects_path: Path | None,
    requirement_coverage: dict | None,
    requirement_coverage_path: Path | None,
    adapter_context: dict | None,
    adapter_context_path: Path | None,
    adapter_probes: dict | None,
    adapter_probes_path: Path | None,
    service_preflight: dict | None,
    service_preflight_path: Path | None,
    service_runtime: dict | None,
    service_runtime_path: Path | None,
) -> list[str]:
    if not verdict or verdict.get("can_claim_pass") is not True:
        return []
    errors: list[str] = []
    inputs = verdict.get("inputs") if isinstance(verdict.get("inputs"), dict) else {}
    expected_inputs = {
        "ledger": ledger_path,
        "audit_summary": audit_summary_path,
        "results": results_path,
    }
    optional_inputs = {
        "plan_audit_summary": (plan_audit_summary, plan_audit_summary_path),
        "defects": (defects, defects_path),
        "requirement_coverage": (requirement_coverage, requirement_coverage_path),
        "adapter_context": (adapter_context, adapter_context_path),
        "adapter_probes": (adapter_probes, adapter_probes_path),
        "service_preflight": (service_preflight, service_preflight_path),
        "service_runtime": (service_runtime, service_runtime_path),
    }
    for name, (artifact, path) in optional_inputs.items():
        if artifact is not None or inputs.get(name) or (path and path.exists()):
            expected_inputs[name] = path
    for name, path in expected_inputs.items():
        recorded = inputs.get(name)
        if path and not path_matches(recorded, path):
            errors.append(f"qa-verdict.json input {name} is not bound to this report's {name} artifact.")
        if recorded and not path:
            errors.append(f"qa-verdict.json was generated with {name}, but this report omitted it.")
    if results:
        result_artifact_dir = resolved_path(results.get("artifactDir"))
        current_dir = artifact_dirs[0] if artifact_dirs else None
        if result_artifact_dir and current_dir and result_artifact_dir != current_dir.resolve():
            errors.append(f"results.json artifactDir={result_artifact_dir} does not match this report's current artifact directory {current_dir.resolve()}; do not claim pass from cross-run results artifacts.")
        if result_artifact_dir and results_path and result_artifact_dir != results_path.parent.resolve():
            errors.append(f"results.json artifactDir={result_artifact_dir} does not match results.json parent {results_path.parent.resolve()}; regenerate results before reporting pass.")
    errors.extend(
        conclusion_artifact_path_errors(
            artifact_dirs,
            {
                "plan_audit_summary": plan_audit_summary_path,
                "defects": defects_path,
                "requirement_coverage": requirement_coverage_path,
                "adapter_context": adapter_context_path,
                "adapter_probes": adapter_probes_path,
                "service_preflight": service_preflight_path,
                "service_runtime": service_runtime_path,
            },
        )
    )
    errors.extend(
        conclusion_artifact_errors(
            plan_audit_summary=plan_audit_summary,
            defects=defects,
            requirement_coverage=requirement_coverage,
            adapter_context=adapter_context,
            adapter_probes=adapter_probes,
            service_preflight=service_preflight,
            service_runtime=service_runtime,
        )
    )
    if not audit_summary:
        errors.append("qa-verdict.json permits pass, but audit-summary.json is missing or unreadable in this report.")
        return errors
    audit_hashes = audit_summary.get("artifact_hashes") if isinstance(audit_summary.get("artifact_hashes"), dict) else {}
    if not audit_hashes:
        errors.append("audit-summary.json has no artifact_hashes; rerun audit_evidence.py before reporting pass.")
        return errors
    for name, path, hash_key in (
        ("ledger", ledger_path, "ledger_sha256"),
        ("results", results_path, "results_sha256"),
    ):
        if not path:
            continue
        expected_hash = audit_hashes.get(hash_key)
        current_hash = file_sha256(path)
        if not expected_hash:
            errors.append(f"audit-summary.json has no {hash_key}; rerun audit_evidence.py before reporting pass.")
        elif current_hash is None:
            errors.append(f"{name} artifact is unreadable during report pass-claim verification: {path}")
        elif current_hash != expected_hash:
            errors.append(f"{name} artifact hash differs from audit-summary.json; regenerate audit/verdict/report.")
    matrix_path = Path(str(audit_summary.get("matrix"))).expanduser().resolve() if has_text(audit_summary.get("matrix")) else None
    if not matrix_path:
        errors.append("audit-summary.json does not declare the audited test-matrix.json.")
    else:
        expected_matrix_hash = audit_hashes.get("matrix_sha256")
        current_matrix_hash = file_sha256(matrix_path)
        if not expected_matrix_hash:
            errors.append("audit-summary.json has no matrix_sha256; rerun audit_evidence.py with --matrix.")
        elif current_matrix_hash is None:
            errors.append(f"test-matrix.json is unreadable during report pass-claim verification: {matrix_path}")
        elif current_matrix_hash != expected_matrix_hash:
            errors.append("test-matrix.json hash differs from audit-summary.json; regenerate audit/verdict/report.")
    evidence_hashes = audit_hashes.get("evidence_artifacts_sha256")
    current_evidence_paths = evidence_artifact_paths(ledger, ledger_path.parent.resolve() if ledger_path else None)
    if current_evidence_paths and not isinstance(evidence_hashes, dict):
        errors.append("audit-summary.json has no evidence_artifacts_sha256; rerun audit_evidence.py before reporting pass.")
    elif isinstance(evidence_hashes, dict):
        for artifact_path in current_evidence_paths:
            path_key = str(artifact_path.resolve())
            expected_hash = evidence_hashes.get(path_key)
            current_hash = file_sha256(artifact_path)
            if current_hash is None:
                errors.append(f"evidence artifact is unreadable during report pass-claim verification: {path_key}")
            elif not expected_hash:
                errors.append(f"audit-summary.json did not hash evidence artifact: {path_key}")
            elif current_hash != expected_hash:
                errors.append(f"evidence artifact hash differs from audit-summary.json: {path_key}")
    return errors


def inline_preview(value: str, limit: int = 500) -> str:
    text = str(value or "").replace("`", "\\`").replace("\n", " / ")
    return text[:limit] + ("...[truncated]" if len(text) > limit else "")


def table_cell(value: object, limit: int = 500) -> str:
    text = str(value or "").replace("\n", "<br>").replace("|", "\\|")
    return text[:limit] + ("...[truncated]" if len(text) > limit else "")


def semantic_binding_errors(
    artifact: dict[str, Any] | None,
    *,
    label: str,
    required_sources: dict[str, Path],
) -> list[str]:
    if not artifact:
        return []
    errors: list[str] = []
    if artifact.get("not_evidence") is not True:
        errors.append(f"{label} is missing not_evidence=true; do not render it as trusted planning context.")
    bindings = artifact.get("source_bindings")
    if not isinstance(bindings, dict):
        errors.append(f"{label} is missing source_bindings; regenerate semantic artifacts before reporting them.")
        return errors
    for source_name, source_path in required_sources.items():
        binding = bindings.get(source_name)
        if not isinstance(binding, dict):
            errors.append(f"{label} is missing source binding for {source_name}.")
            continue
        expected_sha = file_sha256(source_path) if source_path.exists() and not source_path.is_dir() else None
        if binding.get("sha256") != expected_sha:
            errors.append(
                f"{label} source binding mismatch for {source_name}: recorded={binding.get('sha256')} current={expected_sha} path={source_path}"
            )
    return errors


def semantic_artifact_guard_errors(
    *,
    business_model: dict[str, Any] | None,
    oracle_model: dict[str, Any] | None,
    qa_metrics: dict[str, Any] | None,
    closeout_candidates: dict[str, Any] | None,
    current_artifact_dir: Path,
    requirement_path: Path | None,
    plan_path: Path,
    business_model_path: Path | None,
    oracle_model_path: Path | None,
    qa_metrics_path: Path | None,
) -> list[str]:
    matrix_path = current_artifact_dir / "test-matrix.json"
    base_sources: dict[str, Path] = {"plan": plan_path}
    if matrix_path.exists():
        base_sources["matrix"] = matrix_path
    if requirement_path and requirement_path.exists():
        base_sources["requirement"] = requirement_path

    errors: list[str] = []
    errors.extend(semantic_binding_errors(business_model, label="business-model.json", required_sources=base_sources))
    oracle_sources = dict(base_sources)
    if business_model_path and business_model_path.exists():
        oracle_sources["business_model"] = business_model_path
    errors.extend(semantic_binding_errors(oracle_model, label="oracle-model.json", required_sources=oracle_sources))
    metrics_sources = dict(oracle_sources)
    if oracle_model_path and oracle_model_path.exists():
        metrics_sources["oracle_model"] = oracle_model_path
    errors.extend(semantic_binding_errors(qa_metrics, label="qa-metrics.json", required_sources=metrics_sources))
    closeout_sources = dict(metrics_sources)
    if qa_metrics_path and qa_metrics_path.exists():
        closeout_sources["qa_metrics"] = qa_metrics_path
    errors.extend(semantic_binding_errors(closeout_candidates, label="closeout-candidates.json", required_sources=closeout_sources))
    return errors


def hit_test_summary(hit_test: object) -> str:
    if not isinstance(hit_test, dict) or not hit_test:
        return ""
    parts = []
    center = hit_test.get("center") or {}
    if isinstance(center, dict) and center:
        parts.append(f"center=({center.get('x')},{center.get('y')})")
    if hit_test.get("receivesPointerEvents") is not None:
        parts.append(f"receivesPointerEvents={hit_test.get('receivesPointerEvents')}")
    blocker = hit_test.get("blocker") or {}
    if isinstance(blocker, dict) and blocker:
        label = blocker.get("selector") or blocker.get("tag") or "unknown"
        if blocker.get("text"):
            label += f" text={json.dumps(blocker.get('text'), ensure_ascii=False)}"
        parts.append(f"blocker={label}")
    target = hit_test.get("target") or {}
    if isinstance(target, dict) and target:
        parts.append(f"target={target.get('selector') or target.get('tag') or ''}")
    if hit_test.get("actionability"):
        parts.append(f"actionability={hit_test.get('actionability')}")
    return "; ".join(part for part in parts if part)


def signal_summary(item: dict[str, Any]) -> str:
    parts: list[str] = []
    if item.get("status_code") is not None:
        parts.append(f"HTTP {item.get('status_code')}")
    if item.get("messages_seen") is not None:
        parts.append(f"messages={item.get('messages_seen')}")
    if item.get("message_text_contains_matched"):
        parts.append(f"stream_contains={json.dumps(item.get('message_text_contains_matched'), ensure_ascii=False)}")
    if item.get("response_text_contains_matched"):
        parts.append(f"response_contains={json.dumps(item.get('response_text_contains_matched'), ensure_ascii=False)}")
    if item.get("request_text_contains_matched"):
        parts.append(f"request_contains={json.dumps(item.get('request_text_contains_matched'), ensure_ascii=False)}")
    if item.get("stdout_contains_matched"):
        parts.append(f"stdout_contains={json.dumps(item.get('stdout_contains_matched'), ensure_ascii=False)}")
    if item.get("checked_json"):
        parts.append("checked_json")
    if item.get("checked_stdout_json"):
        parts.append("checked_stdout_json")
    if item.get("exit_code") is not None:
        parts.append(f"exit={item.get('exit_code')}")
    return "; ".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a Markdown QA report from a plan and Playwright probe results.")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--requirement")
    parser.add_argument("--ledger", help="Optional evidence-ledger.json for audited requirement coverage.")
    parser.add_argument("--audit-summary", help="Optional audit-summary.json generated by audit_evidence.py.")
    parser.add_argument("--adapter-context", help="Optional adapter-context.json generated by discover_project_context.py.")
    parser.add_argument("--adapter-probes", help="Optional adapter-probes.json generated by synthesize_adapter_probes.py.")
    parser.add_argument("--service-preflight", help="Optional service-preflight.json generated by preflight_runtime.py.")
    parser.add_argument("--service-runtime", help="Optional service-runtime.json generated by service_runtime.py.")
    parser.add_argument("--defects", help="Optional defects.json generated by generate_defects.py.")
    parser.add_argument("--plan-audit-summary", help="Optional plan-audit-summary.json generated by validate_plan.py.")
    parser.add_argument("--requirement-coverage", help="Optional requirement-coverage.json generated by audit_requirement_coverage.py.")
    parser.add_argument("--next-probes", help="Optional next-probes.json generated by generate_next_probes.py.")
    parser.add_argument("--next-probe-application", help="Optional next-probe-application.json generated by apply_next_probes.py.")
    parser.add_argument("--verdict", help="Optional qa-verdict.json generated by generate_verdict.py.")
    parser.add_argument("--business-model", help="Optional business-model.json generated by scaffold/init.")
    parser.add_argument("--oracle-model", help="Optional oracle-model.json generated by scaffold/init.")
    parser.add_argument("--qa-metrics", help="Optional qa-metrics.json generated by scaffold/init.")
    parser.add_argument("--closeout-candidates", help="Optional closeout-candidates.json generated by scaffold/init.")
    parser.add_argument("--out")
    args = parser.parse_args()

    plan_path = Path(args.plan)
    results_path = Path(args.results)
    input_errors: list[dict[str, Any]] = []

    def load_required(name: str, path: Path) -> dict[str, Any]:
        value, load_error = try_load_json(path)
        if load_error:
            input_errors.append({"name": name, "path": str(path), "error": load_error, "required": True})
            return {}
        return value or {}

    def load_optional(name: str, explicit_path: str | None, default_path: Path | None = None) -> tuple[dict[str, Any] | None, Path | None]:
        if explicit_path:
            path = Path(explicit_path)
        else:
            path = default_path
        if path is None:
            return None, None
        if not path.exists() and not explicit_path:
            return None, path
        value, load_error = try_load_json(path)
        if load_error:
            input_errors.append({"name": name, "path": str(path), "error": load_error, "required": False, "explicit": bool(explicit_path)})
            return None, path
        return value, path

    plan = load_required("plan", plan_path)
    results = load_required("results", results_path)
    artifact_dir = Path(results.get("artifactDir") or results_path.parent)
    out_path = Path(args.out) if args.out else artifact_dir / "report.md"
    requirement_text = ""
    requirement_path: Path | None = None
    if args.requirement:
        requirement_path = Path(args.requirement)
        if requirement_path.exists():
            requirement_text = requirement_path.read_text(encoding="utf-8").strip()
    ledger, ledger_path = load_optional("ledger", args.ledger)
    audit_summary, audit_summary_path = load_optional("audit_summary", args.audit_summary)
    current_artifact_dir = ledger_path.parent if ledger_path else artifact_dir
    artifact_dirs = [current_artifact_dir]
    adapter_context, adapter_context_path = load_optional("adapter_context", args.adapter_context, current_artifact_dir / "adapter-context.json")
    adapter_probes, adapter_probes_path = load_optional("adapter_probes", args.adapter_probes, current_artifact_dir / "adapter-probes.json")
    service_preflight, service_preflight_path = load_optional("service_preflight", args.service_preflight, current_artifact_dir / "service-preflight.json")
    service_runtime, service_runtime_path = load_optional("service_runtime", args.service_runtime, current_artifact_dir / "service-runtime.json")
    defects, defects_path = load_optional("defects", args.defects, current_artifact_dir / "defects.json")
    plan_audit_summary, plan_audit_summary_path = load_optional("plan_audit_summary", args.plan_audit_summary, current_artifact_dir / "plan-audit-summary.json")
    requirement_coverage, requirement_coverage_path = load_optional("requirement_coverage", args.requirement_coverage, current_artifact_dir / "requirement-coverage.json")
    next_probes, next_probes_path = load_optional("next_probes", args.next_probes)
    next_probe_application, next_probe_application_path = load_optional("next_probe_application", args.next_probe_application, artifact_dir / "next-probe-application.json")
    verdict, verdict_path = load_optional("verdict", args.verdict, artifact_dir / "qa-verdict.json")
    business_model, business_model_path = load_optional("business_model", args.business_model, current_artifact_dir / "business-model.json")
    oracle_model, oracle_model_path = load_optional("oracle_model", args.oracle_model, current_artifact_dir / "oracle-model.json")
    qa_metrics, qa_metrics_path = load_optional("qa_metrics", args.qa_metrics, current_artifact_dir / "qa-metrics.json")
    closeout_candidates, closeout_candidates_path = load_optional("closeout_candidates", args.closeout_candidates, current_artifact_dir / "closeout-candidates.json")
    report_guard_errors = verdict_report_guard_errors(
        verdict,
        artifact_dirs=artifact_dirs,
        results=results,
        ledger=ledger,
        ledger_path=ledger_path,
        audit_summary=audit_summary,
        audit_summary_path=audit_summary_path,
        results_path=results_path,
        plan_audit_summary=plan_audit_summary,
        plan_audit_summary_path=plan_audit_summary_path,
        defects=defects,
        defects_path=defects_path,
        requirement_coverage=requirement_coverage,
        requirement_coverage_path=requirement_coverage_path,
        adapter_context=adapter_context,
        adapter_context_path=adapter_context_path,
        adapter_probes=adapter_probes,
        adapter_probes_path=adapter_probes_path,
        service_preflight=service_preflight,
        service_preflight_path=service_preflight_path,
        service_runtime=service_runtime,
        service_runtime_path=service_runtime_path,
    )
    semantic_guard_errors = semantic_artifact_guard_errors(
        business_model=business_model,
        oracle_model=oracle_model,
        qa_metrics=qa_metrics,
        closeout_candidates=closeout_candidates,
        current_artifact_dir=current_artifact_dir,
        requirement_path=requirement_path,
        plan_path=plan_path,
        business_model_path=business_model_path,
        oracle_model_path=oracle_model_path,
        qa_metrics_path=qa_metrics_path,
    )
    report_guard_errors.extend(semantic_guard_errors)
    semantic_artifacts_renderable = not semantic_guard_errors
    final_pass_allowed = bool(verdict and verdict.get("can_claim_pass") is True and not report_guard_errors)

    lines = []
    lines.append("# 自动化 QA-Test Report")
    lines.append("")
    lines.append("## 1. Summary")
    lines.append("")
    if input_errors:
        required_error_count = sum(1 for item in input_errors if item.get("required"))
        lines.append(f"- Report input errors: {len(input_errors)} (required={required_error_count}).")
        lines.append("- Report completeness: PARTIAL. Fix the listed input artifacts before claiming a final pass/fail result from this report.")
    lines.append(f"- Final verdict: {verdict_label(verdict)}")
    if verdict:
        lines.append(f"- Verdict statement: {verdict.get('statement', '')}")
        if verdict.get("reasons"):
            lines.append(f"- Verdict blockers/gaps: {len(verdict.get('reasons') or [])} (`{verdict_path}`)")
    lines.append(f"- Pass claim: {pass_claim_label(verdict, report_guard_errors)}")
    if report_guard_errors:
        lines.append(f"- Report verdict binding: BLOCKED ({len(report_guard_errors)} issue(s)). Regenerate audit/verdict/report from the same current artifact set.")
    lines.append(f"- Requirement result: {requirement_result(ledger, audit_summary)}")
    runtime_rows = runtime_disposition_rows(ledger)
    probe_label = status_icon(results.get('status', 'unknown'))
    if results.get("status") == "attention" and runtime_rows:
        probe_label += " (runtime issues dispositioned in evidence ledger)"
    lines.append(f"- Probe result: {probe_label}")
    lines.append(f"- Base URL: {plan.get('baseUrl', '')}")
    if adapter_context:
        boundary = adapter_context.get("environment_boundary", {})
        lines.append(f"- Adapter context: {adapter_context.get('adapter')} (`{adapter_context_path}`)")
        lines.append(f"- Environment boundary: runtime={boundary.get('runtime_mode')}; data={boundary.get('data_boundary_status')}")
    if adapter_probes:
        summary = adapter_probes.get("summary", {})
        lines.append(f"- Adapter probes: proposed={summary.get('proposed_step_count', 0)}, blocked={summary.get('blocked_probe_count', 0)} (`{adapter_probes_path}`)")
    if service_preflight:
        lines.append(f"- Runtime preflight: runnable={service_preflight.get('runnable')}, blockers={len(service_preflight.get('blockers') or [])} (`{service_preflight_path}`)")
    if service_runtime:
        summary = service_runtime.get("summary", {})
        lines.append(
            f"- Service runtime: mode={service_runtime.get('mode')}, started={summary.get('started_count', 0)}, ready={summary.get('ready_count', 0)}, failed={summary.get('failed_count', 0)} (`{service_runtime_path}`)"
        )
    lines.append(f"- Test time: {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"- Results file: `{results_path}`")
    lines.append("- Evidence integrity: Current-run probe evidence only. Do not treat unplanned or unexecuted requirement points as passed.")
    if audit_summary:
        audit_label = "STRUCTURE_PASS" if audit_summary.get("passed") else "FAIL"
        lines.append(f"- Evidence audit: {audit_label} (`{audit_summary_path}`)")
        lines.append(f"- Audited requirements: {audit_summary.get('requirement_count', 0)}")
    else:
        lines.append("- Evidence audit: NOT RUN. Do not treat this report as final pass/fail evidence.")
    if plan_audit_summary:
        coverage = plan_audit_summary.get("strategy_coverage") if isinstance(plan_audit_summary.get("strategy_coverage"), dict) else {}
        lines.append(
            f"- Plan validation: passed={plan_audit_summary.get('passed')}, errors={len(plan_audit_summary.get('errors') or [])}, strategy_gaps={coverage.get('gap_count', 0)} (`{plan_audit_summary_path}`)"
        )
    if ledger:
        status_counts = requirement_status_counts(ledger)
        lines.append(f"- Requirement status counts: `{json.dumps(status_counts, ensure_ascii=False)}`")
        non_passed = sum(count for status, count in status_counts.items() if status != "Passed")
        if non_passed:
            lines.append("- Requirement pass/fail: NOT PASSED. Failed, blocked, untested, or inconclusive items remain.")
        elif final_pass_allowed:
            lines.append("- Requirement pass/fail: PASSED for the audited scope and allowed by final verdict.")
        elif verdict and report_guard_errors:
            lines.append("- Requirement pass/fail: LEDGER PASSED, FINAL PASS BLOCKED by report artifact binding checks.")
        elif verdict:
            lines.append("- Requirement pass/fail: LEDGER PASSED, FINAL PASS BLOCKED by qa-verdict.json.")
        else:
            lines.append("- Requirement pass/fail: LEDGER PASSED, FINAL PASS UNVERIFIED because qa-verdict.json was not generated/readable.")
    if requirement_coverage:
        lines.append(
            f"- Requirement source coverage: passed={requirement_coverage.get('passed')}, covered={requirement_coverage.get('covered_count', 0)}/{requirement_coverage.get('requirement_unit_count', 0)} (`{requirement_coverage_path}`)"
        )
    if ledger and ledger.get("runtime_summary"):
        lines.append(f"- Runtime summary: `{json.dumps(ledger.get('runtime_summary'), ensure_ascii=False)}`")
    if defects:
        defect_summary = defect_finding_summary(defects)
        lines.append(f"- Defects: {defect_summary['finding_count']} (`{defects_path}`)")
        if defect_summary["summary_count"] is not None and defect_summary["summary_count"] != defect_summary["findings_count"]:
            lines.append(f"- Defect summary mismatch: summary={defect_summary['summary_count']}, findings={defect_summary['findings_count']}")
        if defect_summary["severity_counts"]:
            lines.append(f"- Defect severity counts: `{json.dumps(defect_summary['severity_counts'], ensure_ascii=False)}`")
    if next_probes:
        lines.append(f"- Suggested next probes: {next_probes.get('summary', {}).get('recommendation_count', 0)} (`{next_probes_path}`)")
    if next_probe_application:
        summary = next_probe_application.get("summary", {})
        lines.append(
            f"- Next-probe application: applied={summary.get('applied_count', 0)}, skipped={summary.get('skipped_count', 0)} (`{next_probe_application_path}`)"
        )
    if semantic_guard_errors:
        lines.append(f"- Semantic artifact binding: BLOCKED ({len(semantic_guard_errors)} issue(s)). Regenerate semantic artifacts from the current requirement/matrix/plan before rendering them.")
    if semantic_artifacts_renderable and business_model:
        lines.append(
            f"- Business model: actors={len(business_model.get('actors') or [])}, entities={len(business_model.get('entities') or [])}, workflows={len(business_model.get('workflows') or [])} (`{business_model_path}`)"
        )
    if semantic_artifacts_renderable and oracle_model:
        oracle_summary = oracle_model.get("summary") if isinstance(oracle_model.get("summary"), dict) else {}
        lines.append(
            f"- Oracle model: requirements={oracle_summary.get('requirement_count', 0)}, blocked={oracle_summary.get('blocked_oracle_count', 0)} (`{oracle_model_path}`)"
        )
    if semantic_artifacts_renderable and qa_metrics:
        metric_summary = qa_metrics.get("summary") if isinstance(qa_metrics.get("summary"), dict) else {}
        lines.append(
            f"- QA metrics: automation_readiness={qa_metrics.get('effectiveness_metrics', {}).get('automation_readiness')}, manual_intervention_points={qa_metrics.get('effectiveness_metrics', {}).get('manual_intervention_points')}, requirements={metric_summary.get('requirement_count', 0)} (`{qa_metrics_path}`)"
        )
    if semantic_artifacts_renderable and closeout_candidates:
        lines.append(
            f"- Closeout candidates: stable={len(closeout_candidates.get('stable_knowledge_candidates') or [])}, process={len(closeout_candidates.get('qa_process_improvement_candidates') or [])}, confirmation_required={closeout_candidates.get('human_confirmation_required')} (`{closeout_candidates_path}`)"
        )
    lines.append("")

    if input_errors:
        lines.append("## Report Input Errors")
        lines.append("")
        lines.append("| Artifact | Required | Error | Path |")
        lines.append("| --- | --- | --- | --- |")
        for item in input_errors:
            lines.append(
                "| "
                + " | ".join(
                    [
                        table_cell(item.get("name", "")),
                        table_cell(item.get("required", "")),
                        table_cell(item.get("error", ""), 700),
                        table_cell(item.get("path", ""), 900),
                    ]
                )
                + " |"
            )
        lines.append("")

    if verdict:
        lines.append("## Final Verdict")
        lines.append("")
        lines.append(f"- Verdict: {verdict.get('verdict')}")
        lines.append(f"- Can claim pass: {verdict.get('can_claim_pass')}")
        lines.append(f"- Statement: {verdict.get('statement')}")
        if report_guard_errors:
            lines.append("- Report pass claim guard: DO NOT CLAIM PASS; qa-verdict.json is not bound to the current report artifacts.")
            lines.append("")
            lines.append("| Report Guard Issue |")
            lines.append("| --- |")
            for issue in report_guard_errors:
                lines.append(f"| {table_cell(issue, 1000)} |")
        if verdict.get("can_claim_pass") is not True or report_guard_errors:
            lines.append("- Pass claim guard: DO NOT CLAIM PASS from this report.")
        gates = verdict.get("gates") or {}
        if gates:
            lines.append(f"- Gates: `{json.dumps(gates, ensure_ascii=False)}`")
        reasons = verdict.get("reasons") or []
        if reasons:
            lines.append("")
            lines.append("| Code | Category | Severity | Message | Refs |")
            lines.append("| --- | --- | --- | --- | --- |")
            for item in reasons:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            table_cell(item.get("code", "")),
                            table_cell(item.get("category", "")),
                            table_cell(item.get("severity", "")),
                            table_cell(item.get("message", ""), 900),
                            table_cell(", ".join(str(ref) for ref in item.get("refs", [])), 600),
                        ]
                    )
                    + " |"
                )
        else:
            lines.append("- No blockers, failures, or evidence gaps identified by the verdict gate.")
        lines.append("")

    if requirement_coverage:
        lines.append("## Requirement Source Coverage")
        lines.append("")
        lines.append(f"- Passed: {requirement_coverage.get('passed')}")
        lines.append(f"- Covered source units: {requirement_coverage.get('covered_count', 0)} / {requirement_coverage.get('requirement_unit_count', 0)}")
        uncovered = [item for item in requirement_coverage.get("coverage", []) if not item.get("covered")]
        if uncovered:
            lines.append("")
            lines.append("| Source Unit | Source | Text |")
            lines.append("| --- | --- | --- |")
            for item in uncovered:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            table_cell(item.get("id", "")),
                            table_cell(item.get("source", "")),
                            table_cell(item.get("text", ""), 900),
                        ]
                    )
                    + " |"
                )
        else:
            lines.append("- No unmapped requirement source units identified.")
        lines.append("")

    if requirement_text:
        lines.append("## 2. Requirement Source")
        lines.append("")
        preview = requirement_text if len(requirement_text) <= 2500 else requirement_text[:2500] + "\n\n...[truncated]"
        lines.append(preview)
        lines.append("")

    if semantic_guard_errors:
        lines.append("## Semantic Artifact Binding Guard")
        lines.append("")
        lines.append("- Status: BLOCKED. Semantic planning artifacts are not rendered because their source bindings are missing or stale.")
        lines.append("- Rule: regenerate semantic artifacts from the current requirement, matrix, and plan before treating them as planning context.")
        lines.append("")
        lines.append("| Issue |")
        lines.append("| --- |")
        for issue in semantic_guard_errors:
            lines.append(f"| {table_cell(issue, 1000)} |")
        lines.append("")

    if semantic_artifacts_renderable and business_model:
        lines.append("## Business Intent Model")
        lines.append("")
        lines.append(f"- Artifact: `{business_model_path}`")
        lines.append("- Planning context only: it does not prove feature correctness.")
        actors = business_model.get("actors") or []
        entities = business_model.get("entities") or []
        workflows = business_model.get("workflows") or []
        if actors:
            lines.append("")
            lines.append("| Actor | Source Requirements |")
            lines.append("| --- | --- |")
            for item in actors:
                lines.append(f"| {table_cell(item.get('name', ''))} | {table_cell(', '.join(str(value) for value in item.get('source_requirement_ids', [])))} |")
        if entities:
            lines.append("")
            lines.append("| Entity | Source Requirements |")
            lines.append("| --- | --- |")
            for item in entities:
                lines.append(f"| {table_cell(item.get('name', ''))} | {table_cell(', '.join(str(value) for value in item.get('source_requirement_ids', [])))} |")
        if workflows:
            lines.append("")
            lines.append("| Workflow | Evidence Layers | Blocked | Entry Points | API Paths |")
            lines.append("| --- | --- | --- | --- | --- |")
            for item in workflows:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            table_cell(item.get("label", "")),
                            table_cell(", ".join(str(value) for value in item.get("evidence_layers", []))),
                            table_cell(item.get("blocked", "")),
                            table_cell(", ".join(str(value) for value in item.get("entry_points", []))),
                            table_cell(", ".join(str(value) for value in item.get("api_paths", [])), 900),
                        ]
                    )
                    + " |"
                )
        contract = business_model.get("agent_team_contract") if isinstance(business_model.get("agent_team_contract"), dict) else {}
        if contract:
            lines.append("")
            lines.append(f"- Agent team handoff rule: {contract.get('handoff_rule', '')}")
        lines.append("")

    if semantic_artifacts_renderable and oracle_model:
        lines.append("## Oracle Model")
        lines.append("")
        lines.append(f"- Artifact: `{oracle_model_path}`")
        oracle_summary = oracle_model.get("summary") if isinstance(oracle_model.get("summary"), dict) else {}
        lines.append(f"- Evidence layer counts: `{json.dumps(oracle_summary.get('evidence_layer_counts', {}), ensure_ascii=False)}`")
        oracle_rows = oracle_model.get("requirements") or []
        if oracle_rows:
            lines.append("")
            lines.append("| Requirement | Tests | Required Evidence Layers | Weak Signals To Avoid | Blocked Until |")
            lines.append("| --- | --- | --- | --- | --- |")
            for item in oracle_rows:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            table_cell(item.get("requirement_id", "")),
                            table_cell(", ".join(str(value) for value in item.get("oracle_tests", []))),
                            table_cell(", ".join(str(value) for value in item.get("required_evidence_layers", []))),
                            table_cell("<br>".join(str(value) for value in item.get("weak_signals_to_avoid", [])), 900),
                            table_cell("<br>".join(str(value) for value in item.get("blocked_until", [])), 900),
                        ]
                    )
                    + " |"
                )
        lines.append("")

    if semantic_artifacts_renderable and qa_metrics:
        lines.append("## QA Metrics")
        lines.append("")
        lines.append(f"- Artifact: `{qa_metrics_path}`")
        metric_summary = qa_metrics.get("summary") if isinstance(qa_metrics.get("summary"), dict) else {}
        effectiveness = qa_metrics.get("effectiveness_metrics") if isinstance(qa_metrics.get("effectiveness_metrics"), dict) else {}
        lines.append("| Metric | Value |")
        lines.append("| --- | --- |")
        for key in (
            "requirement_count",
            "test_count",
            "planned_step_count",
            "actor_count",
            "entity_count",
            "workflow_count",
            "oracle_requirement_count",
            "blocked_test_count",
            "coverage_gap_count",
        ):
            lines.append(f"| {key} | {table_cell(metric_summary.get(key, 0))} |")
        for key, value in effectiveness.items():
            lines.append(f"| {key} | {table_cell(value)} |")
        lines.append("")

    if semantic_artifacts_renderable and closeout_candidates:
        lines.append("## Closeout Candidates")
        lines.append("")
        lines.append(f"- Artifact: `{closeout_candidates_path}`")
        lines.append(f"- Human confirmation required: {closeout_candidates.get('human_confirmation_required')}")
        lines.append(f"- Rule: {closeout_candidates.get('rule', '')}")
        stable = closeout_candidates.get("stable_knowledge_candidates") or []
        process = closeout_candidates.get("qa_process_improvement_candidates") or []
        if stable:
            lines.append("")
            lines.append("| Stable Knowledge Candidate | Source | Confirmation |")
            lines.append("| --- | --- | --- |")
            for item in stable:
                lines.append(
                    f"| {table_cell(item.get('text', ''), 900)} | {table_cell(item.get('source', ''))} | {table_cell(item.get('confirmation_required', ''))} |"
                )
        if process:
            lines.append("")
            lines.append("| QA Process Improvement Candidate | Source | Confirmation |")
            lines.append("| --- | --- | --- |")
            for item in process:
                lines.append(
                    f"| {table_cell(item.get('text', ''), 900)} | {table_cell(item.get('source', ''))} | {table_cell(item.get('confirmation_required', ''))} |"
                )
        lines.append("")

    if adapter_context:
        lines.append("## Environment Context")
        lines.append("")
        boundary = adapter_context.get("environment_boundary", {})
        lines.append(f"- Adapter: {adapter_context.get('adapter')}")
        lines.append(f"- Project root: `{adapter_context.get('project_root')}`")
        lines.append(f"- Runtime mode: {boundary.get('runtime_mode')}")
        lines.append(f"- Data boundary status: {boundary.get('data_boundary_status')}")
        data_boundaries = boundary.get("data_boundaries") or []
        if data_boundaries:
            lines.append("- Data/config boundaries:")
            for item in data_boundaries:
                lines.append(f"  - {item}")
        lines.append("")
        services = adapter_context.get("services") or []
        if services:
            lines.append("| Service | Role | Path | Probe |")
            lines.append("| --- | --- | --- | --- |")
            for service in services:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            table_cell(service.get("id", "")),
                            table_cell(service.get("role", "")),
                            table_cell(service.get("path", "")),
                            table_cell(service_probe_label(service)),
                        ]
                    )
                    + " |"
                )
            lines.append("")
        evidence_layers = adapter_context.get("evidence_layers") or []
        if evidence_layers:
            lines.append("| Evidence Layer | Strong Signal | Weak Signal To Avoid |")
            lines.append("| --- | --- | --- |")
            for layer in evidence_layers:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            table_cell(layer.get("id", "")),
                            table_cell(layer.get("strong_signal", ""), 900),
                            table_cell(layer.get("weak_signal_to_avoid", ""), 900),
                        ]
                    )
                    + " |"
                )
            lines.append("")

    if service_preflight:
        lines.append("## Runtime Preflight")
        lines.append("")
        lines.append(f"- Runnable now: {service_preflight.get('runnable')}")
        lines.append(f"- Required services: {', '.join(service_preflight.get('required_services') or [])}")
        lines.append(f"- Secret values read: {service_preflight.get('safety', {}).get('secret_values_read')}")
        lines.append(f"- Services started by preflight: {service_preflight.get('safety', {}).get('services_started')}")
        services = service_preflight.get("services") or []
        if services:
            lines.append("")
            lines.append("| Service | Status | Start CWD | Start Command |")
            lines.append("| --- | --- | --- | --- |")
            for service in services:
                start = service.get("start") or {}
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            table_cell(service.get("id", "")),
                            table_cell(preflight_service_label(service), 900),
                            table_cell(start.get("cwd", "")),
                            table_cell(" ".join(str(part) for part in start.get("command", [])), 900),
                        ]
                    )
                    + " |"
                )
        blockers = service_preflight.get("blockers") or []
        if blockers:
            lines.append("")
            lines.append("| Blocker Service | Reason | Detail |")
            lines.append("| --- | --- | --- |")
            for item in blockers:
                detail = item.get("url") or item.get("path") or item.get("executable") or item.get("script") or ", ".join(item.get("candidates", []))
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            table_cell(item.get("service", "")),
                            table_cell(item.get("reason", ""), 900),
                            table_cell(detail, 900),
                        ]
                    )
                    + " |"
                )
        start_plan = service_preflight.get("start_plan") or []
        if start_plan:
            lines.append("")
            lines.append("| Start Candidate | CWD | Command | Reason |")
            lines.append("| --- | --- | --- | --- |")
            for item in start_plan:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            table_cell(item.get("service", "")),
                            table_cell(item.get("cwd", "")),
                            table_cell(" ".join(str(part) for part in item.get("command", [])), 900),
                            table_cell(item.get("reason", ""), 900),
                        ]
                    )
                    + " |"
                )
        lines.append("")

    if service_runtime:
        lines.append("## Service Runtime")
        lines.append("")
        runtime_summary = service_runtime.get("summary") or {}
        runtime_safety = service_runtime.get("safety") or {}
        lines.append(f"- Mode: {service_runtime.get('mode')}")
        lines.append(f"- Planned services: {runtime_summary.get('planned_count', 0)}")
        lines.append(f"- Started services: {runtime_summary.get('started_count', 0)}")
        lines.append(f"- Ready services: {runtime_summary.get('ready_count', 0)}")
        lines.append(f"- Failed services: {runtime_summary.get('failed_count', 0)}")
        lines.append(f"- Secret values read: {runtime_safety.get('secret_values_read')}")
        lines.append(f"- Shell used: {runtime_safety.get('shell_used')}")
        services = service_runtime.get("services") or []
        if services:
            lines.append("")
            lines.append("| Service | Runtime Status | URL | CWD | Command | Logs |")
            lines.append("| --- | --- | --- | --- | --- | --- |")
            for service in services:
                logs = []
                if service.get("stdout_log"):
                    logs.append(f"stdout `{service.get('stdout_log')}`")
                if service.get("stderr_log"):
                    logs.append(f"stderr `{service.get('stderr_log')}`")
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            table_cell(service.get("service", "")),
                            table_cell(service_runtime_label(service), 900),
                            table_cell(service.get("default_url", "")),
                            table_cell(service.get("cwd", "")),
                            table_cell(" ".join(str(part) for part in service.get("command", [])), 900),
                            table_cell("<br>".join(logs), 900),
                        ]
                    )
                    + " |"
                )
        lines.append("")

    if adapter_probes:
        lines.append("## Adapter Probe Synthesis")
        lines.append("")
        lines.append(f"- Applied to plan: {adapter_probes.get('applied')}")
        lines.append(f"- Marker: `{adapter_probes.get('marker', '')}`")
        if adapter_probes.get("proposed_step_ids"):
            lines.append(f"- Proposed steps: {', '.join(adapter_probes.get('proposed_step_ids', []))}")
        recommendations = adapter_probes.get("recommendations") or []
        blocked = adapter_probes.get("blocked") or []
        if recommendations:
            lines.append("")
            lines.append("| Layer | Status | Tests | Step | Strong Signal |")
            lines.append("| --- | --- | --- | --- | --- |")
            for item in recommendations:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            table_cell(item.get("layer", "")),
                            table_cell(item.get("status", "")),
                            table_cell(", ".join(str(value) for value in item.get("test_ids", []))),
                            table_cell(item.get("step_id", "")),
                            table_cell(item.get("strong_signal", "") or item.get("reason", ""), 900),
                        ]
                    )
                    + " |"
                )
        if blocked:
            lines.append("")
            lines.append("| Blocked Layer | Tests | Reason | Required Inputs |")
            lines.append("| --- | --- | --- | --- |")
            for item in blocked:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            table_cell(item.get("layer", "")),
                            table_cell(", ".join(str(value) for value in item.get("test_ids", []))),
                            table_cell(item.get("reason", ""), 900),
                            table_cell(", ".join(str(value) for value in item.get("required_inputs", [])), 900),
                        ]
                    )
                    + " |"
                )
        lines.append("")

    lines.append("## 3. Requirement Coverage")
    lines.append("")
    if ledger:
        evidence_by_id = {item.get("id"): item for item in ledger.get("evidence", [])}
        lines.append("| Requirement | Source Evidence | Status | Evidence | Notes |")
        lines.append("| --- | --- | --- | --- | --- |")
        for req in ledger.get("requirements", []):
            evidence_bits = []
            for evidence_id in req.get("evidence_ids", []):
                ev = evidence_by_id.get(evidence_id, {})
                locator = ev.get("path") or ev.get("file") or ev.get("url") or ev.get("log_ref") or ev.get("value") or ""
                evidence_bits.append(f"{evidence_id}: {ev.get('type', '')} {locator}".strip())
            lines.append(
                "| "
                + " | ".join(
                    [
                        str(req.get("id", "")),
                        str(req.get("source", "")),
                        status_icon(req.get("status", "")),
                        "<br>".join(evidence_bits) if evidence_bits else "",
                        str(req.get("notes", "")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("- No evidence ledger was provided. Requirement-level pass/fail status is not audited.")
    lines.append("")

    lines.append("## 4. Defects")
    lines.append("")
    findings = defects.get("findings", []) if defects else []
    if findings:
        lines.append("| Defect | Severity | Layers | Affected | Actual | Evidence |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for finding in findings:
            evidence_ids = [item.get("id", "") for item in finding.get("evidence", []) if item.get("id")]
            affected = ", ".join(finding.get("affected_tests", []))
            layers = ", ".join(finding.get("layers", []))
            lines.append(
                "| "
                + " | ".join(
                    [
                        table_cell(f"{finding.get('id', '')}: {finding.get('title', '')}"),
                        table_cell(finding.get("severity", "")),
                        table_cell(layers),
                        table_cell(affected),
                        table_cell(finding.get("actual", ""), 700),
                        table_cell(", ".join(evidence_ids)),
                    ]
                )
                + " |"
            )
        lines.append("")
        for finding in findings:
            lines.append(f"### {finding.get('id')}: {finding.get('title')}")
            lines.append("")
            lines.append(f"- Severity: {finding.get('severity')} / Confidence: {finding.get('confidence')}")
            lines.append(f"- Expected: {finding.get('expected', '')}")
            lines.append(f"- Actual: {finding.get('actual', '')}")
            lines.append(f"- {finding.get('inference', '')}")
            if finding.get("repro_steps"):
                lines.append("- Repro:")
                for idx, step in enumerate(finding.get("repro_steps", []), 1):
                    lines.append(f"  {idx}. {step}")
            lines.append("")
    else:
        lines.append("- None generated from the audited evidence ledger.")
        lines.append("")

    lines.append("## 5. Next Probes")
    lines.append("")
    recommendations = next_probes.get("recommendations", []) if next_probes else []
    if recommendations:
        lines.append("| Probe | Priority | Layer | Objective | Reason | Required Inputs |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for rec in recommendations:
            lines.append(
                "| "
                + " | ".join(
                    [
                        table_cell(f"{rec.get('id', '')} ({rec.get('finding_id', '')})"),
                        table_cell(rec.get("priority", "")),
                        table_cell(rec.get("layer", "")),
                        table_cell(rec.get("objective", ""), 500),
                        table_cell(rec.get("reason", ""), 700),
                        table_cell(", ".join(rec.get("required_inputs", [])), 400),
                    ]
                )
                + " |"
            )
    else:
        lines.append("- None generated.")
    lines.append("")

    lines.append("## 6. Scenario Results")
    lines.append("")
    lines.append("| Scenario | Status | Failed Steps | Evidence |")
    lines.append("| --- | --- | --- | --- |")
    for scenario in results.get("scenarios", []):
        failed = [s for s in scenario.get("steps", []) if s.get("status") == "failed"]
        evidence = []
        for step in scenario.get("steps", []):
            if step.get("screenshot"):
                evidence.append(step["screenshot"])
        evidence_text = "<br>".join(f"`{e}`" for e in evidence[:5])
        lines.append(f"| {scenario.get('title') or scenario.get('id')} | {status_icon(scenario.get('status', 'unknown'))} | {len(failed)} | {evidence_text} |")
    lines.append("")

    lines.append("## 7. Step Details")
    lines.append("")
    for scenario in results.get("scenarios", []):
        lines.append(f"### {scenario.get('title') or scenario.get('id')}")
        lines.append("")
        for step in scenario.get("steps", []):
            lines.append(f"- {status_icon(step.get('status', 'unknown'))} `{step.get('action')}` {step.get('title', '')}".rstrip())
            if step.get("url"):
                lines.append(f"  - URL: {step['url']}")
            if step.get("statusCode"):
                lines.append(f"  - Status: {step['statusCode']}")
            if step.get("extractedJson"):
                names = ", ".join(f"`{name}`" for name in sorted(step.get("extractedJson", {}).keys()))
                lines.append(f"  - Extracted vars: {names}")
            if step.get("stdoutPreview"):
                lines.append(f"  - Stdout: `{inline_preview(step['stdoutPreview'])}`")
            if step.get("stderrPreview"):
                lines.append(f"  - Stderr: `{inline_preview(step['stderrPreview'])}`")
            if step.get("error"):
                lines.append(f"  - Error: {step['error']}")
            if step.get("hitTest"):
                lines.append(f"  - Hit test: {hit_test_summary(step.get('hitTest'))}")
            if step.get("screenshot"):
                lines.append(f"  - Screenshot: `{step['screenshot']}`")
        lines.append("")

    lines.append("## 8. Runtime Errors")
    lines.append("")
    lines.append("### Console")
    lines.append("")
    console = results.get("console", [])
    if console:
        for item in console[:50]:
            lines.append(f"- {item.get('type')}: {item.get('text')} ({item.get('url')})")
    else:
        lines.append("- None captured.")
    lines.append("")
    lines.append("### Failed Network/API Responses")
    lines.append("")
    failed_responses = results.get("failedResponses", [])
    if failed_responses:
        for item in failed_responses[:80]:
            lines.append(f"- HTTP {item.get('status')} `{item.get('url')}`")
    else:
        lines.append("- None captured.")
    lines.append("")

    lines.append("### Request Failures")
    lines.append("")
    request_failures = results.get("requestFailures", [])
    if request_failures:
        for item in request_failures[:80]:
            lines.append(f"- {item.get('method', '')} `{item.get('url')}`: {item.get('failure', '')}")
    else:
        lines.append("- None captured.")
    lines.append("")

    lines.append("### Runtime Disposition")
    lines.append("")
    if runtime_rows:
        lines.append("| Evidence | Disposition Signals | Proves |")
        lines.append("| --- | --- | --- |")
        for row in runtime_rows:
            lines.append(f"| {row['id']} | {'<br>'.join(row['signals'])} | {row['proves']} |")
    else:
        lines.append("- No runtime disposition evidence was provided.")
    lines.append("")

    lines.append("## 9. Evidence Inventory")
    lines.append("")
    if ledger and ledger.get("evidence"):
        lines.append("| Evidence | Type | Locator | Hit Test | Signals | Proves |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for item in ledger.get("evidence", []):
            locator = item.get("path") or item.get("file") or item.get("url") or item.get("log_ref") or item.get("value") or ""
            lines.append(
                "| "
                + " | ".join(
                    [
                        table_cell(item.get("id", "")),
                        table_cell(item.get("type", "")),
                        table_cell(f"`{locator}`"),
                        table_cell(hit_test_summary(item.get("hit_test")), 700),
                        table_cell(signal_summary(item), 700),
                        table_cell(str(item.get("proves", "")), 500),
                    ]
                )
                + " |"
            )
    else:
        lines.append("- No evidence ledger inventory was provided.")
    lines.append("")

    lines.append("## 10. Coverage Gaps")
    lines.append("")
    if audit_summary:
        errors = audit_summary.get("errors", [])
        counts = audit_summary.get("status_counts", {})
        if errors:
            for error in errors:
                lines.append(f"- Audit error: {error}")
        elif any(counts.get(status, 0) for status in ("Failed", "Blocked", "Untested", "Inconclusive")):
            lines.append("- Audited scope still has non-passed requirement statuses:")
            for status in ("Failed", "Blocked", "Untested", "Inconclusive"):
                count = counts.get(status, 0)
                if count:
                    lines.append(f"  - {status}: {count}")
        else:
            lines.append("- None identified in the audited scope.")
        if counts:
            lines.append(f"- Requirement status counts: {json.dumps(counts, ensure_ascii=False)}")
    else:
        lines.append("- Evidence audit was not run.")
        lines.append("- Any requirement point not represented in the plan/results must be manually marked `Untested`, `Blocked`, or `Inconclusive`; never infer it as `Passed`.")
        lines.append("- Before final delivery, compare this report against the original requirement source and add missing requirement coverage rows.")
    lines.append("")

    lines.append("## 11. Screenshot Evidence")
    lines.append("")
    screenshots = []
    for scenario in results.get("scenarios", []):
        for step in scenario.get("steps", []):
            if step.get("screenshot"):
                screenshots.append(step["screenshot"])
    if screenshots:
        for idx, shot in enumerate(screenshots, 1):
            lines.append(f"### Screenshot {idx}")
            lines.append("")
            lines.append(f"![Screenshot {idx}]({shot})")
            lines.append("")
    else:
        lines.append("- No screenshots captured.")
        lines.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(out_path)
    return 1 if input_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
