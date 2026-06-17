#!/usr/bin/env python3
import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def trim(value: Any, limit: int = 800) -> str:
    text = str(value or "").strip()
    return text[:limit] + ("...[truncated]" if len(text) > limit else "")


def clean_error(value: str) -> str:
    text = trim(value, 500)
    text = re.sub(r"^(WebSocket|SSE) probe errors:\s*", "", text)
    text = re.sub(r"^Expected exit code 0, got \d+\s*", "Command exited non-zero", text)
    return text or "Observed failure"


def classify_layer(evidence: dict[str, Any], test: dict[str, Any]) -> str:
    haystack = " ".join(
        str(part or "")
        for part in (
            evidence.get("type"),
            evidence.get("action"),
            test.get("type"),
            evidence.get("proves"),
            evidence.get("error"),
            test.get("expected"),
        )
    ).lower()
    if re.search(r"(?<![a-z0-9_])(websocket|sse|stream|answer_done)(?![a-z0-9_])", haystack) or "流式" in haystack:
        return "stream"
    if any(term in haystack for term in ("postgres", "database", "db", "completed", "persistence", "persist", "持久", "数据库")):
        return "persistence"
    if any(term in haystack for term in ("api", "http", "json path", "status_code")):
        return "api"
    if any(term in haystack for term in ("console", "request failure", "failed response", "runtime")):
        return "runtime"
    if any(term in haystack for term in ("click", "visible", "locator", "screenshot", "ui", "interaction", "modal", "overlay")):
        return "ui"
    return "requirement"


def severity_for(layers: list[str], test: dict[str, Any], notes: str) -> str:
    haystack = " ".join([str(test.get("type", "")), str(test.get("expected", "")), notes]).lower()
    if any(term in haystack for term in ("data loss", "corrupt", "security", "unauthorized access", "越权", "数据丢失", "破坏数据")):
        return "P0"
    if any(layer in layers for layer in ("stream", "persistence", "api")):
        return "P1"
    if any(layer in layers for layer in ("ui", "runtime")):
        return "P2"
    return "P2"


def title_for(test: dict[str, Any], evidence_items: list[dict[str, Any]]) -> str:
    primary = next((item for item in evidence_items if item.get("error")), evidence_items[0] if evidence_items else {})
    error = clean_error(primary.get("error", ""))
    ev_type = str(primary.get("type") or test.get("type") or "requirement").replace("_", " ")
    if primary.get("stdout_preview") and "status=failed" in str(primary.get("stdout_preview")):
        return "Persistence check failed: turn status=failed"
    if "JSON error:" in error:
        return error.replace("JSON error:", "returned error:").strip()
    if "JSON path" in error:
        return "API assertion failed: " + error
    if error and error != "Observed failure":
        return f"{ev_type.title()} failed: {error}"
    return f"{ev_type.title()} failed for {test.get('id', 'test')}"


def evidence_ref(item: dict[str, Any]) -> dict[str, Any]:
    locator = item.get("path") or item.get("file") or item.get("url") or item.get("log_ref") or item.get("value") or ""
    ref: dict[str, Any] = {
        "id": item.get("id", ""),
        "type": item.get("type", ""),
        "locator": locator,
        "proves": item.get("proves", ""),
    }
    for key in (
        "scenario_id",
        "step_id",
        "action",
        "status",
        "error",
        "status_code",
        "observed_url",
        "response_after_click",
        "exit_code",
        "messages_seen",
        "message_text_contains_matched",
        "response_text_contains_matched",
        "request_text_contains_matched",
        "stdout_contains_matched",
        "stderr_contains_matched",
        "stdout_preview",
        "stderr_preview",
        "body_path",
        "body_preview",
        "request_body_path",
        "request_body_preview",
        "hit_test",
    ):
        if item.get(key) is not None:
            ref[key] = item.get(key)
    if item.get("assertions"):
        ref["assertions"] = as_list(item.get("assertions"))[:8]
    return ref


def build_actual(test: dict[str, Any], evidence_items: list[dict[str, Any]]) -> str:
    pieces: list[str] = []
    if has_text(test.get("notes")):
        pieces.append(str(test["notes"]))
    for item in evidence_items:
        if has_text(item.get("error")):
            pieces.append(str(item["error"]))
        if has_text(item.get("stdout_preview")):
            pieces.append("stdout: " + str(item["stdout_preview"]).strip())
        if has_text(item.get("stderr_preview")):
            pieces.append("stderr: " + str(item["stderr_preview"]).strip())
        if has_text(item.get("body_preview")):
            pieces.append("response body: " + trim(item["body_preview"], 500))
        if has_text(item.get("body_path")):
            pieces.append("response body artifact: " + str(item["body_path"]))
        if item.get("status_code") is not None:
            pieces.append(f"HTTP status: {item.get('status_code')}")
        if item.get("response_after_click") is not None:
            pieces.append(f"response after click: {item.get('response_after_click')}")
        hit_test = item.get("hit_test") or {}
        if hit_test.get("blocker"):
            blocker = hit_test.get("blocker") or {}
            blocker_label = blocker.get("selector") or blocker.get("tag") or "unknown"
            pieces.append(f"hit-test blocker: {blocker_label}")
    return trim("; ".join(dict.fromkeys(piece for piece in pieces if piece)), 1200)


def build_inference(layers: list[str], actual: str) -> str:
    if "runtime" in layers and "Undispositioned runtime issue" in actual:
        return "Inference: the run captured runtime errors outside mapped requirement evidence; add explicit runtime disposition probes or map the issue to a failed requirement."
    if "stream" in layers and "Session not found" in actual:
        return "Inference: the stream runtime rejected the proxied session identifier before answer completion; verify session ownership and runtime session handoff."
    if "persistence" in layers and "status=failed" in actual:
        return "Inference: the extracted runtime object reached a failed persisted terminal state, so stream completion and persistence are not equivalent."
    if "api" in layers and "message_count" in actual:
        return "Inference: the persisted/read API state is missing an expected assistant-side result after the attempted turn."
    if "stream" in layers:
        return "Inference: the stream did not reach the expected terminal success event; inspect upstream runtime logs and correlated ids."
    if "persistence" in layers:
        return "Inference: the persistence/log layer contradicted the expected terminal state."
    return "Inference: the observed evidence contradicts the mapped expected behavior."


def make_finding(
    index: int,
    test: dict[str, Any],
    req_by_id: dict[str, dict[str, Any]],
    evidence_by_id: dict[str, dict[str, Any]],
    results_path: Path | None,
) -> dict[str, Any]:
    evidence_items = [evidence_by_id[eid] for eid in as_list(test.get("evidence_ids")) if eid in evidence_by_id]
    if not evidence_items:
        evidence_items = []
    layers = sorted({classify_layer(item, test) for item in evidence_items}) or [classify_layer({}, test)]
    actual = build_actual(test, evidence_items)
    affected_requirements = [
        {
            "id": req_id,
            "text": req_by_id.get(req_id, {}).get("text", ""),
        }
        for req_id in as_list(test.get("requirement_ids"))
    ]
    step_ids = [item.get("step_id") for item in evidence_items if has_text(item.get("step_id"))]
    repro_steps = [
        f"Run the QA cycle using `{results_path.parent}`." if results_path else "Run the QA cycle for the generated plan.",
        f"Inspect mapped test `{test.get('id')}` and evidence ids: {', '.join(as_list(test.get('evidence_ids')))}.",
    ]
    if step_ids:
        repro_steps.append("Review failed probe step(s): " + ", ".join(dict.fromkeys(str(step) for step in step_ids)))
    return {
        "id": f"D{index}",
        "title": title_for(test, evidence_items),
        "severity": severity_for(layers, test, actual),
        "confidence": "High" if evidence_items and actual else "Medium",
        "layers": layers,
        "affected_tests": [test.get("id", "")],
        "affected_requirements": affected_requirements,
        "expected": test.get("expected", ""),
        "actual": actual,
        "inference": build_inference(layers, actual),
        "repro_steps": repro_steps,
        "evidence": [evidence_ref(item) for item in evidence_items],
    }


def runtime_issue_items(results: dict[str, Any] | None, category: str) -> list[dict[str, Any]]:
    if not results:
        return []
    if category == "console_errors":
        return [item for item in as_list(results.get("console")) if item.get("type") == "error"]
    if category == "failed_responses":
        return as_list(results.get("failedResponses"))
    if category == "request_failures":
        return as_list(results.get("requestFailures"))
    return []


def nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def has_zero_runtime_disposition(evidence: list[dict[str, Any]], checked_field: str, ignored_field: str, observed_count: int) -> bool:
    for item in evidence:
        if item.get("type") != "runtime":
            continue
        checked = nonnegative_int(item.get(checked_field))
        ignored = nonnegative_int(item.get(ignored_field))
        ignored_count = ignored if ignored is not None else 0
        if checked == 0 and ignored_count == observed_count:
            return True
    return False


def has_explicit_runtime_failure(evidence: list[dict[str, Any]], action: str) -> bool:
    return any(item.get("action") == action and item.get("status") == "failed" for item in evidence)


def runtime_title(category: str, items: list[dict[str, Any]]) -> str:
    labels = {
        "console_errors": "Undispositioned console errors captured",
        "failed_responses": "Undispositioned failed HTTP responses captured",
        "request_failures": "Undispositioned request failures captured",
    }
    return f"{labels.get(category, 'Undispositioned runtime issues captured')}: {len(items)}"


def runtime_actual(category: str, items: list[dict[str, Any]]) -> str:
    details: list[str] = [f"Undispositioned runtime issue category={category} count={len(items)}"]
    for item in items[:5]:
        if category == "console_errors":
            details.append(trim(f"console error: {item.get('text', '')} url={item.get('url', '')}", 300))
        elif category == "failed_responses":
            details.append(trim(f"failed response: status={item.get('status')} url={item.get('url', '')}", 300))
        elif category == "request_failures":
            details.append(trim(f"request failure: method={item.get('method', '')} url={item.get('url', '')} failure={item.get('failure', '')}", 300))
    if len(items) > 5:
        details.append(f"{len(items) - 5} additional runtime issue(s) omitted from preview.")
    return trim("; ".join(details), 1200)


def runtime_evidence_refs(category: str, items: list[dict[str, Any]], results_path: Path | None) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for index, item in enumerate(items[:8], 1):
        ref: dict[str, Any] = {
            "id": f"runtime-{category}-{index}",
            "type": "runtime",
            "locator": str(results_path) if results_path else "results.json",
            "proves": "Probe runner captured a runtime issue that was not explicitly dispositioned.",
            "status": "failed",
        }
        if category == "console_errors":
            ref.update({
                "action": "console",
                "error": trim(item.get("text"), 500),
                "observed_url": item.get("url", ""),
            })
        elif category == "failed_responses":
            ref.update({
                "action": "response",
                "status_code": item.get("status"),
                "observed_url": item.get("url", ""),
            })
        elif category == "request_failures":
            ref.update({
                "action": "requestfailed",
                "error": trim(item.get("failure"), 500),
                "observed_url": item.get("url", ""),
                "method": item.get("method", ""),
            })
        refs.append(ref)
    return refs


def make_runtime_finding(index: int, category: str, items: list[dict[str, Any]], results_path: Path | None) -> dict[str, Any]:
    layers = ["runtime"]
    severity = "P1" if category == "failed_responses" and any(int(item.get("status") or 0) >= 500 for item in items) else "P2"
    actual = runtime_actual(category, items)
    return {
        "id": f"D{index}",
        "title": runtime_title(category, items),
        "severity": severity,
        "confidence": "High",
        "layers": layers,
        "runtime_categories": [category],
        "affected_tests": [],
        "affected_requirements": [],
        "expected": "Runtime issues are either absent, explicitly ignored with evidence, or mapped to a failed/non-passed requirement.",
        "actual": actual,
        "inference": build_inference(layers, actual),
        "repro_steps": [
            f"Run the QA cycle using `{results_path.parent}`." if results_path else "Run the QA cycle for the generated plan.",
            "Inspect `results.json` runtime arrays and add explicit runtime disposition probes or requirement mappings.",
        ],
        "evidence": runtime_evidence_refs(category, items, results_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate structured defects from a QA evidence ledger.")
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--results")
    parser.add_argument("--matrix")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    ledger_path = Path(args.ledger).expanduser().resolve()
    results_path = Path(args.results).expanduser().resolve() if args.results else None
    matrix_path = Path(args.matrix).expanduser().resolve() if args.matrix else None
    out_path = Path(args.out).expanduser().resolve()
    input_artifact_errors: list[dict[str, str]] = []
    ledger, ledger_load_error = try_load_json(ledger_path)
    results, results_load_error = try_load_json(results_path) if results_path else (None, None)
    _matrix, matrix_load_error = try_load_json(matrix_path) if matrix_path else (None, None)
    for name, path, load_error in (
        ("ledger", ledger_path, ledger_load_error),
        ("results", results_path, results_load_error),
        ("matrix", matrix_path, matrix_load_error),
    ):
        if path and load_error:
            input_artifact_errors.append({"name": name, "path": str(path), "error": load_error})
    if input_artifact_errors:
        defects = {
            "schema_version": 1,
            "generated_from": {
                "ledger": str(ledger_path),
                "results": str(results_path) if results_path else None,
                "matrix": str(matrix_path) if matrix_path else None,
            },
            "summary": {
                "finding_count": 0,
                "severity_counts": {},
                "layer_counts": {},
                "input_artifact_error_count": len(input_artifact_errors),
            },
            "findings": [],
            "input_artifact_errors": input_artifact_errors,
        }
        write_json(out_path, defects)
        print(json.dumps(defects, indent=2, ensure_ascii=False))
        return 1
    assert ledger is not None

    req_by_id = {item.get("id"): item for item in as_list(ledger.get("requirements")) if has_text(item.get("id"))}
    evidence_by_id = {item.get("id"): item for item in as_list(ledger.get("evidence")) if has_text(item.get("id"))}
    failed_tests = [item for item in as_list(ledger.get("tests")) if item.get("status") == "Failed"]

    findings = [
        make_finding(index, test, req_by_id, evidence_by_id, results_path)
        for index, test in enumerate(failed_tests, 1)
    ]
    evidence_items = as_list(ledger.get("evidence"))
    runtime_checks = {
        "console_errors": ("checked_console_errors", "ignored_console_errors", "expectNoConsoleErrors"),
        "failed_responses": ("checked_failed_responses", "ignored_failed_responses", "expectNoFailedResponses"),
        "request_failures": ("checked_request_failures", "ignored_request_failures", "expectNoRequestFailures"),
    }
    for category, (checked_field, ignored_field, action) in runtime_checks.items():
        runtime_items = runtime_issue_items(results, category)
        if not runtime_items:
            continue
        if has_zero_runtime_disposition(evidence_items, checked_field, ignored_field, len(runtime_items)) or has_explicit_runtime_failure(evidence_items, action):
            continue
        findings.append(make_runtime_finding(len(findings) + 1, category, runtime_items, results_path))

    severity_counts = Counter(item["severity"] for item in findings)
    layer_counts = Counter(layer for item in findings for layer in item.get("layers", []))
    defects = {
        "schema_version": 1,
        "generated_from": {
            "ledger": str(ledger_path),
            "results": str(results_path) if results_path else None,
            "matrix": str(matrix_path) if matrix_path else None,
        },
        "summary": {
            "finding_count": len(findings),
            "severity_counts": dict(sorted(severity_counts.items())),
            "layer_counts": dict(sorted(layer_counts.items())),
        },
        "findings": findings,
        "input_artifact_errors": input_artifact_errors,
    }
    write_json(out_path, defects)
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
