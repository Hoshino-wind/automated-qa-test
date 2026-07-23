#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any

from qa_common import atomic_write_json

SENSITIVE_QUERY_PARAM_RE = re.compile(r"(?:access[_-]?token|auth[_-]?token|token|session|cookie|key|api[_-]?key|secret)", re.IGNORECASE)


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


def file_sha256(path: Path | None) -> str | None:
    if path is None or not path.exists() or path.is_dir():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generated_from_hashes(defects_path: Path, results_path: Path | None, ledger_path: Path | None) -> dict[str, str | None]:
    return {
        "defects_sha256": file_sha256(defects_path),
        "results_sha256": file_sha256(results_path),
        "ledger_sha256": file_sha256(ledger_path),
    }


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def trim(value: Any, limit: int = 1000) -> str:
    text = str(value or "").strip()
    return text[:limit] + ("...[truncated]" if len(text) > limit else "")


def collect_result_steps(results: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for scenario in as_list(results.get("scenarios")):
        if not isinstance(scenario, dict):
            continue
        for step in as_list(scenario.get("steps")):
            if not isinstance(step, dict):
                continue
            merged = dict(step)
            merged.setdefault("scenarioId", scenario.get("id"))
            out.append(merged)
    return out


def id_set(value: Any) -> set[str]:
    if isinstance(value, list):
        items = value
    else:
        items = [value]
    return {str(item).strip() for item in items if has_text(item)}


def result_step_for_evidence(evidence: dict[str, Any], result_steps: list[dict[str, Any]]) -> dict[str, Any] | None:
    evidence_step_id = str(evidence.get("step_id") or "").strip()
    scenario_id = str(evidence.get("scenario_id") or "").strip()
    action = str(evidence.get("action") or "").strip()
    evidence_test_ids = id_set(evidence.get("test_ids"))
    evidence_req_ids = id_set(evidence.get("requirement_ids"))
    candidates: list[dict[str, Any]] = []
    for step in result_steps:
        candidate_step_id = step.get("stepId") or step.get("id")
        if evidence_step_id and str(candidate_step_id or "").strip() != evidence_step_id:
            continue
        if scenario_id and str(step.get("scenarioId") or "").strip() != scenario_id:
            continue
        if action and str(step.get("action") or "").strip() != action:
            continue
        step_test_ids = id_set(step.get("testIds"))
        step_req_ids = id_set(step.get("requirementIds"))
        if evidence_test_ids and step_test_ids and not evidence_test_ids.intersection(step_test_ids):
            continue
        if evidence_req_ids and step_req_ids and not evidence_req_ids.intersection(step_req_ids):
            continue
        candidates.append(step)
    if len(candidates) == 1:
        return candidates[0]
    if candidates:
        failed_candidates = [step for step in candidates if step.get("status") == "failed"]
        if len(failed_candidates) == 1:
            return failed_candidates[0]
        return None
    if evidence_step_id and not scenario_id:
        fallback = [
            step
            for step in result_steps
            if str(step.get("stepId") or step.get("id") or "").strip() == evidence_step_id
        ]
        if len(fallback) == 1:
            return fallback[0]
    return None


def extract_vars_from_text(text: Any) -> dict[str, str]:
    value = str(text or "")
    variables: dict[str, str] = {}
    id_names = r"session_id|turn_id|job_id|trace_id|request_id|correlation_id"
    for match in re.finditer(rf"\b({id_names})[=:]([A-Za-z0-9_.:-]+)", value):
        variables.setdefault(match.group(1), match.group(2))
    for match in re.finditer(rf'["\']({id_names})["\']\s*:\s*["\']([^"\']+)["\']', value):
        variables.setdefault(match.group(1), match.group(2))
    session_match = re.search(r"/sessions/([A-Za-z0-9_.:-]{8,})", value)
    if session_match:
        variables.setdefault("session_id", session_match.group(1))
    return variables


def api_path_from_text(value: Any) -> str | None:
    text = str(value or "")
    for match in re.finditer(r"https?://[^\s\"'<>]+", text):
        parsed = urllib.parse.urlparse(match.group(0).rstrip(".,;，。；"))
        if parsed.path and parsed.path != "/":
            return path_with_safe_query(parsed)
    match = re.search(r"(/[A-Za-z0-9_~{}:./-]+(?:\?[^\s\"'<>]+)?)", text)
    if match:
        parsed = urllib.parse.urlparse(match.group(1).rstrip(".,;，。；"))
        if parsed.path and parsed.path != "/":
            return path_with_safe_query(parsed)
    return first_path(text)


def path_with_safe_query(parsed: urllib.parse.ParseResult) -> str:
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    safe_pairs = [(key, value) for key, value in pairs if not SENSITIVE_QUERY_PARAM_RE.search(key)]
    safe_query = urllib.parse.urlencode(safe_pairs, doseq=True)
    return parsed.path + (f"?{safe_query}" if safe_query else "")


def finding_vars(finding: dict[str, Any], result_steps: list[dict[str, Any]]) -> dict[str, Any]:
    variables: dict[str, Any] = {}
    for evidence in as_list(finding.get("evidence")):
        step = result_step_for_evidence(evidence, result_steps)
        if not step:
            continue
        extracted = step.get("extractedJson")
        if isinstance(extracted, dict):
            variables.update(extracted)
        variables.update({k: v for k, v in extract_vars_from_text(evidence.get("locator")).items() if k not in variables})
        variables.update({k: v for k, v in extract_vars_from_text(evidence.get("observed_url")).items() if k not in variables})
        variables.update({k: v for k, v in extract_vars_from_text(evidence.get("error")).items() if k not in variables})
        for source in (evidence.get("locator"), evidence.get("observed_url"), evidence.get("error")):
            path = api_path_from_text(source)
            if path:
                variables.setdefault("api_path", path)
    variables.update({k: v for k, v in extract_vars_from_text(finding.get("actual")).items() if k not in variables})
    path = api_path_from_text(finding.get("actual"))
    if path:
        variables.setdefault("api_path", path)
    return variables


def evidence_ids(finding: dict[str, Any]) -> list[str]:
    return [item.get("id", "") for item in as_list(finding.get("evidence")) if has_text(item.get("id"))]


def first_path(value: Any) -> str | None:
    match = re.search(r"(/[A-Za-z0-9_~{}:.-]+(?:/[A-Za-z0-9_~{}:.-]+)*)", str(value or ""))
    if not match:
        return None
    path = match.group(1).rstrip(".,;，。；")
    return path if path != "/" else None


def command_hint(command: list[str], env: dict[str, Any] | None = None, cwd: str | None = None) -> dict[str, Any]:
    step: dict[str, Any] = {
        "action": "command",
        "command": command,
        "expectExitCode": 0,
        "captureStdout": True,
        "captureStderr": True,
    }
    if env:
        step["env"] = env
    if cwd:
        step["cwd"] = cwd
    return step


def api_hint(path: str, expect_status: int = 200) -> dict[str, Any]:
    return {
        "action": "api",
        "method": "GET",
        "path": path,
        "expectStatus": expect_status,
        "captureBody": True,
    }


def first_status_code(finding: dict[str, Any]) -> int | None:
    for evidence in as_list(finding.get("evidence")):
        try:
            return int(evidence.get("status_code"))
        except (TypeError, ValueError):
            continue
    match = re.search(r"\bstatus=(\d{3})\b|\bHTTP status:\s*(\d{3})\b", str(finding.get("actual") or ""), re.IGNORECASE)
    if not match:
        return None
    return int(next(group for group in match.groups() if group))


def recommendation(
    rec_id: str,
    finding: dict[str, Any],
    priority: str,
    layer: str,
    objective: str,
    suggested_probe_type: str,
    reason: str,
    plan_step_hint: dict[str, Any],
    required_inputs: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": rec_id,
        "finding_id": finding.get("id", ""),
        "priority": priority,
        "layer": layer,
        "objective": objective,
        "suggested_probe_type": suggested_probe_type,
        "reason": reason,
        "evidence_ids": evidence_ids(finding),
        "required_inputs": required_inputs or [],
        "plan_step_hint": plan_step_hint,
    }


def stream_recommendations(finding: dict[str, Any], variables: dict[str, Any], start_index: int) -> list[dict[str, Any]]:
    recs: list[dict[str, Any]] = []
    actual = finding.get("actual", "")
    session_id = variables.get("session_id")
    turn_id = variables.get("turn_id")
    if "Session not found" in actual:
        recs.append(recommendation(
            f"NP{start_index}",
            finding,
            "P1",
            "stream",
            "Check whether the runtime can answer without the proxied session id.",
            "websocket",
            "The proxied stream failed with `Session not found`; a direct/no-session runtime probe separates runtime health from session handoff.",
            {
                "action": "websocket",
                "path": "/api/agents/ask/ws",
                "send": {
                    "question": "QA_DIRECT_RUNTIME_HEALTH 请用一句话回答 OK"
                },
                "expectMessageTextContains": "answer_done",
                "captureMessages": True,
                "timeoutMs": 60000
            },
            ["runtime auth/env if the runtime requires authentication"],
        ))
        recs.append(recommendation(
            f"NP{start_index + 1}",
            finding,
            "P1",
            "stream",
            "Inspect server logs around the correlated session/turn id.",
            "command",
            "The gateway emitted ids before the runtime error; log grep can confirm whether the error comes from runtime session lookup or proxy framing.",
            command_hint([
                "bash",
                "-lc",
                "rg -n \"$QA_SESSION_ID|$QA_TURN_ID|Session not found|agent_ws|answer_done\" /tmp/*.log"
            ], env={
                "QA_SESSION_ID": session_id or "",
                "QA_TURN_ID": turn_id or "",
            }),
            ["log file location", "session_id", "turn_id"],
        ))
        return recs
    recs.append(recommendation(
        f"NP{start_index}",
        finding,
        "P1",
        "stream",
        "Replay the stream with captured request shape and require a terminal success event.",
        "websocket",
        "The stream did not reach the expected terminal success event; replay narrows flake vs deterministic failure.",
        {
            "action": "websocket",
            "send": {"question": "QA_STREAM_REPLAY"},
            "expectMessageTextContains": "answer_done",
            "captureMessages": True,
            "timeoutMs": 60000,
        },
    ))
    return recs


def persistence_recommendations(finding: dict[str, Any], variables: dict[str, Any], start_index: int) -> list[dict[str, Any]]:
    recs: list[dict[str, Any]] = []
    actual = finding.get("actual", "")
    session_id = variables.get("session_id")
    turn_id = variables.get("turn_id")
    if session_id:
        recs.append(recommendation(
            f"NP{start_index}",
            finding,
            "P1",
            "persistence",
            "Capture the full session detail for the same session id.",
            "api",
            "The session assertion failed; full body evidence distinguishes missing assistant message, wrong session, or serialization issue.",
            api_hint(f"/api/v1/sessions/{session_id}"),
            ["auth token", "baseUrl"],
        ))
        start_index += 1
    if turn_id:
        recs.append(recommendation(
            f"NP{start_index}",
            finding,
            "P1",
            "persistence",
            "Read the same turn and its saved events from the persistence layer.",
            "command",
            "The turn status contradicted the expected terminal state; event payloads explain whether failure came from upstream error, timeout, or completion append.",
            command_hint([
                "bash",
                "-lc",
                "python3 scripts/check_turn_and_events.py --turn-id \"$QA_TURN_ID\""
            ], env={
                "QA_TURN_ID": turn_id
            }),
            ["project-approved DB/ORM helper", "turn_id"],
        ))
    elif "status=failed" in actual:
        recs.append(recommendation(
            f"NP{start_index}",
            finding,
            "P1",
            "persistence",
            "Re-run the existing persistence status helper with event/log capture enabled.",
            "command",
            "The persisted object is failed but the event trail was not captured in this defect.",
            command_hint(["bash", "-lc", "echo provide project-specific persistence helper here"]),
            ["project persistence helper"],
        ))
    return recs


def api_recommendations(finding: dict[str, Any], variables: dict[str, Any], start_index: int) -> list[dict[str, Any]]:
    session_id = variables.get("session_id")
    path = f"/api/v1/sessions/{session_id}" if session_id else variables.get("api_path") or "<same API path>"
    required_inputs = ["baseUrl"]
    if path == "<same API path>":
        required_inputs.append("failed API path")
    if re.search(r"\b(?:401|403)\b", str(finding.get("actual") or "")):
        required_inputs.append("auth token")
    return [
        recommendation(
            f"NP{start_index}",
            finding,
            "P2",
            "api",
            "Capture the full response body and check the exact missing/incorrect JSON paths.",
            "api",
            "The failure is a JSON assertion mismatch; the next probe should preserve the full body and add focused assertions.",
            api_hint(path),
            required_inputs,
        )
    ]


def log_correlation_recommendations(finding: dict[str, Any], variables: dict[str, Any], start_index: int) -> list[dict[str, Any]]:
    correlation_id = variables.get("trace_id") or variables.get("request_id") or variables.get("correlation_id")
    if not has_text(correlation_id):
        return []
    return [
        recommendation(
            f"NP{start_index}",
            finding,
            "P1",
            "runtime",
            "Correlate the captured trace/request id against local service logs.",
            "command",
            "The failed response carried a diagnostic id; log correlation can connect the API symptom to the server-side stack or service boundary.",
            command_hint(
                [
                    "bash",
                    "-lc",
                    'QA_CORRELATION_ID="${QA_TRACE_ID:-${QA_REQUEST_ID:-${QA_CORRELATION_ID:-}}}"; test -n "$QA_CORRELATION_ID"; rg -n --fixed-strings -- "$QA_CORRELATION_ID" logs /tmp/*.log'
                ],
                env={
                    "QA_TRACE_ID": str(variables.get("trace_id") or ""),
                    "QA_REQUEST_ID": str(variables.get("request_id") or ""),
                    "QA_CORRELATION_ID": str(variables.get("correlation_id") or ""),
                },
            ),
            ["log file location"],
        )
    ]


def ui_recommendations(finding: dict[str, Any], variables: dict[str, Any], start_index: int) -> list[dict[str, Any]]:
    return [
        recommendation(
            f"NP{start_index}",
            finding,
            "P2",
            "ui",
            "Verify clickability and overlay blockers with hit-test evidence, not only visibility.",
            "browser",
            "UI failures can be caused by visible-but-blocked controls; hit-test evidence prevents false passes from screenshots.",
            {
                "action": "expectClickable",
                "selector": "<target selector>",
                "evidenceType": "ui_interaction",
                "proves": "The target element is visible and receives pointer events at its center point."
            },
            ["target selector or role/name"],
        ),
        recommendation(
            f"NP{start_index + 1}",
            finding,
            "P2",
            "ui",
            "Capture a screenshot and locator count at failure time.",
            "screenshot",
            "The follow-up should preserve the rendered state that caused the interaction failure.",
            {
                "action": "screenshot",
                "name": "ui-failure-state",
                "fullPage": True
            },
        ),
    ]


def runtime_recommendations(finding: dict[str, Any], variables: dict[str, Any], start_index: int) -> list[dict[str, Any]]:
    categories = set(as_list(finding.get("runtime_categories")))
    actual = str(finding.get("actual", "")).lower()
    if not categories:
        if "console_errors" in actual or "console error" in actual:
            categories.add("console_errors")
        if "failed_responses" in actual or "failed response" in actual:
            categories.add("failed_responses")
        if "request_failures" in actual or "request failure" in actual:
            categories.add("request_failures")
    if not categories:
        categories = {"console_errors"}

    templates = {
        "console_errors": {
            "action": "expectNoConsoleErrors",
            "objective": "Disposition captured console errors with explicit ignore rules or a mapped failure.",
            "reason": "Console errors were captured outside mapped evidence; a runtime probe must prove zero unignored errors or expose the failure.",
        },
        "failed_responses": {
            "action": "expectNoFailedResponses",
            "objective": "Disposition captured failed HTTP responses with explicit ignore rules or a mapped failure.",
            "reason": "Failed HTTP responses were captured outside mapped evidence; a runtime probe must prove zero unignored failures or expose the failing endpoint.",
        },
        "request_failures": {
            "action": "expectNoRequestFailures",
            "objective": "Disposition captured request failures with explicit ignore rules or a mapped failure.",
            "reason": "Browser request failures were captured outside mapped evidence; a runtime probe must prove zero unignored failures or expose the failing request.",
        },
    }
    recs: list[dict[str, Any]] = []
    for category in sorted(categories):
        spec = templates.get(category, templates["console_errors"])
        recs.append(recommendation(
            f"NP{start_index + len(recs)}",
            finding,
            "P2",
            "runtime",
            spec["objective"],
            "runtime",
            spec["reason"],
            {
                "action": spec["action"],
                "ignorePatterns": [],
                "evidenceType": "runtime",
                "proves": "No unignored runtime issues of this type remain in the current run.",
            },
            ["only add ignorePatterns for known benign, documented runtime noise"],
        ))
        if category == "failed_responses" and has_text(variables.get("api_path")):
            status_code = first_status_code(finding)
            required_inputs = ["baseUrl"]
            if status_code in {401, 403}:
                required_inputs.append("auth token")
            recs.append(recommendation(
                f"NP{start_index + len(recs)}",
                finding,
                "P1" if status_code and status_code >= 500 else "P2",
                "runtime",
                "Capture the failed HTTP response body from the same runtime endpoint.",
                "api",
                "A browser failedResponse included a concrete endpoint; re-running that path with body capture gives root-cause evidence instead of only counting runtime failures.",
                api_hint(str(variables["api_path"])),
                required_inputs,
            ))
    return recs


def requirement_text_for_test(test: dict[str, Any], req_by_id: dict[str, dict[str, Any]]) -> str:
    return " / ".join(
        trim(req_by_id.get(req_id, {}).get("text", ""))
        for req_id in as_list(test.get("requirement_ids"))
        if has_text(req_by_id.get(req_id, {}).get("text"))
    )


def open_test_recommendations(test: dict[str, Any], req_by_id: dict[str, dict[str, Any]], start_index: int) -> list[dict[str, Any]]:
    status = test.get("status")
    if status in {"Passed", "Failed"}:
        return []
    layer = str(test.get("type") or "requirement")
    finding = {"id": f"OPEN-{test.get('id', 'test')}", "evidence": []}
    req_text = requirement_text_for_test(test, req_by_id) or trim(test.get("expected"))
    path = first_path(test.get("expected")) or first_path(req_text)
    priority = "P1" if layer in {"api", "websocket", "sse", "persistence"} else "P2"
    reason = f"Mapped test `{test.get('id')}` is {status}; no current-run evidence proves this requirement yet."
    required_inputs = ["current-run execution evidence"]
    suggested_type = layer
    objective = f"Turn {status} {layer} coverage into executable evidence for: {trim(req_text, 300)}"

    if layer == "ui":
        hint = {
            "action": "goto",
            "path": path or "<entry path>",
            "evidenceType": "navigation",
            "proves": "The generated UI entry point opens before assertions and screenshots are captured.",
        }
        required_inputs.append("auth/storage state if the page requires login")
    elif layer == "api":
        hint = api_hint(path if path and "{" not in path else "<runtime-resolved API path>")
        if not path or "{" in path:
            required_inputs.append("runtime id or concrete API path")
    elif layer in {"websocket", "sse"}:
        hint = {
            "action": "websocket" if layer == "websocket" else "sse",
            "path": path or "<stream endpoint>",
            "send": {"question": "QA_STREAM_PROBE"},
            "expectMessageTextContains": "answer_done",
            "captureMessages": True,
            "timeoutMs": 60000,
        }
        required_inputs.extend(["auth state", "safe payload", "--allow-live-stream when generated from scaffold"])
    elif layer == "persistence":
        hint = command_hint(["bash", "-lc", "echo provide project-approved read-only persistence helper"])
        required_inputs.append("--persistence-command or equivalent read-only helper")
    elif layer == "permission":
        hint = {
            "action": "setLocalStorage",
            "path": path or "/",
            "values": {"<auth key>": {"env": "<TOKEN_ENV>"}},
            "evidenceType": "auth_setup",
        }
        required_inputs.extend(["authorized role/account", "unauthorized role/account when denial is required"])
    else:
        hint = {"action": "command", "command": ["bash", "-lc", "echo add focused requirement probe"]}
        suggested_type = "manual_or_probe"

    rec = recommendation(
        f"NP{start_index}",
        finding,
        priority,
        layer,
        objective,
        suggested_type,
        reason,
        hint,
        required_inputs,
    )
    rec["source_test_id"] = test.get("id")
    rec["source_status"] = status
    rec["requirement_ids"] = as_list(test.get("requirement_ids"))
    return [rec]


def recommendations_for(finding: dict[str, Any], variables: dict[str, Any], start_index: int) -> list[dict[str, Any]]:
    recs: list[dict[str, Any]] = []
    layers = set(as_list(finding.get("layers")))
    if "stream" in layers:
        recs.extend(stream_recommendations(finding, variables, start_index + len(recs)))
    if "persistence" in layers:
        recs.extend(persistence_recommendations(finding, variables, start_index + len(recs)))
    if "api" in layers:
        recs.extend(api_recommendations(finding, variables, start_index + len(recs)))
    if "ui" in layers:
        recs.extend(ui_recommendations(finding, variables, start_index + len(recs)))
    if "runtime" in layers:
        recs.extend(runtime_recommendations(finding, variables, start_index + len(recs)))
    if not recs:
        recs.append(recommendation(
            f"NP{start_index}",
            finding,
            "P2",
            "requirement",
            "Add one focused probe for the failed expected behavior.",
            "manual_or_probe",
            "No specialized layer template matched this failure.",
            {"action": "command", "command": ["bash", "-lc", "echo add project-specific probe"]},
        ))
    recs.extend(log_correlation_recommendations(finding, variables, start_index + len(recs)))
    return recs


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate follow-up probe recommendations from structured QA defects.")
    parser.add_argument("--defects", required=True)
    parser.add_argument("--results")
    parser.add_argument("--ledger")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    defects_path = Path(args.defects).expanduser().resolve()
    results_path = Path(args.results).expanduser().resolve() if args.results else None
    ledger_path = Path(args.ledger).expanduser().resolve() if args.ledger else None
    out_path = Path(args.out).expanduser().resolve()
    input_artifact_errors: list[dict[str, str]] = []
    defects, defects_load_error = try_load_json(defects_path)
    results, results_load_error = try_load_json(results_path) if results_path else ({}, None)
    ledger, ledger_load_error = try_load_json(ledger_path) if ledger_path else ({}, None)
    for name, path, load_error in (
        ("defects", defects_path, defects_load_error),
        ("results", results_path, results_load_error),
        ("ledger", ledger_path, ledger_load_error),
    ):
        if path and load_error:
            input_artifact_errors.append({"name": name, "path": str(path), "error": load_error})
    if input_artifact_errors:
        output = {
            "schema_version": 1,
            "generated_from": {
                "defects": str(defects_path),
                "results": str(results_path) if results_path else None,
                "ledger": str(ledger_path) if ledger_path else None,
            },
            "generated_from_hashes": generated_from_hashes(defects_path, results_path, ledger_path),
            "summary": {
                "recommendation_count": 0,
                "priority_counts": {},
                "layer_counts": {},
                "input_artifact_error_count": len(input_artifact_errors),
            },
            "recommendations": [],
            "input_artifact_errors": input_artifact_errors,
        }
        write_json(out_path, output)
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return 1
    assert defects is not None
    results = results or {}
    ledger = ledger or {}
    result_steps = collect_result_steps(results)

    recommendations: list[dict[str, Any]] = []
    for finding in as_list(defects.get("findings")):
        variables = finding_vars(finding, result_steps)
        finding_recs = recommendations_for(finding, variables, len(recommendations) + 1)
        for rec in finding_recs:
            if variables:
                rec["correlated_vars"] = variables
        recommendations.extend(finding_recs)

    req_by_id = {item.get("id"): item for item in as_list(ledger.get("requirements")) if has_text(item.get("id"))}
    for test in as_list(ledger.get("tests")):
        recommendations.extend(open_test_recommendations(test, req_by_id, len(recommendations) + 1))

    priority_counts = Counter(item.get("priority") for item in recommendations)
    layer_counts = Counter(item.get("layer") for item in recommendations)
    output = {
        "schema_version": 1,
          "generated_from": {
              "defects": str(defects_path),
              "results": str(results_path) if results_path else None,
              "ledger": str(ledger_path) if ledger_path else None,
          },
          "generated_from_hashes": generated_from_hashes(defects_path, results_path, ledger_path),
          "summary": {
            "recommendation_count": len(recommendations),
            "priority_counts": dict(sorted(priority_counts.items())),
            "layer_counts": dict(sorted(layer_counts.items())),
        },
        "recommendations": recommendations,
        "input_artifact_errors": input_artifact_errors,
    }
    write_json(out_path, output)
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
