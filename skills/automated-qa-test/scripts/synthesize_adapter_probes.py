#!/usr/bin/env python3
import argparse
import copy
import json
import re
import shlex
from datetime import datetime
from pathlib import Path
from typing import Any

from adapter_registry import get_adapter_definition
from qa_common import atomic_write_json

VAR_TOKEN_RE = re.compile(r"\{(session_id|turn_id)\}")


def load_json(path: Path) -> dict[str, Any]:
    value, load_error = try_load_json(path)
    if load_error:
        raise SystemExit(f"Invalid JSON input {path}: {load_error}")
    assert value is not None
    return value


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


def write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write_json(path, value)


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def test_type(test: dict[str, Any]) -> str:
    return str(test.get("type") or "").lower()


def req_text(req_by_id: dict[str, dict[str, Any]], test: dict[str, Any]) -> str:
    return " ".join(str(req_by_id.get(req_id, {}).get("text", "")) for req_id in as_list(test.get("requirement_ids")))


def all_steps(plan: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for scenario in as_list(plan.get("scenarios")):
        steps.extend(as_list(scenario.get("steps")))
    return steps


def ensure_scenario(plan: dict[str, Any]) -> dict[str, Any]:
    scenarios = as_list(plan.get("scenarios"))
    for scenario in scenarios:
        if scenario.get("id") == "adapter-synthesized-probes":
            return scenario
    scenario = {
        "id": "adapter-synthesized-probes",
        "title": "Adapter synthesized probes",
        "continueOnFailure": True,
        "steps": [],
    }
    if not isinstance(plan.get("scenarios"), list):
        plan["scenarios"] = []
    plan["scenarios"].append(scenario)
    return scenario


def ids_for_tests(tests: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    test_ids: list[str] = []
    req_ids: list[str] = []
    for test in tests:
        if has_text(test.get("id")):
            test_ids.append(str(test["id"]))
        for req_id in as_list(test.get("requirement_ids")):
            if has_text(req_id) and str(req_id) not in req_ids:
                req_ids.append(str(req_id))
    return test_ids, req_ids


def service_by_id(context: dict[str, Any], service_id: str) -> dict[str, Any] | None:
    for service in as_list(context.get("services")):
        if service.get("id") == service_id:
            return service
    return None


def stopped_service_blockers(context: dict[str, Any], base_url: str) -> list[str]:
    definition = get_adapter_definition(str(context.get("adapter") or ""))
    template = definition.get("probe_template") if isinstance((definition or {}).get("probe_template"), dict) else {}
    if not template:
        return []
    needed = [str(item) for item in as_list(template.get("required_services")) if str(item)]
    resolved_base_url = str(base_url or context.get("base_url") or "")
    for marker, services in (template.get("base_url_service_rules") or {}).items():
        if str(marker) in resolved_base_url:
            needed.extend(str(item) for item in as_list(services) if str(item))
    blockers: list[str] = []
    for service_id in needed:
        service = service_by_id(context, service_id)
        if service and service.get("port_open") is False:
            blockers.append(f"Service `{service_id}` is not reachable on {service.get('default_url')}.")
    return blockers


def command_with_runtime_refs(command: str) -> list[Any]:
    parts = shlex.split(command)
    converted: list[Any] = []
    for part in parts:
        match = VAR_TOKEN_RE.search(part)
        if not match:
            converted.append(part)
            continue
        var_name = match.group(1)
        if VAR_TOKEN_RE.fullmatch(part):
            converted.append({"var": var_name})
            continue
        prefix = part[:match.start()]
        suffix = part[match.end():]
        converted.append({"var": var_name, "prefix": prefix, "suffix": suffix})
    return converted


def set_tests_executable(matrix: dict[str, Any], tests: list[dict[str, Any]]) -> None:
    executable_ids = {str(test.get("id")) for test in tests if has_text(test.get("id"))}
    for test in as_list(matrix.get("tests")):
        if str(test.get("id")) in executable_ids and test.get("status") == "Blocked":
            test["status"] = "Untested"
            if str(test.get("notes", "")).startswith("Generated as a blocked probe"):
                test.pop("notes", None)
    tests_by_req: dict[str, list[dict[str, Any]]] = {}
    for test in as_list(matrix.get("tests")):
        for req_id in as_list(test.get("requirement_ids")):
            tests_by_req.setdefault(str(req_id), []).append(test)
    for req in as_list(matrix.get("requirements")):
        related = tests_by_req.get(str(req.get("id")), [])
        if any(test.get("status") == "Untested" for test in related):
            req["status"] = "Untested"
            if str(req.get("notes", "")).startswith("Generated requirement has no executable"):
                req.pop("notes", None)


def build_stream_step(
    tests: list[dict[str, Any]],
    marker: str,
    question: str,
    ws_path: str,
    terminal_type: str,
    adapter_id: str,
    agent_id: str | None,
    user_id: str | None,
) -> dict[str, Any]:
    test_ids, req_ids = ids_for_tests(tests)
    payload: dict[str, Any] = {
        "question": question,
        "session_id": None,
    }
    if agent_id:
        payload["agent_id"] = agent_id
    if user_id:
        payload["user_id"] = user_id
    return {
        "action": "websocket",
        "id": f"adapter-{adapter_id}-stream-terminal",
        "testIds": test_ids,
        "requirementIds": req_ids,
        "path": ws_path,
        "send": payload,
        "expectJson": {"type": terminal_type},
        "expectMessageTextContains": marker,
        "finishOnJsonTypes": [terminal_type],
        "captureMessages": True,
        "timeoutMs": 60000,
        "maxMessages": 80,
        "extractJson": {
            "session_id": {
                "path": "session_id",
                "matchJson": {"session_id": {"op": "exists"}},
            },
            "turn_id": {
                "path": "turn_id",
                "from": "last",
                "required": False,
            },
        },
        "evidenceType": "websocket",
        "proves": f"The configured adapter stream emits `{terminal_type}` and returned messages contain the unique current-run marker.",
    }


def build_session_api_step(tests: list[dict[str, Any]], marker: str, session_detail_path: str, adapter_id: str) -> dict[str, Any]:
    test_ids, req_ids = ids_for_tests(tests)
    return {
        "action": "api",
        "id": f"adapter-{adapter_id}-session-detail",
        "testIds": test_ids,
        "requirementIds": req_ids,
        "method": "GET",
        "path": {"var": "session_id", "prefix": session_detail_path},
        "expectStatus": 200,
        "expectResponseTextContains": marker,
        "captureBody": True,
        "evidenceType": "api_response",
        "proves": "The same session created or returned by the stream is readable through the session detail API and contains the unique marker.",
    }


def build_persistence_step(tests: list[dict[str, Any]], command: str, adapter_id: str) -> dict[str, Any]:
    test_ids, req_ids = ids_for_tests(tests)
    return {
        "action": "command",
        "id": f"adapter-{adapter_id}-persistence-check",
        "testIds": test_ids,
        "requirementIds": req_ids,
        "command": command_with_runtime_refs(command),
        "expectExitCode": 0,
        "expectStdoutContains": "completed",
        "captureStdout": True,
        "captureStderr": True,
        "evidenceType": "command",
        "proves": "The project-approved read-only persistence helper verifies that the same streamed session or turn reached a completed terminal state.",
    }


def input_error_report(args: argparse.Namespace, context_path: Path, plan_path: Path, matrix_path: Path, input_errors: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "adapter": None,
        "applied": False,
        "marker": args.marker,
        "plan": str(plan_path),
        "matrix": str(matrix_path),
        "adapter_context": str(context_path),
        "added_step_ids": [],
        "proposed_step_ids": [],
        "recommendations": [],
        "blocked": [
            {
                "layer": "input_artifacts",
                "reason": "Adapter probe synthesis cannot run until required input artifacts are readable JSON objects.",
                "required_inputs": [f"{item['name']}: {item['error']}" for item in input_errors],
            }
        ],
        "summary": {
            "stream_test_count": 0,
            "session_api_test_count": 0,
            "persistence_test_count": 0,
            "proposed_step_count": 0,
            "blocked_probe_count": 1,
            "input_artifact_error_count": len(input_errors),
        },
        "safety": {
            "live_stream_requires_explicit_flag": True,
            "persistence_requires_project_approved_command": True,
            "marker_must_appear_in_received_stream_messages": True,
        },
        "input_artifact_errors": input_errors,
    }


def synthesize(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bool]:
    run_dir = Path(args.run_dir).expanduser().resolve()
    context_path = Path(args.adapter_context).expanduser().resolve() if args.adapter_context else run_dir / "adapter-context.json"
    plan_path = Path(args.plan).expanduser().resolve() if args.plan else run_dir / "test-plan.json"
    matrix_path = Path(args.matrix).expanduser().resolve() if args.matrix else run_dir / "test-matrix.json"
    context, context_error = try_load_json(context_path)
    plan, plan_error = try_load_json(plan_path)
    matrix, matrix_error = try_load_json(matrix_path)
    input_errors: list[dict[str, str]] = []
    if context_error:
        input_errors.append({"name": "adapter_context", "path": str(context_path), "error": context_error})
    if plan_error:
        input_errors.append({"name": "plan", "path": str(plan_path), "error": plan_error})
    if matrix_error:
        input_errors.append({"name": "matrix", "path": str(matrix_path), "error": matrix_error})
    if input_errors:
        return input_error_report(args, context_path, plan_path, matrix_path, input_errors), plan or {}, matrix or {}, True

    assert context is not None
    assert plan is not None
    assert matrix is not None
    original_plan = copy.deepcopy(plan)
    original_matrix = copy.deepcopy(matrix)
    adapter_id = str(context.get("adapter") or "")
    adapter_definition = get_adapter_definition(adapter_id)
    probe_template = adapter_definition.get("probe_template") if isinstance((adapter_definition or {}).get("probe_template"), dict) else {}
    ws_path = args.ws_path or str(probe_template.get("ws_path") or "")
    session_detail_path = args.session_detail_path or str(probe_template.get("session_detail_path") or "")
    terminal_type = str(probe_template.get("terminal_type") or "completed")

    req_by_id = {str(req.get("id")): req for req in as_list(matrix.get("requirements")) if has_text(req.get("id"))}
    tests = as_list(matrix.get("tests"))
    stream_tests = [test for test in tests if test_type(test) in {"websocket", "stream", "sse"}]
    session_api_tests = [
        test for test in tests
        if test_type(test) == "api" and ("session_id" in req_text(req_by_id, test).lower() or "/sessions" in req_text(req_by_id, test).lower())
    ]
    persistence_tests = [test for test in tests if test_type(test) in {"persistence", "command"}]

    marker = args.marker or f"QA_BACKTEST_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    question = args.question or f"请在回答中原样包含唯一标记 {marker}，用于自动化回测。"
    recommendations: list[dict[str, Any]] = []
    added_steps: list[str] = []
    proposed_steps: list[dict[str, Any]] = []
    executable_tests: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    existing_step_ids = {str(step.get("id")) for step in all_steps(plan) if has_text(step.get("id"))}
    scenario: dict[str, Any] | None = None

    def record_step(step: dict[str, Any]) -> bool:
        nonlocal scenario
        step_id = str(step.get("id") or "")
        if step_id in existing_step_ids:
            return False
        existing_step_ids.add(step_id)
        proposed_steps.append(step)
        added_steps.append(step_id)
        if args.apply:
            if scenario is None:
                scenario = ensure_scenario(plan)
            scenario.setdefault("steps", []).append(step)
        return True

    if probe_template.get("kind") != "chat_stream_session" or not ws_path or not session_detail_path:
        blocked.append({
            "layer": "adapter",
            "reason": f"Unsupported adapter `{context.get('adapter')}` for automatic adapter probe synthesis.",
            "required_inputs": ["manual project adapter or generic custom plan"],
        })
    else:
        service_blockers = [] if args.allow_stopped_service else stopped_service_blockers(context, plan.get("baseUrl", ""))
        if stream_tests:
            if not args.allow_live_stream:
                blocked.append({
                    "layer": "stream",
                    "test_ids": [test.get("id") for test in stream_tests],
                    "reason": "Live stream probes are not synthesized unless --allow-live-stream is set.",
                    "required_inputs": ["explicit authorization for safe live stream payload"],
                })
            elif service_blockers:
                blocked.append({
                    "layer": "stream",
                    "test_ids": [test.get("id") for test in stream_tests],
                    "reason": "Required service is not currently reachable.",
                    "required_inputs": service_blockers + ["start services or pass --allow-stopped-service to prepare a plan without executing it now"],
                })
            else:
                step = build_stream_step(stream_tests, marker, question, ws_path, terminal_type, adapter_id, args.agent_id, args.user_id)
                record_step(step)
                executable_tests.extend(stream_tests)
                recommendations.append({
                    "layer": "stream",
                    "status": "executable",
                    "test_ids": [test.get("id") for test in stream_tests],
                    "step_id": step["id"],
                    "strong_signal": f"{terminal_type} plus unique marker in received stream messages",
                })
        else:
            recommendations.append({"layer": "stream", "status": "not_applicable", "reason": "No stream/websocket tests detected in the matrix."})

        if session_api_tests:
            if not stream_tests:
                blocked.append({
                    "layer": "session_api",
                    "test_ids": [test.get("id") for test in session_api_tests],
                    "reason": "Session API verification needs a stream or prior step that produces session_id.",
                    "required_inputs": ["stream step with extractJson.session_id or manual session_id plan"],
                })
            elif args.allow_live_stream and not service_blockers:
                step = build_session_api_step(session_api_tests, marker, session_detail_path, adapter_id)
                record_step(step)
                executable_tests.extend(session_api_tests)
                recommendations.append({
                    "layer": "session_api",
                    "status": "executable",
                    "test_ids": [test.get("id") for test in session_api_tests],
                    "step_id": step["id"],
                    "strong_signal": "same session_id is queried after stream completion",
                })
            else:
                blocked.append({
                    "layer": "session_api",
                    "test_ids": [test.get("id") for test in session_api_tests],
                    "reason": "Session API probe is blocked until the stream probe can produce session_id.",
                    "required_inputs": ["--allow-live-stream", "reachable stream service"],
                })

        if persistence_tests:
            if not args.persistence_command:
                blocked.append({
                    "layer": "persistence",
                    "test_ids": [test.get("id") for test in persistence_tests],
                    "reason": "No project-approved read-only persistence command was supplied.",
                    "required_inputs": ["--persistence-command with {session_id} and/or {turn_id} placeholders"],
                })
            elif not stream_tests:
                blocked.append({
                    "layer": "persistence",
                    "test_ids": [test.get("id") for test in persistence_tests],
                    "reason": "Persistence probe needs a runtime session_id or turn_id producer.",
                    "required_inputs": ["stream step with extractJson variables"],
                })
            elif args.allow_live_stream and not service_blockers:
                step = build_persistence_step(persistence_tests, args.persistence_command, adapter_id)
                record_step(step)
                executable_tests.extend(persistence_tests)
                recommendations.append({
                    "layer": "persistence",
                    "status": "executable",
                    "test_ids": [test.get("id") for test in persistence_tests],
                    "step_id": step["id"],
                    "strong_signal": "read-only helper reports completed for the same runtime id",
                })
            else:
                blocked.append({
                    "layer": "persistence",
                    "test_ids": [test.get("id") for test in persistence_tests],
                    "reason": "Persistence probe is blocked until the stream probe can run.",
                    "required_inputs": ["--allow-live-stream", "reachable stream service"],
                })

    if args.apply and executable_tests:
        set_tests_executable(matrix, executable_tests)

    report = {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "adapter": context.get("adapter"),
        "applied": bool(args.apply),
        "marker": marker,
        "plan": str(plan_path),
        "matrix": str(matrix_path),
        "adapter_context": str(context_path),
        "added_step_ids": added_steps if args.apply else [],
        "proposed_step_ids": added_steps,
        "recommendations": recommendations,
        "blocked": blocked,
        "summary": {
            "stream_test_count": len(stream_tests),
            "session_api_test_count": len(session_api_tests),
            "persistence_test_count": len(persistence_tests),
            "proposed_step_count": len(added_steps),
            "blocked_probe_count": len(blocked),
        },
        "safety": {
            "live_stream_requires_explicit_flag": True,
            "persistence_requires_project_approved_command": True,
            "marker_must_appear_in_received_stream_messages": True,
        },
    }
    if not args.apply:
        report["plan_patch"] = {"scenario": "adapter-synthesized-probes", "steps": proposed_steps}
        plan = original_plan
        matrix = original_matrix
    report["input_artifact_errors"] = []
    return report, plan, matrix, False


def main() -> int:
    parser = argparse.ArgumentParser(description="Synthesize adapter-aware QA/backtest probes from adapter-context.json, test-plan.json, and test-matrix.json.")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--adapter-context")
    parser.add_argument("--plan")
    parser.add_argument("--matrix")
    parser.add_argument("--out")
    parser.add_argument("--apply", action="store_true", help="Write executable adapter probes back to plan/matrix.")
    parser.add_argument("--plan-out", help="Defaults to --plan or <run-dir>/test-plan.json when --apply is set.")
    parser.add_argument("--matrix-out", help="Defaults to --matrix or <run-dir>/test-matrix.json when --apply is set.")
    parser.add_argument("--allow-live-stream", action="store_true", help="Authorize safe live stream probe synthesis.")
    parser.add_argument("--allow-stopped-service", action="store_true", help="Prepare probes even when adapter-context says a required local service is down.")
    parser.add_argument("--agent-id")
    parser.add_argument("--user-id")
    parser.add_argument("--marker")
    parser.add_argument("--question")
    parser.add_argument("--ws-path", help="Override the adapter-configured stream path.")
    parser.add_argument("--session-detail-path", help="Override the adapter-configured session detail path.")
    parser.add_argument("--persistence-command", help="Read-only helper command. Use {session_id} or {turn_id} placeholders for runtime refs.")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    report, plan, matrix, has_input_errors = synthesize(args)
    out_path = Path(args.out).expanduser().resolve() if args.out else run_dir / "adapter-probes.json"
    write_json(out_path, report)
    if args.apply and not has_input_errors:
        plan_path = Path(args.plan_out).expanduser().resolve() if args.plan_out else Path(args.plan).expanduser().resolve() if args.plan else run_dir / "test-plan.json"
        matrix_path = Path(args.matrix_out).expanduser().resolve() if args.matrix_out else Path(args.matrix).expanduser().resolve() if args.matrix else run_dir / "test-matrix.json"
        write_json(plan_path, plan)
        write_json(matrix_path, matrix)
    print(out_path)
    return 1 if has_input_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
