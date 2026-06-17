#!/usr/bin/env python3
import argparse
import json
import shlex
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from discover_project_context import discover_context, service_status


OPC_ENV_CANDIDATES = {
    "one_corpus_web": ["one_corpus_web/.env.local", "one_corpus_web/.env.localdesktop", "one_corpus_web/.env.example"],
    "opc-bot": ["opc-bot/configs/config.yaml"],
    "agent_platform": ["agent_platform/.env", "agent_platform/.env.example"],
    "ops_web": ["ops_web/.env.local", "ops_web/.env.example"],
}
OPC_REQUIRED_FOR_BASE_URL = {
    "9527": {"one_corpus_web", "opc-bot"},
    "8081": {"opc-bot"},
    "8000": {"agent_platform"},
    "3070": {"ops_web"},
}


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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def command_parts(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def package_scripts(service_dir: Path) -> dict[str, str]:
    package_path = service_dir / "package.json"
    if not package_path.exists():
        return {}
    try:
        data = json.loads(package_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    scripts = data.get("scripts")
    return scripts if isinstance(scripts, dict) else {}


def command_status(parts: list[str]) -> dict[str, Any]:
    executable = parts[0] if parts else ""
    status: dict[str, Any] = {
        "executable": executable,
        "found": bool(executable and shutil.which(executable)),
        "path": shutil.which(executable) if executable else None,
    }
    if executable == "python" and not status["found"] and shutil.which("python3"):
        status["substitute"] = "python3"
        status["substitute_path"] = shutil.which("python3")
    return status


def npm_script_status(parts: list[str], service_dir: Path) -> dict[str, Any] | None:
    if len(parts) < 3 or parts[0] != "npm" or parts[1] != "run":
        return None
    script = parts[2]
    scripts = package_scripts(service_dir)
    return {
        "script": script,
        "found": script in scripts,
        "available_scripts": sorted(scripts),
    }


def plan_text(plan: dict[str, Any]) -> str:
    return json.dumps(plan, ensure_ascii=False).lower()


def infer_required_services(context: dict[str, Any], plan: dict[str, Any] | None, explicit: list[str]) -> set[str]:
    if explicit:
        return set(explicit)
    adapter = context.get("adapter")
    base_url = str((plan or {}).get("baseUrl") or context.get("base_url") or "")
    required: set[str] = set()
    if adapter == "opc_project":
        for marker, services in OPC_REQUIRED_FOR_BASE_URL.items():
            if marker in base_url:
                required.update(services)
        text = plan_text(plan or {})
        if "/api/v1/" in text:
            required.add("opc-bot")
        if "/api/v1/agents/ask/ws" in text or "websocket" in text:
            required.add("opc-bot")
            if "8000" in base_url:
                required.add("agent_platform")
        if "/aibox" in text:
            required.add("one_corpus_web")
    else:
        for service in as_list(context.get("services")):
            if service.get("default_url") and service.get("default_url") == base_url:
                required.add(str(service.get("id")))
    return required


def env_file_status(service_id: str, context: dict[str, Any], project_root: Path) -> dict[str, Any]:
    candidates = OPC_ENV_CANDIDATES.get(service_id, []) if context.get("adapter") == "opc_project" else []
    existing = [item for item in candidates if (project_root / item).exists()]
    return {
        "candidates": candidates,
        "existing": existing,
        "has_non_example": any(not Path(item).name.endswith(".example") for item in existing),
    }


def assess_service(service: dict[str, Any], context: dict[str, Any], project_root: Path, required_ids: set[str], allow_stopped: bool) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    service_id = str(service.get("id", ""))
    service_dir = project_root / str(service.get("path") or ".")
    required = service_id in required_ids
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    start_parts = command_parts(str(service.get("start_command") or ""))
    cmd_status = command_status(start_parts)
    npm_status = npm_script_status(start_parts, service_dir)
    env_status = env_file_status(service_id, context, project_root)

    item = {
        "id": service_id,
        "role": service.get("role", ""),
        "required": required,
        "path": service.get("path", ""),
        "path_exists": bool(service.get("path_exists")),
        "default_url": service.get("default_url", ""),
        "port": service.get("port"),
        "port_open": service.get("port_open"),
        "http_probe": service.get("http_probe"),
        "start": {
            "cwd": rel(service_dir, project_root),
            "command": start_parts,
            "command_text": service.get("start_command", ""),
            "command_status": cmd_status,
            "npm_script_status": npm_status,
        },
        "env_files": env_status,
    }

    if required and not item["path_exists"]:
        blockers.append({"service": service_id, "reason": "service path is missing", "path": service.get("path", "")})
    if required and service.get("port_open") is False and not allow_stopped:
        blockers.append({"service": service_id, "reason": "required service port is not reachable", "url": service.get("default_url", "")})
    if required and service.get("port_open") is False and allow_stopped:
        warnings.append({"service": service_id, "reason": "required service port is not reachable but allowed for planning", "url": service.get("default_url", "")})
    if required and start_parts and not cmd_status["found"] and not cmd_status.get("substitute"):
        blockers.append({"service": service_id, "reason": "start command executable is missing", "executable": cmd_status.get("executable")})
    if required and npm_status and not npm_status["found"]:
        blockers.append({"service": service_id, "reason": "npm script is missing", "script": npm_status["script"]})
    if required and env_status["candidates"] and not env_status["existing"]:
        blockers.append({"service": service_id, "reason": "expected env/config file path is missing", "candidates": env_status["candidates"]})
    if required and env_status["existing"] and not env_status["has_non_example"]:
        warnings.append({"service": service_id, "reason": "only example env/config files were found", "files": env_status["existing"]})
    if required and cmd_status.get("substitute"):
        warnings.append({"service": service_id, "reason": "start command uses python but only python3 was found", "suggested_executable": cmd_status["substitute"]})
    if not required and service.get("port_open") is False:
        warnings.append({"service": service_id, "reason": "optional service is currently stopped", "url": service.get("default_url", "")})
    return item, blockers, warnings


def build_start_plan(services: list[dict[str, Any]], blockers: list[dict[str, Any]], project_root: Path) -> list[dict[str, Any]]:
    blocked_services = {item.get("service") for item in blockers if item.get("reason") == "required service port is not reachable"}
    plan: list[dict[str, Any]] = []
    for service in services:
        if service.get("id") not in blocked_services:
            continue
        start = service.get("start", {})
        command = start.get("command") or []
        if not command:
            continue
        status = start.get("command_status") or {}
        if not status.get("found") and status.get("substitute"):
            command = [status["substitute"], *command[1:]]
        plan.append({
            "service": service.get("id"),
            "cwd": rel(project_root / str(service.get("path") or "."), project_root),
            "command": command,
            "reason": "required service port is not reachable",
        })
    return plan


def refresh_preserved_service(service: dict[str, Any], project_root: Path, timeout: float, probe_http: bool) -> dict[str, Any]:
    if service.get("default_url"):
        refreshed = service_status(service, project_root, timeout, probe_http)
    else:
        refreshed = {
            **service,
            "path_exists": (project_root / str(service.get("path") or ".")).exists(),
        }
    refreshed["preserved_from_adapter_context"] = True
    return refreshed


def preserve_existing_services(
    context: dict[str, Any],
    existing_context: dict[str, Any],
    project_root: Path,
    timeout: float,
    probe_http: bool,
) -> dict[str, Any]:
    discovered_ids = {str(item.get("id")) for item in as_list(context.get("services")) if item.get("id")}
    preserved = [
        refresh_preserved_service(item, project_root, timeout, probe_http)
        for item in as_list(existing_context.get("services"))
        if isinstance(item, dict)
        and item.get("id")
        and str(item.get("id")) not in discovered_ids
    ]
    if preserved:
        context.setdefault("services", []).extend(preserved)
    return context


def missing_required_service_blockers(required_ids: set[str], services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    known_ids = {str(item.get("id")) for item in services if item.get("id")}
    return [
        {
            "service": service_id,
            "reason": "required service is not present in adapter context",
        }
        for service_id in sorted(required_ids - known_ids)
    ]


def input_error_report(args: argparse.Namespace, context_path: Path, plan_path: Path, input_errors: list[dict[str, str]]) -> dict[str, Any]:
    project_root = Path(args.project_root or ".").expanduser().resolve()
    blockers = [
        {
            "reason": "input artifact is unreadable",
            "artifact": item["name"],
            "path": item["path"],
            "error": item["error"],
        }
        for item in input_errors
    ]
    return {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "adapter": None,
        "project_root": str(project_root),
        "base_url": args.base_url,
        "plan": str(plan_path) if plan_path.exists() else None,
        "adapter_context": str(context_path),
        "runnable": False,
        "required_services": [],
        "services": [],
        "blockers": blockers,
        "warnings": [],
        "start_plan": [],
        "safety": {
            "secret_values_read": False,
            "services_started": False,
            "default_is_check_only": True,
        },
        "input_artifact_errors": input_errors,
    }


def preflight(args: argparse.Namespace) -> dict[str, Any]:
    run_dir = Path(args.run_dir).expanduser().resolve()
    context_path = Path(args.adapter_context).expanduser().resolve() if args.adapter_context else run_dir / "adapter-context.json"
    existing_context, context_error = try_load_json(context_path) if context_path.exists() else ({}, None)
    input_errors: list[dict[str, str]] = []
    if context_error:
        input_errors.append({"name": "adapter_context", "path": str(context_path), "error": context_error})
        existing_context = {}
    project_root = Path(args.project_root or existing_context.get("project_root") or ".").expanduser().resolve()
    base_url = args.base_url or existing_context.get("base_url")
    existing_boundary = existing_context.get("environment_boundary") or {}
    runtime_mode = args.runtime_mode or existing_boundary.get("runtime_mode")
    data_boundary_status = args.data_boundary_status or existing_boundary.get("data_boundary_status")
    if args.refresh_context or not existing_context:
        context = discover_context(
            project_root,
            base_url=base_url,
            probe_http=not args.no_http_probe,
            timeout=args.timeout,
            runtime_mode=runtime_mode,
            data_boundary_status=data_boundary_status,
        )
        if args.refresh_context and existing_context:
            context = preserve_existing_services(
                context,
                existing_context,
                project_root,
                args.timeout,
                not args.no_http_probe,
            )
    else:
        context = existing_context
        if args.runtime_mode or args.data_boundary_status:
            boundary = context.setdefault("environment_boundary", {})
            if args.runtime_mode:
                boundary["runtime_mode"] = args.runtime_mode
            if args.data_boundary_status:
                boundary["data_boundary_status"] = args.data_boundary_status
            context_path.write_text(json.dumps(context, indent=2, ensure_ascii=False), encoding="utf-8")
    plan_path = Path(args.plan).expanduser().resolve() if args.plan else run_dir / "test-plan.json"
    plan = None
    if plan_path.exists():
        plan, plan_error = try_load_json(plan_path)
        if plan_error:
            input_errors.append({"name": "plan", "path": str(plan_path), "error": plan_error})
    if input_errors:
        return input_error_report(args, context_path, plan_path, input_errors)
    required_ids = infer_required_services(context, plan, args.required_service or [])
    services: list[dict[str, Any]] = []
    context_input_errors = as_list(context.get("input_artifact_errors"))
    blockers: list[dict[str, Any]] = [
        {
            "reason": "context input artifact is unreadable",
            "artifact": item.get("name"),
            "path": item.get("path"),
            "error": item.get("error"),
        }
        for item in context_input_errors
        if isinstance(item, dict)
    ]
    warnings: list[dict[str, Any]] = []

    for service in as_list(context.get("services")):
        item, service_blockers, service_warnings = assess_service(service, context, project_root, required_ids, args.allow_stopped_services)
        services.append(item)
        blockers.extend(service_blockers)
        warnings.extend(service_warnings)
    blockers.extend(missing_required_service_blockers(required_ids, services))

    if context.get("environment_boundary", {}).get("runtime_mode") == "unconfirmed":
        warnings.append({"reason": "runtime mode is unconfirmed; report must state local/test/staging/prod before pass/fail"})

    return {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "adapter": context.get("adapter"),
        "project_root": str(project_root),
        "base_url": base_url,
        "plan": str(plan_path) if plan_path.exists() else None,
        "adapter_context": str(context_path),
        "runnable": not blockers,
        "required_services": sorted(required_ids),
        "services": services,
        "blockers": blockers,
        "warnings": warnings,
        "start_plan": build_start_plan(services, blockers, project_root),
        "safety": {
            "secret_values_read": False,
            "services_started": False,
            "default_is_check_only": True,
        },
        "input_artifact_errors": [item for item in context_input_errors if isinstance(item, dict)],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Preflight runtime services and local tooling before an automated QA/backtest run.")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--adapter-context")
    parser.add_argument("--plan")
    parser.add_argument("--project-root")
    parser.add_argument("--base-url")
    parser.add_argument("--runtime-mode", help="Declared runtime mode to preserve/write in adapter-context.json.")
    parser.add_argument("--data-boundary-status", help="Declared data boundary to preserve/write in adapter-context.json.")
    parser.add_argument("--out")
    parser.add_argument("--refresh-context", action="store_true", help="Re-probe ports/files from project-root before writing service-preflight.json.")
    parser.add_argument("--no-http-probe", action="store_true")
    parser.add_argument("--timeout", type=float, default=0.8)
    parser.add_argument("--required-service", action="append", help="Explicit service id to require. May be repeated.")
    parser.add_argument("--allow-stopped-services", action="store_true", help="Do not block when required service ports are currently stopped.")
    parser.add_argument("--fail-on-blockers", action="store_true", help="Exit non-zero when blockers are present after writing the artifact.")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    report = preflight(args)
    out_path = Path(args.out).expanduser().resolve() if args.out else run_dir / "service-preflight.json"
    write_json(out_path, report)
    print(out_path)
    if report.get("input_artifact_errors"):
        return 1
    if args.fail_on_blockers and report.get("blockers"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
