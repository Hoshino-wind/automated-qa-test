#!/usr/bin/env python3
import argparse
import json
import re
import shlex
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from adapter_registry import get_adapter_definition
from discover_project_context import discover_context, service_status
from qa_common import atomic_write_json

ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
PACKAGE_CROSS_ENV_EXEC_SUBCOMMANDS = {"exec", "dlx", "x"}
PACKAGE_MANAGER_EXECUTABLES = {"npm", "pnpm", "yarn"}
PACKAGE_RUNNER_OPTIONS_WITH_VALUE = {
    "--cache", "--call", "-c", "--cwd", "-C", "--dir", "--filter", "-F",
    "--package", "-p", "--registry", "--userconfig",
}
NPM_OPTIONS_WITH_VALUE = {"--prefix", "--workspace", "-w", "--userconfig", "--cache"}
PACKAGE_DIR_OPTIONS = {"--prefix", "--dir", "-C", "--cwd"}

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


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def command_parts(command: Any) -> list[str]:
    if isinstance(command, list):
        return [str(part) for part in command]
    try:
        return shlex.split(str(command or ""))
    except ValueError:
        return str(command or "").split()


def strip_leading_env_assignments(parts: list[str]) -> list[str]:
    index = 0
    while index < len(parts) and ENV_ASSIGNMENT_RE.match(parts[index]):
        index += 1
    if index < len(parts) - 1 and Path(parts[index]).name.lower() == "env":
        nested_index = env_wrapper_nested_command_index(parts, index)
        if nested_index is not None:
            return parts[nested_index:]
    return parts[index:]


def skip_package_runner_options(parts: list[str], index: int) -> int:
    while index < len(parts):
        part = str(parts[index])
        if part == "--":
            return index + 1
        if not part.startswith("-"):
            break
        option = part.split("=", 1)[0]
        index += 1
        if "=" not in part and option in PACKAGE_RUNNER_OPTIONS_WITH_VALUE and index < len(parts):
            index += 1
    return index


def package_runner_cross_env_index(parts: list[str], start_index: int = 0) -> int | None:
    if start_index >= len(parts):
        return None
    starter = Path(parts[start_index]).name.lower()
    if starter == "cross-env":
        return start_index
    if starter == "corepack" and start_index + 1 < len(parts):
        return package_runner_cross_env_index(parts, start_index + 1)
    if starter == "npx":
        index = skip_package_runner_options(parts, start_index + 1)
        if index < len(parts) and Path(parts[index]).name.lower() == "cross-env":
            return index
        return None
    if starter not in {"npm", "pnpm", "yarn"}:
        return None
    index = skip_package_runner_options(parts, start_index + 1)
    if index >= len(parts) or parts[index] not in PACKAGE_CROSS_ENV_EXEC_SUBCOMMANDS:
        return None
    index = skip_package_runner_options(parts, index + 1)
    if index < len(parts) and Path(parts[index]).name.lower() == "cross-env":
        return index
    return None


def env_wrapper_nested_command_index(parts: list[str], env_index: int = 0) -> int | None:
    if env_index >= len(parts) or Path(parts[env_index]).name.lower() != "env":
        return None
    index = env_index + 1
    while index < len(parts):
        part = str(parts[index])
        if part == "--":
            index += 1
            break
        if ENV_ASSIGNMENT_RE.match(part):
            index += 1
            continue
        if part in {"-i", "--ignore-environment"}:
            index += 1
            continue
        if part == "-u":
            if index + 1 >= len(parts) or not ENV_NAME_RE.match(str(parts[index + 1])):
                return None
            index += 2
            continue
        if part.startswith("--unset="):
            if not ENV_NAME_RE.match(part.split("=", 1)[1]):
                return None
            index += 1
            continue
        break
    if index >= len(parts):
        return None
    return index


def strip_cross_env_assignments(parts: list[str]) -> list[str]:
    cross_env_start = package_runner_cross_env_index(parts)
    if cross_env_start is None:
        return parts
    index = cross_env_start + 1
    while index < len(parts) and ENV_ASSIGNMENT_RE.match(parts[index]):
        index += 1
    if index < len(parts) and parts[index] == "--":
        index += 1
    return parts[index:]


def strip_corepack_runner(parts: list[str]) -> list[str]:
    if len(parts) >= 2 and Path(parts[0]).name.lower() == "corepack" and Path(parts[1]).name.lower() in PACKAGE_MANAGER_EXECUTABLES:
        return parts[1:]
    return parts


def normalize_command_wrappers(parts: list[str]) -> list[str]:
    parts = strip_leading_env_assignments(parts)
    parts = strip_cross_env_assignments(parts)
    return strip_corepack_runner(parts)


def command_executable_parts(parts: list[str]) -> list[str]:
    parts = strip_leading_env_assignments(parts)
    if not parts:
        return parts
    starter = Path(parts[0]).name.lower()
    if starter in {"corepack", "npx"} or starter in PACKAGE_MANAGER_EXECUTABLES:
        return parts
    return strip_cross_env_assignments(parts)


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


def resolve_command_dir(path_value: str, service_dir: Path) -> Path:
    path = Path(str(path_value)).expanduser()
    if path.is_absolute():
        return path.resolve(strict=False)
    return (service_dir / path).resolve(strict=False)


def option_value(part: str, parts: list[str], index: int) -> tuple[str, str | None, int]:
    if "=" in part and part.startswith("-"):
        name, value = part.split("=", 1)
        return name, value, 1
    if index + 1 < len(parts):
        return part, str(parts[index + 1]), 2
    return part, None, 1


def command_package_dir(parts: list[str], service_dir: Path, project_root: Path) -> Path:
    parts = normalize_command_wrappers(parts)
    if not parts:
        return service_dir
    executable = Path(parts[0]).name.lower()
    package_dir = service_dir
    if executable == "npm":
        index = 1
        while index < len(parts):
            part = str(parts[index])
            if part == "--":
                break
            option_name = part.split("=", 1)[0]
            if option_name in PACKAGE_DIR_OPTIONS:
                _, value, consumed = option_value(part, parts, index)
                if value:
                    package_dir = resolve_command_dir(value, service_dir)
                index += consumed
                continue
            if part.startswith("-"):
                if option_name in NPM_OPTIONS_WITH_VALUE and "=" not in part and index + 1 < len(parts):
                    index += 2
                else:
                    index += 1
                continue
            break
        return package_dir
    if executable in {"pnpm", "yarn"}:
        index = 1
        while index < len(parts):
            part = str(parts[index])
            if part == "--":
                break
            option_name = part.split("=", 1)[0]
            if option_name in PACKAGE_DIR_OPTIONS:
                _, value, consumed = option_value(part, parts, index)
                if value:
                    package_dir = resolve_command_dir(value, service_dir)
                index += consumed
                continue
            if part.startswith("-"):
                if option_name in PACKAGE_RUNNER_OPTIONS_WITH_VALUE and "=" not in part and index + 1 < len(parts):
                    index += 2
                else:
                    index += 1
                continue
            break
        return package_dir
    return package_dir


def command_status(parts: list[str]) -> dict[str, Any]:
    parts = command_executable_parts(parts)
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


def nested_cross_env_command_parts(parts: list[str]) -> list[str]:
    stripped = strip_leading_env_assignments(parts)
    nested = strip_cross_env_assignments(stripped)
    if not nested or nested == stripped:
        return []
    primary = command_executable_parts(parts)
    if primary and Path(primary[0]).name.lower() == Path(nested[0]).name.lower():
        return []
    return nested


def nested_command_status(parts: list[str], service_dir: Path, project_root: Path) -> dict[str, Any] | None:
    nested = nested_cross_env_command_parts(parts)
    if not nested:
        return None
    status = command_status(nested)
    if status["found"] or status.get("substitute"):
        return status
    executable = str(status.get("executable") or "")
    if not executable or "/" in executable or "\\" in executable:
        return status
    for base_dir in (service_dir, project_root):
        candidate = base_dir / "node_modules" / ".bin" / executable
        if candidate.exists() and candidate.is_file():
            status["found"] = True
            status["path"] = str(candidate)
            status["source"] = "node_modules_bin"
            return status
    return status


def npm_script_status(parts: list[str], service_dir: Path, project_root: Path | None = None) -> dict[str, Any] | None:
    root = project_root or service_dir
    parts = normalize_command_wrappers(parts)
    if not parts:
        return None
    executable = Path(parts[0]).name.lower()
    script: str | None = None
    package_dir = command_package_dir(parts, service_dir, root)
    if executable == "npm":
        index = 1
        while index < len(parts):
            part = str(parts[index])
            if part == "--":
                index += 1
                break
            option_name = part.split("=", 1)[0]
            if option_name in PACKAGE_DIR_OPTIONS:
                _, _, consumed = option_value(part, parts, index)
                index += consumed
                continue
            if part.startswith("-"):
                if option_name in NPM_OPTIONS_WITH_VALUE and "=" not in part and index + 1 < len(parts):
                    index += 2
                else:
                    index += 1
                continue
            break
        if index < len(parts):
            if parts[index] == "run" and index + 1 < len(parts):
                script = parts[index + 1]
            elif parts[index] in {"test", "start", "lint"}:
                script = parts[index]
    elif executable in {"pnpm", "yarn"}:
        index = 1
        while index < len(parts):
            part = str(parts[index])
            if part == "--":
                index += 1
                break
            option_name = part.split("=", 1)[0]
            if part.startswith("-"):
                if option_name in PACKAGE_RUNNER_OPTIONS_WITH_VALUE and "=" not in part and index + 1 < len(parts):
                    index += 2
                else:
                    index += 1
                continue
            break
        if index < len(parts):
            if parts[index] == "run" and index + 1 < len(parts):
                script = parts[index + 1]
            elif parts[index] not in {"exec", "dlx", "x", "add", "install", "i", "remove", "rm"}:
                script = str(parts[index])
    if not script:
        return None
    scripts = package_scripts(package_dir)
    return {
        "script": script,
        "found": script in scripts,
        "available_scripts": sorted(scripts),
        "package_dir": rel(package_dir, root),
    }


def node_dependency_status(parts: list[str], service_dir: Path, project_root: Path) -> dict[str, Any] | None:
    parts = normalize_command_wrappers(parts)
    if not parts or Path(parts[0]).name.lower() not in PACKAGE_MANAGER_EXECUTABLES:
        return None
    package_dir = command_package_dir(parts, service_dir, project_root)
    candidates: list[Path] = []
    for candidate_dir in (package_dir, service_dir, project_root):
        candidate = candidate_dir / "node_modules"
        if not any(existing.resolve(strict=False) == candidate.resolve(strict=False) for existing in candidates):
            candidates.append(candidate)
    existing = [rel(path, project_root) for path in candidates if path.exists() and path.is_dir()]
    return {
        "required": True,
        "found": bool(existing),
        "candidates": [rel(path, project_root) for path in candidates],
        "existing": existing,
    }


def iter_plan_required_path_specs(plan: dict[str, Any] | None):
    if not isinstance(plan, dict):
        return
    containers = [("plan", plan)]
    preflight = plan.get("preflight")
    if isinstance(preflight, dict):
        containers.append(("plan.preflight", preflight))
    for prefix, container in containers:
        for field, expected_kind in (
            ("requiredFiles", "file"),
            ("required_files", "file"),
            ("requiredDirectories", "directory"),
            ("required_directories", "directory"),
            ("requiredDirs", "directory"),
            ("required_dirs", "directory"),
            ("requiredPaths", "path"),
            ("required_paths", "path"),
        ):
            value = container.get(field)
            if value is None:
                continue
            items = value if isinstance(value, list) else [value]
            for item in items:
                if isinstance(item, dict):
                    path_value = item.get("path")
                    kind = str(item.get("type") or item.get("kind") or expected_kind)
                    reason = item.get("reason")
                else:
                    path_value = item
                    kind = expected_kind
                    reason = None
                yield f"{prefix}.{field}", path_value, kind, reason


def plan_required_path_blockers(plan: dict[str, Any] | None, project_root: Path) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    for source, path_value, kind, reason in iter_plan_required_path_specs(plan):
        if not has_text(path_value):
            blockers.append({"reason": "required plan path is missing", "source": source, "path": "", "kind": kind, "detail": "path is empty"})
            continue
        raw_path = Path(str(path_value)).expanduser()
        path = raw_path if raw_path.is_absolute() else project_root / raw_path
        normalized_kind = str(kind).lower().replace("-", "_")
        if normalized_kind in {"file", "required_file"}:
            if not path.exists():
                blockers.append({"reason": "required plan path is missing", "source": source, "path": str(path), "kind": "file", "detail": reason})
            elif not path.is_file():
                blockers.append({"reason": "required plan path is not a file", "source": source, "path": str(path), "kind": "file", "detail": reason})
        elif normalized_kind in {"directory", "dir", "required_directory"}:
            if not path.exists():
                blockers.append({"reason": "required plan path is missing", "source": source, "path": str(path), "kind": "directory", "detail": reason})
            elif not path.is_dir():
                blockers.append({"reason": "required plan path is not a directory", "source": source, "path": str(path), "kind": "directory", "detail": reason})
        elif not path.exists():
            blockers.append({"reason": "required plan path is missing", "source": source, "path": str(path), "kind": normalized_kind or "path", "detail": reason})
    return blockers


def resolve_step_path(path_value: Any, plan_dir: Path, cwd_path: Path | None = None) -> Path | None:
    if not has_text(path_value):
        return None
    path = Path(str(path_value)).expanduser()
    if path.is_absolute():
        return path.resolve(strict=False)
    base = cwd_path if cwd_path is not None else plan_dir
    return (base / path).resolve(strict=False)


def iter_command_steps(plan: dict[str, Any] | None):
    if not isinstance(plan, dict):
        return
    for scenario_index, scenario in enumerate(as_list(plan.get("scenarios")), 1):
        if not isinstance(scenario, dict):
            continue
        scenario_id = str(scenario.get("id") or f"scenario[{scenario_index}]")
        for step_index, step in enumerate(as_list(scenario.get("steps")), 1):
            if not isinstance(step, dict) or step.get("action") != "command":
                continue
            step_id = str(step.get("id") or f"step[{step_index}]")
            yield f"{scenario_id}.{step_id}", step


def iter_step_required_path_specs(step: dict[str, Any]):
    for field, expected_kind in (
        ("requiredFiles", "file"),
        ("required_files", "file"),
        ("requiredDirectories", "directory"),
        ("required_directories", "directory"),
        ("requiredDirs", "directory"),
        ("required_dirs", "directory"),
        ("requiredPaths", "path"),
        ("required_paths", "path"),
    ):
        value = step.get(field)
        if value is None:
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            if isinstance(item, dict):
                path_value = item.get("path")
                kind = str(item.get("type") or item.get("kind") or expected_kind)
                detail = item.get("reason")
            else:
                path_value = item
                kind = expected_kind
                detail = None
            yield field, path_value, kind, detail


def command_step_path_blocker(path: Path | None, kind: str, location: str, source: str, detail: Any = None) -> dict[str, Any] | None:
    if path is None:
        return {"reason": "required command path is missing", "location": location, "source": source, "path": "", "kind": kind, "detail": detail or "path is empty"}
    normalized_kind = str(kind).lower().replace("-", "_")
    if normalized_kind in {"file", "required_file"}:
        if not path.exists():
            return {"reason": "required command path is missing", "location": location, "source": source, "path": str(path), "kind": "file", "detail": detail}
        if not path.is_file():
            return {"reason": "required command path is not a file", "location": location, "source": source, "path": str(path), "kind": "file", "detail": detail}
    elif normalized_kind in {"directory", "dir", "required_directory"}:
        if not path.exists():
            return {"reason": "required command path is missing", "location": location, "source": source, "path": str(path), "kind": "directory", "detail": detail}
        if not path.is_dir():
            return {"reason": "required command path is not a directory", "location": location, "source": source, "path": str(path), "kind": "directory", "detail": detail}
    elif not path.exists():
        return {"reason": "required command path is missing", "location": location, "source": source, "path": str(path), "kind": normalized_kind or "path", "detail": detail}
    return None


def is_mypy_command(parts: list[str]) -> bool:
    parts = strip_leading_env_assignments(parts)
    parts = strip_cross_env_assignments(parts)
    if not parts:
        return False
    executable = Path(parts[0]).name.lower()
    if executable == "mypy":
        return True
    python_like = executable in {"python", "python.exe"} or executable.startswith(("python2", "python3"))
    if len(parts) >= 3 and python_like and parts[1] == "-m" and parts[2] == "mypy":
        return True
    if executable in {"uv", "poetry", "pipenv", "pdm", "rye", "hatch"} and len(parts) >= 3 and parts[1] == "run":
        return is_mypy_command(parts[2:])
    return False


def plan_command_prerequisite_blockers(plan: dict[str, Any] | None, plan_path: Path, project_root: Path) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    command_base = project_root
    for location, step in iter_command_steps(plan):
        cwd_path: Path | None = None
        cwd_value = step.get("cwd")
        if cwd_value not in (None, ""):
            cwd_path = resolve_step_path(cwd_value, command_base)
            if cwd_path is None:
                blockers.append({"reason": "command cwd path is missing", "location": location, "path": "", "detail": "cwd is empty"})
            elif not cwd_path.exists():
                blockers.append({"reason": "command cwd path is missing", "location": location, "path": str(cwd_path)})
            elif not cwd_path.is_dir():
                blockers.append({"reason": "command cwd path is not a directory", "location": location, "path": str(cwd_path)})

        for field, path_value, kind, detail in iter_step_required_path_specs(step):
            blocker = command_step_path_blocker(resolve_step_path(path_value, command_base, cwd_path), kind, location, field, detail)
            if blocker:
                blockers.append(blocker)

        parts = command_parts(step.get("command") or step.get("cmd") or "")
        service_dir = cwd_path or project_root
        status = command_status(parts)
        if parts and not status["found"] and not status.get("substitute"):
            blockers.append({
                "reason": "command executable is missing",
                "location": location,
                "executable": status.get("executable"),
            })
        nested_status = nested_command_status(parts, service_dir, project_root)
        if nested_status and not nested_status["found"] and not nested_status.get("substitute"):
            blockers.append({
                "reason": "command executable is missing",
                "location": location,
                "executable": nested_status.get("executable"),
            })
        npm_status = npm_script_status(parts, service_dir, project_root)
        if npm_status and not npm_status["found"]:
            blockers.append({
                "reason": "npm script is missing",
                "location": location,
                "script": npm_status["script"],
                "available_scripts": npm_status["available_scripts"],
                "package_dir": npm_status.get("package_dir"),
            })
        node_status = node_dependency_status(parts, service_dir, project_root)
        if node_status and not node_status["found"]:
            blockers.append({
                "reason": "node dependencies are missing",
                "location": location,
                "candidates": node_status["candidates"],
            })
        if not is_mypy_command(parts):
            continue
        for index, part in enumerate(parts):
            config_value: str | None = None
            if part == "--config-file" and index + 1 < len(parts):
                config_value = parts[index + 1]
            elif part.startswith("--config-file="):
                config_value = part.split("=", 1)[1]
            if not config_value:
                continue
            config_path = resolve_step_path(config_value, command_base, cwd_path)
            if config_path is None or not config_path.exists():
                blockers.append({"reason": "mypy config file is missing", "location": location, "path": str(config_path or config_value)})
            elif not config_path.is_file():
                blockers.append({"reason": "mypy config path is not a file", "location": location, "path": str(config_path)})
    return blockers


def plan_text(plan: dict[str, Any]) -> str:
    return json.dumps(plan, ensure_ascii=False).lower()


def infer_required_services(context: dict[str, Any], plan: dict[str, Any] | None, explicit: list[str]) -> set[str]:
    if explicit:
        return set(explicit)
    adapter = context.get("adapter")
    base_url = str((plan or {}).get("baseUrl") or context.get("base_url") or "")
    required: set[str] = set()
    definition = get_adapter_definition(str(adapter))
    if definition:
        preflight = definition.get("preflight") if isinstance(definition.get("preflight"), dict) else {}
        for marker, services in (preflight.get("base_url_contains") or {}).items():
            if str(marker) in base_url:
                required.update(str(item) for item in as_list(services) if str(item))
        text = plan_text(plan or {})
        for marker, services in (preflight.get("plan_text_contains") or {}).items():
            if str(marker).lower() in text:
                required.update(str(item) for item in as_list(services) if str(item))
    else:
        for service in as_list(context.get("services")):
            if service.get("default_url") and service.get("default_url") == base_url:
                required.add(str(service.get("id")))
    return required


def env_file_status(service_id: str, context: dict[str, Any], project_root: Path) -> dict[str, Any]:
    definition = get_adapter_definition(str(context.get("adapter") or ""))
    preflight = definition.get("preflight") if isinstance((definition or {}).get("preflight"), dict) else {}
    env_candidates = preflight.get("env_candidates") if isinstance(preflight.get("env_candidates"), dict) else {}
    candidates = [str(item) for item in as_list(env_candidates.get(service_id)) if str(item)]
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
    npm_status = npm_script_status(start_parts, service_dir, project_root)
    node_status = node_dependency_status(start_parts, service_dir, project_root)
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
            "node_dependency_status": node_status,
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
        blockers.append({"service": service_id, "reason": "npm script is missing", "script": npm_status["script"], "package_dir": npm_status.get("package_dir")})
    if required and node_status and not node_status["found"]:
        blockers.append({"service": service_id, "reason": "node dependencies are missing", "candidates": node_status["candidates"]})
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
            write_json(context_path, context)
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
    blockers.extend(plan_required_path_blockers(plan, project_root))
    blockers.extend(plan_command_prerequisite_blockers(plan, plan_path, project_root))

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
