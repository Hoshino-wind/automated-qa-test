#!/usr/bin/env python3
import argparse
import json
import os
import re
import signal
import socket
import subprocess
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any


DESTRUCTIVE_COMMAND_RE = re.compile(
    r"\b(rm\s+-rf|mkfs|dd\s+if=|drop\s+table|truncate\s+table|delete\s+from|update\s+\w+\s+set|insert\s+into|gh\s+repo\s+delete|kubectl\s+delete|docker\s+(?:rm|rmi|system\s+prune|compose\s+down))\b",
    re.IGNORECASE,
)
SHELL_META_RE = re.compile(r"[;&|`<>]")


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


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


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def parse_url_port(url: str) -> tuple[str | None, int | None]:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None, None
    if not parsed.hostname:
        return None, None
    if parsed.port:
        return parsed.hostname, parsed.port
    if parsed.scheme == "https":
        return parsed.hostname, 443
    if parsed.scheme == "http":
        return parsed.hostname, 80
    return parsed.hostname, None


def tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def readiness(service: dict[str, Any], timeout: float = 0.5) -> dict[str, Any]:
    url = str(service.get("default_url") or "")
    host, port = parse_url_port(url)
    if not host or not port:
        return {"check": "none", "ready": None, "reason": "service has no default_url/port"}
    return {
        "check": "tcp",
        "url": url,
        "host": host,
        "port": port,
        "ready": tcp_open(host, port, timeout),
    }


def input_error_report(args: argparse.Namespace, artifact_name: str, artifact_path: Path, error: str, mode: str) -> dict[str, Any]:
    run_dir = Path(args.run_dir).expanduser().resolve()
    report: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": now(),
        "mode": mode,
        "run_dir": str(run_dir),
        "services": [],
        "summary": {
            "planned_count": 0,
            "started_count": 0,
            "ready_count": 0,
            "failed_count": 1,
            "dry_run_count": 0,
            "input_artifact_error_count": 1,
        },
        "safety": {
            "secret_values_read": False,
            "shell_used": False,
            "default_is_dry_run": True,
            "services_started": False,
        },
        "input_artifact_errors": [{"name": artifact_name, "path": str(artifact_path), "error": error}],
    }
    if artifact_name == "preflight":
        report["preflight"] = str(artifact_path)
        report["project_root"] = str(Path(".").resolve())
        report["selected_services"] = sorted(args.service or []) if args.service else "all_start_plan_services"
    else:
        report["runtime"] = str(artifact_path)
        report["summary"] = {"stopped_count": 0, "skipped_count": 0, "failed_count": 1, "input_artifact_error_count": 1}
        report["safety"] = {
            "only_recorded_service_pids": True,
            "requires_command_match": True,
        }
    return report


def service_by_id(preflight: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item.get("id")): item for item in as_list(preflight.get("services")) if item.get("id")}


def validate_start_item(item: dict[str, Any], service: dict[str, Any], project_root: Path) -> tuple[bool, list[str], Path | None, list[str]]:
    errors: list[str] = []
    command = [str(part) for part in as_list(item.get("command")) if str(part)]
    cwd_raw = str(item.get("cwd") or service.get("path") or ".")
    cwd = (project_root / cwd_raw).resolve()
    if not command:
        errors.append("start command is missing or not an array")
    if not is_relative_to(cwd, project_root):
        errors.append(f"cwd escapes project root: {cwd_raw}")
    for part in command:
        if SHELL_META_RE.search(part):
            errors.append(f"command token contains shell metacharacters: {part}")
    command_text = " ".join(command)
    if DESTRUCTIVE_COMMAND_RE.search(command_text):
        errors.append(f"command looks destructive: {command_text}")
    return not errors, errors, cwd, command


def wait_until_ready(service: dict[str, Any], proc: subprocess.Popen[Any], wait_timeout: float, poll_interval: float) -> dict[str, Any]:
    deadline = time.time() + wait_timeout
    last_check: dict[str, Any] = {}
    while time.time() <= deadline:
        exit_code = proc.poll()
        last_check = readiness(service)
        if last_check.get("ready") is True:
            return {"ready": True, "check": last_check, "exit_code": exit_code}
        if exit_code is not None:
            return {"ready": False, "check": last_check, "exit_code": exit_code, "reason": "process exited before readiness"}
        time.sleep(max(poll_interval, 0.1))
    return {"ready": False, "check": last_check, "exit_code": proc.poll(), "reason": "timed out waiting for service readiness"}


def start_services(args: argparse.Namespace) -> dict[str, Any]:
    run_dir = Path(args.run_dir).expanduser().resolve()
    preflight_path = Path(args.preflight).expanduser().resolve() if args.preflight else run_dir / "service-preflight.json"
    preflight, preflight_error = try_load_json(preflight_path)
    if preflight_error:
        return input_error_report(args, "preflight", preflight_path, preflight_error, "start" if args.start else "dry_run")
    assert preflight is not None
    project_root = Path(preflight.get("project_root") or ".").expanduser().resolve()
    services = service_by_id(preflight)
    selected = set(args.service or [])
    plan = [item for item in as_list(preflight.get("start_plan")) if not selected or item.get("service") in selected]
    log_dir = run_dir / "service-logs"
    results: list[dict[str, Any]] = []

    report: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": now(),
        "mode": "start" if args.start else "dry_run",
        "run_dir": str(run_dir),
        "preflight": str(preflight_path),
        "project_root": str(project_root),
        "selected_services": sorted(selected) if selected else "all_start_plan_services",
        "services": results,
        "summary": {
            "planned_count": len(plan),
            "started_count": 0,
            "ready_count": 0,
            "failed_count": 0,
            "dry_run_count": 0,
        },
        "safety": {
            "secret_values_read": False,
            "shell_used": False,
            "default_is_dry_run": True,
            "services_started": False,
        },
        "input_artifact_errors": [],
    }

    if not plan:
        report["summary"]["note"] = "No start candidates found in service-preflight.json."
        return report

    for item in plan:
        service_id = str(item.get("service") or "")
        service = services.get(service_id, {"id": service_id})
        ok, validation_errors, cwd, command = validate_start_item(item, service, project_root)
        entry: dict[str, Any] = {
            "service": service_id,
            "reason": item.get("reason"),
            "cwd": str(cwd) if cwd else None,
            "command": command,
            "default_url": service.get("default_url"),
            "pre_start_readiness": readiness(service),
        }
        if not ok:
            entry["status"] = "blocked_by_safety"
            entry["errors"] = validation_errors
            report["summary"]["failed_count"] += 1
            results.append(entry)
            continue
        if entry["pre_start_readiness"].get("ready") is True and not args.force:
            entry["status"] = "already_ready"
            entry["post_start_readiness"] = entry["pre_start_readiness"]
            report["summary"]["ready_count"] += 1
            results.append(entry)
            continue
        if not args.start:
            entry["status"] = "dry_run"
            entry["would_start"] = True
            report["summary"]["dry_run_count"] += 1
            results.append(entry)
            continue

        stdout_path = log_dir / f"{service_id}.stdout.log"
        stderr_path = log_dir / f"{service_id}.stderr.log"
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_handle = stdout_path.open("ab")
        stderr_handle = stderr_path.open("ab")
        try:
            proc = subprocess.Popen(
                command,
                cwd=str(cwd),
                stdout=stdout_handle,
                stderr=stderr_handle,
                stdin=subprocess.DEVNULL,
                env=os.environ.copy(),
                start_new_session=True,
            )
        except Exception as exc:
            stdout_handle.close()
            stderr_handle.close()
            entry["status"] = "failed_to_start"
            entry["error"] = f"{type(exc).__name__}: {exc}"
            entry["stdout_log"] = str(stdout_path)
            entry["stderr_log"] = str(stderr_path)
            report["summary"]["failed_count"] += 1
            results.append(entry)
            continue
        finally:
            try:
                stdout_handle.close()
                stderr_handle.close()
            except Exception:
                pass

        entry.update(
            {
                "status": "started",
                "pid": proc.pid,
                "pgid": os.getpgid(proc.pid),
                "started_at": now(),
                "stdout_log": str(stdout_path),
                "stderr_log": str(stderr_path),
                "started_by": "automated-qa-test/scripts/service_runtime.py",
            }
        )
        report["summary"]["started_count"] += 1
        report["safety"]["services_started"] = True
        if args.no_wait:
            entry["status"] = "started_no_wait"
            results.append(entry)
            continue
        wait_result = wait_until_ready(service, proc, args.wait_timeout, args.poll_interval)
        entry["post_start_readiness"] = wait_result.get("check")
        entry["exit_code"] = wait_result.get("exit_code")
        if wait_result.get("ready"):
            entry["status"] = "ready"
            entry["ready_at"] = now()
            report["summary"]["ready_count"] += 1
        else:
            entry["status"] = "unready"
            entry["error"] = wait_result.get("reason")
            report["summary"]["failed_count"] += 1
        results.append(entry)

    return report


def process_command(pid: int) -> str:
    try:
        proc = subprocess.run(["ps", "-p", str(pid), "-o", "command="], text=True, capture_output=True, check=False)
    except Exception:
        return ""
    return proc.stdout.strip()


def process_matches(pid: int, command: list[Any]) -> bool:
    actual = process_command(pid)
    if not actual:
        return False
    first = Path(str(command[0])).name if command else ""
    if first and first in actual:
        return True
    remaining = [str(part) for part in command[1:] if str(part)]
    if not remaining:
        return False
    cursor = 0
    for token in remaining:
        found = actual.find(token, cursor)
        if found == -1:
            return False
        cursor = found + len(token)
    return True


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def stop_services(args: argparse.Namespace) -> dict[str, Any]:
    run_dir = Path(args.run_dir).expanduser().resolve()
    runtime_path = Path(args.runtime).expanduser().resolve() if args.runtime else run_dir / "service-runtime.json"
    runtime, runtime_error = try_load_json(runtime_path)
    if runtime_error:
        return input_error_report(args, "runtime", runtime_path, runtime_error, "stop")
    assert runtime is not None
    selected = set(args.service or [])
    stopped: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": now(),
        "mode": "stop",
        "run_dir": str(run_dir),
        "runtime": str(runtime_path),
        "services": stopped,
        "summary": {"stopped_count": 0, "skipped_count": 0, "failed_count": 0},
        "safety": {
            "only_recorded_service_pids": True,
            "requires_command_match": True,
        },
        "input_artifact_errors": [],
    }
    for item in as_list(runtime.get("services")):
        service_id = str(item.get("service") or "")
        if selected and service_id not in selected:
            continue
        pid = item.get("pid")
        command = as_list(item.get("command"))
        entry = {"service": service_id, "pid": pid, "command": command}
        if not isinstance(pid, int) or pid <= 1:
            entry["status"] = "skipped"
            entry["reason"] = "no recorded service pid"
            report["summary"]["skipped_count"] += 1
            stopped.append(entry)
            continue
        if not pid_alive(pid):
            entry["status"] = "already_stopped"
            report["summary"]["skipped_count"] += 1
            stopped.append(entry)
            continue
        if not process_matches(pid, command):
            entry["status"] = "blocked_by_safety"
            entry["reason"] = "pid command does not match recorded command"
            entry["actual_command"] = process_command(pid)
            report["summary"]["failed_count"] += 1
            stopped.append(entry)
            continue
        pgid = item.get("pgid") if isinstance(item.get("pgid"), int) else pid
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            entry["status"] = "already_stopped"
            report["summary"]["skipped_count"] += 1
            stopped.append(entry)
            continue
        except Exception as exc:
            entry["status"] = "failed"
            entry["error"] = f"{type(exc).__name__}: {exc}"
            report["summary"]["failed_count"] += 1
            stopped.append(entry)
            continue
        deadline = time.time() + args.stop_timeout
        while time.time() <= deadline and pid_alive(pid):
            time.sleep(0.2)
        if pid_alive(pid):
            try:
                os.killpg(pgid, signal.SIGKILL)
                entry["status"] = "killed"
            except Exception as exc:
                entry["status"] = "failed"
                entry["error"] = f"{type(exc).__name__}: {exc}"
                report["summary"]["failed_count"] += 1
                stopped.append(entry)
                continue
        else:
            entry["status"] = "stopped"
        report["summary"]["stopped_count"] += 1
        stopped.append(entry)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Start or dry-run local services from service-preflight.json start_plan.")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--preflight", help="Defaults to <run-dir>/service-preflight.json")
    parser.add_argument("--runtime", help="Runtime artifact to stop. Defaults to <run-dir>/service-runtime.json")
    parser.add_argument("--out")
    parser.add_argument("--service", action="append", help="Limit to one service id. May be repeated.")
    parser.add_argument("--start", action="store_true", help="Actually start services. Omit for dry-run.")
    parser.add_argument("--stop", action="store_true", help="Stop services recorded in a service-runtime.json artifact.")
    parser.add_argument("--force", action="store_true", help="Start even if the service port already appears ready.")
    parser.add_argument("--no-wait", action="store_true", help="Do not wait for started service ports.")
    parser.add_argument("--wait-timeout", type=float, default=45.0)
    parser.add_argument("--poll-interval", type=float, default=0.5)
    parser.add_argument("--stop-timeout", type=float, default=6.0)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    if args.stop:
        report = stop_services(args)
        default_name = "service-runtime-stop.json"
        failed = bool(report.get("summary", {}).get("failed_count"))
    else:
        report = start_services(args)
        default_name = "service-runtime.json"
        failed = bool(args.start and report.get("summary", {}).get("failed_count"))
    out_path = Path(args.out).expanduser().resolve() if args.out else run_dir / default_name
    write_json(out_path, report)
    print(out_path)
    return 1 if report.get("input_artifact_errors") or failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
