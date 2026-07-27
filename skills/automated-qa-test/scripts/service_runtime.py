#!/usr/bin/env python3
import argparse
import contextlib
import json
import os
import re
import shlex
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any

from qa_common import atomic_write_json, safe_output_path

DESTRUCTIVE_COMMAND_RE = re.compile(
    r"\b(rm\s+-rf|mkfs|dd\s+if=|drop\s+table|truncate\s+table|delete\s+from|update\s+\w+\s+set|insert\s+into|gh\s+repo\s+delete|kubectl\s+delete|docker\s+(?:rm|rmi|system\s+prune|compose\s+down))\b",
    re.IGNORECASE,
)
SHELL_META_RE = re.compile(r"[;&|`<>]")
SERVICE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class ServiceRuntimeInterrupted(RuntimeError):
    """Raised so termination requests unwind through emergency cleanup."""


class ServiceLaunchGuard:
    """Own newly spawned service groups until their runtime artifact is durable."""

    def __init__(self, output_path: Path | None = None) -> None:
        self.output_path = output_path
        self.report: dict[str, Any] | None = None
        self._managed: list[
            tuple[subprocess.Popen[Any], int, str]
        ] = []
        self._armed = True

    def attach(self, report: dict[str, Any]) -> None:
        self.report = report
        self.persist()

    def track(
        self,
        proc: subprocess.Popen[Any],
        *,
        pgid: int,
        service_id: str,
    ) -> None:
        self._managed.append((proc, pgid, service_id))

    def persist(self) -> None:
        if self.output_path is not None and self.report is not None:
            write_json(self.output_path, self.report)

    def disarm(self) -> None:
        self._armed = False
        self._managed.clear()

    def terminate_all(self) -> dict[str, Any]:
        """Best-effort emergency cleanup using handles created by this process."""

        attempted: list[tuple[subprocess.Popen[Any], int, str]] = []
        errors: list[dict[str, str]] = []
        if not self._armed:
            return {
                "attempted_count": 0,
                "remaining_count": 0,
                "errors": [],
            }
        for proc, pgid, service_id in reversed(self._managed):
            if proc.poll() is not None:
                continue
            attempted.append((proc, pgid, service_id))
            try:
                if pgid <= 1 or pgid == os.getpgrp():
                    raise RuntimeError("unsafe managed process group")
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                continue
            except Exception as error:
                errors.append(
                    {
                        "service": service_id,
                        "error": f"{type(error).__name__}: {error}",
                    }
                )
        deadline = time.time() + 0.75
        while (
            any(proc.poll() is None for proc, _, _ in attempted)
            and time.time() < deadline
        ):
            time.sleep(0.02)
        for proc, pgid, service_id in attempted:
            if proc.poll() is not None:
                continue
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                continue
            except Exception as error:
                errors.append(
                    {
                        "service": service_id,
                        "error": f"{type(error).__name__}: {error}",
                    }
                )
        remaining = sum(
            proc.poll() is None for proc, _, _ in attempted
        )
        return {
            "attempted_count": len(attempted),
            "remaining_count": remaining,
            "errors": errors,
        }


@contextlib.contextmanager
def blocked_termination_signals():
    """Defer normal termination across the Popen-to-track critical section."""

    pthread_sigmask = getattr(signal, "pthread_sigmask", None)
    if pthread_sigmask is None:
        yield
        return
    blocked = {signal.SIGTERM, signal.SIGINT}
    previous = pthread_sigmask(signal.SIG_BLOCK, blocked)
    try:
        yield
    finally:
        pthread_sigmask(signal.SIG_SETMASK, previous)


@contextlib.contextmanager
def termination_cleanup_handlers():
    """Translate normal termination signals into a catchable exception."""

    previous: dict[int, Any] = {}

    def interrupt(signum: int, _frame: Any) -> None:
        raise ServiceRuntimeInterrupted(
            f"received termination signal {signum}"
        )

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, interrupt)
    try:
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


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
    service_id = str(item.get("service") or "")
    if not SERVICE_ID_RE.fullmatch(service_id):
        errors.append(
            "service id must use 1-128 safe filename characters"
        )
    if str(service.get("id") or "") != service_id:
        errors.append(
            "start plan references an unknown or mismatched service id"
        )
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


def open_service_log_handles(
    run_dir: Path,
    service_id: str,
) -> tuple[Path, Path, Any, Any]:
    """Open append-only logs through a pinned, non-symlink directory."""

    if not SERVICE_ID_RE.fullmatch(service_id):
        raise ValueError("unsafe service id for log files")
    log_dir = run_dir / "service-logs"
    log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    observed = log_dir.lstat()
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(
        observed.st_mode
    ):
        raise ValueError("service log directory must be a real directory")
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_descriptor = os.open(log_dir, directory_flags)
    handles: list[Any] = []
    names = (
        f"{service_id}.stdout.log",
        f"{service_id}.stderr.log",
    )
    try:
        for name in names:
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_APPEND
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(
                name,
                flags,
                0o600,
                dir_fd=directory_descriptor,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                os.close(descriptor)
                raise ValueError(
                    "service log must be a single-link regular file"
                )
            handles.append(os.fdopen(descriptor, "ab"))
    except Exception:
        for handle in handles:
            handle.close()
        raise
    finally:
        os.close(directory_descriptor)
    return (
        log_dir / names[0],
        log_dir / names[1],
        handles[0],
        handles[1],
    )


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


def start_services(
    args: argparse.Namespace,
    *,
    launch_guard: ServiceLaunchGuard | None = None,
) -> dict[str, Any]:
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
            "launch_attempted": False,
            "incremental_runtime_persistence": (
                launch_guard is not None
                and launch_guard.output_path is not None
            ),
        },
        "input_artifact_errors": [],
    }
    if launch_guard is not None:
        launch_guard.attach(report)

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
            if launch_guard is not None:
                launch_guard.persist()
            continue
        if entry["pre_start_readiness"].get("ready") is True and not args.force:
            entry["status"] = "already_ready"
            entry["post_start_readiness"] = entry["pre_start_readiness"]
            report["summary"]["ready_count"] += 1
            results.append(entry)
            if launch_guard is not None:
                launch_guard.persist()
            continue
        if not args.start:
            entry["status"] = "dry_run"
            entry["would_start"] = True
            report["summary"]["dry_run_count"] += 1
            results.append(entry)
            if launch_guard is not None:
                launch_guard.persist()
            continue

        entry["status"] = "launch_intent"
        entry["launch_sequence"] = len(results) + 1
        report["safety"]["launch_attempted"] = True
        results.append(entry)
        if launch_guard is not None:
            launch_guard.persist()
        try:
            (
                stdout_path,
                stderr_path,
                stdout_handle,
                stderr_handle,
            ) = open_service_log_handles(run_dir, service_id)
        except (OSError, ValueError) as exc:
            entry["status"] = "failed_to_start"
            entry["error"] = (
                "service log boundary rejected launch: "
                f"{type(exc).__name__}: {exc}"
            )
            report["summary"]["failed_count"] += 1
            if launch_guard is not None:
                launch_guard.persist()
            continue
        try:
            with blocked_termination_signals():
                proc = subprocess.Popen(
                    command,
                    cwd=str(cwd),
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    stdin=subprocess.DEVNULL,
                    env=os.environ.copy(),
                    start_new_session=True,
                )
                if launch_guard is not None:
                    launch_guard.track(
                        proc,
                        pgid=proc.pid,
                        service_id=service_id,
                    )
        except ServiceRuntimeInterrupted:
            raise
        except Exception as exc:
            stdout_handle.close()
            stderr_handle.close()
            entry["status"] = "failed_to_start"
            entry["error"] = f"{type(exc).__name__}: {exc}"
            entry["stdout_log"] = str(stdout_path)
            entry["stderr_log"] = str(stderr_path)
            report["summary"]["failed_count"] += 1
            if launch_guard is not None:
                launch_guard.persist()
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
        if launch_guard is not None:
            launch_guard.persist()
        if args.no_wait:
            entry["status"] = "started_no_wait"
            entry["process_identity"] = stable_process_identity(proc)
            if launch_guard is not None:
                launch_guard.persist()
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
        entry["process_identity"] = stable_process_identity(proc)
        if launch_guard is not None:
            launch_guard.persist()

    return report


def process_command(pid: int) -> str:
    try:
        proc = subprocess.run(["ps", "-p", str(pid), "-o", "command="], text=True, capture_output=True, check=False)
    except Exception:
        return ""
    return proc.stdout.strip()


def process_start_time(pid: int) -> str:
    try:
        proc = subprocess.run(["ps", "-p", str(pid), "-o", "lstart="], text=True, capture_output=True, check=False)
    except Exception:
        return ""
    return " ".join(proc.stdout.split())


def command_sha256(command: str) -> str:
    import hashlib

    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def process_identity(pid: int) -> dict[str, Any]:
    command = process_command(pid)
    try:
        pgid = os.getpgid(pid)
    except OSError:
        pgid = None
    return {
        "pid": pid,
        "pgid": pgid,
        "command": command,
        "command_sha256": command_sha256(command) if command else None,
        "os_started_at": process_start_time(pid) or None,
    }


def stable_process_identity(
    proc: subprocess.Popen[Any],
    *,
    attempts: int = 20,
    interval_seconds: float = 0.01,
) -> dict[str, Any]:
    """Capture identity after runtime startup has stopped rewriting process metadata."""

    previous: dict[str, Any] | None = None
    for _ in range(max(2, attempts)):
        current = process_identity(proc.pid)
        if (
            current == previous
            and current.get("command")
            and current.get("command_sha256")
            and current.get("os_started_at")
            and current.get("pgid") is not None
        ):
            return current
        previous = current
        if proc.poll() is not None:
            break
        time.sleep(max(0.0, interval_seconds))
    return previous or process_identity(proc.pid)


def process_matches(pid: int, command: list[Any]) -> bool:
    actual = process_command(pid)
    expected = [str(part) for part in command if str(part)]
    if not actual or not expected:
        return False
    try:
        actual_parts = shlex.split(actual)
    except ValueError:
        return False
    if not actual_parts or Path(actual_parts[0]).name != Path(expected[0]).name:
        return False
    return actual_parts[1:] == expected[1:]


def process_identity_errors(item: dict[str, Any], current: dict[str, Any]) -> list[str]:
    recorded = item.get("process_identity")
    if not isinstance(recorded, dict):
        return ["runtime artifact has no process_identity; legacy PID-only stop is refused"]
    errors: list[str] = []
    for field in ("pid", "pgid", "command_sha256", "os_started_at"):
        if recorded.get(field) is None:
            errors.append(f"recorded process_identity.{field} is missing")
        elif current.get(field) != recorded.get(field):
            errors.append(f"process_identity.{field} does not match the current OS process")
    if item.get("pid") != recorded.get("pid"):
        errors.append("service pid does not match process_identity.pid")
    if item.get("pgid") != recorded.get("pgid"):
        errors.append("service pgid does not match process_identity.pgid")
    if recorded.get("command") != current.get("command"):
        errors.append("process_identity.command does not match the current OS process")
    return errors


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
            "requires_process_identity_match": True,
            "requires_process_group_match": True,
        },
        "input_artifact_errors": [],
    }
    pending: list[tuple[dict[str, Any], int, int]] = []
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
        current_identity = process_identity(pid)
        identity_errors = process_identity_errors(item, current_identity)
        if identity_errors:
            entry["status"] = "blocked_by_safety"
            entry["reason"] = "current process identity does not exactly match the recorded start identity"
            entry["errors"] = identity_errors
            entry["current_process_identity"] = current_identity
            report["summary"]["failed_count"] += 1
            stopped.append(entry)
            continue
        pgid = current_identity.get("pgid")
        if not isinstance(pgid, int) or pgid <= 1 or pgid == os.getpgrp():
            entry["status"] = "blocked_by_safety"
            entry["reason"] = "recorded process group is invalid or matches the QA controller process group"
            report["summary"]["failed_count"] += 1
            stopped.append(entry)
            continue
        entry["status"] = "terminating"
        stopped.append(entry)
        pending.append((entry, pid, pgid))

    term_pending: list[tuple[dict[str, Any], int, int]] = []
    for entry, pid, pgid in pending:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            entry["status"] = "already_stopped"
            report["summary"]["skipped_count"] += 1
            continue
        except Exception as exc:
            entry["status"] = "failed"
            entry["error"] = f"{type(exc).__name__}: {exc}"
            report["summary"]["failed_count"] += 1
            continue
        term_pending.append((entry, pid, pgid))

    deadline = time.time() + args.stop_timeout
    while (
        any(pid_alive(pid) for _, pid, _ in term_pending)
        and time.time() <= deadline
    ):
        time.sleep(0.05)

    kill_pending: list[tuple[dict[str, Any], int, int]] = []
    for entry, pid, pgid in term_pending:
        if pid_alive(pid):
            try:
                os.killpg(pgid, signal.SIGKILL)
                kill_pending.append((entry, pid, pgid))
            except Exception as exc:
                entry["status"] = "failed"
                entry["error"] = f"{type(exc).__name__}: {exc}"
                report["summary"]["failed_count"] += 1
        else:
            entry["status"] = "stopped"
            report["summary"]["stopped_count"] += 1

    kill_deadline = time.time() + min(1.0, args.stop_timeout)
    while (
        any(pid_alive(pid) for _, pid, _ in kill_pending)
        and time.time() <= kill_deadline
    ):
        time.sleep(0.02)
    for entry, pid, _ in kill_pending:
        if pid_alive(pid):
            entry["status"] = "failed"
            entry["reason"] = "process remained alive after SIGKILL"
            report["summary"]["failed_count"] += 1
        else:
            entry["status"] = "killed"
            report["summary"]["stopped_count"] += 1
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
    default_name = (
        "service-runtime-stop.json"
        if args.stop
        else "service-runtime.json"
    )
    requested_out = (
        Path(args.out).expanduser()
        if args.out
        else run_dir / default_name
    )
    if args.stop:
        protected = (
            Path(args.runtime).expanduser()
            if args.runtime
            else run_dir / "service-runtime.json"
        )
    else:
        protected = (
            Path(args.preflight).expanduser()
            if args.preflight
            else run_dir / "service-preflight.json"
        )
    try:
        out_path = safe_output_path(
            requested_out,
            protected_paths=(protected,),
        )
    except ValueError as error:
        raise SystemExit(str(error)) from error

    launch_guard = ServiceLaunchGuard(
        out_path if args.start and not args.stop else None
    )
    try:
        with termination_cleanup_handlers():
            if args.stop:
                report = stop_services(args)
            else:
                report = start_services(
                    args,
                    launch_guard=launch_guard,
                )
            write_json(out_path, report)
            launch_guard.disarm()
    except (Exception, KeyboardInterrupt) as error:
        cleanup = launch_guard.terminate_all()
        report = launch_guard.report or {
            "schema_version": 1,
            "generated_at": now(),
            "mode": (
                "stop"
                if args.stop
                else "start"
                if args.start
                else "dry_run"
            ),
            "run_dir": str(run_dir),
            "services": [],
            "summary": {
                "planned_count": 0,
                "started_count": 0,
                "ready_count": 0,
                "failed_count": 1,
                "dry_run_count": 0,
            },
            "safety": {
                "secret_values_read": False,
                "shell_used": False,
                "default_is_dry_run": True,
                "services_started": False,
                "launch_attempted": bool(args.start),
                "incremental_runtime_persistence": bool(
                    launch_guard.output_path
                ),
            },
            "input_artifact_errors": [],
        }
        report.setdefault("runtime_errors", []).append(
            {
                "code": "service_runtime_interrupted",
                "type": type(error).__name__,
                "message": str(error),
            }
        )
        report.setdefault("safety", {})[
            "emergency_cleanup"
        ] = cleanup
        summary = report.setdefault("summary", {})
        failed_count = summary.get("failed_count")
        summary["failed_count"] = max(
            1,
            failed_count
            if isinstance(failed_count, int)
            and not isinstance(failed_count, bool)
            else 0,
        )
        try:
            write_json(out_path, report)
        except Exception as persist_error:
            print(
                "service runtime emergency report could not be persisted: "
                f"{persist_error}",
                file=sys.stderr,
            )
        print(
            f"service runtime failed closed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        print(out_path)
        return 1

    failed = bool(
        report.get("input_artifact_errors")
        or (
            (args.start or args.stop)
            and report.get("summary", {}).get("failed_count")
        )
    )
    print(out_path)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
