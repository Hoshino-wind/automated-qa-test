#!/usr/bin/env python3
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.runtime import RunBudget  # noqa: E402
from qa_core.runtime.budget import BudgetExceeded  # noqa: E402
from qa_core.runtime.session import (  # noqa: E402
    AGENT_OWNER_PREFIX,
    CYCLE_OWNER_PREFIX,
    RunSession,
)


def load_agent_loop() -> Any:
    spec = importlib.util.spec_from_file_location(
        "qa_agent_loop_budget_under_test",
        SCRIPT_DIR / "qa_agent_loop.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("无法加载 qa_agent_loop.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cycle_args(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "strict_runtime": False,
        "require_environment_boundary": False,
        "skip_probe": False,
        "preflight_runtime": False,
        "start_missing_services": False,
        "service_start_no_wait": False,
        "allow_preflight_blockers": False,
        "refresh_adapter_context": False,
        "synthesize_adapter_probes": False,
        "allow_live_stream": False,
        "allow_stopped_service": False,
        "allow_unsafe_command": False,
        "allow_unmapped_requirement_source": False,
        "allow_mutating_api": False,
        "skip_report": False,
        "node_bin": "node",
        "agent_id": None,
        "user_id": None,
        "marker": None,
        "question": None,
        "ws_path": None,
        "session_detail_path": None,
        "persistence_command": None,
        "project_root": ".",
        "runtime_mode": None,
        "data_boundary_status": None,
        "required_service": [],
        "service_start_timeout": 60.0,
        "total_timeout_seconds": 30.0,
        "stage_timeout_seconds": 7.0,
        "max_probes": 11,
        "max_output_bytes": 4096,
        "termination_grace_seconds": 0.25,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def flag_value(command: list[str], flag: str) -> str:
    return command[command.index(flag) + 1]


class AgentLoopBudgetTests(unittest.TestCase):
    def test_cli_rejects_unbounded_or_invalid_limits(self) -> None:
        module = load_agent_loop()
        invalid = (
            ["--total-timeout-seconds", "0"],
            ["--stage-timeout-seconds", "nan"],
            ["--max-probes", "0"],
            ["--max-output-bytes", "-1"],
            ["--termination-grace-seconds", "-0.1"],
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                original_argv = sys.argv[:]
                try:
                    sys.argv = [
                        "qa_agent_loop.py",
                        "--run-dir",
                        "/tmp/qa-agent-invalid-budget",
                        *arguments,
                    ]
                    with (
                        contextlib.redirect_stdout(io.StringIO()),
                        contextlib.redirect_stderr(io.StringIO()),
                        self.assertRaises(SystemExit) as caught,
                    ):
                        module.main()
                finally:
                    sys.argv = original_argv
                self.assertEqual(caught.exception.code, 2)

    def test_cycle_command_forwards_remaining_and_explicit_budget(self) -> None:
        module = load_agent_loop()
        budget = RunBudget(
            total_timeout=30,
            default_stage_timeout=7,
            max_probes=11,
            max_output_bytes=4096,
        )

        command = module.build_cycle_cmd(
            cycle_args(),
            SCRIPT_DIR,
            Path("/tmp/qa-agent-budget-forward"),
            apply_next=False,
            budget=budget,
        )

        remaining = float(flag_value(command, "--total-timeout-seconds"))
        self.assertGreater(remaining, 0)
        self.assertLessEqual(remaining, 30)
        self.assertEqual(flag_value(command, "--stage-timeout-seconds"), "7.0")
        self.assertEqual(flag_value(command, "--max-probes"), "11")
        self.assertEqual(flag_value(command, "--max-output-bytes"), "4096")
        self.assertEqual(
            flag_value(command, "--termination-grace-seconds"),
            "0.25",
        )

    def test_cycle_command_forwards_remaining_output_and_never_zero(
        self,
    ) -> None:
        module = load_agent_loop()
        budget = RunBudget(
            total_timeout=30,
            default_stage_timeout=7,
            max_probes=11,
            max_output_bytes=4096,
        )
        budget.consume_output(1024)

        command = module.build_cycle_cmd(
            cycle_args(),
            SCRIPT_DIR,
            Path("/tmp/qa-agent-budget-output-remaining"),
            apply_next=False,
            budget=budget,
        )

        self.assertEqual(
            flag_value(command, "--max-output-bytes"),
            "3072",
        )
        budget.consume_output(3072)
        with self.assertRaises(BudgetExceeded) as caught:
            module.build_cycle_cmd(
                cycle_args(),
                SCRIPT_DIR,
                Path("/tmp/qa-agent-budget-output-exhausted"),
                apply_next=False,
                budget=budget,
            )
        self.assertEqual(
            caught.exception.reason.value,
            "output_byte_limit",
        )

    def test_cycle_reservations_share_output_and_probe_totals(
        self,
    ) -> None:
        module = load_agent_loop()
        with tempfile.TemporaryDirectory(
            prefix="qa-agent-shared-budget-"
        ) as raw:
            run_dir = Path(raw)
            (run_dir / "test-plan.json").write_text(
                json.dumps(
                    {
                        "scenarios": [
                            {"id": "one", "steps": [{"id": "probe"}]}
                        ]
                    }
                ),
                encoding="utf-8",
            )
            budget = RunBudget(
                total_timeout=30,
                default_stage_timeout=7,
                max_probes=3,
                max_output_bytes=100,
            )

            first = module.reserve_cycle_resources(run_dir, budget)
            budget.consume_output(30)
            second = module.reserve_cycle_resources(run_dir, budget)

            self.assertEqual(first, (1, 3, 100))
            self.assertEqual(second, (1, 2, 70))
            self.assertEqual(budget.snapshot().probes_used, 2)
            self.assertEqual(budget.snapshot().output_bytes_used, 30)

    def test_child_cycle_inherits_outer_writer_lease(self) -> None:
        module = load_agent_loop()
        with tempfile.TemporaryDirectory(
            prefix="qa-agent-child-lease-"
        ) as raw:
            run_dir = Path(raw)
            holder = RunSession.open(
                run_dir,
                owner_prefix=AGENT_OWNER_PREFIX,
            )
            module._ACTIVE_RUN_BUDGET = RunBudget(
                total_timeout=10,
                default_stage_timeout=5,
                max_output_bytes=4096,
            )
            child_code = (
                "import json, sys; "
                "from pathlib import Path; "
                "from qa_core.runtime.session import "
                "CYCLE_OWNER_PREFIX, RunSession; "
                "session = RunSession.open("
                "Path(sys.argv[1]), "
                "owner_prefix=CYCLE_OWNER_PREFIX, "
                "allow_parent_inheritance=True); "
                "print(json.dumps(session.to_dict())); "
                "session.close()"
            )
            try:
                result = module.run_command(
                    [
                        sys.executable,
                        "-c",
                        child_code,
                        str(run_dir),
                    ],
                    SCRIPT_DIR,
                )
                inherited = json.loads(
                    result["stdout"].strip().splitlines()[-1]
                )
                current = holder.lease.read()
            finally:
                module._ACTIVE_RUN_BUDGET = None
                holder.close()

            self.assertEqual(result["exit_code"], 0)
            self.assertTrue(inherited["inherited"])
            self.assertEqual(inherited["owner"], holder.owner)
            self.assertIsNotNone(current)
            self.assertEqual(current.owner, holder.owner)
            self.assertTrue(holder.owner.startswith(AGENT_OWNER_PREFIX))
            self.assertEqual(CYCLE_OWNER_PREFIX, "qa-cycle")

    def test_run_command_uses_shared_process_budget(self) -> None:
        module = load_agent_loop()
        module._ACTIVE_RUN_BUDGET = RunBudget(
            total_timeout=3,
            default_stage_timeout=1,
            max_output_bytes=8,
        )
        module._ACTIVE_TERMINATION_GRACE_SECONDS = 0.02
        try:
            result = module.run_command(
                [
                    sys.executable,
                    "-c",
                    "import os, signal, sys, time; "
                    "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); "
                    "os.write(1, b'x' * 32); "
                    "time.sleep(5)",
                ],
                Path.cwd(),
            )
        finally:
            module._ACTIVE_RUN_BUDGET = None

        self.assertEqual(result["termination_reason"], "output_byte_limit")
        self.assertEqual(result["exit_code"], 125)
        self.assertEqual(result["raw_exit_code"], 0)
        self.assertIn("started_at_epoch", result)
        self.assertIn("finished_at_epoch", result)

    def test_outer_boundaries_fail_closed_with_two_argument_monkeypatch(
        self,
    ) -> None:
        cases = (
            ("deadline_exceeded", ["--total-timeout-seconds", "0.01"]),
            ("cancelled", []),
            ("output_byte_limit", ["--max-output-bytes", "8"]),
        )
        for expected_reason, extra_args in cases:
            with self.subTest(expected_reason=expected_reason):
                self._assert_boundary_handoff(expected_reason, extra_args)

    def _assert_boundary_handoff(
        self,
        expected_reason: str,
        extra_args: list[str],
    ) -> None:
        module = load_agent_loop()
        with tempfile.TemporaryDirectory(prefix="qa-agent-boundary-") as raw:
            run_dir = Path(raw)
            (run_dir / "test-plan.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 2,
                        "baseUrl": "http://127.0.0.1:9527",
                        "scenarios": [],
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "test-matrix.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 2,
                        "requirements": [],
                        "tests": [],
                    }
                ),
                encoding="utf-8",
            )
            calls: list[list[str]] = []

            def fake_run_command(
                command: list[str],
                cwd: Path,
            ) -> dict[str, Any]:
                calls.append(command)
                if expected_reason == "deadline_exceeded":
                    time.sleep(0.03)
                elif expected_reason == "cancelled":
                    module._ACTIVE_RUN_BUDGET.cancel("测试取消")
                stdout = "0123456789abcdef" if expected_reason == "output_byte_limit" else ""
                return {
                    "command": command,
                    "cwd": str(cwd),
                    "exit_code": 0,
                    "stdout": stdout,
                    "stderr": "",
                }

            original_argv = sys.argv[:]
            original_run_command = module.run_command
            try:
                module.run_command = fake_run_command
                sys.argv = [
                    "qa_agent_loop.py",
                    "--run-dir",
                    str(run_dir),
                    "--max-iterations",
                    "1",
                    "--stage-timeout-seconds",
                    "2",
                    *extra_args,
                ]
                with (
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    exit_code = module.main()
            finally:
                module.run_command = original_run_command
                sys.argv = original_argv

            summary = json.loads(
                (run_dir / "qa-agent-summary.json").read_text(
                    encoding="utf-8"
                )
            )
            boundary = summary["execution_boundary"]
            final = summary["final"]
            handoff = (run_dir / "qa-agent-handoff.md").read_text(
                encoding="utf-8"
            )

            self.assertEqual(len(calls), 1)
            self.assertEqual(exit_code, 1)
            self.assertEqual(
                boundary["termination_reason"],
                expected_reason,
            )
            self.assertNotEqual(boundary["exit_code"], 0)
            self.assertEqual(final["verdict"], "Inconclusive")
            self.assertFalse(final["can_claim_pass"])
            self.assertFalse(summary["loop_control"]["pass_claim_allowed"])
            self.assertIn("Execution Boundary", handoff)

    def test_probe_budget_is_total_and_blocks_second_cycle_before_spawn(
        self,
    ) -> None:
        module = load_agent_loop()
        with tempfile.TemporaryDirectory(
            prefix="qa-agent-total-probes-"
        ) as raw:
            run_dir = Path(raw)
            (run_dir / "test-plan.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 2,
                        "scenarios": [
                            {
                                "id": "scenario-1",
                                "steps": [
                                    {"id": "probe-1"},
                                    {"id": "probe-2"},
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "test-matrix.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 2,
                        "requirements": [],
                        "tests": [],
                    }
                ),
                encoding="utf-8",
            )
            calls: list[list[str]] = []

            def fake_run_command(
                command: list[str],
                cwd: Path,
            ) -> dict[str, Any]:
                calls.append(command)
                return {
                    "command": command,
                    "cwd": str(cwd),
                    "exit_code": 0,
                    "stdout": "",
                    "stderr": "",
                }

            def fake_cycle_status(
                *_args: Any,
                **_kwargs: Any,
            ) -> dict[str, Any]:
                return {
                    "verdict": "Failed",
                    "can_claim_pass": False,
                    "reason_codes": ["requirement_failed"],
                    "preview_summary": {"applied_count": 1},
                }

            def fake_next_action(**_kwargs: Any) -> dict[str, Any]:
                return {
                    "action": "continue_with_safe_next_probes",
                    "automatable": True,
                    "next_iteration_applies_preview": True,
                    "expected_next_probes_sha256": "probe-hash",
                    "failure_analysis": {
                        "category": "runtime_evidence_gap",
                        "blocking_layer": "probe",
                        "source": "test",
                    },
                }

            originals = {
                "run_command": module.run_command,
                "cycle_status": module.cycle_status,
                "build_next_action": module.build_next_action,
                "next_probes_sha256": module.next_probes_sha256,
            }
            original_argv = sys.argv[:]
            try:
                module.run_command = fake_run_command
                module.cycle_status = fake_cycle_status
                module.build_next_action = fake_next_action
                module.next_probes_sha256 = lambda _run_dir: "probe-hash"
                sys.argv = [
                    "qa_agent_loop.py",
                    "--run-dir",
                    str(run_dir),
                    "--max-iterations",
                    "2",
                    "--max-probes",
                    "3",
                ]
                with (
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    exit_code = module.main()
            finally:
                module.run_command = originals["run_command"]
                module.cycle_status = originals["cycle_status"]
                module.build_next_action = originals[
                    "build_next_action"
                ]
                module.next_probes_sha256 = originals[
                    "next_probes_sha256"
                ]
                sys.argv = original_argv

            cycle_calls = [
                command
                for command in calls
                if any(
                    str(part).endswith("run_qa_cycle.py")
                    for part in command
                )
            ]
            summary = json.loads(
                (run_dir / "qa-agent-summary.json").read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(exit_code, 1)
            self.assertEqual(len(cycle_calls), 1)
            self.assertEqual(
                flag_value(cycle_calls[0], "--max-probes"),
                "3",
            )
            self.assertEqual(
                summary["execution_boundary"]["termination_reason"],
                "probe_limit",
            )
            self.assertEqual(summary["budget"]["probes_used"], 2)
            self.assertFalse(summary["final"]["can_claim_pass"])
            self.assertFalse(
                (run_dir / ".qa-run-lease.json").exists()
            )

    def test_competing_outer_writer_redirects_default_summary(
        self,
    ) -> None:
        self._assert_writer_conflict(summary_name=None)

    def test_competing_outer_writer_never_uses_requested_run_path(
        self,
    ) -> None:
        self._assert_writer_conflict(
            summary_name="requested-inside-run.json"
        )

    def _assert_writer_conflict(
        self,
        *,
        summary_name: str | None,
    ) -> None:
        module = load_agent_loop()
        with tempfile.TemporaryDirectory(
            prefix="qa-agent-writer-conflict-"
        ) as raw:
            root = Path(raw)
            run_dir = root / "run"
            run_dir.mkdir()
            sentinel_path = run_dir / (
                summary_name or "qa-agent-summary.json"
            )
            sentinel_path.write_text(
                "owned-by-first-writer",
                encoding="utf-8",
            )
            handoff_sentinel = run_dir / "qa-agent-handoff.md"
            handoff_sentinel.write_text(
                "owned-by-first-writer",
                encoding="utf-8",
            )
            holder = RunSession.open(
                run_dir,
                owner_prefix=AGENT_OWNER_PREFIX,
            )
            before = {
                path.name: path.read_bytes()
                for path in run_dir.iterdir()
                if path.is_file()
            }

            arguments = [
                "qa_agent_loop.py",
                "--run-dir",
                str(run_dir),
                "--out-dir",
                str(root / "safe-output"),
            ]
            if summary_name:
                arguments.extend(
                    ["--summary", str(run_dir / summary_name)]
                )
            original_argv = sys.argv[:]
            stdout = io.StringIO()
            try:
                sys.argv = arguments
                with (
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    exit_code = module.main()
                after = {
                    path.name: path.read_bytes()
                    for path in run_dir.iterdir()
                    if path.is_file()
                }
            finally:
                sys.argv = original_argv
                holder.close()

            summary_path = Path(
                [
                    line
                    for line in stdout.getvalue().splitlines()
                    if line.strip()
                ][-1]
            ).resolve()
            summary = json.loads(
                summary_path.read_text(encoding="utf-8")
            )
            handoff_path = Path(summary["handoff"]).resolve()

            self.assertEqual(exit_code, 1)
            self.assertEqual(before, after)
            self.assertFalse(summary_path.is_relative_to(run_dir))
            self.assertFalse(handoff_path.is_relative_to(run_dir))
            self.assertEqual(
                summary["stop_reason"],
                "agent_loop_writer_conflict",
            )
            self.assertEqual(
                summary["writer_conflict"]["current_lease"]["owner"],
                holder.owner,
            )
            self.assertEqual(summary["final"]["verdict"], "Inconclusive")
            self.assertFalse(summary["final"]["can_claim_pass"])
            self.assertFalse(
                summary["loop_control"]["pass_claim_allowed"]
            )
            self.assertTrue(handoff_path.is_file())


if __name__ == "__main__":
    unittest.main()
