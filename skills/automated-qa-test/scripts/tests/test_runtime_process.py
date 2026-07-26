#!/usr/bin/env python3
import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.runtime import (  # noqa: E402
    BudgetReason,
    ProcessExecutor,
    RunBudget,
)


def python_command(source: str, *args: str) -> list[str]:
    return [sys.executable, "-c", source, *args]


class ProcessExecutorTests(unittest.TestCase):
    def assert_iso_timing(self, result: dict[str, object]) -> None:
        started_at = datetime.fromisoformat(str(result["started_at"]))
        finished_at = datetime.fromisoformat(str(result["finished_at"]))
        self.assertIsNotNone(started_at.tzinfo)
        self.assertIsNotNone(finished_at.tzinfo)
        self.assertLessEqual(started_at, finished_at)
        self.assertGreaterEqual(float(result["duration_seconds"]), 0.0)

    def test_constructor_rejects_non_finite_timing_values(self) -> None:
        budget = RunBudget()

        with self.assertRaisesRegex(ValueError, "must be finite"):
            ProcessExecutor(budget, "probe", poll_interval=float("nan"))
        with self.assertRaisesRegex(ValueError, "must be finite"):
            ProcessExecutor(budget, "probe", termination_grace=float("inf"))
        with self.assertRaisesRegex(ValueError, "must be >= 0"):
            ProcessExecutor(budget, "probe").run(
                python_command("raise SystemExit(0)"),
                probe_count=-1,
            )

    def test_helper_command_defaults_to_zero_probes_and_collects_tails(self) -> None:
        stdout = b"prefix-stdout-tail"
        stderr = b"prefix-stderr-tail"
        budget = RunBudget(
            total_timeout=5,
            stage_timeouts={"probe": 2},
            max_probes=0,
            max_output_bytes=1024,
        )
        executor = ProcessExecutor(
            budget,
            "probe",
            tail_bytes=8,
            poll_interval=0.01,
        )

        result = executor.run(
            python_command(
                "import os; "
                f"os.write(1, {stdout!r}); "
                f"os.write(2, {stderr!r})"
            )
        )

        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["raw_exit_code"], 0)
        self.assertFalse(result["timed_out"])
        self.assertIsNone(result["termination_reason"])
        self.assertIsNone(result["budget_error"])
        self.assertEqual(result["stdout"], stdout[-8:].decode())
        self.assertEqual(result["stderr"], stderr[-8:].decode())
        self.assertEqual(result["stdout_bytes"], len(stdout))
        self.assertEqual(result["stderr_bytes"], len(stderr))
        self.assertEqual(result["output_bytes"], len(stdout) + len(stderr))
        self.assertTrue(result["stdout_truncated"])
        self.assertTrue(result["stderr_truncated"])
        self.assertEqual(budget.probes_used, 0)
        self.assertEqual(budget.output_bytes_used, len(stdout) + len(stderr))
        self.assert_iso_timing(result)

    def test_explicit_probe_count_reserves_multiple_and_fails_closed(self) -> None:
        budget = RunBudget(max_probes=2)
        executor = ProcessExecutor(budget, "probe")

        first = executor.run(
            python_command("raise SystemExit(0)"),
            probe_count=2,
        )
        blocked = executor.run(
            python_command("raise SystemExit('must not execute')"),
            probe_count=1,
        )

        self.assertEqual(first["exit_code"], 0)
        self.assertEqual(budget.probes_used, 2)
        self.assertFalse(blocked["started"])
        self.assertEqual(blocked["exit_code"], 125)
        self.assertIsNone(blocked["raw_exit_code"])
        self.assertEqual(blocked["termination_reason"], "probe_limit")
        self.assertEqual(
            blocked["budget_error"]["reason"],
            BudgetReason.PROBE_LIMIT.value,
        )
        self.assertEqual(blocked["output_bytes"], 0)
        self.assert_iso_timing(blocked)

    def test_stage_timeout_escalates_from_term_to_kill(self) -> None:
        budget = RunBudget(
            total_timeout=3,
            stage_timeouts={"probe": 0.15},
        )
        executor = ProcessExecutor(
            budget,
            "probe",
            poll_interval=0.01,
            termination_grace=0.05,
        )

        result = executor.run(
            python_command(
                "import signal, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "time.sleep(5)"
            )
        )

        self.assertTrue(result["timed_out"])
        self.assertEqual(result["exit_code"], 124)
        self.assertNotEqual(result["raw_exit_code"], 0)
        self.assertEqual(result["termination_reason"], "stage_timeout")
        self.assertEqual(
            result["budget_error"]["reason"],
            BudgetReason.STAGE_TIMEOUT.value,
        )
        self.assertTrue(result["term_sent"])
        self.assertTrue(result["kill_sent"])
        self.assertIsNotNone(result["exit_code"])

    def test_total_deadline_terminates_process(self) -> None:
        budget = RunBudget(total_timeout=0.12)
        executor = ProcessExecutor(
            budget,
            "probe",
            poll_interval=0.01,
            termination_grace=0.02,
        )

        result = executor.run(python_command("import time; time.sleep(5)"))

        self.assertTrue(result["timed_out"])
        self.assertEqual(result["exit_code"], 124)
        self.assertNotEqual(result["raw_exit_code"], 0)
        self.assertEqual(result["termination_reason"], "deadline_exceeded")
        self.assertEqual(
            result["budget_error"]["reason"],
            BudgetReason.DEADLINE_EXCEEDED.value,
        )
        self.assertTrue(result["term_sent"])

    def test_explicit_cancel_terminates_process_group(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qa-process-cancel-") as raw:
            ready = Path(raw) / "ready"
            budget = RunBudget(total_timeout=3)
            executor = ProcessExecutor(
                budget,
                "probe",
                poll_interval=0.01,
                termination_grace=0.05,
            )

            def cancel_after_ready() -> None:
                deadline = time.monotonic() + 2
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                budget.cancel("test requested cancellation")

            cancel_thread = threading.Thread(target=cancel_after_ready)
            cancel_thread.start()
            try:
                result = executor.run(
                    python_command(
                        "import pathlib, signal, sys, time; "
                        "signal.signal("
                        "signal.SIGTERM, lambda *_: sys.exit(0)); "
                        "pathlib.Path(sys.argv[1]).write_text('ready'); "
                        "time.sleep(5)",
                        str(ready),
                    )
                )
            finally:
                cancel_thread.join(timeout=3)

        self.assertFalse(result["timed_out"])
        self.assertEqual(result["exit_code"], 130)
        self.assertEqual(result["raw_exit_code"], 0)
        self.assertEqual(result["termination_reason"], "cancelled")
        self.assertEqual(
            result["budget_error"]["reason"],
            BudgetReason.CANCELLED.value,
        )
        self.assertEqual(
            result["budget_error"]["detail"],
            "test requested cancellation",
        )
        self.assertTrue(result["term_sent"])

    def test_output_budget_counts_observed_bytes_before_termination(self) -> None:
        budget = RunBudget(
            total_timeout=3,
            max_output_bytes=16,
        )
        executor = ProcessExecutor(
            budget,
            "probe",
            poll_interval=0.01,
            termination_grace=0.02,
            read_size=64,
        )

        result = executor.run(
            python_command(
                "import os, signal, sys, time; "
                "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); "
                "os.write(1, b'x' * 64); "
                "time.sleep(5)"
            )
        )

        self.assertFalse(result["timed_out"])
        self.assertEqual(result["exit_code"], 125)
        self.assertEqual(result["raw_exit_code"], 0)
        self.assertEqual(result["termination_reason"], "output_byte_limit")
        self.assertEqual(
            result["budget_error"]["reason"],
            BudgetReason.OUTPUT_BYTE_LIMIT.value,
        )
        self.assertGreaterEqual(result["output_bytes"], 64)
        self.assertTrue(result["term_sent"])

    def test_spawn_error_has_command_not_found_exit_code(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qa-process-spawn-") as raw:
            missing = Path(raw) / "missing-command"
            result = ProcessExecutor(RunBudget(), "helper").run(
                [str(missing)]
            )

        self.assertFalse(result["started"])
        self.assertEqual(result["exit_code"], 127)
        self.assertIsNone(result["raw_exit_code"])
        self.assertEqual(result["termination_reason"], "spawn_error")
        self.assertIsNotNone(result["spawn_error"])
        self.assert_iso_timing(result)

    def test_executor_error_has_boundary_exit_code(self) -> None:
        executor = ProcessExecutor(
            RunBudget(total_timeout=3),
            "helper",
            poll_interval=0.01,
            termination_grace=0.02,
        )

        with mock.patch(
            "qa_core.runtime.process.os.set_blocking",
            side_effect=RuntimeError("injected selector setup failure"),
        ):
            result = executor.run(
                python_command("import time; time.sleep(5)")
            )

        self.assertEqual(result["exit_code"], 125)
        self.assertEqual(result["termination_reason"], "executor_error")
        self.assertEqual(result["executor_error"]["type"], "RuntimeError")

    @unittest.skipUnless(os.name == "posix", "需要 POSIX 进程组信号")
    def test_successful_parent_with_live_child_is_boundary_failure(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="qa-process-cleanup-",
        ) as raw:
            sentinel = Path(raw) / "descendant-survived"
            child_source = (
                "import pathlib, sys, time; "
                "time.sleep(0.8); "
                "pathlib.Path(sys.argv[1]).write_text('alive')"
            )
            parent_source = (
                "import subprocess, sys; "
                "subprocess.Popen([sys.executable, '-c', "
                f"{child_source!r}, sys.argv[1]])"
            )

            result = ProcessExecutor(
                RunBudget(total_timeout=3),
                "helper",
                poll_interval=0.01,
                termination_grace=0.03,
            ).run(python_command(parent_source, str(sentinel)))
            time.sleep(0.9)

            self.assertEqual(result["raw_exit_code"], 0)
            self.assertEqual(result["exit_code"], 125)
            self.assertEqual(
                result["termination_reason"],
                "process_group_cleanup",
            )
            self.assertTrue(result["process_group_cleanup"])
            self.assertFalse(sentinel.exists())

    @unittest.skipUnless(os.name == "posix", "需要 POSIX 进程组信号")
    def test_timeout_kills_descendant_process_in_the_same_group(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="qa-process-group-",
        ) as raw:
            sentinel = Path(raw) / "descendant-survived"
            child_source = (
                "import pathlib, sys, time; "
                "time.sleep(0.8); "
                "pathlib.Path(sys.argv[1]).write_text('alive')"
            )
            parent_source = (
                "import subprocess, sys, time; "
                "subprocess.Popen([sys.executable, '-c', "
                f"{child_source!r}, sys.argv[1]]); "
                "time.sleep(5)"
            )
            budget = RunBudget(
                total_timeout=3,
                stage_timeouts={"probe": 0.12},
            )
            executor = ProcessExecutor(
                budget,
                "probe",
                poll_interval=0.01,
                termination_grace=0.03,
            )

            result = executor.run(
                python_command(parent_source, str(sentinel))
            )
            time.sleep(0.9)

            self.assertEqual(
                result["termination_reason"],
                "stage_timeout",
            )
            self.assertEqual(result["exit_code"], 124)
            self.assertFalse(
                sentinel.exists(),
                "阶段超时后同组子进程仍在运行",
            )


if __name__ == "__main__":
    unittest.main()
