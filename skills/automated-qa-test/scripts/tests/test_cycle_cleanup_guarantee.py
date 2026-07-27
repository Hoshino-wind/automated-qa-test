#!/usr/bin/env python3
"""Regression tests for the outer managed-service cleanup boundary."""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.state import EventLogError  # noqa: E402


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class _FakeRuntime:
    def __init__(self) -> None:
        self.summary: dict[str, object] = {}
        self.summary_path = Path("/tmp/unused-summary.json")
        self.cleanup_phase_fails = False

    def enter_phase(self, phase: str) -> None:
        if self.cleanup_phase_fails and phase == "run_cleanup_stage":
            raise EventLogError("fixture_state_failure", "fixture")

    def cleanup_required(self) -> bool:
        return True

    def emergency_state_failure(
        self,
        error: EventLogError,
        *,
        phase: str,
    ) -> int:
        del error, phase
        return 1


class CycleCleanupGuaranteeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cycle = load_module(
            "run_qa_cycle_cleanup_guarantee_test",
            SCRIPT_DIR / "run_qa_cycle.py",
        )
        cls.service = load_module(
            "service_runtime_cleanup_guarantee_test",
            SCRIPT_DIR / "service_runtime.py",
        )

    def test_unexpected_stage_exception_still_enters_emergency_cleanup(
        self,
    ) -> None:
        runtime = _FakeRuntime()

        def exploding_stage(_runtime: object) -> int:
            raise RuntimeError("fixture crash")

        exploding_stage.__name__ = "prepare_cycle"
        with (
            mock.patch.object(
                self.cycle,
                "CycleRuntime",
                return_value=runtime,
            ),
            mock.patch.object(
                self.cycle,
                "prepare_cycle",
                new=exploding_stage,
            ),
            mock.patch.object(
                self.cycle,
                "emergency_stop_managed_services",
                return_value=True,
            ) as cleanup,
        ):
            with self.assertRaisesRegex(RuntimeError, "fixture crash"):
                self.cycle.run_with_session(
                    SimpleNamespace(),
                    SimpleNamespace(),
                )

        cleanup.assert_called_once_with(
            runtime,
            reason="finally_after_prepare_cycle",
        )

    def test_cleanup_state_append_failure_cannot_skip_emergency_stop(
        self,
    ) -> None:
        runtime = _FakeRuntime()
        runtime.cleanup_phase_fails = True

        def stopped_stage(_runtime: object) -> int:
            return 1

        stopped_stage.__name__ = "prepare_cycle"
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    self.cycle,
                    "CycleRuntime",
                    return_value=runtime,
                )
            )
            cleanup = stack.enter_context(
                mock.patch.object(
                    self.cycle,
                    "emergency_stop_managed_services",
                    return_value=True,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.cycle,
                    "prepare_cycle",
                    new=stopped_stage,
                )
            )
            result = self.cycle.run_with_session(
                SimpleNamespace(),
                SimpleNamespace(),
            )

        self.assertEqual(result, 1)
        cleanup.assert_called_once_with(
            runtime,
            reason="finally_after_run_cleanup_stage",
        )

    def test_emergency_cleanup_terminates_a_real_detached_service(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="qa-cycle-emergency-cleanup-",
        ) as raw:
            run_dir = Path(raw)
            launch = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import subprocess,sys;"
                        "p=subprocess.Popen("
                        "[sys.executable,'-c','import time;time.sleep(120)'],"
                        "start_new_session=True,"
                        "stdin=subprocess.DEVNULL,"
                        "stdout=subprocess.DEVNULL,"
                        "stderr=subprocess.DEVNULL);"
                        "print(p.pid)"
                    ),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            pid = int(launch.stdout.strip())
            process_group = os.getpgid(pid)
            try:
                identity: dict[str, object] = {}
                for _ in range(30):
                    identity = self.service.process_identity(pid)
                    if all(
                        identity.get(field) is not None
                        for field in (
                            "pgid",
                            "command_sha256",
                            "os_started_at",
                        )
                    ):
                        break
                    time.sleep(0.02)
                runtime_path = run_dir / "service-runtime.json"
                runtime_path.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "services": [
                                {
                                    "service": "fixture",
                                    "pid": pid,
                                    "pgid": process_group,
                                    "command": [
                                        sys.executable,
                                        "-c",
                                        "import time;time.sleep(120)",
                                    ],
                                    "process_identity": identity,
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                runtime = SimpleNamespace(
                    args=SimpleNamespace(
                        termination_grace_seconds=0.1,
                    ),
                    script_dir=SCRIPT_DIR,
                    run_dir=run_dir,
                    service_runtime_path=runtime_path,
                    service_runtime_stop_path=(
                        run_dir / "service-runtime-stop.json"
                    ),
                    service_start_attempted=True,
                    current_artifacts=set(),
                    summary={},
                    cleanup_required=lambda: True,
                )

                cleanup_succeeded = (
                    self.cycle.emergency_stop_managed_services(
                        runtime,
                        reason="fixture_exception",
                    )
                )
                self.assertTrue(
                    cleanup_succeeded,
                    runtime.summary,
                )
                for _ in range(50):
                    if not self.service.pid_alive(pid):
                        break
                    time.sleep(0.02)
                self.assertFalse(self.service.pid_alive(pid))
                self.assertTrue(
                    runtime.summary["emergency_service_cleanup"][
                        "succeeded"
                    ]
                )
            finally:
                if self.service.pid_alive(pid):
                    try:
                        os.killpg(process_group, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == "__main__":
    unittest.main()
