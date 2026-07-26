#!/usr/bin/env python3
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.runtime import (  # noqa: E402
    CYCLE_OWNER_PREFIX,
    AttemptStore,
    RunSession,
)
from qa_core.runtime.cycle_attempt import CycleAttemptError  # noqa: E402
from qa_core.runtime.lease import RunLease  # noqa: E402
from qa_core.runtime.session import LEASE_FILENAME  # noqa: E402


def load_cycle_module():
    spec = importlib.util.spec_from_file_location(
        "run_qa_cycle_runtime_controls",
        SCRIPT_DIR / "run_qa_cycle.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load run_qa_cycle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CycleRuntimeControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_cycle_module()

    def test_stage_timeout_writes_non_pass_handoff_and_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw)
            args = self.module.parse_cycle_options(
                [
                    "--run-dir",
                    str(run_dir),
                    "--stage-timeout-seconds",
                    "0.1",
                    "--termination-grace-seconds",
                    "0.01",
                ]
            )
            session = RunSession.open(
                run_dir,
                owner_prefix=CYCLE_OWNER_PREFIX,
            )
            try:
                runtime = self.module.CycleRuntime(args, session=session)
                result = runtime.execute_stage(
                    "slow_fixture",
                    [
                        sys.executable,
                        "-c",
                        "import time; time.sleep(5)",
                    ],
                    run_dir,
                    0,
                )
                runtime.complete_state(1)
            finally:
                session.close()

            self.assertEqual(result["termination_reason"], "stage_timeout")
            self.assertEqual(result["exit_code"], 124)
            error = json.loads(
                (run_dir / "qa-cycle-error.json").read_text(encoding="utf-8")
            )
            verdict = json.loads(
                (run_dir / "qa-verdict.json").read_text(encoding="utf-8")
            )
            state = json.loads(
                (run_dir / "run-state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(error["code"], "cycle_budget_exceeded")
            self.assertFalse(verdict["can_claim_pass"])
            self.assertEqual(state["status"], "inconclusive")
            self.assertTrue((run_dir / "run-manifest.json").is_file())
            self.assertFalse((run_dir / LEASE_FILENAME).exists())

    def test_probe_limit_rejects_before_process_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw)
            marker = run_dir / "spawned.txt"
            args = self.module.parse_cycle_options(
                [
                    "--run-dir",
                    str(run_dir),
                    "--max-probes",
                    "1",
                ]
            )
            session = RunSession.open(
                run_dir,
                owner_prefix=CYCLE_OWNER_PREFIX,
            )
            try:
                runtime = self.module.CycleRuntime(args, session=session)
                result = runtime.execute_stage(
                    "probe",
                    [
                        sys.executable,
                        "-c",
                        (
                            "from pathlib import Path; "
                            f"Path({str(marker)!r}).write_text('spawned')"
                        ),
                    ],
                    run_dir,
                    2,
                )
                runtime.complete_state(1)
            finally:
                session.close()

            self.assertEqual(result["termination_reason"], "probe_limit")
            self.assertFalse(result["started"])
            self.assertFalse(marker.exists())
            self.assertFalse(
                json.loads(
                    (run_dir / "qa-verdict.json").read_text(
                        encoding="utf-8"
                    )
                )["can_claim_pass"]
            )

    def test_conflicting_writer_is_rejected_without_terminal_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw)
            lease = RunLease(run_dir / LEASE_FILENAME)
            record = lease.acquire(
                "run-conflict",
                "unrelated-writer",
                pid=os.getpid(),
            )
            try:
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT_DIR / "run_qa_cycle.py"),
                        "--run-dir",
                        str(run_dir),
                    ],
                    text=True,
                    capture_output=True,
                )
            finally:
                lease.release(
                    record.run_id,
                    record.owner,
                    record.generation,
                )

            self.assertEqual(
                completed.returncode,
                self.module.CONTROL_BOUNDARY_EXIT_CODE,
            )
            error = json.loads(completed.stderr.strip())
            self.assertEqual(error["phase"], "session_acquire")
            self.assertFalse((run_dir / "qa-run-summary.json").exists())
            self.assertFalse((run_dir / "qa-verdict.json").exists())

    def test_missing_inputs_finish_as_non_pass_and_release_lease(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "run_qa_cycle.py"),
                    "--run-dir",
                    str(run_dir),
                    "--allow-unconfirmed-environment",
                    "--skip-report",
                ],
                text=True,
                capture_output=True,
            )

            self.assertNotEqual(completed.returncode, 0)
            summary = json.loads(
                (run_dir / "qa-run-summary.json").read_text(
                    encoding="utf-8"
                )
            )
            state = json.loads(
                (run_dir / "run-state.json").read_text(encoding="utf-8")
            )
            self.assertNotEqual(summary["status"], "passed")
            self.assertNotEqual(state["status"], "passed")
            self.assertFalse(summary["verdict"]["can_claim_pass"])
            self.assertEqual(
                summary["attempt_commit"]["status"],
                "committed",
            )
            self.assertTrue((run_dir / "run-manifest.json").is_file())
            self.assertFalse((run_dir / LEASE_FILENAME).exists())

    def test_attempt_publish_failure_overwrites_candidate_pass(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw)
            args = self.module.parse_cycle_options(
                ["--run-dir", str(run_dir)]
            )
            session = RunSession.open(
                run_dir,
                owner_prefix=CYCLE_OWNER_PREFIX,
            )
            try:
                runtime = self.module.CycleRuntime(args, session=session)
                runtime.verdict_path.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "verdict": "passed",
                            "can_claim_pass": True,
                        }
                    ),
                    encoding="utf-8",
                )
                runtime.current_artifacts.add(
                    runtime.verdict_path.resolve()
                )
                injected = CycleAttemptError(
                    "injected_publish_failure",
                    "publish_manifest",
                    "injected failure",
                )
                with mock.patch.object(
                    self.module,
                    "commit_cycle_attempt",
                    side_effect=injected,
                ):
                    exit_code = runtime.complete_state(0)
            finally:
                session.close()

            verdict = json.loads(
                (run_dir / "qa-verdict.json").read_text(encoding="utf-8")
            )
            state = json.loads(
                (run_dir / "run-state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(exit_code, 1)
            self.assertFalse(verdict["can_claim_pass"])
            self.assertNotEqual(state["status"], "passed")
            self.assertEqual(
                runtime.summary["attempt_commit"]["status"],
                "error",
            )

    def test_preexisting_pass_and_results_cannot_enter_new_proof_bundle(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw)
            (run_dir / "qa-verdict.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "verdict": "passed",
                        "can_claim_pass": True,
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "results.json").write_text(
                '{"status":"passed","stale":true}',
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "run_qa_cycle.py"),
                    "--run-dir",
                    str(run_dir),
                    "--allow-unconfirmed-environment",
                    "--skip-report",
                ],
                text=True,
                capture_output=True,
            )

            self.assertNotEqual(completed.returncode, 0)
            verdict = json.loads(
                (run_dir / "qa-verdict.json").read_text(encoding="utf-8")
            )
            self.assertFalse(verdict["can_claim_pass"])
            manifest = AttemptStore(run_dir).read_run_manifest()
            assert manifest is not None
            attempt = AttemptStore(run_dir).load_attempt(
                manifest["attempts"][0]["attempt_id"]
            )
            artifact_names = {
                artifact.name for artifact in attempt.artifacts
            }
            self.assertNotIn("results.json", artifact_names)
            self.assertIn("qa-verdict.json", artifact_names)


if __name__ == "__main__":
    unittest.main()
