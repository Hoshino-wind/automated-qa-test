#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_common import file_sha256  # noqa: E402
from qa_core.observability import aggregate_run_directories  # noqa: E402
from qa_core.proof import verify_run_proof  # noqa: E402
from qa_core.runtime import CYCLE_OWNER_PREFIX, RunSession  # noqa: E402
from qa_eval import hash_evaluator_bundle  # noqa: E402


def load_cycle_module():
    spec = importlib.util.spec_from_file_location(
        "run_qa_cycle_terminal_observation",
        SCRIPT_DIR / "run_qa_cycle.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load run_qa_cycle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TerminalObservationProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_cycle_module()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _candidate_arguments(self, run_dir: Path) -> list[str]:
        source_root = run_dir / "candidate-sources"
        source_root.mkdir(parents=True)
        bundle_root = SCRIPT_DIR
        policy_path = source_root / "policy.json"
        memory_path = source_root / "memory.json"
        policy_path.write_text(
            '{"schema_version":1,"policy":"deterministic"}',
            encoding="utf-8",
        )
        memory_path.write_text(
            '{"schema_version":1,"entries":[]}',
            encoding="utf-8",
        )
        registration = {
            "schema_version": 1,
            "agent_bundle_sha256": hash_evaluator_bundle(bundle_root),
            "policy_sha256": file_sha256(policy_path),
            "tool_registry_sha256": (
                self.module.build_default_tool_registry().canonical_sha256
            ),
            "model_id": "fixture-model-v1",
            "memory_snapshot_sha256": file_sha256(memory_path),
        }
        registration_path = source_root / "identity.json"
        registration_path.write_text(
            json.dumps(registration),
            encoding="utf-8",
        )
        return [
            "--candidate-identity-registration",
            str(registration_path),
            "--agent-bundle-dir",
            str(bundle_root),
            "--candidate-policy",
            str(policy_path),
            "--candidate-memory-snapshot",
            str(memory_path),
            "--candidate-model-id",
            "fixture-model-v1",
        ]

    def _create_observation(
        self,
        name: str,
        *,
        timeout: bool,
        with_invalid_human: bool = False,
    ) -> Path:
        run_dir = self.root / name
        run_dir.mkdir()
        argv = [
            "--run-dir",
            str(run_dir),
            "--total-timeout-seconds",
            "5",
            "--stage-timeout-seconds",
            "0.05",
            "--termination-grace-seconds",
            "0.01",
            *self._candidate_arguments(run_dir),
        ]
        args = self.module.parse_cycle_options(argv)
        session = RunSession.open(
            run_dir,
            owner_prefix=CYCLE_OWNER_PREFIX,
        )
        try:
            runtime = self.module.CycleRuntime(args, session=session)
            result = runtime.execute_stage(
                "terminal_fixture",
                (
                    [
                        sys.executable,
                        "-c",
                        "import time; time.sleep(2)",
                    ]
                    if timeout
                    else [
                        sys.executable,
                        "-c",
                        "raise SystemExit(7)",
                    ]
                ),
                run_dir,
                0,
            )
            if timeout:
                self.assertEqual(
                    result["termination_reason"],
                    "stage_timeout",
                )
            else:
                self.assertEqual(result["exit_code"], 7)
                runtime.record_integrity_failure(
                    code="fixture_execution_failed",
                    phase="terminal_fixture",
                    message="intentional nonzero fixture",
                )
            if with_invalid_human:
                runtime.human_authorization_path.write_text(
                    '{"schema_version":1,"status":"forged"}',
                    encoding="utf-8",
                )
                human_hash = file_sha256(
                    runtime.human_authorization_path
                )
                runtime.human_authorization_file_sha256 = human_hash
                runtime.current_artifacts.add(
                    runtime.human_authorization_path.resolve()
                )
                runtime.state.record_component_versions(
                    {
                        "human_authorization_file_sha256": human_hash,
                        "human_authorization_sha256": "f" * 64,
                    }
                )
            self.assertNotEqual(runtime.complete_state(1), 0)
        finally:
            session.close()
        return run_dir

    def test_real_failure_and_timeout_are_valid_non_pass_proofs(self) -> None:
        failed = verify_run_proof(
            self._create_observation("failed", timeout=False)
        )
        timed_out = verify_run_proof(
            self._create_observation("timeout", timeout=True)
        )

        self.assertTrue(failed.proof_valid, failed.errors)
        self.assertFalse(failed.can_claim_pass)
        self.assertEqual(failed.outcome_category, "failure")
        self.assertTrue(timed_out.proof_valid, timed_out.errors)
        self.assertFalse(timed_out.can_claim_pass)
        self.assertEqual(
            timed_out.outcome_category,
            "cancellation_or_timeout",
        )
        for proof in (failed, timed_out):
            with self.subTest(outcome=proof.outcome_category):
                self.assertEqual(proof.errors, ())
                self.assertIn("attempt", proof.verified_refs)
                self.assertIn("budget", proof.verified_refs)
                self.assertIn("candidate_identity", proof.verified_refs)
                self.assertIn("terminal_observation", proof.verified_refs)
                self.assertEqual(
                    proof.to_dict()["proof_kind"],
                    "terminal_observation",
                )

    def test_tampering_trace_or_candidate_identity_fails_closed(self) -> None:
        trace_run = self._create_observation("trace-tamper", timeout=True)
        trace_path = trace_run / "agent-trace.jsonl"
        trace_path.write_bytes(trace_path.read_bytes() + b"\n")

        trace_proof = verify_run_proof(trace_run)

        self.assertFalse(trace_proof.proof_valid)
        self.assertFalse(trace_proof.can_claim_pass)
        self.assertIn(
            "trace_journal_invalid",
            {error["code"] for error in trace_proof.errors},
        )

        identity_run = self._create_observation(
            "identity-tamper",
            timeout=False,
        )
        identity_path = identity_run / "candidate-identity.json"
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        identity["candidate_identity"]["model_id"] = "forged-model"
        identity_path.write_text(json.dumps(identity), encoding="utf-8")

        identity_proof = verify_run_proof(identity_run)

        self.assertFalse(identity_proof.proof_valid)
        self.assertFalse(identity_proof.can_claim_pass)
        self.assertTrue(
            {
                "input_hash_mismatch",
                "candidate_identity_file_hash_mismatch",
            }
            & {error["code"] for error in identity_proof.errors}
        )

    def test_non_pass_proof_rejects_forged_human_artifact(
        self,
    ) -> None:
        run_dir = self._create_observation(
            "human-tamper",
            timeout=False,
            with_invalid_human=True,
        )

        proof = verify_run_proof(run_dir)

        self.assertFalse(proof.proof_valid)
        self.assertFalse(proof.can_claim_pass)
        self.assertIn(
            "human_authorization_invalid",
            {error["code"] for error in proof.errors},
        )

    def test_slo_accepts_independently_verified_non_pass_outcomes(self) -> None:
        failure_run = self._create_observation("slo-failure", timeout=False)
        timeout_run = self._create_observation("slo-timeout", timeout=True)
        identity = verify_run_proof(
            failure_run
        ).verified_refs["candidate_identity"]
        observed_at = datetime.now(UTC)
        contract = {
            "schema_version": 1,
            "mode": "development",
            "registered_at": (
                observed_at - timedelta(hours=2)
            ).isoformat().replace("+00:00", "Z"),
            "window_started_at": (
                observed_at - timedelta(hours=1)
            ).isoformat().replace("+00:00", "Z"),
            "window_ended_at": (
                observed_at + timedelta(seconds=1)
            ).isoformat().replace("+00:00", "Z"),
            "maximum_run_age_seconds": 3600,
            "minimum_run_count": 2,
            "required_categories": [
                "cancellation_or_timeout",
                "failure",
            ],
        }

        report = aggregate_run_directories(
            [failure_run, timeout_run],
            expected_candidate_identity=identity,
            sampling_contract=contract,
            now=observed_at + timedelta(seconds=2),
        )

        self.assertEqual(report["provenance"], "verified_run_proof")
        self.assertTrue(
            all(item["valid"] for item in report["proof_results"])
        )
        self.assertEqual(
            {
                item["outcome_category"]
                for item in report["proof_results"]
            },
            {"failure", "cancellation_or_timeout"},
        )
        sampling_codes = {
            failure["code"]
            for failure in report["gate_failures"]
            if failure["gate"] == "sampling"
        }
        self.assertEqual(
            sampling_codes,
            {"development_sampling_not_production"},
        )
        self.assertEqual(
            report["sampling"]["proof_outcome_counts"],
            {
                "cancellation_or_timeout": 1,
                "failure": 1,
                "success": 0,
            },
        )
        self.assertEqual(
            report["metrics"]["convergence"]["convergence_rate"],
            1.0,
        )
        self.assertEqual(
            report["metrics"]["cancellation_stop_dispatch"][
                "sample_count"
            ],
            1,
        )
        self.assertEqual(
            report["metrics"]["cancellation_stop_dispatch"][
                "stop_success_rate"
            ],
            1.0,
        )
        self.assertTrue(report["not_production_qualified"])


if __name__ == "__main__":
    unittest.main()
