#!/usr/bin/env python3
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_common import file_sha256  # noqa: E402
from qa_core.runtime import (  # noqa: E402
    CYCLE_OWNER_PREFIX,
    RunSession,
    RunStateCoordinator,
)
from qa_core.runtime.lease import RunLeaseError  # noqa: E402


class RunStateCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temporary.name)
        self.session = RunSession.open(
            self.run_dir,
            owner_prefix=CYCLE_OWNER_PREFIX,
        )

    def tearDown(self) -> None:
        self.session.close()
        self.temporary.cleanup()

    def open_coordinator(self) -> RunStateCoordinator:
        return RunStateCoordinator.open(
            self.session,
            goal="证明登录流程符合需求",
            scope=["web", "api"],
            component_versions={"cycle": "2"},
            initial_budget={"remaining_time": 30.0},
        )

    def write_verdict(
        self,
        *,
        verdict: str = "passed",
        can_claim_pass: bool = True,
    ) -> Path:
        path = self.run_dir / "qa-verdict.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "verdict": verdict,
                    "can_claim_pass": can_claim_pass,
                }
            ),
            encoding="utf-8",
        )
        return path

    @staticmethod
    def attempt_ref() -> dict[str, object]:
        return {
            "attempt_id": "attempt-1",
            "attempt_manifest_sha256": "a" * 64,
            "run_manifest_sequence": 1,
            "run_manifest_sha256": "b" * 64,
        }

    def test_current_deterministic_verdict_can_publish_hash_bound_pass(self) -> None:
        coordinator = self.open_coordinator()
        coordinator.before_stage("generate_verdict")
        path = self.write_verdict()

        state = coordinator.finish(
            exit_code=0,
            verdict_path=path,
            verdict_is_current=True,
            final_budget={"remaining_time": 10.0},
            attempt_ref=self.attempt_ref(),
            verdict_committed=True,
        )

        self.assertEqual(state.status, "passed")
        self.assertEqual(
            state.evidence[next(iter(state.evidence))]["sha256"],
            file_sha256(path),
        )
        self.assertEqual(coordinator.projection()["status"], "passed")

    def test_stale_or_failed_cycle_never_publishes_pass(self) -> None:
        for current, exit_code in ((False, 0), (True, 1)):
            with self.subTest(current=current, exit_code=exit_code):
                run_dir = self.run_dir / f"{current}-{exit_code}"
                session = RunSession.open(
                    run_dir,
                    owner_prefix=CYCLE_OWNER_PREFIX,
                )
                try:
                    coordinator = RunStateCoordinator.open(
                        session,
                        goal="拒绝陈旧裁决",
                        scope=["web"],
                        component_versions={"cycle": "2"},
                        initial_budget={},
                    )
                    path = run_dir / "qa-verdict.json"
                    path.write_text(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "verdict": "passed",
                                "can_claim_pass": True,
                            }
                        ),
                        encoding="utf-8",
                    )
                    state = coordinator.finish(
                        exit_code=exit_code,
                        verdict_path=path,
                        verdict_is_current=current,
                        final_budget={},
                        attempt_ref=self.attempt_ref(),
                        verdict_committed=True,
                    )
                    self.assertEqual(state.status, "inconclusive")
                finally:
                    session.close()

    def test_non_pass_verdict_is_preserved_without_pass_authority(self) -> None:
        coordinator = self.open_coordinator()
        path = self.write_verdict(
            verdict="failed",
            can_claim_pass=False,
        )

        state = coordinator.finish(
            exit_code=1,
            verdict_path=path,
            verdict_is_current=True,
            final_budget={},
            attempt_ref=self.attempt_ref(),
            verdict_committed=True,
        )

        self.assertEqual(state.status, "failed")
        last = coordinator.store.load_events()[-1]
        self.assertEqual(last.payload["authority"], "qa-cycle-orchestrator")

    def test_pass_without_committed_attempt_is_downgraded(self) -> None:
        coordinator = self.open_coordinator()
        path = self.write_verdict()

        state = coordinator.finish(
            exit_code=0,
            verdict_path=path,
            verdict_is_current=True,
            final_budget={},
            attempt_ref=None,
            verdict_committed=True,
        )

        self.assertEqual(state.status, "inconclusive")

    def test_pass_with_uncommitted_verdict_is_downgraded(self) -> None:
        coordinator = self.open_coordinator()
        path = self.write_verdict()

        state = coordinator.finish(
            exit_code=0,
            verdict_path=path,
            verdict_is_current=True,
            final_budget={},
            attempt_ref=self.attempt_ref(),
            verdict_committed=False,
        )

        self.assertEqual(state.status, "inconclusive")

    def test_reopening_run_immediately_revokes_old_pass(self) -> None:
        first = self.open_coordinator()
        path = self.write_verdict()
        first.finish(
            exit_code=0,
            verdict_path=path,
            verdict_is_current=True,
            final_budget={},
            attempt_ref=self.attempt_ref(),
            verdict_committed=True,
        )
        self.session.close()

        self.session = RunSession.open(
            self.run_dir,
            owner_prefix=CYCLE_OWNER_PREFIX,
        )
        resumed = self.open_coordinator()

        self.assertEqual(resumed.state.status, "running")
        self.assertEqual(resumed.state.run_id, first.state.run_id)

    def test_lost_lease_blocks_state_append_before_mutation(self) -> None:
        coordinator = self.open_coordinator()
        sequence = coordinator.state.sequence
        current = self.session.lease.read()
        assert current is not None
        replacement = self.session.lease.takeover(
            current.run_id,
            "replacement-writer",
            expected_owner=current.owner,
            expected_generation=current.generation,
            stale_after_seconds=1e-12,
        )

        with self.assertRaises(RunLeaseError):
            coordinator.before_stage("must-not-append")

        self.assertEqual(
            coordinator.store.load_state().sequence,
            sequence,
        )
        self.session.record = replacement


if __name__ == "__main__":
    unittest.main()
