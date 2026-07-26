#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.runtime.attempts import AttemptIntegrityError, AttemptStore
from qa_core.runtime.cycle_attempt import (
    CycleAttemptError,
    commit_cycle_attempt,
)
from qa_core.runtime.lease import RunLease
from qa_core.runtime.session import LEASE_FILENAME


class CycleAttemptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.run_dir = (Path(self.temporary.name) / "run").resolve()
        self.run_dir.mkdir()
        self.plan_hash = "a" * 64
        self.lease = RunLease(self.run_dir / LEASE_FILENAME)
        self.lease_record = self.lease.acquire(
            "run-1",
            "cycle-attempt-test",
        )
        self.addCleanup(self.release_current_lease)

    def release_current_lease(self) -> None:
        current = self.lease.read()
        if current is not None:
            self.lease.release(
                current.run_id,
                current.owner,
                current.generation,
            )

    def write_output(self, filename: str, payload: bytes) -> Path:
        path = self.run_dir / filename
        path.write_bytes(payload)
        return path

    def commit(
        self,
        *,
        generation: int = 1,
        iteration: int = 1,
        expected_sequence: int = 0,
        output_names=("results",),
        current_artifacts=None,
    ):
        selected_names = tuple(output_names)
        if current_artifacts is None:
            filenames = {
                "results": "results.json",
                "ledger": "evidence-ledger.json",
            }
            current_artifacts = [
                self.run_dir / filenames[name]
                for name in selected_names
                if name in filenames
            ]
        return commit_cycle_attempt(
            run_dir=self.run_dir,
            run_id="run-1",
            lease_owner=self.lease_record.owner,
            generation=generation,
            iteration=iteration,
            stage="cycle_complete",
            tool="run_qa_cycle",
            input_hashes={"plan": self.plan_hash},
            expected_sequence=expected_sequence,
            output_names=selected_names,
            current_artifacts=current_artifacts,
        )

    def test_commits_selected_cycle_outputs_with_authority_and_verified_hashes(self) -> None:
        results = self.write_output("results.json", b'{"status":"passed"}\n')
        ledger = self.write_output("evidence-ledger.json", b'{"evidence":[]}\n')

        committed = self.commit(output_names=("results", "ledger"))

        self.assertEqual(committed.run_manifest_sequence, 1)
        self.assertEqual(committed.attempt.run_id, "run-1")
        self.assertEqual(committed.attempt.generation, 1)
        self.assertEqual(committed.attempt.iteration, 1)
        self.assertEqual(committed.attempt.stage, "cycle_complete")
        self.assertEqual(committed.attempt.tool, "run_qa_cycle")
        self.assertEqual(committed.attempt.input_hashes, {"plan": self.plan_hash})
        refs = {artifact.name: artifact for artifact in committed.attempt.artifacts}
        self.assertEqual(refs["results.json"].sha256, hashlib.sha256(results.read_bytes()).hexdigest())
        self.assertEqual(refs["evidence-ledger.json"].size, ledger.stat().st_size)
        self.assertEqual(committed.to_dict()["status"], "committed")
        json.dumps(committed.to_dict())

        store = AttemptStore(self.run_dir)
        self.assertEqual(store.load_attempt(committed.attempt.attempt_id), committed.attempt)
        run_manifest = store.read_run_manifest()
        self.assertEqual(run_manifest["sequence"], 1)
        self.assertEqual(
            run_manifest["attempts"],
            [
                {
                    "attempt_id": committed.attempt.attempt_id,
                    "manifest_sha256": committed.attempt.manifest_sha256,
                }
            ],
        )

    def test_same_generation_publish_retains_prior_attempt_references(self) -> None:
        self.write_output("results.json", b"first")
        first = self.commit(output_names=("results",))
        self.write_output("evidence-ledger.json", b"second")

        second = self.commit(
            iteration=2,
            expected_sequence=1,
            output_names=("ledger",),
        )

        run_manifest = AttemptStore(self.run_dir).read_run_manifest()
        self.assertEqual(run_manifest["sequence"], 2)
        self.assertEqual(
            {item["attempt_id"] for item in run_manifest["attempts"]},
            {first.attempt.attempt_id, second.attempt.attempt_id},
        )

    def test_symlink_and_non_output_names_fail_with_structured_error(self) -> None:
        target = self.run_dir / "outside-results.json"
        target.write_text("outside", encoding="utf-8")
        (self.run_dir / "results.json").symlink_to(target)

        with self.assertRaises(CycleAttemptError) as symlink_error:
            self.commit()

        payload = symlink_error.exception.to_dict()
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["code"], "cycle_output_invalid")
        self.assertEqual(payload["phase"], "select_outputs")
        self.assertFalse((self.run_dir / "run-manifest.json").exists())

        with self.assertRaises(CycleAttemptError) as unknown_error:
            self.commit(output_names=("plan",))
        self.assertEqual(unknown_error.exception.code, "cycle_output_invalid")

    def test_stale_existing_output_is_not_committed_without_current_marker(self) -> None:
        self.write_output("results.json", b"stale")

        with self.assertRaises(CycleAttemptError) as caught:
            self.commit(current_artifacts=[])

        self.assertEqual(caught.exception.phase, "select_outputs")
        self.assertIn("current artifact", str(caught.exception))
        self.assertFalse((self.run_dir / "attempts").exists())

    def test_duplicate_sequence_does_not_overwrite_published_manifest(self) -> None:
        self.write_output("results.json", b"first")
        first = self.commit()

        with self.assertRaises(CycleAttemptError) as caught:
            self.commit(expected_sequence=0)

        self.assertEqual(caught.exception.phase, "manifest_preflight")
        self.assertEqual(caught.exception.details["store_code"], "sequence_conflict")
        current = AttemptStore(self.run_dir).read_run_manifest()
        self.assertEqual(current["sequence"], 1)
        self.assertEqual(current["manifest_sha256"], first.run_manifest_sha256)

    def test_concurrent_duplicate_publish_has_one_cas_winner(self) -> None:
        self.write_output("results.json", b"shared")
        barrier = threading.Barrier(2)
        original_read = AttemptStore.read_run_manifest

        def synchronized_read(store):
            current = original_read(store)
            barrier.wait()
            return current

        def publish():
            try:
                return ("won", self.commit())
            except CycleAttemptError as error:
                return ("lost", error)

        with patch.object(AttemptStore, "read_run_manifest", synchronized_read):
            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(lambda _: publish(), range(2)))

        winners = [result for status, result in outcomes if status == "won"]
        losers = [error for status, error in outcomes if status == "lost"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(losers), 1)
        self.assertEqual(losers[0].phase, "publish_manifest")
        self.assertEqual(losers[0].details["store_code"], "sequence_conflict")
        self.assertEqual(AttemptStore(self.run_dir).read_run_manifest()["sequence"], 1)

    def test_stale_generation_is_rejected_without_replacing_new_generation(self) -> None:
        self.write_output("results.json", b"generation-one")
        self.commit()
        current_lease = self.lease.read()
        assert current_lease is not None
        self.lease_record = self.lease.takeover(
            "run-1",
            "cycle-attempt-test-generation-2",
            expected_owner=current_lease.owner,
            expected_generation=current_lease.generation,
            stale_after_seconds=1e-12,
        )
        self.write_output("results.json", b"generation-two")
        current = self.commit(
            generation=2,
            iteration=2,
            expected_sequence=1,
        )

        with self.assertRaises(CycleAttemptError) as caught:
            self.commit(
                generation=1,
                iteration=3,
                expected_sequence=2,
            )

        self.assertEqual(caught.exception.code, "cycle_lease_invalid")
        run_manifest = AttemptStore(self.run_dir).read_run_manifest()
        self.assertEqual(run_manifest["generation"], 2)
        self.assertEqual(run_manifest["manifest_sha256"], current.run_manifest_sha256)

    def test_committed_artifact_hash_detects_post_publish_tampering(self) -> None:
        self.write_output("results.json", b"trusted")
        committed = self.commit()
        artifact = committed.attempt.artifacts[0]
        committed_path = self.run_dir / artifact.path
        os.chmod(committed_path, 0o600)
        committed_path.write_bytes(b"tampered")

        with self.assertRaises(AttemptIntegrityError):
            AttemptStore(self.run_dir).load_attempt(committed.attempt.attempt_id)
        with self.assertRaises(AttemptIntegrityError):
            AttemptStore(self.run_dir).read_run_manifest()

    def test_copy_failure_exposes_attempt_identity_and_original_cause(self) -> None:
        self.write_output("results.json", b"ready")
        original_open = os.open

        def fail_scratch_open(path, flags, mode=0o777, *, dir_fd=None):
            if isinstance(path, Path) and path.name == "results.json" and dir_fd is None:
                raise OSError("injected scratch write failure")
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with patch("qa_core.runtime.cycle_attempt.os.open", side_effect=fail_scratch_open):
            with self.assertRaises(CycleAttemptError) as caught:
                self.commit()

        self.assertEqual(caught.exception.phase, "copy_outputs")
        self.assertIn("attempt_id", caught.exception.details)
        self.assertIsInstance(caught.exception.__cause__, OSError)
        json.dumps(caught.exception.to_dict())

    def test_missing_active_lease_fails_before_attempt_creation(self) -> None:
        self.write_output("results.json", b"ready")
        self.release_current_lease()

        with self.assertRaises(CycleAttemptError) as caught:
            self.commit()

        self.assertEqual(caught.exception.code, "cycle_lease_invalid")
        self.assertEqual(caught.exception.phase, "lease_preflight")
        self.assertFalse((self.run_dir / "attempts").exists())


if __name__ == "__main__":
    unittest.main()
