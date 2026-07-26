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
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.runtime.attempts import (
    AttemptAlreadyCommittedError,
    AttemptIntegrityError,
    AttemptSourceError,
    AttemptStore,
    ManifestConflictError,
    StaleGenerationError,
)


class AttemptStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.run_dir = (Path(self.temporary.name) / "run").resolve()
        self.store = AttemptStore(self.run_dir)

    def begin_attempt(self, **overrides):
        context = {
            "run_id": "run-1",
            "generation": 1,
            "iteration": 1,
            "stage": "probe",
            "tool": "command",
            "input_hashes": {
                "context": "a" * 64,
                "plan": "b" * 64,
            },
        }
        context.update(overrides)
        return self.store.begin(**context)

    def begin_with_file(self, name: str = "result.json", payload: bytes = b'{"ok":true}\n', **overrides):
        handle = self.begin_attempt(**overrides)
        source = handle.scratch_dir / name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(payload)
        return handle, source

    def test_begin_creates_distinct_unpredictable_attempt_workspace(self) -> None:
        first = self.begin_attempt()
        second = self.begin_attempt()

        self.assertRegex(first.attempt_id, r"^att_[0-9a-f]{32}$")
        self.assertNotEqual(first.attempt_id, second.attempt_id)
        self.assertEqual(first.attempt_dir.parent, self.run_dir / "attempts")
        self.assertTrue(first.scratch_dir.is_dir())
        metadata = json.loads((first.attempt_dir / "attempt.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["attempt_id"], first.attempt_id)
        self.assertEqual(metadata["created_at"], first.created_at)
        self.assertEqual(metadata["run_id"], "run-1")
        self.assertEqual(metadata["generation"], 1)
        self.assertEqual(metadata["iteration"], 1)
        self.assertEqual(metadata["stage"], "probe")
        self.assertEqual(metadata["tool"], "command")
        self.assertEqual(metadata["input_hashes"], {"context": "a" * 64, "plan": "b" * 64})

    def test_begin_rejects_missing_malformed_and_unknown_parent_contract(self) -> None:
        with self.assertRaises(ValueError):
            self.begin_attempt(input_hashes={})
        with self.assertRaises(AttemptIntegrityError):
            self.begin_attempt(input_hashes={"plan": "not-a-sha256"})
        with self.assertRaises(TypeError):
            self.store.begin(
                run_id="run-1",
                generation=1,
                iteration=1,
                stage="probe",
                tool="command",
                input_hashes={"plan": "a" * 64},
                unknown_parent="forbidden",
            )
        self.assertFalse(self.run_dir.exists())

    def test_handle_cannot_impersonate_other_run_generation_or_parent_hash(self) -> None:
        handle, source = self.begin_with_file()
        forged_handles = (
            replace(handle, run_id="run-2"),
            replace(handle, generation=2),
            replace(handle, input_hashes={"plan": "c" * 64}),
        )

        for forged in forged_handles:
            with self.subTest(forged=forged):
                with self.assertRaises(AttemptIntegrityError):
                    self.store.commit(forged, {"result.json": source})

        manifest = self.store.commit(handle, {"result.json": source})
        self.assertEqual(manifest.run_id, handle.run_id)
        self.assertEqual(manifest.generation, handle.generation)
        self.assertEqual(manifest.iteration, handle.iteration)
        self.assertEqual(manifest.stage, handle.stage)
        self.assertEqual(manifest.tool, handle.tool)
        self.assertEqual(manifest.input_hashes, handle.input_hashes)

    def test_commit_copies_regular_files_and_binds_hash_size_and_path(self) -> None:
        handle = self.begin_attempt()
        result = handle.scratch_dir / "result.json"
        log = handle.scratch_dir / "logs" / "stdout.txt"
        log.parent.mkdir()
        result.write_bytes(b'{"status":"passed"}\n')
        log.write_bytes(b"probe output\n")

        manifest = self.store.commit(
            handle,
            {
                "results/result.json": result,
                "logs/stdout.txt": Path("logs/stdout.txt"),
            },
        )

        self.assertEqual(manifest.attempt_id, handle.attempt_id)
        self.assertEqual([item.name for item in manifest.artifacts], ["logs/stdout.txt", "results/result.json"])
        result_ref = next(item for item in manifest.artifacts if item.name == "results/result.json")
        self.assertEqual(result_ref.sha256, hashlib.sha256(result.read_bytes()).hexdigest())
        self.assertEqual(result_ref.size, result.stat().st_size)
        self.assertEqual(
            result_ref.path,
            f"attempts/{handle.attempt_id}/committed/artifacts/results/result.json",
        )
        result.write_bytes(b"scratch may change after commit\n")
        self.assertEqual(self.store.load_attempt(handle.attempt_id), manifest)
        committed = self.run_dir / result_ref.path
        self.assertEqual(committed.read_bytes(), b'{"status":"passed"}\n')

    def test_commit_rejects_symlink_directory_and_outside_scratch(self) -> None:
        handle = self.begin_attempt()
        ordinary = handle.scratch_dir / "ordinary.txt"
        ordinary.write_text("ok", encoding="utf-8")
        directory = handle.scratch_dir / "directory"
        directory.mkdir()
        symlink = handle.scratch_dir / "link.txt"
        symlink.symlink_to(ordinary)
        fifo = handle.scratch_dir / "stream.pipe"
        os.mkfifo(fifo)
        outside = self.run_dir / "outside.txt"
        outside.write_text("outside", encoding="utf-8")

        invalid_sources = (directory, symlink, fifo, outside, Path("../outside.txt"))
        for index, source in enumerate(invalid_sources):
            with self.subTest(source=source):
                with self.assertRaises(AttemptSourceError):
                    self.store.commit(handle, {f"bad-{index}.txt": source})

        valid = self.store.commit(handle, {"ordinary.txt": ordinary})
        self.assertEqual(len(valid.artifacts), 1)

    def test_committed_attempt_is_never_overwritten(self) -> None:
        handle, source = self.begin_with_file(payload=b"first")
        first = self.store.commit(handle, {"result.bin": source})
        committed_path = self.run_dir / first.artifacts[0].path
        source.write_bytes(b"second")

        with self.assertRaises(AttemptAlreadyCommittedError):
            self.store.commit(handle, {"result.bin": source})

        self.assertEqual(committed_path.read_bytes(), b"first")
        self.assertEqual(self.store.load_attempt(handle.attempt_id), first)

    def test_concurrent_commit_has_exactly_one_immutable_winner(self) -> None:
        handle = self.begin_attempt()
        first_source = handle.scratch_dir / "first.txt"
        second_source = handle.scratch_dir / "second.txt"
        first_source.write_bytes(b"first")
        second_source.write_bytes(b"second")
        barrier = threading.Barrier(2)

        def commit(name: str, source: Path):
            barrier.wait()
            try:
                return ("won", self.store.commit(handle, {name: source}))
            except AttemptAlreadyCommittedError:
                return ("lost", None)

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(
                executor.map(
                    lambda args: commit(*args),
                    (("first.txt", first_source), ("second.txt", second_source)),
                )
            )

        winners = [manifest for status, manifest in outcomes if status == "won"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(sum(status == "lost" for status, _ in outcomes), 1)
        self.assertEqual(self.store.load_attempt(handle.attempt_id), winners[0])

    def test_artifact_tampering_invalidates_attempt_and_run_publish(self) -> None:
        handle, source = self.begin_with_file(payload=b"trusted")
        manifest = self.store.commit(handle, {"result.bin": source})
        committed_path = self.run_dir / manifest.artifacts[0].path
        os.chmod(committed_path, 0o600)
        committed_path.write_bytes(b"tampered")

        with self.assertRaisesRegex(AttemptIntegrityError, "篡改"):
            self.store.load_attempt(handle.attempt_id)
        with self.assertRaises(AttemptIntegrityError):
            self.store.publish_run_manifest(
                run_id="run-1",
                generation=1,
                expected_sequence=0,
                attempts=[manifest],
            )
        self.assertFalse(self.store.run_manifest_path.exists())

    def test_parent_hash_tampering_invalidates_committed_attempt(self) -> None:
        handle, source = self.begin_with_file()
        self.store.commit(handle, {"result.json": source})
        manifest_path = handle.attempt_dir / "committed" / "attempt-manifest.json"
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["input_hashes"]["plan"] = "f" * 64
        manifest_path.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaisesRegex(AttemptIntegrityError, "哈希"):
            self.store.load_attempt(handle.attempt_id)

    def test_publish_rejects_attempt_from_other_run_or_generation(self) -> None:
        foreign_handle, foreign_source = self.begin_with_file(run_id="run-2")
        foreign = self.store.commit(foreign_handle, {"foreign.json": foreign_source})
        future_handle, future_source = self.begin_with_file(generation=2)
        future = self.store.commit(future_handle, {"future.json": future_source})

        for attempt in (foreign, future):
            with self.subTest(attempt=attempt.attempt_id):
                with self.assertRaises(AttemptIntegrityError):
                    self.store.publish_run_manifest(
                        run_id="run-1",
                        generation=1,
                        expected_sequence=0,
                        attempts=[attempt],
                    )
        self.assertFalse(self.store.run_manifest_path.exists())

    def test_publish_binds_attempt_hash_generation_and_sequence(self) -> None:
        handle, source = self.begin_with_file()
        attempt = self.store.commit(handle, {"result.json": source})

        published = self.store.publish_run_manifest(
            run_id="run-1",
            generation=1,
            expected_sequence=0,
            attempts=[attempt],
        )

        self.assertEqual(published["sequence"], 1)
        self.assertEqual(published["generation"], 1)
        self.assertIsNone(published["previous_manifest_sha256"])
        self.assertEqual(
            published["attempts"],
            [{"attempt_id": attempt.attempt_id, "manifest_sha256": attempt.manifest_sha256}],
        )
        self.assertEqual(self.store.read_run_manifest(), published)

        takeover_handle, takeover_source = self.begin_with_file(
            payload=b'{"generation":2}\n',
            generation=2,
            iteration=2,
            input_hashes={"plan": "c" * 64},
        )
        takeover_attempt = self.store.commit(
            takeover_handle,
            {"result.json": takeover_source},
        )
        takeover = self.store.publish_run_manifest(
            run_id="run-1",
            generation=2,
            expected_sequence=1,
            attempts=[takeover_attempt],
        )
        self.assertEqual(takeover["sequence"], 2)
        self.assertEqual(takeover["previous_manifest_sha256"], published["manifest_sha256"])

        with self.assertRaises(StaleGenerationError):
            self.store.publish_run_manifest(
                run_id="run-1",
                generation=1,
                expected_sequence=2,
                attempts=[attempt],
            )
        with self.assertRaises(ManifestConflictError):
            self.store.publish_run_manifest(
                run_id="run-1",
                generation=4,
                expected_sequence=2,
                attempts=[attempt],
            )
        self.assertEqual(self.store.read_run_manifest(), takeover)

    def test_concurrent_publish_uses_expected_sequence_cas(self) -> None:
        handle, source = self.begin_with_file()
        attempt = self.store.commit(handle, {"result.json": source})
        barrier = threading.Barrier(2)

        def publish():
            contender = AttemptStore(self.run_dir)
            barrier.wait()
            try:
                return (
                    "won",
                    contender.publish_run_manifest(
                        run_id="run-1",
                        generation=1,
                        expected_sequence=0,
                        attempts=[attempt],
                    ),
                )
            except ManifestConflictError:
                return ("lost", None)

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _: publish(), range(2)))

        winners = [manifest for status, manifest in outcomes if status == "won"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(sum(status == "lost" for status, _ in outcomes), 1)
        self.assertEqual(self.store.read_run_manifest(), winners[0])

    def test_sequence_conflict_and_forged_attempt_do_not_replace_manifest(self) -> None:
        handle, source = self.begin_with_file()
        attempt = self.store.commit(handle, {"result.json": source})
        current = self.store.publish_run_manifest(
            run_id="run-1",
            generation=1,
            expected_sequence=0,
            attempts=[attempt],
        )

        with self.assertRaises(ManifestConflictError):
            self.store.publish_run_manifest(
                run_id="run-1",
                generation=1,
                expected_sequence=0,
                attempts=[attempt],
            )
        forged = replace(attempt, input_hashes={"plan": "0" * 64})
        with self.assertRaises(AttemptIntegrityError):
            self.store.publish_run_manifest(
                run_id="run-1",
                generation=1,
                expected_sequence=1,
                attempts=[forged],
            )
        self.assertEqual(self.store.read_run_manifest(), current)

    def test_tampered_run_manifest_fails_closed(self) -> None:
        handle, source = self.begin_with_file()
        attempt = self.store.commit(handle, {"result.json": source})
        self.store.publish_run_manifest(
            run_id="run-1",
            generation=1,
            expected_sequence=0,
            attempts=[attempt],
        )
        payload = json.loads(self.store.run_manifest_path.read_text(encoding="utf-8"))
        payload["sequence"] = 999
        self.store.run_manifest_path.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaisesRegex(AttemptIntegrityError, "哈希"):
            self.store.read_run_manifest()
        with self.assertRaises(AttemptIntegrityError):
            self.store.publish_run_manifest(
                run_id="run-1",
                generation=1,
                expected_sequence=1,
                attempts=[attempt],
            )

    def test_failed_atomic_publish_keeps_previous_manifest(self) -> None:
        handle, source = self.begin_with_file()
        attempt = self.store.commit(handle, {"result.json": source})
        first = self.store.publish_run_manifest(
            run_id="run-1",
            generation=1,
            expected_sequence=0,
            attempts=[attempt],
        )

        with patch("qa_core.runtime.attempts.os.replace", side_effect=OSError("injected replace failure")):
            with self.assertRaisesRegex(OSError, "injected replace failure"):
                self.store.publish_run_manifest(
                    run_id="run-1",
                    generation=1,
                    expected_sequence=1,
                    attempts=[attempt],
                )

        self.assertEqual(self.store.read_run_manifest(), first)
        self.assertEqual(
            [path for path in self.run_dir.iterdir() if path.suffix == ".tmp"],
            [],
        )

    def test_failed_commit_manifest_write_leaves_attempt_retryable(self) -> None:
        handle, source = self.begin_with_file()

        with patch("qa_core.runtime.attempts.os.replace", side_effect=OSError("injected replace failure")):
            with self.assertRaisesRegex(OSError, "injected replace failure"):
                self.store.commit(handle, {"result.json": source})

        self.assertFalse((handle.attempt_dir / "committed").exists())
        self.assertEqual(
            [path for path in handle.attempt_dir.iterdir() if path.name.startswith(".commit-")],
            [],
        )
        recovered = self.store.commit(handle, {"result.json": source})
        self.assertEqual(self.store.load_attempt(handle.attempt_id), recovered)


if __name__ == "__main__":
    unittest.main()
