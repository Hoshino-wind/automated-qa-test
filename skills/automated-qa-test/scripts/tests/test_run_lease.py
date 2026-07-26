#!/usr/bin/env python3
from __future__ import annotations

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

from qa_core.runtime.lease import (
    LeaseAlreadyHeldError,
    LeaseClockError,
    LeaseNotFoundError,
    LeaseNotStaleError,
    LeaseOwnershipError,
    LeaseRecordError,
    RunLease,
)


class MutableClock:
    def __init__(self, value: float) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class RunLeaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.lease_path = Path(self.temporary_directory.name) / "run-lease.json"

    def test_acquire_persists_complete_generation_one_record(self) -> None:
        lease = RunLease(self.lease_path, clock=lambda: 100.25)

        record = lease.acquire("run-1", "worker-a", pid=321)

        self.assertEqual(record.run_id, "run-1")
        self.assertEqual(record.owner, "worker-a")
        self.assertEqual(record.generation, 1)
        self.assertEqual(record.pid, 321)
        self.assertEqual(record.acquired_at, 100.25)
        self.assertEqual(record.heartbeat_at, 100.25)
        self.assertEqual(
            set(json.loads(self.lease_path.read_text(encoding="utf-8"))),
            {
                "run_id",
                "owner",
                "generation",
                "pid",
                "acquired_at",
                "heartbeat_at",
            },
        )
        self.assertEqual(lease.read(), record)
        self.assertEqual(self.lease_path.stat().st_mode & 0o777, 0o600)

    def test_second_acquire_reports_current_owner_without_overwriting(self) -> None:
        first = RunLease(self.lease_path, clock=lambda: 10.0)
        second = RunLease(self.lease_path, clock=lambda: 20.0)
        original = first.acquire("run-1", "worker-a", pid=111)

        with self.assertRaises(LeaseAlreadyHeldError) as raised:
            second.acquire("run-1", "worker-b", pid=222)

        self.assertEqual(raised.exception.current, original)
        self.assertEqual(first.read(), original)

    def test_concurrent_acquire_has_exactly_one_winner(self) -> None:
        worker_count = 16
        barrier = threading.Barrier(worker_count)

        def acquire(index: int) -> tuple[str, object]:
            contender = RunLease(self.lease_path, clock=lambda: 50.0)
            barrier.wait()
            try:
                return ("won", contender.acquire("run-race", f"worker-{index}", pid=index + 1))
            except LeaseAlreadyHeldError as error:
                return ("lost", error.current)

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            outcomes = list(executor.map(acquire, range(worker_count)))

        winners = [record for outcome, record in outcomes if outcome == "won"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(
            RunLease(self.lease_path).read(),
            winners[0],
        )
        self.assertTrue(
            all(record == winners[0] for outcome, record in outcomes if outcome == "lost")
        )

    def test_heartbeat_requires_full_identity_and_never_moves_backwards(self) -> None:
        clock = MutableClock(100.0)
        lease = RunLease(self.lease_path, clock=clock)
        original = lease.acquire("run-1", "worker-a", pid=111)
        clock.value = 105.0

        updated = lease.heartbeat("run-1", "worker-a", original.generation)

        self.assertEqual(updated.acquired_at, 100.0)
        self.assertEqual(updated.heartbeat_at, 105.0)
        with self.assertRaises(LeaseOwnershipError):
            lease.heartbeat("run-1", "worker-b", original.generation)
        with self.assertRaises(LeaseOwnershipError):
            lease.heartbeat("run-1", "worker-a", original.generation + 1)

        clock.value = 104.0
        with self.assertRaises(LeaseClockError):
            lease.heartbeat("run-1", "worker-a", original.generation)
        self.assertEqual(lease.read(), updated)

    def test_takeover_requires_matching_observation_and_explicit_staleness(self) -> None:
        clock = MutableClock(100.0)
        lease = RunLease(self.lease_path, clock=clock)
        original = lease.acquire("run-1", "worker-a", pid=111)
        clock.value = 109.999

        with self.assertRaises(LeaseNotStaleError):
            lease.takeover(
                "run-1",
                "worker-b",
                expected_owner=original.owner,
                expected_generation=original.generation,
                stale_after_seconds=10.0,
                pid=222,
            )

        clock.value = 110.0
        with self.assertRaises(LeaseOwnershipError):
            lease.takeover(
                "run-1",
                "worker-b",
                expected_owner="wrong-owner",
                expected_generation=original.generation,
                stale_after_seconds=10.0,
                pid=222,
            )
        with self.assertRaises(LeaseOwnershipError):
            lease.takeover(
                "run-1",
                "worker-b",
                expected_owner=original.owner,
                expected_generation=original.generation + 1,
                stale_after_seconds=10.0,
                pid=222,
            )

        replacement = lease.takeover(
            "run-1",
            "worker-b",
            expected_owner=original.owner,
            expected_generation=original.generation,
            stale_after_seconds=10.0,
            pid=222,
        )

        self.assertEqual(replacement.owner, "worker-b")
        self.assertEqual(replacement.generation, 2)
        self.assertEqual(replacement.pid, 222)
        self.assertEqual(replacement.acquired_at, 110.0)
        self.assertEqual(replacement.heartbeat_at, 110.0)
        with self.assertRaises(LeaseOwnershipError):
            lease.release("run-1", original.owner, original.generation)
        with self.assertRaises(LeaseOwnershipError):
            lease.heartbeat("run-1", original.owner, original.generation)

    def test_concurrent_stale_takeover_allows_only_one_generation_two_owner(self) -> None:
        original_lease = RunLease(self.lease_path, clock=lambda: 10.0)
        original = original_lease.acquire("run-race", "worker-old", pid=100)
        contenders = 8
        barrier = threading.Barrier(contenders)

        def takeover(index: int) -> tuple[str, object]:
            contender = RunLease(self.lease_path, clock=lambda: 30.0)
            barrier.wait()
            try:
                return (
                    "won",
                    contender.takeover(
                        "run-race",
                        f"worker-{index}",
                        expected_owner=original.owner,
                        expected_generation=original.generation,
                        stale_after_seconds=10.0,
                        pid=index + 200,
                    ),
                )
            except LeaseOwnershipError as error:
                return ("lost", error.current)

        with ThreadPoolExecutor(max_workers=contenders) as executor:
            outcomes = list(executor.map(takeover, range(contenders)))

        winners = [record for outcome, record in outcomes if outcome == "won"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(winners[0].generation, 2)
        self.assertEqual(original_lease.read(), winners[0])
        self.assertTrue(
            all(record == winners[0] for outcome, record in outcomes if outcome == "lost")
        )

    def test_release_requires_current_identity_and_missing_release_fails_closed(self) -> None:
        lease = RunLease(self.lease_path, clock=lambda: 10.0)
        record = lease.acquire("run-1", "worker-a", pid=111)

        with self.assertRaises(LeaseOwnershipError):
            lease.release("run-2", record.owner, record.generation)
        with self.assertRaises(LeaseOwnershipError):
            lease.release(record.run_id, "worker-b", record.generation)
        with self.assertRaises(LeaseOwnershipError):
            lease.release(record.run_id, record.owner, record.generation + 1)

        lease.release(record.run_id, record.owner, record.generation)
        self.assertFalse(self.lease_path.exists())
        self.assertIsNone(lease.read())
        with self.assertRaises(LeaseNotFoundError):
            lease.release(record.run_id, record.owner, record.generation)

    def test_malformed_existing_record_is_never_replaced_by_acquire(self) -> None:
        invalid_payload = b'{"run_id":"run-1"}\n'
        self.lease_path.write_bytes(invalid_payload)
        lease = RunLease(self.lease_path, clock=lambda: 10.0)

        with self.assertRaises(LeaseRecordError):
            lease.acquire("run-1", "worker-a", pid=111)

        self.assertEqual(self.lease_path.read_bytes(), invalid_payload)

    def test_failed_atomic_heartbeat_keeps_previous_record_and_cleans_temporary_file(self) -> None:
        clock = MutableClock(10.0)
        lease = RunLease(self.lease_path, clock=clock)
        original = lease.acquire("run-1", "worker-a", pid=111)
        clock.value = 11.0

        with patch("qa_core.runtime.lease.os.replace", side_effect=OSError("injected replace failure")):
            with self.assertRaisesRegex(OSError, "injected replace failure"):
                lease.heartbeat(original.run_id, original.owner, original.generation)

        self.assertEqual(lease.read(), original)
        self.assertEqual(
            [path for path in self.lease_path.parent.iterdir() if path.suffix == ".tmp"],
            [],
        )

    def test_failed_initial_sync_removes_incomplete_exclusive_record(self) -> None:
        lease = RunLease(self.lease_path, clock=lambda: 10.0)

        with patch("qa_core.runtime.lease.os.fsync", side_effect=OSError("injected sync failure")):
            with self.assertRaisesRegex(OSError, "injected sync failure"):
                lease.acquire("run-1", "worker-a", pid=111)

        self.assertFalse(self.lease_path.exists())
        self.assertIsNone(lease.read())

    def test_invalid_inputs_fail_before_mutating_disk(self) -> None:
        lease = RunLease(self.lease_path, clock=lambda: 10.0)

        invalid_acquires = (
            ("", "worker-a", 1),
            ("run-1", "", 1),
            ("run-1", "worker-a", 0),
        )
        for run_id, owner, pid in invalid_acquires:
            with self.subTest(run_id=run_id, owner=owner, pid=pid):
                with self.assertRaises(ValueError):
                    lease.acquire(run_id, owner, pid=pid)
        self.assertFalse(self.lease_path.exists())

        record = lease.acquire("run-1", "worker-a", pid=os.getpid())
        for threshold in (0, -1, float("inf"), float("nan")):
            with self.subTest(threshold=threshold):
                with self.assertRaises(ValueError):
                    lease.takeover(
                        record.run_id,
                        "worker-b",
                        expected_owner=record.owner,
                        expected_generation=record.generation,
                        stale_after_seconds=threshold,
                    )
        self.assertEqual(lease.read(), record)


if __name__ == "__main__":
    unittest.main()
