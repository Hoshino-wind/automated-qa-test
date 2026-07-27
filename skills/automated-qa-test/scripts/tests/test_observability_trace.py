#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.observability import (  # noqa: E402
    ObservabilityError,
    TraceEvent,
    TraceJournal,
)

_ORIGIN = datetime(2026, 7, 26, tzinfo=UTC)
_ATTEMPT_ID = "att_" + "1" * 32


def _time(seconds: float) -> str:
    return (_ORIGIN + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _event(
    *,
    kind: str = "action",
    action: str = "probe",
    started: float = 1,
    duration: float = 1,
    attributes: dict | None = None,
    artifact_refs: list[dict] | None = None,
) -> dict:
    defaults = {
        "run": {
            "expected_stage_count": 1,
            "expected_action_count": 1,
            "state_start_sequence": 0,
            "state_end_sequence": 1,
            "cleanup_required": True,
            "handoff_required": True,
            "recovery_required": True,
            "converged": True,
        },
        "stage": {"command_sha256": "c" * 64},
        "action": {},
        "cancellation": {},
        "cleanup": {"managed_resources_remaining": 0},
        "handoff": {"structured": True},
        "artifact_validation": {
            "required_ref_count": len(artifact_refs or []),
            "valid_ref_count": len(artifact_refs or []),
        },
        "recovery": {"resumed": True, "duplicate_committed_actions": 0},
        "plan_validation": {
            "valid_context": True,
            "executable": True,
            "plan_sha256": "a" * 64,
            "context_sha256": "b" * 64,
        },
    }
    return {
        "schema_version": 1,
        "run_id": "run-1",
        "generation": 1,
        "iteration": 1,
        "attempt_id": _ATTEMPT_ID,
        "kind": kind,
        "stage": "execute",
        "action": action,
        "status": "succeeded",
        "started_at": _time(started),
        "ended_at": _time(started + duration),
        "duration_seconds": duration,
        "budget": {
            "total_seconds": 100.0,
            "deadline_at": _time(100),
            "remaining_seconds_at_start": max(0.0, 100 - started),
            "remaining_seconds_at_end": max(0.0, 100 - started - duration),
            "probes_used": 1,
            "max_probes": 10,
            "output_bytes_used": 20,
            "max_output_bytes": 1000,
            "cancelled": kind == "cancellation",
        },
        "reason": {"code": "completed", "detail": None},
        "artifact_refs": artifact_refs or [],
        "attributes": defaults[kind] if attributes is None else attributes,
    }


class ObservabilityTraceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "trace.jsonl"
        self.journal = TraceJournal(self.path)

    def test_new_empty_snapshot_does_not_create_writer_files(self) -> None:
        before_names = sorted(
            item.name for item in self.path.parent.iterdir()
        )

        snapshot = self.journal.snapshot()

        self.assertEqual(snapshot.records, ())
        self.assertEqual(snapshot.byte_size, 0)
        self.assertEqual(
            sorted(item.name for item in self.path.parent.iterdir()),
            before_names,
        )
        self.assertFalse(self.path.exists())
        self.assertFalse(self.journal.guard_path.exists())

    def test_append_builds_verified_hash_chain_and_snapshot_hash(self) -> None:
        first = self.journal.append(TraceEvent.from_dict(_event(action="one")))
        second = self.journal.append(_event(action="two", started=3))

        snapshot = self.journal.snapshot()

        self.assertEqual([item.sequence for item in snapshot.records], [1, 2])
        self.assertIsNone(first.previous_event_sha256)
        self.assertEqual(second.previous_event_sha256, first.event_sha256)
        self.assertEqual(snapshot.records[-1], second)
        self.assertEqual(snapshot.byte_size, self.path.stat().st_size)
        self.assertEqual(len(snapshot.sha256), 64)

    def test_unknown_top_level_and_nested_fields_are_rejected(self) -> None:
        top_level = _event()
        top_level["surprise"] = True
        with self.assertRaises(ObservabilityError) as top_error:
            TraceEvent.from_dict(top_level)
        self.assertEqual(top_error.exception.code, "schema_unknown_fields")

        nested = _event()
        nested["budget"]["surprise"] = True
        with self.assertRaises(ObservabilityError) as nested_error:
            TraceEvent.from_dict(nested)
        self.assertEqual(nested_error.exception.code, "schema_unknown_fields")

    def test_precommit_stage_allows_no_attempt_but_artifacts_do_not(self) -> None:
        stage = _event(kind="stage")
        stage["attempt_id"] = None
        parsed = TraceEvent.from_dict(stage)
        self.assertIsNone(parsed.attempt_id)

        artifact = {
            "attempt_id": _ATTEMPT_ID,
            "name": "results.json",
            "path": f"attempts/{_ATTEMPT_ID}/committed/artifacts/results.json",
            "sha256": "a" * 64,
            "size": 12,
        }
        invalid = _event(
            kind="artifact_validation",
            artifact_refs=[artifact],
        )
        invalid["attempt_id"] = None
        with self.assertRaises(ObservabilityError) as caught:
            TraceEvent.from_dict(invalid)
        self.assertEqual(caught.exception.code, "trace_attempt_id_missing")

    def test_tampered_line_fails_hash_verification(self) -> None:
        self.journal.append(_event(action="trusted"))
        value = json.loads(self.path.read_text(encoding="utf-8"))
        value["action"] = "tampered"
        self.path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(ObservabilityError) as caught:
            self.journal.read()

        self.assertEqual(caught.exception.code, "trace_event_hash_mismatch")

    def test_partial_last_line_is_rejected_and_blocks_append(self) -> None:
        self.journal.append(_event())
        with self.path.open("ab") as stream:
            stream.write(b'{"schema_version":1')

        with self.assertRaises(ObservabilityError) as read_error:
            self.journal.read()
        self.assertEqual(read_error.exception.code, "trace_partial_line")

        with self.assertRaises(ObservabilityError) as append_error:
            self.journal.append(_event(action="later", started=3))
        self.assertEqual(append_error.exception.code, "trace_partial_line")

    def test_duration_and_artifact_counts_must_close(self) -> None:
        mismatch = _event(duration=2)
        mismatch["ended_at"] = _time(4)
        with self.assertRaises(ObservabilityError) as duration_error:
            TraceEvent.from_dict(mismatch)
        self.assertEqual(duration_error.exception.code, "trace_duration_mismatch")

        artifact = {
            "attempt_id": _ATTEMPT_ID,
            "name": "results.json",
            "path": f"attempts/{_ATTEMPT_ID}/committed/artifacts/results.json",
            "sha256": "a" * 64,
            "size": 12,
        }
        invalid = _event(
            kind="artifact_validation",
            artifact_refs=[artifact],
            attributes={"required_ref_count": 2, "valid_ref_count": 1},
        )
        with self.assertRaises(ObservabilityError) as artifact_error:
            TraceEvent.from_dict(invalid)
        self.assertEqual(
            artifact_error.exception.code,
            "trace_artifact_counts_invalid",
        )

    def test_concurrent_append_has_one_contiguous_chain(self) -> None:
        def append(index: int):
            return self.journal.append(
                _event(
                    action=f"probe-{index}",
                    started=1 + index,
                )
            )

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(append, range(20)))

        records = self.journal.read()
        self.assertEqual([record.sequence for record in records], list(range(1, 21)))
        for previous, current in zip(records, records[1:]):
            self.assertEqual(
                current.previous_event_sha256,
                previous.event_sha256,
            )

    def test_hardlinked_journal_is_rejected(self) -> None:
        self.journal.append(_event())
        alias = self.path.with_name("trace-alias.jsonl")
        os.link(self.path, alias)

        with self.assertRaises(ObservabilityError) as caught:
            self.journal.read()

        self.assertEqual(
            caught.exception.code,
            "trace_journal_hardlink_rejected",
        )

    def test_snapshot_is_read_only_without_writer_guard(self) -> None:
        self.journal.append(_event())
        self.journal.guard_path.unlink()
        os.chmod(self.path, 0o444)
        os.chmod(self.path.parent, 0o555)
        before_names = sorted(
            item.name for item in self.path.parent.iterdir()
        )
        before_payload = self.path.read_bytes()

        try:
            snapshot = self.journal.snapshot()
            after_names = sorted(
                item.name for item in self.path.parent.iterdir()
            )
            after_payload = self.path.read_bytes()
        finally:
            os.chmod(self.path.parent, 0o755)
            os.chmod(self.path, 0o600)

        self.assertEqual(len(snapshot.records), 1)
        self.assertEqual(after_names, before_names)
        self.assertEqual(after_payload, before_payload)
        self.assertFalse(self.journal.guard_path.exists())

    def test_missing_guard_in_writable_package_is_rejected(self) -> None:
        self.journal.append(_event())
        self.journal.guard_path.unlink()

        with self.assertRaises(ObservabilityError) as caught:
            self.journal.snapshot()

        self.assertEqual(
            caught.exception.code,
            "trace_guard_missing_untrusted",
        )
        self.assertFalse(self.journal.guard_path.exists())


if __name__ == "__main__":
    unittest.main()
