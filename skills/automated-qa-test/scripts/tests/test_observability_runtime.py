#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.observability import (  # noqa: E402
    TRACE_JOURNAL_FILENAME,
    CycleTracer,
    ObservabilityError,
    TraceEvent,
    TraceJournal,
)
from qa_core.runtime import BudgetSnapshot  # noqa: E402

_ORIGIN = datetime(2026, 7, 26, tzinfo=UTC)
_ATTEMPT_ID = "att_" + "3" * 32
_PLAN_SHA256 = "a" * 64
_CONTEXT_SHA256 = "b" * 64


def _time(seconds: float) -> str:
    return (_ORIGIN + timedelta(seconds=seconds)).isoformat().replace(
        "+00:00",
        "Z",
    )


def _budget(
    *,
    remaining: float = 60,
    probes: int = 0,
    output: int = 0,
) -> BudgetSnapshot:
    return BudgetSnapshot(
        started_at=100,
        deadline=160,
        remaining_time=remaining,
        probes_used=probes,
        max_probes=10,
        output_bytes_used=output,
        max_output_bytes=1000,
        cancelled=False,
        cancel_detail=None,
        cancelled_at=None,
    )


def _process_result(
    *,
    stage: str = "validate_plan",
    started: float = 1,
    duration: float = 1,
    exit_code: int = 0,
    termination_reason: str | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "command": ["python3", "helper.py"],
        "cwd": "/tmp/run",
        "stage": stage,
        "started": True,
        "exit_code": exit_code,
        "raw_exit_code": exit_code,
        "timed_out": termination_reason
        in {"deadline_exceeded", "stage_timeout"},
        "termination_reason": termination_reason,
        "budget_error": None,
        "stdout": "",
        "stderr": "",
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "output_bytes": 0,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "term_sent": termination_reason is not None,
        "kill_sent": False,
        "process_group_cleanup": False,
        "spawn_error": None,
        "executor_error": None,
        "started_at": _time(started),
        "finished_at": _time(started + duration),
        "duration_seconds": duration,
    }


def _results(
    *steps: dict[str, object],
    scenario_id: str = "scenario-1",
) -> dict[str, object]:
    return {
        "schemaVersion": 2,
        "status": "passed",
        "startedAt": _time(2),
        "finishedAt": _time(8),
        "scenarios": [
            {
                "id": scenario_id,
                "status": "passed",
                "steps": list(steps),
            }
        ],
    }


def _step(
    *,
    scenario_id: str = "scenario-1",
    step_id: str = "step-1",
    action: str = "goto",
    status: str = "passed",
    started: float = 2,
    duration: float = 1,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "scenarioId": scenario_id,
        "stepId": step_id,
        "action": action,
        "status": status,
        "startedAt": _time(started),
        "finishedAt": _time(started + duration),
    }
    if status == "failed":
        payload["error"] = "assertion failed"
    if status == "skipped":
        payload["skipReason"] = "blocked by prior step"
    return payload


def _attempt(run_dir: Path, *, content: bytes = b'{"ok":true}\n') -> dict:
    relative = (
        Path("attempts")
        / _ATTEMPT_ID
        / "committed"
        / "artifacts"
        / "results.json"
    )
    target = run_dir / relative
    target.parent.mkdir(parents=True)
    target.write_bytes(content)
    return {
        "attempt_id": _ATTEMPT_ID,
        "artifacts": [
            {
                "attempt_id": _ATTEMPT_ID,
                "name": "results.json",
                "path": relative.as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        ],
    }


def _prior_action() -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": "run-1",
        "generation": 1,
        "iteration": 1,
        "attempt_id": None,
        "kind": "action",
        "stage": "probe:scenario-1",
        "action": "step-1:goto",
        "status": "succeeded",
        "started_at": _time(1),
        "ended_at": _time(2),
        "duration_seconds": 1,
        "budget": {
            "total_seconds": 60.0,
            "deadline_at": _time(60),
            "remaining_seconds_at_start": 59,
            "remaining_seconds_at_end": 58,
            "probes_used": 1,
            "max_probes": 10,
            "output_bytes_used": 0,
            "max_output_bytes": 1000,
            "cancelled": False,
        },
        "reason": {"code": "action_completed", "detail": None},
        "artifact_refs": [],
        "attributes": {},
    }


class ObservabilityRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.run_dir = Path(self.temporary.name)
        self.journal = TraceJournal(
            self.run_dir / TRACE_JOURNAL_FILENAME
        )

    def tracer(
        self,
        *,
        generation: int = 1,
        iteration: int = 1,
        started_at: str | None = None,
        terminal_at: float = 20,
    ) -> CycleTracer:
        return CycleTracer(
            self.journal,
            run_id="run-1",
            generation=generation,
            iteration=iteration,
            initial_budget=_budget(),
            started_at=started_at or _time(0),
            initial_snapshot=self.journal.snapshot(),
            clock=lambda: _ORIGIN + timedelta(seconds=terminal_at),
        )

    def test_stage_and_plan_spans_use_no_fake_attempt_id(self) -> None:
        tracer = self.tracer()
        result = _process_result()

        stage = tracer.record_stage(
            "validate_plan",
            result,
            _budget(),
            _budget(remaining=58),
        )
        context_result = _process_result(
            stage="compile_agent_context",
            started=3,
        )
        tracer.record_stage(
            "compile_agent_context",
            context_result,
            _budget(remaining=58),
            _budget(remaining=57),
        )
        plan = tracer.record_plan_validation(
            result,
            _budget(),
            _budget(remaining=57),
            plan_sha256=_PLAN_SHA256,
            context_sha256=_CONTEXT_SHA256,
            context_result=context_result,
        )

        self.assertIsNone(stage.attempt_id)
        self.assertIsNone(plan.attempt_id)
        self.assertEqual(stage.status, "succeeded")
        self.assertTrue(plan.attributes["valid_context"])
        self.assertTrue(plan.attributes["executable"])
        self.assertEqual(tracer.stage_count, 2)

    def test_process_result_schema_is_exact_and_failure_is_recorded(self) -> None:
        tracer = self.tracer()
        malformed = _process_result()
        malformed["surprise"] = True

        with self.assertRaises(ObservabilityError) as malformed_error:
            tracer.record_stage(
                "validate_plan",
                malformed,
                _budget(),
                _budget(),
            )
        self.assertEqual(
            malformed_error.exception.code,
            "trace_process_result_schema_invalid",
        )
        self.assertEqual(self.journal.read(), ())

        failed = _process_result(exit_code=2)
        event = tracer.record_stage(
            "validate_plan",
            failed,
            _budget(),
            _budget(remaining=58),
        )
        self.assertEqual(event.status, "failed")
        self.assertEqual(event.reason.code, "nonzero_exit")

    def test_action_import_validates_all_steps_before_append(self) -> None:
        tracer = self.tracer()
        invalid = _step(step_id="step-2", started=4)
        invalid["finishedAt"] = _time(3)

        with self.assertRaises(ObservabilityError):
            tracer.record_actions(
                _results(_step(), invalid),
                _budget(remaining=50, probes=2),
            )

        self.assertEqual(self.journal.read(), ())
        self.assertEqual(tracer.action_count, 0)

    def test_action_statuses_and_identities_are_stable(self) -> None:
        tracer = self.tracer()
        events = tracer.record_actions(
            _results(
                _step(),
                _step(
                    step_id="step-2",
                    action="assertText",
                    status="failed",
                    started=4,
                ),
                _step(
                    step_id="step-3",
                    action="cleanupApi",
                    status="skipped",
                    started=6,
                ),
            ),
            _budget(remaining=50),
        )

        self.assertEqual(
            [event.status for event in events],
            ["succeeded", "failed", "blocked"],
        )
        self.assertEqual(
            [event.action for event in events],
            [
                "step-1:goto",
                "step-2:assertText",
                "step-3:cleanupApi",
            ],
        )
        self.assertTrue(all(event.attempt_id is None for event in events))

    def test_finalize_verifies_artifact_and_commits_run_last(self) -> None:
        tracer = self.tracer(terminal_at=12)
        tracer.record_plan_validation(
            _process_result(),
            _budget(),
            _budget(remaining=58),
            plan_sha256=_PLAN_SHA256,
            context_sha256=_CONTEXT_SHA256,
            context_result=_process_result(
                stage="compile_agent_context",
                started=3,
            ),
        )
        tracer.record_actions(
            _results(_step()),
            _budget(remaining=50),
        )
        attempt = _attempt(self.run_dir)

        snapshot = tracer.finalize(
            attempt=attempt,
            status="passed",
            reason="completed",
            final_budget=_budget(remaining=48),
            expected_actions=1,
        )

        events = [record.event for record in snapshot.records]
        self.assertEqual(
            [event.kind for event in events],
            [
                "plan_validation",
                "action",
                "artifact_validation",
                "run",
            ],
        )
        self.assertEqual(events[-1].attempt_id, _ATTEMPT_ID)
        self.assertEqual(events[-1].status, "succeeded")
        self.assertEqual(events[-1].deadline_datetime, _ORIGIN + timedelta(seconds=60))
        self.assertEqual(
            events[-2].artifact_refs[0].sha256,
            attempt["artifacts"][0]["sha256"],
        )
        self.assertTrue(tracer.finalized)

    def test_finalize_rejects_self_reported_action_count(self) -> None:
        tracer = self.tracer()
        tracer.record_actions(
            _results(_step()),
            _budget(remaining=50),
        )

        with self.assertRaises(ObservabilityError) as caught:
            tracer.finalize(
                attempt=_attempt(self.run_dir),
                status="passed",
                reason="completed",
                final_budget=_budget(remaining=48),
                expected_actions=2,
            )

        self.assertEqual(caught.exception.code, "trace_action_count_mismatch")
        self.assertEqual(
            [record.event.kind for record in self.journal.read()],
            ["action"],
        )

    def test_required_cleanup_and_handoff_need_real_spans(self) -> None:
        tracer = self.tracer()

        with self.assertRaises(ObservabilityError) as cleanup_error:
            tracer.finalize(
                attempt=None,
                status="failed",
                reason="failed",
                final_budget=_budget(),
                expected_actions=0,
                cleanup_required=True,
            )
        self.assertEqual(cleanup_error.exception.code, "trace_cleanup_missing")

        with self.assertRaises(ObservabilityError) as handoff_error:
            tracer.finalize(
                attempt=None,
                status="failed",
                reason="failed",
                final_budget=_budget(),
                expected_actions=0,
                handoff_required=True,
            )
        self.assertEqual(handoff_error.exception.code, "trace_handoff_missing")
        self.assertEqual(self.journal.read(), ())

    def test_recovery_uses_prior_incomplete_trace_and_blocks_duplicates(self) -> None:
        self.journal.append(TraceEvent.from_dict(_prior_action()))
        tracer = self.tracer(
            iteration=2,
            started_at=_time(10),
            terminal_at=20,
        )
        tracer.record_plan_validation(
            _process_result(started=11),
            _budget(),
            _budget(remaining=48),
            plan_sha256=_PLAN_SHA256,
            context_sha256=_CONTEXT_SHA256,
            context_result=_process_result(
                stage="compile_agent_context",
                started=13,
            ),
        )
        tracer.record_actions(
            _results(
                _step(started=12),
            ),
            _budget(remaining=45),
        )

        with self.assertRaises(ObservabilityError) as caught:
            tracer.finalize(
                attempt=_attempt(self.run_dir),
                status="passed",
                reason="completed",
                final_budget=_budget(remaining=40),
                expected_actions=1,
            )
        self.assertEqual(
            caught.exception.code,
            "trace_recovery_duplicate_action",
        )
        self.assertEqual(
            self.journal.read()[-1].event.kind,
            "recovery",
        )
        self.assertEqual(
            self.journal.read()[-1]
            .event.attributes["duplicate_committed_actions"],
            1,
        )

        snapshot = tracer.finalize(
            attempt=None,
            status="failed",
            reason="recovery_duplicate_action",
            final_budget=_budget(remaining=40),
            expected_actions=1,
        )
        self.assertEqual(snapshot.records[-1].event.kind, "run")
        self.assertEqual(snapshot.records[-1].event.status, "failed")
        self.assertIsNone(snapshot.records[-1].event.attempt_id)

    def test_success_requires_real_attempt_and_tamper_never_records_validation(self) -> None:
        tracer = self.tracer()
        with self.assertRaises(ObservabilityError) as missing:
            tracer.finalize(
                attempt=None,
                status="passed",
                reason="completed",
                final_budget=_budget(),
                expected_actions=0,
            )
        self.assertEqual(missing.exception.code, "trace_attempt_required")

        attempt = _attempt(self.run_dir)
        artifact_path = self.run_dir / attempt["artifacts"][0]["path"]
        artifact_path.write_text("tampered", encoding="utf-8")
        tracer.record_plan_validation(
            _process_result(),
            _budget(),
            _budget(remaining=58),
            plan_sha256=_PLAN_SHA256,
            context_sha256=_CONTEXT_SHA256,
            context_result=_process_result(
                stage="compile_agent_context",
                started=3,
            ),
        )
        tracer.record_actions(
            _results(),
            _budget(remaining=57),
        )
        with self.assertRaises(ObservabilityError) as tampered:
            tracer.finalize(
                attempt=attempt,
                status="passed",
                reason="completed",
                final_budget=_budget(remaining=56),
                expected_actions=0,
            )
        self.assertEqual(
            tampered.exception.code,
            "trace_artifact_integrity_mismatch",
        )
        self.assertEqual(
            [record.event.kind for record in self.journal.read()],
            ["plan_validation"],
        )

    def test_finalized_run_rejects_later_events(self) -> None:
        tracer = self.tracer()
        tracer.finalize(
            attempt=None,
            status="failed",
            reason="failed",
            final_budget=_budget(),
            expected_actions=0,
        )

        with self.assertRaises(ObservabilityError) as caught:
            tracer.record_actions(_results(), _budget())
        self.assertEqual(caught.exception.code, "trace_run_finalized")

    def test_budget_counters_and_remaining_time_are_contiguous(self) -> None:
        tracer = self.tracer()
        tracer.record_stage(
            "first",
            _process_result(stage="first"),
            _budget(),
            _budget(remaining=58, probes=1),
        )

        with self.assertRaises(ObservabilityError) as counters:
            tracer.record_stage(
                "second",
                _process_result(stage="second", started=3),
                _budget(remaining=57),
                _budget(remaining=56),
            )
        self.assertEqual(
            counters.exception.code,
            "trace_budget_discontinuous",
        )

        with self.assertRaises(ObservabilityError) as remaining:
            tracer.record_stage(
                "second",
                _process_result(stage="second", started=3),
                _budget(remaining=59, probes=1),
                _budget(remaining=57, probes=1),
            )
        self.assertEqual(
            remaining.exception.code,
            "trace_budget_time_regressed",
        )

    def test_lease_takeover_recovers_prior_generation(self) -> None:
        self.journal.append(TraceEvent.from_dict(_prior_action()))

        tracer = self.tracer(
            generation=2,
            iteration=1,
            started_at=_time(10),
        )

        self.assertTrue(tracer.recovery_required)


if __name__ == "__main__":
    unittest.main()
