#!/usr/bin/env python3
import json
import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.runtime import (  # noqa: E402
    BudgetExceeded,
    BudgetReason,
    RunBudget,
)


class FakeClock:
    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class RunBudgetTests(unittest.TestCase):
    def test_total_timeout_exposes_deadline_and_remaining_time(self) -> None:
        clock = FakeClock(100.0)
        budget = RunBudget(total_timeout=10.0, clock=clock)

        self.assertEqual(budget.started_at, 100.0)
        self.assertEqual(budget.deadline, 110.0)
        self.assertEqual(budget.remaining_time(), 10.0)

        clock.advance(4.25)
        self.assertEqual(budget.remaining_time(), 5.75)
        budget.check()

    def test_absolute_deadline_fails_closed_at_the_boundary(self) -> None:
        clock = FakeClock(5.0)
        budget = RunBudget(deadline=7.0, clock=clock)
        clock.advance(2.0)

        with self.assertRaises(BudgetExceeded) as caught:
            budget.check()

        error = caught.exception
        self.assertEqual(error.reason, BudgetReason.DEADLINE_EXCEEDED)
        self.assertEqual(error.limit, 7.0)
        self.assertEqual(error.observed, 7.0)
        self.assertEqual(error.snapshot.remaining_time, 0.0)

    def test_stage_uses_smaller_stage_and_run_deadlines(self) -> None:
        clock = FakeClock(10.0)
        budget = RunBudget(
            total_timeout=20.0,
            stage_timeouts={"probe": 5.0, "report": 30.0},
            clock=clock,
        )
        probe = budget.stage("probe")
        report = budget.stage("report")

        self.assertEqual(probe.deadline, 15.0)
        self.assertEqual(report.deadline, 30.0)
        clock.advance(4.0)
        self.assertEqual(probe.remaining_time(), 1.0)
        self.assertEqual(report.remaining_time(), 16.0)

    def test_stage_deadline_reserve_preserves_cleanup_time(self) -> None:
        clock = FakeClock(10.0)
        budget = RunBudget(total_timeout=20.0, clock=clock)
        work = budget.stage("probe", deadline_reserve=4.0)

        self.assertEqual(work.deadline, 26.0)
        clock.advance(16.0)
        with self.assertRaises(BudgetExceeded) as caught:
            work.check()

        self.assertEqual(
            caught.exception.reason,
            BudgetReason.DEADLINE_EXCEEDED,
        )
        self.assertEqual(budget.remaining_time(), 4.0)
        self.assertIn("reserved 4.0 seconds", caught.exception.detail)
        budget.stage("service_runtime_stop").check()

    def test_stage_output_reserve_preserves_cleanup_bytes(self) -> None:
        budget = RunBudget(
            max_output_bytes=100,
            clock=FakeClock(),
        )
        work = budget.stage("probe", output_byte_reserve=20)

        self.assertEqual(work.consume_output(80), 80)
        with self.assertRaises(BudgetExceeded) as caught:
            work.consume_output(1)

        self.assertEqual(
            caught.exception.reason,
            BudgetReason.OUTPUT_BYTE_LIMIT,
        )
        self.assertEqual(caught.exception.limit, 80)
        cleanup = budget.stage("service_runtime_stop")
        self.assertEqual(cleanup.consume_output(20), 100)

    def test_default_stage_timeout_covers_unregistered_stage_names(self) -> None:
        clock = FakeClock()
        budget = RunBudget(
            default_stage_timeout=4.0,
            stage_timeouts={"probe": 2.0},
            clock=clock,
        )

        self.assertEqual(budget.stage("report").deadline, 4.0)
        self.assertEqual(budget.stage("probe").deadline, 2.0)

    def test_stage_timeout_has_structured_stage_reason(self) -> None:
        clock = FakeClock()
        budget = RunBudget(
            total_timeout=30.0,
            stage_timeouts={"probe": 3.0},
            clock=clock,
        )
        stage = budget.stage("probe")
        clock.advance(3.0)

        with self.assertRaises(BudgetExceeded) as caught:
            stage.check()

        error = caught.exception
        self.assertEqual(error.reason, BudgetReason.STAGE_TIMEOUT)
        self.assertEqual(error.stage, "probe")
        self.assertEqual(error.limit, 3.0)
        self.assertEqual(error.observed, 3.0)

    def test_stage_context_checks_budget_on_exit(self) -> None:
        clock = FakeClock()
        budget = RunBudget(
            stage_timeouts={"planning": 2.0},
            clock=clock,
        )

        with self.assertRaises(BudgetExceeded) as caught:
            with budget.stage("planning"):
                clock.advance(2.0)

        self.assertEqual(caught.exception.reason, BudgetReason.STAGE_TIMEOUT)

    def test_probe_reservation_is_atomic_when_limit_is_exceeded(self) -> None:
        budget = RunBudget(max_probes=2, clock=FakeClock())

        self.assertEqual(budget.consume_probe(2), 2)
        with self.assertRaises(BudgetExceeded) as caught:
            budget.consume_probe()

        error = caught.exception
        self.assertEqual(error.reason, BudgetReason.PROBE_LIMIT)
        self.assertEqual(error.limit, 2)
        self.assertEqual(error.observed, 3)
        self.assertEqual(budget.probes_used, 2)

    def test_output_reservation_is_atomic_and_keeps_stage_context(self) -> None:
        budget = RunBudget(
            max_output_bytes=8,
            clock=FakeClock(),
        )
        stage = budget.stage("report")

        self.assertEqual(stage.consume_output(5), 5)
        with self.assertRaises(BudgetExceeded) as caught:
            stage.consume_output(4)

        error = caught.exception
        self.assertEqual(error.reason, BudgetReason.OUTPUT_BYTE_LIMIT)
        self.assertEqual(error.stage, "report")
        self.assertEqual(error.limit, 8)
        self.assertEqual(error.observed, 9)
        self.assertEqual(budget.output_bytes_used, 5)

    def test_cancel_is_idempotent_and_stops_all_future_work(self) -> None:
        clock = FakeClock(12.0)
        budget = RunBudget(clock=clock)

        self.assertTrue(budget.cancel("operator requested stop"))
        clock.advance(1.0)
        self.assertFalse(budget.cancel("must not replace first detail"))
        self.assertEqual(budget.remaining_time(), 0.0)

        with self.assertRaises(BudgetExceeded) as caught:
            budget.consume_probe()

        error = caught.exception
        self.assertEqual(error.reason, BudgetReason.CANCELLED)
        self.assertEqual(error.detail, "operator requested stop")
        self.assertEqual(error.snapshot.cancelled_at, 12.0)

    def test_budget_exception_is_json_serializable(self) -> None:
        budget = RunBudget(max_output_bytes=1, clock=FakeClock())

        with self.assertRaises(BudgetExceeded) as caught:
            budget.consume_output(2)

        payload = caught.exception.to_dict()
        self.assertEqual(payload["error"], "budget_exceeded")
        self.assertEqual(payload["reason"], "output_byte_limit")
        self.assertEqual(payload["budget"]["output_bytes_used"], 0)
        json.dumps(payload)

    def test_unlimited_budget_tracks_usage_without_time_limit(self) -> None:
        budget = RunBudget(clock=FakeClock())

        self.assertIsNone(budget.deadline)
        self.assertIsNone(budget.remaining_time())
        self.assertEqual(budget.consume_probe(), 1)
        self.assertEqual(budget.consume_output(128), 128)
        budget.check()

    def test_invalid_limits_and_usage_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            RunBudget(total_timeout=-1, clock=FakeClock())
        with self.assertRaises(ValueError):
            RunBudget(stage_timeouts={"probe": -1}, clock=FakeClock())
        with self.assertRaises(TypeError):
            RunBudget(max_probes=True, clock=FakeClock())
        with self.assertRaises(ValueError):
            RunBudget(
                deadline=10,
                total_timeout=5,
                clock=FakeClock(),
            )

        budget = RunBudget(clock=FakeClock())
        with self.assertRaises(ValueError):
            budget.consume_probe(-1)
        with self.assertRaises(TypeError):
            budget.consume_output(1.5)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
