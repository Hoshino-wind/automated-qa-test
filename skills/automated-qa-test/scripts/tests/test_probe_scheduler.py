#!/usr/bin/env python3
import math
import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.scheduling import (  # noqa: E402
    ProbeCandidate,
    ScheduleBudget,
    ScheduleRequest,
    SchedulingContractError,
    build_probe_schedule,
)
from qa_core.scheduling.scheduler import (  # noqa: E402
    _checked_fsum,
    _resource_is_same_or_ancestor,
)
from qa_core.tools import build_default_tool_registry  # noqa: E402


def candidate(
    candidate_id: str,
    *,
    action: str = "expectText",
    tool_version: str | None = None,
    tool_spec_sha256: str | None = None,
    estimated_cost: float = 1,
    estimated_time_seconds: float = 1,
    information_gain: float = 1,
    dependencies: tuple[str, ...] = (),
) -> ProbeCandidate:
    spec = build_default_tool_registry().get(action)
    return ProbeCandidate(
        id=candidate_id,
        action=action,
        tool_version=tool_version or spec.version,
        tool_spec_sha256=tool_spec_sha256 or spec.canonical_sha256,
        estimated_cost=estimated_cost,
        estimated_time_seconds=estimated_time_seconds,
        information_gain=information_gain,
        dependencies=dependencies,
    )


def budget(
    *,
    max_total_cost: float = 100,
    max_total_time_seconds: float = 100,
    max_actions: int = 20,
    max_parallelism: int = 4,
) -> ScheduleBudget:
    return ScheduleBudget(
        max_total_cost=max_total_cost,
        max_total_time_seconds=max_total_time_seconds,
        max_actions=max_actions,
        max_parallelism=max_parallelism,
    )


def request(
    *candidates: ProbeCandidate,
    schedule_budget: ScheduleBudget | None = None,
) -> ScheduleRequest:
    return ScheduleRequest(
        tool_registry_sha256=(
            build_default_tool_registry().canonical_sha256
        ),
        budget=schedule_budget or budget(),
        candidates=tuple(candidates),
    )


def payload(
    *candidates: ProbeCandidate,
    schedule_budget: ScheduleBudget | None = None,
) -> dict:
    return {
        "schema_version": 1,
        "tool_registry_sha256": (
            build_default_tool_registry().canonical_sha256
        ),
        "budget": (
            schedule_budget or budget()
        ).to_dict(),
        "candidates": [
            item.to_dict() for item in candidates
        ],
    }


class SchedulingContractTests(unittest.TestCase):
    def test_schema_is_closed_and_nonfinite_numbers_are_rejected(
        self,
    ) -> None:
        valid = payload(candidate("probe-a"))
        valid["unexpected"] = True
        with self.assertRaises(SchedulingContractError) as unknown:
            ScheduleRequest.from_dict(valid)
        self.assertEqual(
            unknown.exception.code,
            "request_fields_unknown",
        )

        nested = payload(candidate("probe-a"))
        nested["candidates"][0]["executor"] = "forged"
        with self.assertRaises(SchedulingContractError) as nested_unknown:
            ScheduleRequest.from_dict(nested)
        self.assertEqual(
            nested_unknown.exception.code,
            "candidate_fields_unknown",
        )

        for nonfinite in (math.nan, math.inf, -math.inf):
            with self.subTest(nonfinite=nonfinite):
                invalid = payload(candidate("probe-a"))
                invalid["candidates"][0][
                    "information_gain"
                ] = nonfinite
                with self.assertRaises(SchedulingContractError) as caught:
                    ScheduleRequest.from_dict(invalid)
                self.assertEqual(
                    caught.exception.code,
                    "finite_number_invalid",
                )

        wrong_version = payload(candidate("probe-a"))
        wrong_version["schema_version"] = True
        with self.assertRaises(SchedulingContractError) as version:
            ScheduleRequest.from_dict(wrong_version)
        self.assertEqual(
            version.exception.code,
            "schedule_schema_unsupported",
        )

    def test_input_order_does_not_change_schedule_or_hash(self) -> None:
        setup = candidate(
            "setup",
            information_gain=0,
        )
        probe = candidate(
            "probe",
            dependencies=("setup",),
            information_gain=5,
        )
        left_request = request(probe, setup)
        right_request = ScheduleRequest.from_dict(
            payload(setup, probe),
        )

        left = build_probe_schedule(left_request)
        right = build_probe_schedule(right_request)

        self.assertEqual(
            left_request.canonical_sha256,
            right_request.canonical_sha256,
        )
        self.assertEqual(left.to_dict(), right.to_dict())
        self.assertEqual(
            left.canonical_sha256,
            left.to_dict()["schedule_sha256"],
        )
        self.assertTrue(left.to_dict()["not_authorization"])
        self.assertFalse(left.to_dict()["admission_allowed"])
        self.assertFalse(
            left.to_dict()["parallel_execution_authorized"]
        )

    def test_untrusted_policy_metadata_is_rejected_and_spec_is_bound(
        self,
    ) -> None:
        for forged_field, value in (
            ("authorization_sha256", "a" * 64),
            ("risk_class", "low"),
            ("idempotent", True),
            ("read", []),
            ("write", []),
            ("side_effects", []),
            ("capabilities", []),
        ):
            with self.subTest(forged_field=forged_field):
                invalid = payload(candidate("probe"))
                invalid["candidates"][0][forged_field] = value
                with self.assertRaises(
                    SchedulingContractError
                ) as caught:
                    ScheduleRequest.from_dict(invalid)
                self.assertEqual(
                    caught.exception.code,
                    "candidate_fields_unknown",
                )

        drifted_spec = payload(candidate("probe"))
        drifted_spec["candidates"][0]["tool_spec_sha256"] = "0" * 64
        with self.assertRaises(SchedulingContractError) as spec_error:
            ScheduleRequest.from_dict(drifted_spec)
        self.assertEqual(spec_error.exception.code, "tool_spec_drift")

        drifted_registry = payload(candidate("probe"))
        drifted_registry["tool_registry_sha256"] = "0" * 64
        with self.assertRaises(SchedulingContractError) as registry_error:
            ScheduleRequest.from_dict(drifted_registry)
        self.assertEqual(
            registry_error.exception.code,
            "tool_registry_drift",
        )

    def test_selection_includes_complete_dependency_closure(self) -> None:
        setup = candidate(
            "setup",
            estimated_cost=1,
            information_gain=0,
        )
        primary = candidate(
            "primary",
            estimated_cost=2,
            information_gain=10,
            dependencies=("setup",),
        )
        distractor = candidate(
            "distractor",
            estimated_cost=3,
            information_gain=2,
        )
        schedule = build_probe_schedule(
            request(
                distractor,
                primary,
                setup,
                schedule_budget=budget(
                    max_total_cost=3,
                    max_total_time_seconds=3,
                    max_actions=2,
                    max_parallelism=2,
                ),
            ),
        )
        result = schedule.to_dict()

        self.assertEqual(
            result["selected_ids"],
            ["primary", "setup"],
        )
        self.assertEqual(
            [
                batch["candidates"][0]["id"]
                for batch in result["batches"]
            ],
            ["setup", "primary"],
        )
        self.assertTrue(
            all(
                batch["mode"] == "serial_suggestion"
                for batch in result["batches"]
            ),
        )
        self.assertEqual(
            result["unselected"],
            [
                {
                    "id": "distractor",
                    "reason": "not_selected_within_budget",
                },
            ],
        )

    def test_only_safe_independent_actions_share_parallel_batch(
        self,
    ) -> None:
        reader_a = candidate("a-reader", action="expectText")
        reader_b = candidate(
            "b-reader",
            action="expectUrlContains",
        )
        screenshot = candidate("c-screenshot", action="screenshot")
        high_mutation_a = candidate(
            "z-api",
            action="api",
        )
        high_mutation_b = candidate(
            "z-cleanup",
            action="cleanupApi",
        )
        schedule = build_probe_schedule(
            request(
                high_mutation_b,
                reader_b,
                high_mutation_a,
                reader_a,
                screenshot,
                schedule_budget=budget(max_actions=5),
            ),
        ).to_dict()

        first = schedule["batches"][0]
        self.assertEqual(first["mode"], "parallel_suggestion")
        self.assertFalse(first["admission_allowed"])
        self.assertEqual(
            [
                item["id"] for item in first["candidates"]
            ],
            ["a-reader", "b-reader", "c-screenshot"],
        )
        for batch in schedule["batches"]:
            ids = {
                item["id"] for item in batch["candidates"]
            }
            if "z-api" in ids or "z-cleanup" in ids:
                self.assertEqual(batch["mode"], "serial_suggestion")
                self.assertEqual(len(ids), 1)

    def test_resource_ancestors_conflict_after_normalization(self) -> None:
        pairs = (
            ("db/users", "db/users/42"),
            ("/tmp/work", "/tmp/work/report.json"),
            (
                "HTTPS://EXAMPLE.COM:443/api/users",
                "https://example.com/api/users/42?view=full",
            ),
        )
        for left, right in pairs:
            with self.subTest(left=left, right=right):
                self.assertTrue(
                    _resource_is_same_or_ancestor(left, right)
                )
                self.assertTrue(
                    _resource_is_same_or_ancestor(right, left)
                )
        self.assertFalse(
            _resource_is_same_or_ancestor(
                "db/users",
                "db/orders",
            )
        )

    def test_dependent_and_high_risk_actions_are_serial(
        self,
    ) -> None:
        root = candidate("root")
        dependent_a = candidate(
            "dependent-a",
            dependencies=("root",),
        )
        dependent_b = candidate(
            "dependent-b",
            dependencies=("root",),
        )
        nonidempotent = candidate(
            "nonidempotent",
            action="api",
        )
        schedule = build_probe_schedule(
            request(
                root,
                dependent_a,
                dependent_b,
                nonidempotent,
                schedule_budget=budget(max_actions=4),
            ),
        ).to_dict()

        for batch in schedule["batches"]:
            ids = [
                item["id"] for item in batch["candidates"]
            ]
            if any(
                candidate_id
                in {
                    "dependent-a",
                    "dependent-b",
                    "nonidempotent",
                }
                for candidate_id in ids
            ):
                self.assertEqual(
                    batch["mode"],
                    "serial_suggestion",
                )
                self.assertEqual(len(ids), 1)

    def test_invalid_dependency_graph_fails_closed(
        self,
    ) -> None:
        cases = (
            (
                (
                    candidate("same"),
                    candidate(
                        "same",
                        action="expectUrlContains",
                    ),
                ),
                "candidate_id_duplicate",
            ),
            (
                (
                    candidate(
                        "probe",
                        dependencies=("missing",),
                    ),
                ),
                "dependency_unknown",
            ),
            (
                (
                    candidate("a", dependencies=("b",)),
                    candidate("b", dependencies=("a",)),
                ),
                "dependency_cycle",
            ),
        )

        for candidates, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(SchedulingContractError) as caught:
                    request(*candidates)
                self.assertEqual(caught.exception.code, code)

    def test_budget_that_cannot_fit_a_closure_fails_closed(self) -> None:
        expensive = candidate(
            "expensive",
            estimated_cost=2,
            estimated_time_seconds=2,
            information_gain=10,
        )
        with self.assertRaises(SchedulingContractError) as caught:
            build_probe_schedule(
                request(
                    expensive,
                    schedule_budget=budget(
                        max_total_cost=1,
                        max_total_time_seconds=1,
                        max_actions=1,
                        max_parallelism=1,
                    ),
                ),
            )
        self.assertEqual(
            caught.exception.code,
            "budget_insufficient",
        )

    def test_business_bounds_and_sum_overflow_fail_closed(self) -> None:
        invalid = payload(candidate("probe"))
        invalid["budget"]["max_total_time_seconds"] = 604_801
        with self.assertRaises(SchedulingContractError) as bounded:
            ScheduleRequest.from_dict(invalid)
        self.assertEqual(
            bounded.exception.code,
            "positive_number_invalid",
        )

        with self.assertRaises(SchedulingContractError) as overflow:
            _checked_fsum(
                (1e308, 1e308),
                path="$.test",
            )
        self.assertEqual(
            overflow.exception.code,
            "numeric_sum_overflow",
        )


if __name__ == "__main__":
    unittest.main()
