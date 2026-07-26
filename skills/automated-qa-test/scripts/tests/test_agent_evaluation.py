#!/usr/bin/env python3
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_eval import EvaluationContractError, score_evaluation  # noqa: E402


def manifest() -> dict:
    common = {
        "project_id": "project-a",
        "semantic_group": "checkout",
        "safety_critical": False,
        "valid_input": True,
        "budget": {"max_seconds": 60, "max_actions": 10},
    }
    return {
        "schema_version": 1,
        "suite_id": "suite-1",
        "cases": [
            {
                **common,
                "scenario_id": "defect-1",
                "seed": 1,
                "kind": "defect",
                "safety_critical": True,
                "defect_family": "integrity",
                "required_defect_ids": ["D1"],
                "expected_failure_layer": "persistence",
            },
            {
                **common,
                "scenario_id": "clean-1",
                "seed": 1,
                "kind": "clean",
                "required_defect_ids": [],
                "expected_failure_layer": None,
            },
            {
                **common,
                "scenario_id": "blocker-1",
                "seed": 1,
                "kind": "blocker",
                "required_defect_ids": [],
                "expected_failure_layer": "environment",
            },
        ],
    }


def observations() -> dict:
    common = {
        "unsafe_action_count": 0,
        "stale_required_evidence_count": 0,
        "double_commit_count": 0,
        "proof_bundle_complete": True,
        "handoff_structured": True,
        "plan_executable": True,
        "converged": True,
        "elapsed_seconds": 10.0,
        "action_count": 3,
        "manual_plan_edits": 0,
    }
    return {
        "schema_version": 1,
        "suite_id": "suite-1",
        "agent_bundle_hash": "a" * 64,
        "policy_hash": "b" * 64,
        "tool_registry_hash": "c" * 64,
        "records": [
            {
                **common,
                "scenario_id": "defect-1",
                "seed": 1,
                "verdict": "failed",
                "can_claim_pass": False,
                "detected_defect_ids": ["D1"],
                "attributed_layer": "persistence",
            },
            {
                **common,
                "scenario_id": "clean-1",
                "seed": 1,
                "verdict": "passed",
                "can_claim_pass": True,
                "detected_defect_ids": [],
                "attributed_layer": None,
            },
            {
                **common,
                "scenario_id": "blocker-1",
                "seed": 1,
                "verdict": "blocked",
                "can_claim_pass": False,
                "detected_defect_ids": [],
                "attributed_layer": "environment",
            },
        ],
    }


def production_inputs() -> tuple[dict, dict, dict]:
    cases = []
    records = []
    for index in range(200):
        if index < 80:
            kind = "defect"
        elif index < 120:
            kind = "clean"
        else:
            kind = "blocker"
        scenario_id = f"scenario-{index:03d}"
        required = [f"D{index}"] if kind == "defect" else []
        expected_layer = None if kind == "clean" else "persistence"
        for seed in range(3):
            case = {
                "scenario_id": scenario_id,
                "seed": seed,
                "project_id": f"project-{index // 10}",
                "semantic_group": f"group-{index // 5}",
                "kind": kind,
                "safety_critical": index < 40,
                "required_defect_ids": required,
                "expected_failure_layer": expected_layer,
                "valid_input": True,
                "budget": {
                    "max_seconds": 60,
                    "max_actions": 10,
                },
                "tags": [],
            }
            if kind == "defect":
                case["defect_family"] = f"family-{index % 8}"
            cases.append(case)
            passed = kind == "clean"
            verdict = (
                "passed"
                if passed
                else "failed"
                if kind == "defect"
                else "blocked"
            )
            records.append(
                {
                    "scenario_id": scenario_id,
                    "seed": seed,
                    "verdict": verdict,
                    "can_claim_pass": passed,
                    "detected_defect_ids": required,
                    "attributed_layer": expected_layer,
                    "unsafe_action_count": 0,
                    "stale_required_evidence_count": 0,
                    "double_commit_count": 0,
                    "proof_bundle_complete": True,
                    "handoff_structured": True,
                    "plan_executable": True,
                    "converged": True,
                    "elapsed_seconds": 10.0,
                    "action_count": 3,
                    "manual_plan_edits": 0,
                }
            )
    corpus_hash = hashlib.sha256(
        json.dumps(
            cases,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    production_manifest = {
        "schema_version": 1,
        "suite_id": "production-suite",
        "frozen_at": "2026-07-26T00:00:00Z",
        "corpus_hash": corpus_hash,
        "independence": {
            "evaluator_owner": "independent-evaluator",
            "agent_read_only": True,
            "gold_hidden": True,
            "candidate_frozen_before_reveal": True,
            "pre_registered": True,
        },
        "cases": cases,
    }
    production_observations = {
        "schema_version": 1,
        "suite_id": "production-suite",
        "agent_bundle_hash": "a" * 64,
        "policy_hash": "b" * 64,
        "tool_registry_hash": "c" * 64,
        "records": records,
    }
    baseline = {
        "schema_version": 1,
        "suite_id": "production-suite",
        "candidate_kind": "deterministic_baseline",
        "agent_bundle_hash": "d" * 64,
        "policy_hash": "e" * 64,
        "tool_registry_hash": "f" * 64,
        "metrics": {
            "macro_defect_recall": 0.80,
            "mean_manual_plan_edits": 1.0,
        },
    }
    return production_manifest, production_observations, baseline


class AgentEvaluationTests(unittest.TestCase):
    def test_perfect_development_suite_qualifies(self) -> None:
        report = score_evaluation(manifest(), observations())

        self.assertTrue(report["qualified"])
        self.assertEqual(report["safety"]["erroneous_pass_count"], 0)
        self.assertEqual(report["metrics"]["macro_defect_recall"], 1.0)

    def test_erroneous_pass_is_lexicographic_release_blocker(self) -> None:
        rows = observations()
        rows["records"][0]["can_claim_pass"] = True
        rows["records"][0]["verdict"] = "passed"

        report = score_evaluation(manifest(), rows)

        self.assertFalse(report["qualified"])
        self.assertIn(
            "erroneous_pass",
            {failure["code"] for failure in report["gate_failures"]},
        )

    def test_unsafe_execution_blocks_even_with_perfect_quality(self) -> None:
        rows = observations()
        rows["records"][2]["unsafe_action_count"] = 1

        report = score_evaluation(manifest(), rows)

        self.assertFalse(report["qualified"])
        self.assertEqual(report["safety"]["unsafe_action_count"], 1)

    def test_missing_or_extra_observations_are_rejected(self) -> None:
        missing = observations()
        missing["records"].pop()
        with self.assertRaises(EvaluationContractError) as missing_error:
            score_evaluation(manifest(), missing)
        self.assertEqual(missing_error.exception.code, "case_coverage_mismatch")

        extra = observations()
        extra["records"].append(
            {
                **copy.deepcopy(extra["records"][0]),
                "scenario_id": "unknown",
            }
        )
        with self.assertRaises(EvaluationContractError) as extra_error:
            score_evaluation(manifest(), extra)
        self.assertEqual(extra_error.exception.code, "case_coverage_mismatch")

    def test_empty_defect_or_clean_denominators_never_score_as_success(self) -> None:
        no_defect_manifest = manifest()
        no_defect_manifest["cases"] = [no_defect_manifest["cases"][1]]
        no_defect_rows = observations()
        no_defect_rows["records"] = [no_defect_rows["records"][1]]

        with self.assertRaises(EvaluationContractError) as caught:
            score_evaluation(no_defect_manifest, no_defect_rows)

        self.assertEqual(caught.exception.code, "defect_denominator_empty")

    def test_no_detected_claims_have_zero_precision(self) -> None:
        rows = observations()
        rows["records"][0]["detected_defect_ids"] = []

        report = score_evaluation(manifest(), rows)

        self.assertEqual(report["metrics"]["claim_precision"], 0.0)
        self.assertFalse(report["qualified"])

    def test_wrong_layer_and_false_clean_claim_reduce_quality(self) -> None:
        rows = observations()
        rows["records"][0]["attributed_layer"] = "ui"
        rows["records"][1]["detected_defect_ids"] = ["invented"]

        report = score_evaluation(manifest(), rows)

        self.assertEqual(report["metrics"]["attribution_accuracy"], 0.0)
        self.assertEqual(report["metrics"]["clean_specificity"], 0.0)
        self.assertFalse(report["qualified"])

    def test_baseline_gain_is_a_separate_gate(self) -> None:
        baseline = {
            "metrics": {
                "macro_defect_recall": 0.95,
                "mean_manual_plan_edits": 2.0,
            }
        }

        report = score_evaluation(
            manifest(),
            observations(),
            baseline=baseline,
        )

        self.assertFalse(report["qualified"])
        self.assertIn(
            "baseline_recall_gain",
            {failure["code"] for failure in report["gate_failures"]},
        )

    def test_production_mode_requires_registered_corpus_shape(self) -> None:
        with self.assertRaises(EvaluationContractError) as caught:
            score_evaluation(
                manifest(),
                observations(),
                production=True,
            )

        self.assertEqual(
            caught.exception.code,
            "production_corpus_insufficient",
        )

    def test_unknown_fields_are_rejected(self) -> None:
        candidate = observations()
        candidate["records"][0]["self_reported_score"] = 1.0

        with self.assertRaises(EvaluationContractError) as caught:
            score_evaluation(manifest(), candidate)

        self.assertEqual(caught.exception.code, "fields_invalid")

    def test_verdict_and_pass_boolean_must_be_consistent(self) -> None:
        candidate = observations()
        candidate["records"][1]["can_claim_pass"] = False

        with self.assertRaises(EvaluationContractError) as caught:
            score_evaluation(manifest(), candidate)

        self.assertEqual(caught.exception.code, "verdict_pass_mismatch")

    def test_budget_overrun_is_a_lexicographic_blocker(self) -> None:
        candidate = observations()
        candidate["records"][0]["elapsed_seconds"] = 61.0

        report = score_evaluation(manifest(), candidate)

        self.assertFalse(report["qualified"])
        self.assertEqual(report["safety"]["budget_violation_count"], 1)
        self.assertIn(
            "budget_exceeded",
            {failure["code"] for failure in report["gate_failures"]},
        )

    def test_report_binds_all_frozen_input_hashes(self) -> None:
        baseline = {
            "metrics": {
                "macro_defect_recall": 0.5,
                "mean_manual_plan_edits": 2.0,
            }
        }

        report = score_evaluation(
            manifest(),
            observations(),
            baseline=baseline,
        )

        self.assertEqual(
            len(report["frozen_inputs"]["manifest_sha256"]),
            64,
        )
        self.assertEqual(
            len(report["frozen_inputs"]["observations_sha256"]),
            64,
        )
        self.assertEqual(
            len(report["frozen_inputs"]["baseline_sha256"]),
            64,
        )

    def test_registered_production_corpus_can_reach_release_gate(self) -> None:
        production_manifest, production_observations, baseline = (
            production_inputs()
        )

        report = score_evaluation(
            production_manifest,
            production_observations,
            baseline=baseline,
            production=True,
        )

        self.assertTrue(report["qualified"])
        self.assertEqual(report["scenario_count"], 200)
        self.assertEqual(report["case_count"], 600)


if __name__ == "__main__":
    unittest.main()
