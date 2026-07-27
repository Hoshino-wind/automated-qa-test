#!/usr/bin/env python3
import base64
import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_eval import (  # noqa: E402
    EvaluationContractError,
    EvaluationThresholds,
    hash_evaluator_bundle,
    production_registration_signing_bytes,
    score_evaluation,
)

EVALUATOR_BUNDLE_ROOT = (
    Path(__file__).resolve().parent / "fixtures" / "evaluator_bundle"
)
PRODUCTION_VERIFICATION_NOW = datetime(
    2026,
    7,
    26,
    9,
    0,
    tzinfo=UTC,
)


def canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


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
                    "infrastructure_retry_count": 0,
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
            "evaluator_bundle_hash": hash_evaluator_bundle(
                EVALUATOR_BUNDLE_ROOT
            ),
            "development_set_hash": "8" * 64,
            "split_unit": "project_defect_family_semantic_group",
            "deduplication_method": "repository and mutation-family hashes",
        },
        "cases": cases,
    }
    production_observations = {
        "schema_version": 1,
        "suite_id": "production-suite",
        "agent_bundle_hash": "a" * 64,
        "policy_hash": "b" * 64,
        "tool_registry_hash": "c" * 64,
        "model_id": "candidate-model-v1",
        "memory_snapshot_hash": "7" * 64,
        "public_regression": {
            "suite_sha256": "6" * 64,
            "baseline_score": 0.95,
            "candidate_score": 0.95,
        },
        "records": records,
    }
    budget_contract_hash = canonical_hash(
        [
            {
                "scenario_id": case["scenario_id"],
                "seed": case["seed"],
                "budget": case["budget"],
            }
            for case in cases
        ]
    )
    baseline = {
        "schema_version": 1,
        "suite_id": "production-suite",
        "candidate_kind": "deterministic_baseline",
        "agent_bundle_hash": "d" * 64,
        "policy_hash": "e" * 64,
        "tool_registry_hash": "f" * 64,
        "frozen_at": "2026-07-26T01:00:00Z",
        "corpus_hash": corpus_hash,
        "budget_contract_hash": budget_contract_hash,
        "case_count": 600,
        "scenario_count": 200,
        "seed_count_per_scenario": 3,
        "metrics": {
            "macro_defect_recall": 0.80,
            "mean_manual_plan_edits": 1.0,
        },
    }
    return production_manifest, production_observations, baseline


def signed_production_inputs(
    *,
    slo_input_set_sha256: str = "1" * 64,
    slo_thresholds_sha256: str = "2" * 64,
    slo_sampling_contract_sha256: str = "3" * 64,
    candidate_tool_registry_sha256: str = "c" * 64,
    public_candidate_score: float = 0.95,
    infrastructure_retry_count: int = 0,
) -> tuple[dict, dict, dict, dict, dict]:
    production_manifest, production_observations, baseline = (
        production_inputs()
    )
    production_observations["tool_registry_hash"] = (
        candidate_tool_registry_sha256
    )
    production_observations["public_regression"]["candidate_score"] = (
        public_candidate_score
    )
    for record in production_observations["records"]:
        record["infrastructure_retry_count"] = infrastructure_retry_count
        if infrastructure_retry_count:
            record["infrastructure_retry_reason"] = "evaluator infrastructure"
    private_key = Ed25519PrivateKey.generate()
    public_key = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    registration = {
        "schema_version": 2,
        "suite_id": "production-suite",
        "authority": "independent-evaluator",
        "key_id": "release-key-1",
        "algorithm": "Ed25519",
        "issued_at": "2026-07-26T08:30:00Z",
        "corpus_frozen_at": "2026-07-26T00:00:00Z",
        "baseline_frozen_at": "2026-07-26T01:00:00Z",
        "candidate_frozen_at": "2026-07-26T02:00:00Z",
        "gold_revealed_at": "2026-07-26T03:00:00Z",
        "evaluation_completed_at": "2026-07-26T04:00:00Z",
        "manifest_sha256": canonical_hash(production_manifest),
        "observations_sha256": canonical_hash(production_observations),
        "baseline_sha256": canonical_hash(baseline),
        "thresholds_sha256": canonical_hash(
            asdict(EvaluationThresholds())
        ),
        "corpus_sha256": production_manifest["corpus_hash"],
        "budget_contract_sha256": baseline["budget_contract_hash"],
        "evaluator_bundle_sha256": hash_evaluator_bundle(
            EVALUATOR_BUNDLE_ROOT
        ),
        "slo_input_set_sha256": slo_input_set_sha256,
        "slo_thresholds_sha256": slo_thresholds_sha256,
        "slo_sampling_contract_sha256": (
            slo_sampling_contract_sha256
        ),
        "candidate": {
            "agent_bundle_sha256": "a" * 64,
            "policy_sha256": "b" * 64,
            "tool_registry_sha256": candidate_tool_registry_sha256,
            "model_id": "candidate-model-v1",
            "memory_snapshot_sha256": "7" * 64,
        },
        "baseline": {
            "agent_bundle_sha256": "d" * 64,
            "policy_sha256": "e" * 64,
            "tool_registry_sha256": "f" * 64,
        },
    }
    signature = private_key.sign(
        production_registration_signing_bytes(registration)
    )
    registration["signature"] = (
        base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    )
    trust = {
        "schema_version": 2,
        "checked_at": "2026-07-26T08:00:00Z",
        "expires_at": "2026-07-27T08:00:00Z",
        "trusted_evaluators": [
            {
                "authority": "independent-evaluator",
                "key_id": "release-key-1",
                "algorithm": "Ed25519",
                "public_key_pem": public_key,
                "suite_ids": ["production-suite"],
                "purpose": "qa_agent_production_evaluator",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "revoked": False,
            }
        ],
    }
    return (
        production_manifest,
        production_observations,
        baseline,
        registration,
        trust,
    )


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

    def test_scorer_does_not_trust_self_reported_run_proof_outcome(
        self,
    ) -> None:
        candidate = observations()
        candidate["records"][0].update(
            {
                "proof_valid": True,
                "outcome_category": "success",
                "proof_graph_sha256": "f" * 64,
            }
        )

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
        (
            production_manifest,
            production_observations,
            baseline,
            registration,
            trust,
        ) = (
            signed_production_inputs()
        )

        report = score_evaluation(
            production_manifest,
            production_observations,
            baseline=baseline,
            production=True,
            production_registration=registration,
            evaluator_trust=trust,
            evaluator_bundle_root=EVALUATOR_BUNDLE_ROOT,
            verification_now=PRODUCTION_VERIFICATION_NOW,
        )

        self.assertTrue(report["qualified"])
        self.assertTrue(report["not_authorization"])
        self.assertFalse(report["p2_admission_allowed"])
        self.assertEqual(report["scenario_count"], 200)
        self.assertEqual(report["case_count"], 600)

    def test_unsigned_or_tampered_production_inputs_fail_closed(self) -> None:
        (
            production_manifest,
            production_observations,
            baseline,
            registration,
            trust,
        ) = signed_production_inputs()

        with self.assertRaises(EvaluationContractError) as unsigned:
            score_evaluation(
                production_manifest,
                production_observations,
                baseline=baseline,
                production=True,
            )
        self.assertEqual(
            unsigned.exception.code,
            "production_registration_missing",
        )

        baseline["metrics"]["macro_defect_recall"] = 0.1
        with self.assertRaises(EvaluationContractError) as tampered:
            score_evaluation(
                production_manifest,
                production_observations,
                baseline=baseline,
                production=True,
                production_registration=registration,
                evaluator_trust=trust,
                evaluator_bundle_root=EVALUATOR_BUNDLE_ROOT,
                verification_now=PRODUCTION_VERIFICATION_NOW,
            )
        self.assertEqual(
            tampered.exception.code,
            "production_registration_binding_mismatch",
        )

    def test_public_regression_and_retry_limits_are_release_gates(self) -> None:
        degraded = signed_production_inputs(public_candidate_score=0.90)
        degraded_report = score_evaluation(
            degraded[0],
            degraded[1],
            baseline=degraded[2],
            production=True,
            production_registration=degraded[3],
            evaluator_trust=degraded[4],
            evaluator_bundle_root=EVALUATOR_BUNDLE_ROOT,
            verification_now=PRODUCTION_VERIFICATION_NOW,
        )
        self.assertFalse(degraded_report["qualified"])
        self.assertIn(
            "public_regression_drop",
            {
                failure["code"]
                for failure in degraded_report["gate_failures"]
            },
        )

        retried = signed_production_inputs(infrastructure_retry_count=2)
        retry_report = score_evaluation(
            retried[0],
            retried[1],
            baseline=retried[2],
            production=True,
            production_registration=retried[3],
            evaluator_trust=retried[4],
            evaluator_bundle_root=EVALUATOR_BUNDLE_ROOT,
            verification_now=PRODUCTION_VERIFICATION_NOW,
        )
        self.assertFalse(retry_report["qualified"])
        self.assertIn(
            "infrastructure_retry_limit_exceeded",
            {
                failure["code"]
                for failure in retry_report["gate_failures"]
            },
        )

    def test_signature_key_revocation_and_freeze_order_fail_closed(self) -> None:
        values = signed_production_inputs()
        manifest_value, observation_value, baseline = values[:3]
        registration = copy.deepcopy(values[3])
        trust = copy.deepcopy(values[4])

        registration["signature"] = (
            registration["signature"][:-1]
            + ("A" if registration["signature"][-1] != "A" else "B")
        )
        with self.assertRaises(EvaluationContractError) as signature:
            score_evaluation(
                manifest_value,
                observation_value,
                baseline=baseline,
                production=True,
                production_registration=registration,
                evaluator_trust=trust,
                evaluator_bundle_root=EVALUATOR_BUNDLE_ROOT,
                verification_now=PRODUCTION_VERIFICATION_NOW,
            )
        self.assertEqual(
            signature.exception.code,
            "production_registration_signature_invalid",
        )

        registration = values[3]
        trust["trusted_evaluators"][0]["revoked"] = True
        with self.assertRaises(EvaluationContractError) as revoked:
            score_evaluation(
                manifest_value,
                observation_value,
                baseline=baseline,
                production=True,
                production_registration=registration,
                evaluator_trust=trust,
                evaluator_bundle_root=EVALUATOR_BUNDLE_ROOT,
                verification_now=PRODUCTION_VERIFICATION_NOW,
            )
        self.assertEqual(
            revoked.exception.code,
            "production_evaluator_key_revoked",
        )

        invalid_order = copy.deepcopy(values[3])
        invalid_order["candidate_frozen_at"] = invalid_order[
            "gold_revealed_at"
        ]
        with self.assertRaises(EvaluationContractError) as ordering:
            score_evaluation(
                manifest_value,
                observation_value,
                baseline=baseline,
                production=True,
                production_registration=invalid_order,
                evaluator_trust=values[4],
                evaluator_bundle_root=EVALUATOR_BUNDLE_ROOT,
                verification_now=PRODUCTION_VERIFICATION_NOW,
            )
        self.assertEqual(
            ordering.exception.code,
            "production_registration_time_order_invalid",
        )

    def test_registration_currentness_and_bundle_are_recomputed(self) -> None:
        values = signed_production_inputs()

        with self.assertRaises(EvaluationContractError) as missing_bundle:
            score_evaluation(
                values[0],
                values[1],
                baseline=values[2],
                production=True,
                production_registration=values[3],
                evaluator_trust=values[4],
                verification_now=PRODUCTION_VERIFICATION_NOW,
            )
        self.assertEqual(
            missing_bundle.exception.code,
            "production_evaluator_bundle_unavailable",
        )

        with tempfile.TemporaryDirectory() as temporary:
            foreign_bundle = Path(temporary)
            (foreign_bundle / "evaluator.py").write_text(
                "print('foreign')\n",
                encoding="utf-8",
            )
            with self.assertRaises(EvaluationContractError) as mismatch:
                score_evaluation(
                    values[0],
                    values[1],
                    baseline=values[2],
                    production=True,
                    production_registration=values[3],
                    evaluator_trust=values[4],
                    evaluator_bundle_root=foreign_bundle,
                    verification_now=PRODUCTION_VERIFICATION_NOW,
                )
            self.assertEqual(
                mismatch.exception.code,
                "production_evaluator_bundle_content_mismatch",
            )

        with self.assertRaises(EvaluationContractError) as future:
            score_evaluation(
                values[0],
                values[1],
                baseline=values[2],
                production=True,
                production_registration=values[3],
                evaluator_trust=values[4],
                evaluator_bundle_root=EVALUATOR_BUNDLE_ROOT,
                verification_now=datetime(
                    2026,
                    7,
                    26,
                    8,
                    29,
                    tzinfo=UTC,
                ),
            )
        self.assertEqual(
            future.exception.code,
            "production_registration_issued_in_future",
        )

        with self.assertRaises(EvaluationContractError) as stale:
            score_evaluation(
                values[0],
                values[1],
                baseline=values[2],
                production=True,
                production_registration=values[3],
                evaluator_trust=values[4],
                evaluator_bundle_root=EVALUATOR_BUNDLE_ROOT,
                verification_now=datetime(
                    2026,
                    9,
                    1,
                    tzinfo=UTC,
                ),
            )
        self.assertEqual(
            stale.exception.code,
            "production_registration_stale",
        )

        stale_trust = copy.deepcopy(values[4])
        stale_trust["checked_at"] = "2026-07-24T08:00:00Z"
        stale_trust["expires_at"] = "2026-07-27T08:00:00Z"
        with self.assertRaises(EvaluationContractError) as trust:
            score_evaluation(
                values[0],
                values[1],
                baseline=values[2],
                production=True,
                production_registration=values[3],
                evaluator_trust=stale_trust,
                evaluator_bundle_root=EVALUATOR_BUNDLE_ROOT,
                verification_now=PRODUCTION_VERIFICATION_NOW,
            )
        self.assertIn(
            trust.exception.code,
            {
                "production_trust_snapshot_stale",
                "production_trust_snapshot_window_invalid",
            },
        )

        expired_key = copy.deepcopy(values[4])
        expired_key["trusted_evaluators"][0][
            "valid_until"
        ] = "2026-07-26T08:30:00Z"
        with self.assertRaises(EvaluationContractError) as key:
            score_evaluation(
                values[0],
                values[1],
                baseline=values[2],
                production=True,
                production_registration=values[3],
                evaluator_trust=expired_key,
                evaluator_bundle_root=EVALUATOR_BUNDLE_ROOT,
                verification_now=PRODUCTION_VERIFICATION_NOW,
            )
        self.assertEqual(
            key.exception.code,
            "production_evaluator_key_outside_validity",
        )

    def test_evaluator_bundle_tree_rejects_symlink_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.py"
            source.write_text("print('fixture')\n", encoding="utf-8")
            alias = root / "alias.py"
            os.link(source, alias)

            with self.assertRaises(EvaluationContractError) as hardlink:
                hash_evaluator_bundle(root)

            self.assertEqual(
                hardlink.exception.code,
                "production_evaluator_bundle_hardlink_rejected",
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.py"
            target.write_text("print('fixture')\n", encoding="utf-8")
            (root / "alias.py").symlink_to(target)

            with self.assertRaises(EvaluationContractError) as symlink:
                hash_evaluator_bundle(root)

            self.assertEqual(
                symlink.exception.code,
                "production_evaluator_bundle_symlink_rejected",
            )


if __name__ == "__main__":
    unittest.main()
