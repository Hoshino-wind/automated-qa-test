#!/usr/bin/env python3
from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import agent_release_admission  # noqa: E402
from qa_core.tools import build_default_tool_registry  # noqa: E402
from qa_eval import (  # noqa: E402
    EvaluationContractError,
    evaluate_p2_release_admission,
    score_evaluation,
)

from tests.test_agent_evaluation import (  # noqa: E402
    EVALUATOR_BUNDLE_ROOT,
    PRODUCTION_VERIFICATION_NOW,
    canonical_hash,
    signed_production_inputs,
)


def _sampling_contract() -> dict:
    return {
        "schema_version": 1,
        "mode": "production",
        "registered_at": "2026-07-19T00:00:00Z",
        "window_started_at": "2026-07-20T00:00:00Z",
        "window_ended_at": "2026-07-26T08:00:00Z",
        "maximum_run_age_seconds": 604800,
        "minimum_run_count": 20,
        "required_categories": [
            "cancellation_or_timeout",
            "failure",
            "success",
        ],
    }


def _qualified_inputs() -> tuple[dict, dict, tuple[dict, ...]]:
    slo_input_hash = "1" * 64
    slo_threshold_hash = "2" * 64
    sampling_contract = _sampling_contract()
    sampling_hash = canonical_hash(sampling_contract)
    (
        manifest,
        observations,
        baseline,
        registration,
        trust,
    ) = signed_production_inputs(
        slo_input_set_sha256=slo_input_hash,
        slo_thresholds_sha256=slo_threshold_hash,
        slo_sampling_contract_sha256=sampling_hash,
        candidate_tool_registry_sha256=(
            build_default_tool_registry().canonical_sha256
        ),
    )
    evaluation = score_evaluation(
        manifest,
        observations,
        baseline=baseline,
        production=True,
        production_registration=registration,
        evaluator_trust=trust,
        evaluator_bundle_root=EVALUATOR_BUNDLE_ROOT,
        verification_now=PRODUCTION_VERIFICATION_NOW,
    )
    candidate = evaluation["candidate_identity"]
    slo = {
        "schema_version": 2,
        "qualified": True,
        "analysis_qualified": True,
        "not_production_qualified": False,
        "provenance": "verified_run_proof",
        "proof_results": [
            {
                "run_dir": "/isolated/evaluator/run-1",
                "valid": True,
                "candidate_identity": candidate,
            }
        ],
        "candidate_identity": candidate,
        "candidate_identity_sha256": canonical_hash(candidate),
        "sampling_contract": sampling_contract,
        "sampling_contract_sha256": sampling_hash,
        "sampling": {
            "mode": "production",
            "passed": True,
            "run_count": 20,
        },
        "inputs": {
            "input_set_sha256": slo_input_hash,
            "thresholds_sha256": slo_threshold_hash,
            "sha256": {"sampling_contract": sampling_hash},
        },
    }
    return (
        evaluation,
        slo,
        (manifest, observations, baseline, registration, trust),
    )


def _evaluate(
    values: tuple[dict, ...],
    *,
    supplied_evaluation: dict,
    supplied_slo: dict,
    recomputed_slo: dict,
) -> dict:
    with patch(
        "qa_eval.admission.aggregate_run_directories",
        return_value=recomputed_slo,
    ):
        return evaluate_p2_release_admission(
            manifest=values[0],
            observations=values[1],
            baseline=values[2],
            production_registration=values[3],
            evaluator_trust=values[4],
            supplied_evaluation_report=supplied_evaluation,
            supplied_slo_report=supplied_slo,
            run_dirs=["/isolated/evaluator/run-1"],
            slo_sampling_contract=_sampling_contract(),
            evaluator_bundle_root=EVALUATOR_BUNDLE_ROOT,
            verification_now=PRODUCTION_VERIFICATION_NOW,
        )


class ReleaseAdmissionTests(unittest.TestCase):
    def test_both_recomputed_gates_issue_release_only_admission(self) -> None:
        evaluation, slo, values = _qualified_inputs()

        admission = _evaluate(
            values,
            supplied_evaluation=evaluation,
            supplied_slo=slo,
            recomputed_slo=slo,
        )

        self.assertTrue(admission["admission_allowed"])
        self.assertTrue(admission["not_authorization"])
        self.assertEqual(
            admission["authorization_scope"],
            "release_admission_only",
        )
        self.assertFalse(admission["runtime_tool_authorization"])
        self.assertEqual(
            admission["scope"],
            "p2_parallel_multi_agent_release",
        )

    def test_missing_or_forged_report_cannot_unlock_admission(self) -> None:
        evaluation, slo, values = _qualified_inputs()
        forged = copy.deepcopy(evaluation)
        forged["qualified"] = False

        with self.assertRaises(EvaluationContractError) as caught:
            _evaluate(
                values,
                supplied_evaluation=forged,
                supplied_slo=slo,
                recomputed_slo=slo,
            )
        self.assertEqual(
            caught.exception.code,
            "evaluation_report_not_current",
        )

        with self.assertRaises(EvaluationContractError) as missing:
            _evaluate(
                values,
                supplied_evaluation=evaluation,
                supplied_slo={},
                recomputed_slo=slo,
            )
        self.assertEqual(missing.exception.code, "slo_report_not_current")

    def test_either_gate_or_signed_cross_binding_failure_rejects(self) -> None:
        evaluation, slo, values = _qualified_inputs()
        failed_slo = copy.deepcopy(slo)
        failed_slo["qualified"] = False

        admission = _evaluate(
            values,
            supplied_evaluation=evaluation,
            supplied_slo=failed_slo,
            recomputed_slo=failed_slo,
        )
        self.assertFalse(admission["admission_allowed"])
        self.assertTrue(admission["not_authorization"])
        self.assertIn(
            "proof_backed_slo_not_qualified",
            {item["code"] for item in admission["gate_failures"]},
        )

        mismatched_slo = copy.deepcopy(slo)
        mismatched_slo["inputs"]["input_set_sha256"] = "3" * 64
        admission = _evaluate(
            values,
            supplied_evaluation=evaluation,
            supplied_slo=mismatched_slo,
            recomputed_slo=mismatched_slo,
        )
        self.assertFalse(admission["admission_allowed"])
        self.assertIn(
            "signed_slo_input_set_mismatch",
            {item["code"] for item in admission["gate_failures"]},
        )

    def test_evaluation_a_cannot_be_spliced_with_candidate_b_runs(self) -> None:
        evaluation, slo, values = _qualified_inputs()
        foreign_slo = copy.deepcopy(slo)
        foreign_identity = copy.deepcopy(
            foreign_slo["candidate_identity"]
        )
        foreign_identity["agent_bundle_sha256"] = "4" * 64
        foreign_slo["candidate_identity"] = foreign_identity
        foreign_slo["proof_results"][0][
            "candidate_identity"
        ] = foreign_identity

        admission = _evaluate(
            values,
            supplied_evaluation=evaluation,
            supplied_slo=foreign_slo,
            recomputed_slo=foreign_slo,
        )

        self.assertFalse(admission["admission_allowed"])
        self.assertTrue(admission["not_authorization"])
        self.assertIn(
            "slo_candidate_identity_mismatch",
            {item["code"] for item in admission["gate_failures"]},
        )

    def test_cli_recomputes_both_reports_before_issuing_admission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            run_dir.mkdir()
            evaluation, slo, values = _qualified_inputs()
            slo["proof_results"][0]["run_dir"] = str(run_dir)
            named_values = {
                "manifest": values[0],
                "observations": values[1],
                "baseline": values[2],
                "registration": values[3],
                "trust": values[4],
                "evaluation": evaluation,
                "slo": slo,
                "sampling_contract": _sampling_contract(),
            }
            paths = {}
            for name, value in named_values.items():
                path = root / f"{name}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                paths[name] = path
            output_path = root / "admission.json"

            with patch(
                "qa_eval.admission.aggregate_run_directories",
                return_value=slo,
            ), patch(
                "qa_eval.registration._trusted_now",
                return_value=PRODUCTION_VERIFICATION_NOW,
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                exit_code = agent_release_admission.main(
                    [
                        "--manifest",
                        str(paths["manifest"]),
                        "--observations",
                        str(paths["observations"]),
                        "--baseline",
                        str(paths["baseline"]),
                        "--registration",
                        str(paths["registration"]),
                        "--trust-config",
                        str(paths["trust"]),
                        "--evaluation-report",
                        str(paths["evaluation"]),
                        "--slo-report",
                        str(paths["slo"]),
                        "--slo-sampling-contract",
                        str(paths["sampling_contract"]),
                        "--evaluator-bundle-dir",
                        str(EVALUATOR_BUNDLE_ROOT),
                        "--run-dir",
                        str(run_dir),
                        "--out",
                        str(output_path),
                    ]
                )

            self.assertEqual(exit_code, 0)
            admission = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(admission["admission_allowed"])
            self.assertTrue(admission["not_authorization"])
            self.assertFalse(admission["runtime_tool_authorization"])


if __name__ == "__main__":
    unittest.main()
