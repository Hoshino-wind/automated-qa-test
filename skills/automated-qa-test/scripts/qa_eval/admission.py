"""Deterministic P2 release admission over recomputed evaluation and SLO gates."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from typing import Any, Mapping

from qa_core.observability import (
    SloSamplingContract,
    SloThresholds,
    aggregate_run_directories,
)
from qa_core.tools import build_default_tool_registry

from .scoring import EvaluationContractError, score_evaluation


def evaluate_p2_release_admission(
    *,
    manifest: Mapping[str, Any],
    observations: Mapping[str, Any],
    baseline: Mapping[str, Any],
    production_registration: Mapping[str, Any],
    evaluator_trust: Mapping[str, Any],
    supplied_evaluation_report: Mapping[str, Any],
    supplied_slo_report: Mapping[str, Any],
    run_dirs: list[str | os.PathLike[str]] | tuple[str | os.PathLike[str], ...],
    slo_sampling_contract: SloSamplingContract | Mapping[str, Any],
    evaluator_bundle_root: str | os.PathLike[str],
    slo_thresholds: SloThresholds | None = None,
    additional_slo_input_hashes: Mapping[str, str] | None = None,
    verification_now: datetime | None = None,
) -> dict[str, Any]:
    """Recompute both gates and issue a release-only admission.

    The returned document never authorizes individual tools or actions.  It
    only admits the signed candidate identity to the P2 parallel/multi-agent
    release scope when both independent gates are current and pass.
    """

    recomputed_evaluation_report = score_evaluation(
        manifest,
        observations,
        baseline=baseline,
        production=True,
        production_registration=production_registration,
        evaluator_trust=evaluator_trust,
        evaluator_bundle_root=evaluator_bundle_root,
        verification_now=verification_now,
    )
    recomputed_evaluation = _object(
        "recomputed_evaluation_report",
        recomputed_evaluation_report,
    )
    candidate = _object(
        "evaluation_report.candidate_identity",
        recomputed_evaluation.get("candidate_identity"),
    )
    recomputed_slo_report = aggregate_run_directories(
        run_dirs,
        thresholds=slo_thresholds,
        additional_input_hashes=additional_slo_input_hashes,
        expected_candidate_identity=candidate,
        sampling_contract=slo_sampling_contract,
        now=verification_now,
    )
    supplied_evaluation = _object(
        "supplied_evaluation_report",
        supplied_evaluation_report,
    )
    supplied_slo = _object("supplied_slo_report", supplied_slo_report)
    recomputed_slo = _object("recomputed_slo_report", recomputed_slo_report)
    if _canonical_sha256(supplied_evaluation) != _canonical_sha256(
        recomputed_evaluation
    ):
        raise EvaluationContractError(
            "evaluation_report_not_current",
            "supplied evaluation report does not match a fresh production score",
        )
    if _canonical_sha256(supplied_slo) != _canonical_sha256(recomputed_slo):
        raise EvaluationContractError(
            "slo_report_not_current",
            "supplied SLO report does not match fresh proof-backed aggregation",
        )

    registration = _object(
        "evaluation_report.production_registration",
        recomputed_evaluation.get("production_registration"),
    )
    slo_inputs = _object(
        "slo_report.inputs",
        recomputed_slo.get("inputs"),
    )
    slo_candidate = _object(
        "slo_report.candidate_identity",
        recomputed_slo.get("candidate_identity"),
    )
    current_registry_hash = (
        build_default_tool_registry().canonical_sha256
    )
    contract_failures: list[dict[str, Any]] = []
    _require(
        contract_failures,
        gate="evaluation",
        code="production_evaluation_required",
        condition=(
            recomputed_evaluation.get("mode") == "production"
            and recomputed_evaluation.get("qualification_scope")
            == "evaluation_gate"
            and recomputed_evaluation.get("not_authorization") is True
            and recomputed_evaluation.get("p2_admission_allowed") is False
            and bool(registration)
        ),
    )
    _require(
        contract_failures,
        gate="binding",
        code="slo_candidate_identity_mismatch",
        condition=(
            registration.get("candidate_identity") == candidate
            and slo_candidate == candidate
            and all(
                isinstance(item, Mapping)
                and item.get("candidate_identity") == candidate
                for item in recomputed_slo.get("proof_results", [])
            )
        ),
    )
    _require(
        contract_failures,
        gate="provenance",
        code="proof_backed_slo_required",
        condition=(
            recomputed_slo.get("provenance") == "verified_run_proof"
            and recomputed_slo.get("not_production_qualified") is False
            and isinstance(recomputed_slo.get("proof_results"), list)
            and bool(recomputed_slo.get("proof_results"))
            and isinstance(recomputed_slo.get("sampling"), Mapping)
            and recomputed_slo["sampling"].get("mode") == "production"
            and recomputed_slo["sampling"].get("passed") is True
            and all(
                isinstance(item, Mapping) and item.get("valid") is True
                for item in recomputed_slo.get("proof_results", [])
            )
        ),
    )
    _require(
        contract_failures,
        gate="binding",
        code="signed_slo_sampling_contract_mismatch",
        condition=(
            registration.get("slo_sampling_contract_sha256")
            == recomputed_slo.get("sampling_contract_sha256")
            == slo_inputs.get("sha256", {}).get("sampling_contract")
        ),
    )
    _require(
        contract_failures,
        gate="binding",
        code="slo_sampling_after_registration",
        condition=(
            _utc_timestamp(
                "slo_report.sampling_contract.window_ended_at",
                _object(
                    "slo_report.sampling_contract",
                    recomputed_slo.get("sampling_contract"),
                ).get("window_ended_at"),
            )
            <= _utc_timestamp(
                "production_registration.issued_at",
                registration.get("issued_at"),
            )
        ),
    )
    _require(
        contract_failures,
        gate="binding",
        code="signed_slo_input_set_mismatch",
        condition=(
            registration.get("slo_input_set_sha256")
            == slo_inputs.get("input_set_sha256")
        ),
    )
    _require(
        contract_failures,
        gate="binding",
        code="signed_slo_thresholds_mismatch",
        condition=(
            registration.get("slo_thresholds_sha256")
            == slo_inputs.get("thresholds_sha256")
        ),
    )
    _require(
        contract_failures,
        gate="binding",
        code="candidate_tool_registry_not_current",
        condition=(
            candidate.get("tool_registry_sha256")
            == current_registry_hash
        ),
    )

    gate_results = [
        {
            "gate": "production_evaluation",
            "passed": (
                recomputed_evaluation.get("qualified") is True
                and not any(
                    item["gate"] == "evaluation"
                    for item in contract_failures
                )
            ),
        },
        {
            "gate": "proof_backed_slo",
            "passed": (
                recomputed_slo.get("qualified") is True
                and not any(
                    item["gate"] == "provenance"
                    for item in contract_failures
                )
            ),
        },
        {
            "gate": "cross_report_binding",
            "passed": not any(
                item["gate"] == "binding"
                for item in contract_failures
            ),
        },
    ]
    failures = [
        *contract_failures,
        *(
            []
            if recomputed_evaluation.get("qualified") is True
            else [
                {
                    "gate": "evaluation",
                    "code": "production_evaluation_not_qualified",
                }
            ]
        ),
        *(
            []
            if recomputed_slo.get("qualified") is True
            else [
                {
                    "gate": "provenance",
                    "code": "proof_backed_slo_not_qualified",
                }
            ]
        ),
    ]
    admitted = not failures and all(item["passed"] for item in gate_results)
    unsigned = {
        "schema_version": 1,
        "scope": "p2_parallel_multi_agent_release",
        "decision": "admitted" if admitted else "rejected",
        "admission_allowed": admitted,
        "not_authorization": True,
        "authorization_scope": "release_admission_only",
        "runtime_tool_authorization": False,
        "candidate_identity": candidate,
        "gate_results": gate_results,
        "gate_failures": failures,
        "bindings": {
            "evaluation_report_sha256": _canonical_sha256(
                recomputed_evaluation,
            ),
            "slo_report_sha256": _canonical_sha256(recomputed_slo),
            "registration_sha256": registration.get(
                "registration_sha256",
            ),
            "signed_payload_sha256": registration.get(
                "signed_payload_sha256",
            ),
            "slo_input_set_sha256": slo_inputs.get(
                "input_set_sha256",
            ),
            "slo_thresholds_sha256": slo_inputs.get(
                "thresholds_sha256",
            ),
            "slo_sampling_contract_sha256": recomputed_slo.get(
                "sampling_contract_sha256",
            ),
            "candidate_identity_sha256": recomputed_slo.get(
                "candidate_identity_sha256",
            ),
        },
    }
    return {**unsigned, "admission_sha256": _canonical_sha256(unsigned)}


def _require(
    failures: list[dict[str, Any]],
    *,
    gate: str,
    code: str,
    condition: bool,
) -> None:
    if not condition:
        failures.append({"gate": gate, "code": code})


def _object(name: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise EvaluationContractError(
            "release_admission_input_invalid",
            f"{name} must be a JSON object",
        )
    normalized = dict(value)
    try:
        json.dumps(normalized, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EvaluationContractError(
            "release_admission_input_invalid",
            f"{name} must be finite JSON",
        ) from exc
    return normalized


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _utc_timestamp(name: str, value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EvaluationContractError(
            "release_admission_timestamp_invalid",
            f"{name} must be an RFC3339 UTC timestamp ending in Z",
        )
    try:
        parsed = datetime.fromisoformat(
            value.removesuffix("Z") + "+00:00"
        )
    except ValueError as exc:
        raise EvaluationContractError(
            "release_admission_timestamp_invalid",
            f"{name} must be an RFC3339 UTC timestamp",
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise EvaluationContractError(
            "release_admission_timestamp_invalid",
            f"{name} must use UTC",
        )
    return parsed
