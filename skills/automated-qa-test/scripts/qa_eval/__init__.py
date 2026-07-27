"""独立 QA Agent 评测合同与评分器。"""

from .admission import evaluate_p2_release_admission
from .io import JsonInputSnapshot, read_json_object, require_distinct_inputs
from .registration import (
    VerifiedProductionRegistration,
    hash_evaluator_bundle,
    production_registration_signing_bytes,
    production_registration_signing_payload,
    verify_candidate_identity_sources,
    verify_production_registration,
)
from .scoring import (
    EvaluationContractError,
    EvaluationThresholds,
    score_evaluation,
)

__all__ = [
    "EvaluationContractError",
    "EvaluationThresholds",
    "JsonInputSnapshot",
    "VerifiedProductionRegistration",
    "evaluate_p2_release_admission",
    "hash_evaluator_bundle",
    "production_registration_signing_bytes",
    "production_registration_signing_payload",
    "read_json_object",
    "require_distinct_inputs",
    "score_evaluation",
    "verify_production_registration",
    "verify_candidate_identity_sources",
]
