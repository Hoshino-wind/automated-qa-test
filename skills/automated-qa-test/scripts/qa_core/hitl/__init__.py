"""人工确认（HITL）请求、决策与持久化公共接口。"""

from ._journal import HumanControlJournalError
from .auth import (
    ApprovalVerifier,
    canonical_receipt_bytes,
    public_key_pem,
    signed_receipt_dict,
)
from .checkpoint import (
    JOURNAL_CHECKPOINT_SCHEMA_VERSION,
    LOCAL_TEST_MODE,
    PRODUCTION_MODE,
    JournalCheckpoint,
    JournalCheckpointVerifier,
    canonical_checkpoint_bytes,
    canonical_journal_path_sha256,
    checkpoint_signing_payload,
)
from .contracts import (
    HUMAN_CONTROL_SCHEMA_VERSION,
    ApprovalOperation,
    ApprovalReceipt,
    HITLConsumption,
    HITLDecision,
    HITLRequest,
    HumanControlContractError,
    HumanDecision,
    OperatorIdentity,
    canonical_sha256,
    canonical_timestamp,
    hitl_decision_subject_sha256,
    validate_hitl_decision,
)
from .store import HITLState, HITLStore, HITLStoreError

__all__ = [
    "HITLState",
    "HITLStore",
    "HITLStoreError",
    "HITLDecision",
    "HITLConsumption",
    "HITLRequest",
    "HUMAN_CONTROL_SCHEMA_VERSION",
    "JOURNAL_CHECKPOINT_SCHEMA_VERSION",
    "LOCAL_TEST_MODE",
    "PRODUCTION_MODE",
    "ApprovalOperation",
    "ApprovalReceipt",
    "ApprovalVerifier",
    "JournalCheckpoint",
    "JournalCheckpointVerifier",
    "HumanControlContractError",
    "HumanControlJournalError",
    "HumanDecision",
    "OperatorIdentity",
    "canonical_sha256",
    "canonical_receipt_bytes",
    "canonical_checkpoint_bytes",
    "canonical_journal_path_sha256",
    "canonical_timestamp",
    "hitl_decision_subject_sha256",
    "checkpoint_signing_payload",
    "public_key_pem",
    "signed_receipt_dict",
    "validate_hitl_decision",
]
