"""人工确认请求、操作者身份与审批收据的严格合同。"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self

HUMAN_CONTROL_SCHEMA_VERSION = 1
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")


class HumanControlContractError(ValueError):
    """人工控制输入不满足严格合同。"""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str = "$",
    ) -> None:
        self.code = code
        self.path = path
        super().__init__(message)

    def to_dict(self) -> dict[str, str | int]:
        return {
            "schema_version": HUMAN_CONTROL_SCHEMA_VERSION,
            "error": "human_control_contract_error",
            "code": self.code,
            "path": self.path,
            "message": str(self),
        }


class ApprovalOperation(StrEnum):
    """审批收据允许绑定的操作。"""

    KNOWLEDGE_WRITE = "knowledge_write"
    KNOWLEDGE_REVOKE = "knowledge_revoke"
    HITL_DECISION = "hitl_decision"


class HumanDecision(StrEnum):
    """人工请求的确定性决策。"""

    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class OperatorIdentity:
    """来自明确身份提供方的操作者身份。"""

    operator_id: str
    identity_provider: str
    identity_subject: str
    schema_version: int = HUMAN_CONTROL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema_version(self.schema_version, path="$.schema_version")
        object.__setattr__(
            self,
            "operator_id",
            _identifier("operator_id", self.operator_id),
        )
        object.__setattr__(
            self,
            "identity_provider",
            _text("identity_provider", self.identity_provider),
        )
        object.__setattr__(
            self,
            "identity_subject",
            _text("identity_subject", self.identity_subject),
        )

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        path: str = "$",
    ) -> Self:
        payload = _strict_object(
            value,
            required={
                "schema_version",
                "operator_id",
                "identity_provider",
                "identity_subject",
            },
            path=path,
        )
        return cls(
            schema_version=payload["schema_version"],
            operator_id=payload["operator_id"],
            identity_provider=payload["identity_provider"],
            identity_subject=payload["identity_subject"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "operator_id": self.operator_id,
            "identity_provider": self.identity_provider,
            "identity_subject": self.identity_subject,
        }


@dataclass(frozen=True, slots=True)
class ApprovalReceipt:
    """外部审批系统产生、与单个 subject hash 绑定的收据。"""

    receipt_id: str
    operation: ApprovalOperation | str
    operator_id: str
    subject_sha256: str
    decision: HumanDecision | str
    approved_at: str
    authority: str
    key_id: str
    algorithm: str
    external_receipt_sha256: str
    signature: str
    schema_version: int = HUMAN_CONTROL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema_version(self.schema_version, path="$.schema_version")
        object.__setattr__(
            self,
            "receipt_id",
            _identifier("receipt_id", self.receipt_id),
        )
        object.__setattr__(
            self,
            "operation",
            _enum_value(
                "operation",
                self.operation,
                ApprovalOperation,
            ),
        )
        object.__setattr__(
            self,
            "operator_id",
            _identifier("operator_id", self.operator_id),
        )
        object.__setattr__(
            self,
            "subject_sha256",
            _sha256("subject_sha256", self.subject_sha256),
        )
        object.__setattr__(
            self,
            "decision",
            _enum_value("decision", self.decision, HumanDecision),
        )
        object.__setattr__(
            self,
            "approved_at",
            canonical_timestamp(self.approved_at, path="$.approved_at"),
        )
        object.__setattr__(
            self,
            "authority",
            _text("authority", self.authority),
        )
        object.__setattr__(
            self,
            "key_id",
            _identifier("key_id", self.key_id),
        )
        if self.algorithm != "Ed25519":
            raise HumanControlContractError(
                "approval_algorithm_invalid",
                "approval receipt algorithm 必须是 Ed25519",
                path="$.algorithm",
            )
        object.__setattr__(
            self,
            "external_receipt_sha256",
            _sha256(
                "external_receipt_sha256",
                self.external_receipt_sha256,
            ),
        )
        object.__setattr__(
            self,
            "signature",
            _text("signature", self.signature),
        )

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        path: str = "$",
    ) -> Self:
        payload = _strict_object(
            value,
            required={
                "schema_version",
                "receipt_id",
                "operation",
                "operator_id",
                "subject_sha256",
                "decision",
                "approved_at",
                "authority",
                "key_id",
                "algorithm",
                "external_receipt_sha256",
                "signature",
            },
            path=path,
        )
        return cls(
            schema_version=payload["schema_version"],
            receipt_id=payload["receipt_id"],
            operation=payload["operation"],
            operator_id=payload["operator_id"],
            subject_sha256=payload["subject_sha256"],
            decision=payload["decision"],
            approved_at=payload["approved_at"],
            authority=payload["authority"],
            key_id=payload["key_id"],
            algorithm=payload["algorithm"],
            external_receipt_sha256=payload[
                "external_receipt_sha256"
            ],
            signature=payload["signature"],
        )

    def signing_payload(self) -> dict[str, Any]:
        """返回唯一可签名 payload；signature 字段本身必须排除。"""

        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "operation": self.operation.value,
            "operator_id": self.operator_id,
            "subject_sha256": self.subject_sha256,
            "decision": self.decision.value,
            "approved_at": self.approved_at,
            "authority": self.authority,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "external_receipt_sha256": (
                self.external_receipt_sha256
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.signing_payload(),
            "signature": self.signature,
        }


@dataclass(frozen=True, slots=True)
class HITLRequest:
    """可持久化、可恢复且绑定当前 run/context/action 的人工请求。"""

    request_id: str
    run_id: str
    lease_generation: int
    context_sha256: str
    action_sha256: str
    policy_sha256: str
    authorization_sha256: str
    action_summary: str
    question: str
    allowed_decisions: tuple[HumanDecision | str, ...]
    created_at: str
    expires_at: str
    not_evidence: bool = True
    schema_version: int = HUMAN_CONTROL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema_version(self.schema_version, path="$.schema_version")
        object.__setattr__(
            self,
            "request_id",
            _identifier("request_id", self.request_id),
        )
        object.__setattr__(
            self,
            "run_id",
            _identifier("run_id", self.run_id),
        )
        object.__setattr__(
            self,
            "lease_generation",
            _generation(self.lease_generation),
        )
        object.__setattr__(
            self,
            "context_sha256",
            _sha256("context_sha256", self.context_sha256),
        )
        object.__setattr__(
            self,
            "action_sha256",
            _sha256("action_sha256", self.action_sha256),
        )
        object.__setattr__(
            self,
            "policy_sha256",
            _sha256("policy_sha256", self.policy_sha256),
        )
        object.__setattr__(
            self,
            "authorization_sha256",
            _sha256(
                "authorization_sha256",
                self.authorization_sha256,
            ),
        )
        object.__setattr__(
            self,
            "action_summary",
            _text("action_summary", self.action_summary),
        )
        object.__setattr__(
            self,
            "question",
            _text("question", self.question),
        )
        decisions = _decision_tuple(self.allowed_decisions)
        if not decisions:
            raise HumanControlContractError(
                "allowed_decisions_empty",
                "allowed_decisions 至少需要一个值",
                path="$.allowed_decisions",
            )
        required_decisions = {
            HumanDecision.APPROVED,
            HumanDecision.REJECTED,
        }
        if not required_decisions.issubset(decisions):
            raise HumanControlContractError(
                "allowed_decisions_incomplete",
                "allowed_decisions 必须同时允许 approved 与 rejected",
                path="$.allowed_decisions",
            )
        object.__setattr__(self, "allowed_decisions", decisions)
        created_at = canonical_timestamp(
            self.created_at,
            path="$.created_at",
        )
        expires_at = canonical_timestamp(
            self.expires_at,
            path="$.expires_at",
        )
        if parse_timestamp(expires_at) <= parse_timestamp(created_at):
            raise HumanControlContractError(
                "request_expiry_invalid",
                "expires_at 必须晚于 created_at",
                path="$.expires_at",
            )
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "expires_at", expires_at)
        if self.not_evidence is not True:
            raise HumanControlContractError(
                "not_evidence_required",
                "HITL request 必须标记 not_evidence=true",
                path="$.not_evidence",
            )

    @property
    def canonical_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        path: str = "$",
    ) -> Self:
        payload = _strict_object(
            value,
            required={
                "schema_version",
                "request_id",
                "run_id",
                "lease_generation",
                "context_sha256",
                "action_sha256",
                "policy_sha256",
                "authorization_sha256",
                "action_summary",
                "question",
                "allowed_decisions",
                "created_at",
                "expires_at",
                "not_evidence",
            },
            path=path,
        )
        raw_decisions = payload["allowed_decisions"]
        if not isinstance(raw_decisions, list):
            raise HumanControlContractError(
                "allowed_decisions_invalid",
                "allowed_decisions 必须是 JSON array",
                path=f"{path}.allowed_decisions",
            )
        return cls(
            schema_version=payload["schema_version"],
            request_id=payload["request_id"],
            run_id=payload["run_id"],
            lease_generation=payload["lease_generation"],
            context_sha256=payload["context_sha256"],
            action_sha256=payload["action_sha256"],
            policy_sha256=payload["policy_sha256"],
            authorization_sha256=payload["authorization_sha256"],
            action_summary=payload["action_summary"],
            question=payload["question"],
            allowed_decisions=tuple(raw_decisions),
            created_at=payload["created_at"],
            expires_at=payload["expires_at"],
            not_evidence=payload["not_evidence"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "run_id": self.run_id,
            "lease_generation": self.lease_generation,
            "context_sha256": self.context_sha256,
            "action_sha256": self.action_sha256,
            "policy_sha256": self.policy_sha256,
            "authorization_sha256": self.authorization_sha256,
            "action_summary": self.action_summary,
            "question": self.question,
            "allowed_decisions": [
                item.value
                for item in self.allowed_decisions
            ],
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "not_evidence": self.not_evidence,
        }


@dataclass(frozen=True, slots=True)
class HITLDecision:
    """人工对一个请求作出的、不可变且哈希绑定的决策。"""

    decision_id: str
    request_id: str
    run_id: str
    lease_generation: int
    context_sha256: str
    action_sha256: str
    policy_sha256: str
    authorization_sha256: str
    decision: HumanDecision | str
    reason: str
    decided_at: str
    operator: OperatorIdentity
    approval_receipt: ApprovalReceipt
    not_evidence: bool = True
    schema_version: int = HUMAN_CONTROL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema_version(self.schema_version, path="$.schema_version")
        for field_name in ("decision_id", "request_id", "run_id"):
            object.__setattr__(
                self,
                field_name,
                _identifier(field_name, getattr(self, field_name)),
            )
        object.__setattr__(
            self,
            "lease_generation",
            _generation(self.lease_generation),
        )
        for field_name in (
            "context_sha256",
            "action_sha256",
            "policy_sha256",
            "authorization_sha256",
        ):
            object.__setattr__(
                self,
                field_name,
                _sha256(field_name, getattr(self, field_name)),
            )
        object.__setattr__(
            self,
            "decision",
            _enum_value("decision", self.decision, HumanDecision),
        )
        object.__setattr__(
            self,
            "reason",
            _text("reason", self.reason),
        )
        object.__setattr__(
            self,
            "decided_at",
            canonical_timestamp(self.decided_at, path="$.decided_at"),
        )
        if not isinstance(self.operator, OperatorIdentity):
            raise HumanControlContractError(
                "operator_invalid",
                "operator 必须是 OperatorIdentity",
                path="$.operator",
            )
        if not isinstance(self.approval_receipt, ApprovalReceipt):
            raise HumanControlContractError(
                "approval_receipt_invalid",
                "approval_receipt 必须是 ApprovalReceipt",
                path="$.approval_receipt",
            )
        if self.approval_receipt.operation is not ApprovalOperation.HITL_DECISION:
            raise HumanControlContractError(
                "approval_operation_mismatch",
                "HITL decision 必须使用 hitl_decision 收据",
                path="$.approval_receipt.operation",
            )
        if self.approval_receipt.operator_id != self.operator.operator_id:
            raise HumanControlContractError(
                "approval_operator_mismatch",
                "审批收据与 operator identity 不一致",
                path="$.approval_receipt.operator_id",
            )
        if self.approval_receipt.decision is not self.decision:
            raise HumanControlContractError(
                "approval_decision_mismatch",
                "审批收据与 HITL decision 不一致",
                path="$.approval_receipt.decision",
            )
        if self.approval_receipt.approved_at != self.decided_at:
            raise HumanControlContractError(
                "approval_time_mismatch",
                "decided_at 必须等于审批收据 approved_at",
                path="$.decided_at",
            )
        if self.not_evidence is not True:
            raise HumanControlContractError(
                "not_evidence_required",
                "HITL decision 必须标记 not_evidence=true",
                path="$.not_evidence",
            )

    @property
    def canonical_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        path: str = "$",
    ) -> Self:
        payload = _strict_object(
            value,
            required={
                "schema_version",
                "decision_id",
                "request_id",
                "run_id",
                "lease_generation",
                "context_sha256",
                "action_sha256",
                "policy_sha256",
                "authorization_sha256",
                "decision",
                "reason",
                "decided_at",
                "operator",
                "approval_receipt",
                "not_evidence",
            },
            path=path,
        )
        return cls(
            schema_version=payload["schema_version"],
            decision_id=payload["decision_id"],
            request_id=payload["request_id"],
            run_id=payload["run_id"],
            lease_generation=payload["lease_generation"],
            context_sha256=payload["context_sha256"],
            action_sha256=payload["action_sha256"],
            policy_sha256=payload["policy_sha256"],
            authorization_sha256=payload["authorization_sha256"],
            decision=payload["decision"],
            reason=payload["reason"],
            decided_at=payload["decided_at"],
            operator=OperatorIdentity.from_dict(
                payload["operator"],
                path=f"{path}.operator",
            ),
            approval_receipt=ApprovalReceipt.from_dict(
                payload["approval_receipt"],
                path=f"{path}.approval_receipt",
            ),
            not_evidence=payload["not_evidence"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "decision_id": self.decision_id,
            "request_id": self.request_id,
            "run_id": self.run_id,
            "lease_generation": self.lease_generation,
            "context_sha256": self.context_sha256,
            "action_sha256": self.action_sha256,
            "policy_sha256": self.policy_sha256,
            "authorization_sha256": self.authorization_sha256,
            "decision": self.decision.value,
            "reason": self.reason,
            "decided_at": self.decided_at,
            "operator": self.operator.to_dict(),
            "approval_receipt": self.approval_receipt.to_dict(),
            "not_evidence": self.not_evidence,
        }


@dataclass(frozen=True, slots=True)
class HITLConsumption:
    """一次性消费已批准 decision 的不可变执行授权事件。"""

    consumption_id: str
    request_id: str
    decision_id: str
    run_id: str
    lease_generation: int
    context_sha256: str
    action_sha256: str
    policy_sha256: str
    authorization_sha256: str
    consumed_at: str
    not_evidence: bool = True
    schema_version: int = HUMAN_CONTROL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema_version(self.schema_version, path="$.schema_version")
        for field_name in (
            "consumption_id",
            "request_id",
            "decision_id",
            "run_id",
        ):
            object.__setattr__(
                self,
                field_name,
                _identifier(field_name, getattr(self, field_name)),
            )
        object.__setattr__(
            self,
            "lease_generation",
            _generation(self.lease_generation),
        )
        for field_name in (
            "context_sha256",
            "action_sha256",
            "policy_sha256",
            "authorization_sha256",
        ):
            object.__setattr__(
                self,
                field_name,
                _sha256(field_name, getattr(self, field_name)),
            )
        object.__setattr__(
            self,
            "consumed_at",
            canonical_timestamp(
                self.consumed_at,
                path="$.consumed_at",
            ),
        )
        if self.not_evidence is not True:
            raise HumanControlContractError(
                "not_evidence_required",
                "HITL consumption 必须标记 not_evidence=true",
                path="$.not_evidence",
            )

    @property
    def canonical_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        path: str = "$",
    ) -> Self:
        payload = _strict_object(
            value,
            required={
                "schema_version",
                "consumption_id",
                "request_id",
                "decision_id",
                "run_id",
                "lease_generation",
                "context_sha256",
                "action_sha256",
                "policy_sha256",
                "authorization_sha256",
                "consumed_at",
                "not_evidence",
            },
            path=path,
        )
        return cls(**payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "consumption_id": self.consumption_id,
            "request_id": self.request_id,
            "decision_id": self.decision_id,
            "run_id": self.run_id,
            "lease_generation": self.lease_generation,
            "context_sha256": self.context_sha256,
            "action_sha256": self.action_sha256,
            "policy_sha256": self.policy_sha256,
            "authorization_sha256": self.authorization_sha256,
            "consumed_at": self.consumed_at,
            "not_evidence": self.not_evidence,
        }


def hitl_decision_subject_sha256(
    request: HITLRequest,
    *,
    decision_id: str,
    decision: HumanDecision | str,
    reason: str,
    decided_at: str,
    operator: OperatorIdentity,
) -> str:
    """计算外部审批收据必须绑定的 HITL decision subject。"""

    if not isinstance(request, HITLRequest):
        raise HumanControlContractError(
            "request_invalid",
            "request 必须是 HITLRequest",
        )
    if not isinstance(operator, OperatorIdentity):
        raise HumanControlContractError(
            "operator_invalid",
            "operator 必须是 OperatorIdentity",
        )
    normalized_decision = _enum_value(
        "decision",
        decision,
        HumanDecision,
    )
    normalized_id = _identifier("decision_id", decision_id)
    normalized_reason = _text("reason", reason)
    normalized_time = canonical_timestamp(
        decided_at,
        path="$.decided_at",
    )
    return canonical_sha256(
        {
            "schema_version": HUMAN_CONTROL_SCHEMA_VERSION,
            "operation": ApprovalOperation.HITL_DECISION.value,
            "request_sha256": request.canonical_sha256,
            "decision_id": normalized_id,
            "decision": normalized_decision.value,
            "reason": normalized_reason,
            "decided_at": normalized_time,
            "operator": operator.to_dict(),
        },
    )


def validate_hitl_decision(
    request: HITLRequest,
    decision: HITLDecision,
) -> None:
    """验证 decision 与原请求、有效期和审批 subject 的完整绑定。"""

    if not isinstance(request, HITLRequest):
        raise HumanControlContractError(
            "request_invalid",
            "request 必须是 HITLRequest",
        )
    if not isinstance(decision, HITLDecision):
        raise HumanControlContractError(
            "decision_invalid",
            "decision 必须是 HITLDecision",
        )
    bindings = {
        "request_id": request.request_id,
        "run_id": request.run_id,
        "lease_generation": request.lease_generation,
        "context_sha256": request.context_sha256,
        "action_sha256": request.action_sha256,
        "policy_sha256": request.policy_sha256,
        "authorization_sha256": request.authorization_sha256,
    }
    for field_name, expected in bindings.items():
        if getattr(decision, field_name) != expected:
            raise HumanControlContractError(
                "decision_binding_mismatch",
                f"decision.{field_name} 与 request 不一致",
                path=f"$.{field_name}",
            )
    if decision.decision not in request.allowed_decisions:
        raise HumanControlContractError(
            "decision_not_allowed",
            "decision 不在 request.allowed_decisions 中",
            path="$.decision",
        )
    decided_at = parse_timestamp(decision.decided_at)
    if decided_at < parse_timestamp(request.created_at):
        raise HumanControlContractError(
            "decision_before_request",
            "decided_at 不得早于 request.created_at",
            path="$.decided_at",
        )
    if decided_at >= parse_timestamp(request.expires_at):
        raise HumanControlContractError(
            "decision_after_expiry",
            "decided_at 必须早于 request.expires_at",
            path="$.decided_at",
        )
    expected_subject = hitl_decision_subject_sha256(
        request,
        decision_id=decision.decision_id,
        decision=decision.decision,
        reason=decision.reason,
        decided_at=decision.decided_at,
        operator=decision.operator,
    )
    if decision.approval_receipt.subject_sha256 != expected_subject:
        raise HumanControlContractError(
            "approval_subject_mismatch",
            "审批收据未绑定当前 HITL request/decision",
            path="$.approval_receipt.subject_sha256",
        )


def canonical_sha256(value: Any) -> str:
    """对标准 JSON 进行稳定 SHA-256。"""

    return hashlib.sha256(
        json.dumps(
            _plain_json(value, path="$"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8"),
    ).hexdigest()


def canonical_timestamp(value: Any, *, path: str) -> str:
    """只接受带时区且已规范化为 UTC `Z` 的 RFC3339 时间。"""

    if not isinstance(value, str) or not value:
        raise HumanControlContractError(
            "timestamp_invalid",
            "时间必须是非空 RFC3339 字符串",
            path=path,
        )
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00"
            if value.endswith("Z")
            else value,
        )
    except ValueError as exc:
        raise HumanControlContractError(
            "timestamp_invalid",
            "时间不是合法 RFC3339",
            path=path,
        ) from exc
    if parsed.tzinfo is None:
        raise HumanControlContractError(
            "timestamp_timezone_missing",
            "时间必须包含时区",
            path=path,
        )
    canonical = parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if value != canonical:
        raise HumanControlContractError(
            "timestamp_not_canonical",
            f"时间必须使用规范 UTC 形式：{canonical}",
            path=path,
        )
    return canonical


def parse_timestamp(value: str) -> datetime:
    """解析已经规范化的 UTC 时间。"""

    normalized = canonical_timestamp(value, path="$")
    return datetime.fromisoformat(normalized[:-1] + "+00:00")


def _schema_version(value: Any, *, path: str) -> None:
    if value != HUMAN_CONTROL_SCHEMA_VERSION:
        raise HumanControlContractError(
            "schema_version_unsupported",
            (
                "schema_version 必须等于 "
                f"{HUMAN_CONTROL_SCHEMA_VERSION}"
            ),
            path=path,
        )


def _strict_object(
    value: Mapping[str, Any],
    *,
    required: set[str],
    path: str,
) -> dict[str, Any]:
    payload = _plain_json(value, path=path)
    if not isinstance(payload, dict):
        raise HumanControlContractError(
            "object_required",
            "值必须是 JSON object",
            path=path,
        )
    fields = set(payload)
    unknown = sorted(fields - required)
    if unknown:
        raise HumanControlContractError(
            "fields_unknown",
            f"包含未知字段：{', '.join(unknown)}",
            path=path,
        )
    missing = sorted(required - fields)
    if missing:
        raise HumanControlContractError(
            "fields_missing",
            f"缺少字段：{', '.join(missing)}",
            path=path,
        )
    return payload


def _plain_json(value: Any, *, path: str) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise HumanControlContractError(
                    "json_key_invalid",
                    "JSON object key 必须是字符串",
                    path=path,
                )
            result[key] = _plain_json(
                item,
                path=f"{path}.{key}",
            )
        return result
    if isinstance(value, (list, tuple)):
        return [
            _plain_json(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise HumanControlContractError(
        "json_value_invalid",
        "值必须能无损表示为标准 JSON",
        path=path,
    )


def _identifier(name: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or _IDENTIFIER_PATTERN.fullmatch(value) is None
    ):
        raise HumanControlContractError(
            "identifier_invalid",
            f"{name} 不是合法标识符",
            path=f"$.{name}",
        )
    return value


def _text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HumanControlContractError(
            "text_invalid",
            f"{name} 必须是非空字符串",
            path=f"$.{name}",
        )
    if value != value.strip():
        raise HumanControlContractError(
            "text_not_canonical",
            f"{name} 首尾不得包含空白",
            path=f"$.{name}",
        )
    return value


def _sha256(name: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or _SHA256_PATTERN.fullmatch(value) is None
    ):
        raise HumanControlContractError(
            "sha256_invalid",
            f"{name} 必须是 64 位小写 SHA-256",
            path=f"$.{name}",
        )
    return value


def _generation(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise HumanControlContractError(
            "lease_generation_invalid",
            "lease_generation 必须是正整数",
            path="$.lease_generation",
        )
    return value


def _enum_value(
    name: str,
    value: Any,
    enum_type: type[StrEnum],
):
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise HumanControlContractError(
            "enum_invalid",
            f"{name} 不是受支持的值",
            path=f"$.{name}",
        ) from exc


def _decision_tuple(
    values: tuple[HumanDecision | str, ...],
) -> tuple[HumanDecision, ...]:
    if isinstance(values, (str, bytes)):
        raise HumanControlContractError(
            "allowed_decisions_invalid",
            "allowed_decisions 必须是 array",
            path="$.allowed_decisions",
        )
    try:
        normalized = tuple(
            _enum_value(
                "allowed_decisions",
                item,
                HumanDecision,
            )
            for item in values
        )
    except TypeError as exc:
        raise HumanControlContractError(
            "allowed_decisions_invalid",
            "allowed_decisions 必须是 array",
            path="$.allowed_decisions",
        ) from exc
    if len(normalized) != len(set(normalized)):
        raise HumanControlContractError(
            "allowed_decisions_duplicate",
            "allowed_decisions 不得重复",
            path="$.allowed_decisions",
        )
    return tuple(sorted(normalized, key=lambda item: item.value))
