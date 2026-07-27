"""人工确认 Knowledge Store 的严格数据合同。"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Self

from qa_core.hitl.contracts import (
    HUMAN_CONTROL_SCHEMA_VERSION,
    ApprovalOperation,
    ApprovalReceipt,
    HumanControlContractError,
    HumanDecision,
    OperatorIdentity,
    canonical_sha256,
    canonical_timestamp,
    parse_timestamp,
)

KNOWLEDGE_SCHEMA_VERSION = HUMAN_CONTROL_SCHEMA_VERSION
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SCOPE_PATTERN = re.compile(
    r"[a-z][a-z0-9_.-]{0,63}:[A-Za-z0-9][A-Za-z0-9._@/=-]{0,191}",
)


@dataclass(frozen=True, slots=True)
class KnowledgeProvenance:
    """一条知识声明的内容寻址来源。"""

    source_id: str
    source_type: str
    reference: str
    sha256: str
    observed_at: str
    schema_version: int = KNOWLEDGE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema_version(self.schema_version)
        object.__setattr__(
            self,
            "source_id",
            _identifier("source_id", self.source_id),
        )
        object.__setattr__(
            self,
            "source_type",
            _text("source_type", self.source_type),
        )
        object.__setattr__(
            self,
            "reference",
            _text("reference", self.reference),
        )
        object.__setattr__(
            self,
            "sha256",
            _sha256("sha256", self.sha256),
        )
        object.__setattr__(
            self,
            "observed_at",
            canonical_timestamp(
                self.observed_at,
                path="$.observed_at",
            ),
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
                "source_id",
                "source_type",
                "reference",
                "sha256",
                "observed_at",
            },
            path=path,
        )
        return cls(
            schema_version=payload["schema_version"],
            source_id=payload["source_id"],
            source_type=payload["source_type"],
            reference=payload["reference"],
            sha256=payload["sha256"],
            observed_at=payload["observed_at"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "reference": self.reference,
            "sha256": self.sha256,
            "observed_at": self.observed_at,
        }


@dataclass(frozen=True, slots=True)
class KnowledgeCandidate:
    """尚未附加人工审批的知识候选。"""

    entry_id: str
    topic: str
    statement: str
    provenance: tuple[KnowledgeProvenance, ...]
    scope: tuple[str, ...]
    version: int
    proposed_at: str
    expires_at: str | None = None
    not_evidence: bool = True
    schema_version: int = KNOWLEDGE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _schema_version(self.schema_version)
        object.__setattr__(
            self,
            "entry_id",
            _identifier("entry_id", self.entry_id),
        )
        object.__setattr__(self, "topic", _text("topic", self.topic))
        object.__setattr__(
            self,
            "statement",
            _text("statement", self.statement),
        )
        provenance = _provenance_tuple(self.provenance)
        if not provenance:
            raise HumanControlContractError(
                "provenance_empty",
                "Knowledge candidate 至少需要一条 provenance",
                path="$.provenance",
            )
        object.__setattr__(self, "provenance", provenance)
        scope = _scope_tuple(self.scope)
        if not scope:
            raise HumanControlContractError(
                "scope_empty",
                "Knowledge candidate 至少需要一个 scope token",
                path="$.scope",
            )
        object.__setattr__(self, "scope", scope)
        if isinstance(self.version, bool) or not isinstance(
            self.version,
            int,
        ) or self.version < 1:
            raise HumanControlContractError(
                "knowledge_version_invalid",
                "Knowledge version 必须是正整数",
                path="$.version",
            )
        proposed_at = canonical_timestamp(
            self.proposed_at,
            path="$.proposed_at",
        )
        object.__setattr__(self, "proposed_at", proposed_at)
        for item in provenance:
            if parse_timestamp(item.observed_at) > parse_timestamp(
                proposed_at,
            ):
                raise HumanControlContractError(
                    "provenance_after_proposal",
                    "provenance.observed_at 不得晚于 proposed_at",
                    path="$.provenance",
                )
        if self.expires_at is not None:
            expires_at = canonical_timestamp(
                self.expires_at,
                path="$.expires_at",
            )
            if parse_timestamp(expires_at) <= parse_timestamp(proposed_at):
                raise HumanControlContractError(
                    "knowledge_expiry_invalid",
                    "expires_at 必须晚于 proposed_at",
                    path="$.expires_at",
                )
            object.__setattr__(self, "expires_at", expires_at)
        if self.not_evidence is not True:
            raise HumanControlContractError(
                "not_evidence_required",
                "Knowledge 必须标记 not_evidence=true",
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
                "entry_id",
                "topic",
                "statement",
                "provenance",
                "scope",
                "version",
                "proposed_at",
            },
            optional={"expires_at", "not_evidence"},
            path=path,
        )
        raw_provenance = payload["provenance"]
        raw_scope = payload["scope"]
        if not isinstance(raw_provenance, list):
            raise HumanControlContractError(
                "provenance_invalid",
                "provenance 必须是 JSON array",
                path=f"{path}.provenance",
            )
        if not isinstance(raw_scope, list):
            raise HumanControlContractError(
                "scope_invalid",
                "scope 必须是 JSON array",
                path=f"{path}.scope",
            )
        return cls(
            schema_version=payload["schema_version"],
            entry_id=payload["entry_id"],
            topic=payload["topic"],
            statement=payload["statement"],
            provenance=tuple(
                KnowledgeProvenance.from_dict(
                    item,
                    path=f"{path}.provenance[{index}]",
                )
                for index, item in enumerate(raw_provenance)
            ),
            scope=tuple(raw_scope),
            version=payload["version"],
            proposed_at=payload["proposed_at"],
            expires_at=payload.get("expires_at"),
            not_evidence=payload.get("not_evidence", True),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "entry_id": self.entry_id,
            "topic": self.topic,
            "statement": self.statement,
            "provenance": [
                item.to_dict()
                for item in self.provenance
            ],
            "scope": list(self.scope),
            "version": self.version,
            "proposed_at": self.proposed_at,
            "expires_at": self.expires_at,
            "not_evidence": self.not_evidence,
        }


@dataclass(frozen=True, slots=True)
class KnowledgeEntry:
    """已人工确认、可审计但永远不能充当 evidence 的知识条目。"""

    entry_id: str
    topic: str
    statement: str
    provenance: tuple[KnowledgeProvenance, ...]
    scope: tuple[str, ...]
    version: int
    proposed_at: str
    committed_at: str
    created_by: OperatorIdentity
    approval_receipt: ApprovalReceipt
    expires_at: str | None = None
    revoked_at: str | None = None
    revoked_by: OperatorIdentity | None = None
    revocation_receipt: ApprovalReceipt | None = None
    not_evidence: bool = True
    schema_version: int = KNOWLEDGE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        candidate = KnowledgeCandidate(
            schema_version=self.schema_version,
            entry_id=self.entry_id,
            topic=self.topic,
            statement=self.statement,
            provenance=self.provenance,
            scope=self.scope,
            version=self.version,
            proposed_at=self.proposed_at,
            expires_at=self.expires_at,
            not_evidence=self.not_evidence,
        )
        for field_name in (
            "entry_id",
            "topic",
            "statement",
            "provenance",
            "scope",
            "version",
            "proposed_at",
            "expires_at",
            "not_evidence",
        ):
            object.__setattr__(
                self,
                field_name,
                getattr(candidate, field_name),
            )
        if not isinstance(self.created_by, OperatorIdentity):
            raise HumanControlContractError(
                "operator_invalid",
                "created_by 必须是 OperatorIdentity",
                path="$.created_by",
            )
        _validate_write_receipt(
            candidate,
            operator=self.created_by,
            receipt=self.approval_receipt,
        )
        committed_at = canonical_timestamp(
            self.committed_at,
            path="$.committed_at",
        )
        object.__setattr__(self, "committed_at", committed_at)
        if parse_timestamp(
            self.approval_receipt.approved_at,
        ) < parse_timestamp(self.proposed_at):
            raise HumanControlContractError(
                "approval_before_proposal",
                "Knowledge 审批时间不得早于 proposed_at",
                path="$.approval_receipt.approved_at",
            )
        if parse_timestamp(
            self.approval_receipt.approved_at,
        ) > parse_timestamp(self.committed_at):
            raise HumanControlContractError(
                "approval_after_commit",
                "Knowledge 审批时间不得晚于 committed_at",
                path="$.approval_receipt.approved_at",
            )
        if (
            self.expires_at is not None
            and parse_timestamp(self.expires_at)
            <= parse_timestamp(self.committed_at)
        ):
            raise HumanControlContractError(
                "knowledge_expired_before_commit",
                "expires_at 必须晚于 committed_at",
                path="$.expires_at",
            )
        revoked_fields = (
            self.revoked_at,
            self.revoked_by,
            self.revocation_receipt,
        )
        if all(item is None for item in revoked_fields):
            return
        if any(item is None for item in revoked_fields):
            raise HumanControlContractError(
                "revocation_fields_incomplete",
                "revoked_at、revoked_by、revocation_receipt 必须同时存在",
                path="$.revoked_at",
            )
        revoked_at = canonical_timestamp(
            self.revoked_at,
            path="$.revoked_at",
        )
        if parse_timestamp(revoked_at) < parse_timestamp(self.committed_at):
            raise HumanControlContractError(
                "revocation_before_commit",
                "revoked_at 不得早于 committed_at",
                path="$.revoked_at",
            )
        object.__setattr__(self, "revoked_at", revoked_at)
        if not isinstance(self.revoked_by, OperatorIdentity):
            raise HumanControlContractError(
                "operator_invalid",
                "revoked_by 必须是 OperatorIdentity",
                path="$.revoked_by",
            )
        if not isinstance(self.revocation_receipt, ApprovalReceipt):
            raise HumanControlContractError(
                "approval_receipt_invalid",
                "revocation_receipt 必须是 ApprovalReceipt",
                path="$.revocation_receipt",
            )
        active = self.without_revocation()
        _validate_revoke_receipt(
            active,
            revoked_at=revoked_at,
            operator=self.revoked_by,
            receipt=self.revocation_receipt,
        )
        if parse_timestamp(
            self.revocation_receipt.approved_at,
        ) > parse_timestamp(revoked_at):
            raise HumanControlContractError(
                "approval_after_revocation",
                "撤销审批时间不得晚于 revoked_at",
                path="$.revocation_receipt.approved_at",
            )

    @property
    def canonical_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    @property
    def candidate(self) -> KnowledgeCandidate:
        return KnowledgeCandidate(
            schema_version=self.schema_version,
            entry_id=self.entry_id,
            topic=self.topic,
            statement=self.statement,
            provenance=self.provenance,
            scope=self.scope,
            version=self.version,
            proposed_at=self.proposed_at,
            expires_at=self.expires_at,
            not_evidence=self.not_evidence,
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
                "entry_id",
                "topic",
                "statement",
                "provenance",
                "scope",
                "version",
                "proposed_at",
                "committed_at",
                "expires_at",
                "created_by",
                "approval_receipt",
                "revoked_at",
                "revoked_by",
                "revocation_receipt",
                "not_evidence",
            },
            path=path,
        )
        raw_provenance = payload["provenance"]
        raw_scope = payload["scope"]
        if not isinstance(raw_provenance, list):
            raise HumanControlContractError(
                "provenance_invalid",
                "provenance 必须是 JSON array",
                path=f"{path}.provenance",
            )
        if not isinstance(raw_scope, list):
            raise HumanControlContractError(
                "scope_invalid",
                "scope 必须是 JSON array",
                path=f"{path}.scope",
            )
        revoked_by = payload["revoked_by"]
        revocation_receipt = payload["revocation_receipt"]
        return cls(
            schema_version=payload["schema_version"],
            entry_id=payload["entry_id"],
            topic=payload["topic"],
            statement=payload["statement"],
            provenance=tuple(
                KnowledgeProvenance.from_dict(
                    item,
                    path=f"{path}.provenance[{index}]",
                )
                for index, item in enumerate(raw_provenance)
            ),
            scope=tuple(raw_scope),
            version=payload["version"],
            proposed_at=payload["proposed_at"],
            committed_at=payload["committed_at"],
            expires_at=payload["expires_at"],
            created_by=OperatorIdentity.from_dict(
                payload["created_by"],
                path=f"{path}.created_by",
            ),
            approval_receipt=ApprovalReceipt.from_dict(
                payload["approval_receipt"],
                path=f"{path}.approval_receipt",
            ),
            revoked_at=payload["revoked_at"],
            revoked_by=(
                OperatorIdentity.from_dict(
                    revoked_by,
                    path=f"{path}.revoked_by",
                )
                if revoked_by is not None
                else None
            ),
            revocation_receipt=(
                ApprovalReceipt.from_dict(
                    revocation_receipt,
                    path=f"{path}.revocation_receipt",
                )
                if revocation_receipt is not None
                else None
            ),
            not_evidence=payload["not_evidence"],
        )

    def without_revocation(self) -> Self:
        return KnowledgeEntry(
            schema_version=self.schema_version,
            entry_id=self.entry_id,
            topic=self.topic,
            statement=self.statement,
            provenance=self.provenance,
            scope=self.scope,
            version=self.version,
            proposed_at=self.proposed_at,
            committed_at=self.committed_at,
            expires_at=self.expires_at,
            created_by=self.created_by,
            approval_receipt=self.approval_receipt,
            revoked_at=None,
            revoked_by=None,
            revocation_receipt=None,
            not_evidence=self.not_evidence,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.candidate.to_dict(),
            "committed_at": self.committed_at,
            "created_by": self.created_by.to_dict(),
            "approval_receipt": self.approval_receipt.to_dict(),
            "revoked_at": self.revoked_at,
            "revoked_by": (
                self.revoked_by.to_dict()
                if self.revoked_by is not None
                else None
            ),
            "revocation_receipt": (
                self.revocation_receipt.to_dict()
                if self.revocation_receipt is not None
                else None
            ),
        }


def knowledge_write_subject_sha256(
    candidate: KnowledgeCandidate,
    *,
    operator: OperatorIdentity,
) -> str:
    """计算 knowledge write 审批收据必须绑定的 subject。"""

    if not isinstance(candidate, KnowledgeCandidate):
        raise HumanControlContractError(
            "knowledge_candidate_invalid",
            "candidate 必须是 KnowledgeCandidate",
        )
    if not isinstance(operator, OperatorIdentity):
        raise HumanControlContractError(
            "operator_invalid",
            "operator 必须是 OperatorIdentity",
        )
    return canonical_sha256(
        {
            "schema_version": KNOWLEDGE_SCHEMA_VERSION,
            "operation": ApprovalOperation.KNOWLEDGE_WRITE.value,
            "candidate": candidate.to_dict(),
            "operator": operator.to_dict(),
        },
    )


def normalize_knowledge_scope(
    values: tuple[str, ...] | list[str],
) -> tuple[str, ...]:
    """规范化查询 scope；entry scope 必须是其子集才可读取。"""

    return _scope_tuple(tuple(values))


def build_knowledge_entry(
    candidate: KnowledgeCandidate,
    *,
    operator: OperatorIdentity,
    approval_receipt: ApprovalReceipt,
    committed_at: str,
) -> KnowledgeEntry:
    """把已绑定审批收据的 candidate 转成最终条目。"""

    _validate_write_receipt(
        candidate,
        operator=operator,
        receipt=approval_receipt,
    )
    return KnowledgeEntry(
        schema_version=candidate.schema_version,
        entry_id=candidate.entry_id,
        topic=candidate.topic,
        statement=candidate.statement,
        provenance=candidate.provenance,
        scope=candidate.scope,
        version=candidate.version,
        proposed_at=candidate.proposed_at,
        committed_at=committed_at,
        expires_at=candidate.expires_at,
        created_by=operator,
        approval_receipt=approval_receipt,
        not_evidence=True,
    )


def knowledge_revoke_subject_sha256(
    entry: KnowledgeEntry,
    *,
    operator: OperatorIdentity,
) -> str:
    """计算 knowledge revoke 审批收据必须绑定的 subject。"""

    if not isinstance(entry, KnowledgeEntry):
        raise HumanControlContractError(
            "knowledge_entry_invalid",
            "entry 必须是 KnowledgeEntry",
        )
    if entry.revoked_at is not None:
        raise HumanControlContractError(
            "knowledge_already_revoked",
            "已撤销条目不能再次计算撤销 subject",
        )
    if not isinstance(operator, OperatorIdentity):
        raise HumanControlContractError(
            "operator_invalid",
            "operator 必须是 OperatorIdentity",
        )
    return canonical_sha256(
        {
            "schema_version": KNOWLEDGE_SCHEMA_VERSION,
            "operation": ApprovalOperation.KNOWLEDGE_REVOKE.value,
            "entry_sha256": entry.canonical_sha256,
            "entry_id": entry.entry_id,
            "version": entry.version,
            "operator": operator.to_dict(),
        },
    )


def revoke_knowledge_entry(
    entry: KnowledgeEntry,
    *,
    revoked_at: str,
    operator: OperatorIdentity,
    approval_receipt: ApprovalReceipt,
) -> KnowledgeEntry:
    """生成带完整撤销 provenance 的新 projection 条目。"""

    _validate_revoke_receipt(
        entry,
        revoked_at=revoked_at,
        operator=operator,
        receipt=approval_receipt,
    )
    return KnowledgeEntry(
        schema_version=entry.schema_version,
        entry_id=entry.entry_id,
        topic=entry.topic,
        statement=entry.statement,
        provenance=entry.provenance,
        scope=entry.scope,
        version=entry.version,
        proposed_at=entry.proposed_at,
        committed_at=entry.committed_at,
        expires_at=entry.expires_at,
        created_by=entry.created_by,
        approval_receipt=entry.approval_receipt,
        revoked_at=revoked_at,
        revoked_by=operator,
        revocation_receipt=approval_receipt,
        not_evidence=True,
    )


def _validate_write_receipt(
    candidate: KnowledgeCandidate,
    *,
    operator: OperatorIdentity,
    receipt: ApprovalReceipt,
) -> None:
    if not isinstance(operator, OperatorIdentity):
        raise HumanControlContractError(
            "operator_invalid",
            "operator 必须是 OperatorIdentity",
        )
    if not isinstance(receipt, ApprovalReceipt):
        raise HumanControlContractError(
            "approval_receipt_invalid",
            "approval_receipt 必须是 ApprovalReceipt",
        )
    if receipt.operation is not ApprovalOperation.KNOWLEDGE_WRITE:
        raise HumanControlContractError(
            "approval_operation_mismatch",
            "Knowledge 写入必须使用 knowledge_write 收据",
            path="$.approval_receipt.operation",
        )
    if receipt.decision is not HumanDecision.APPROVED:
        raise HumanControlContractError(
            "approval_required",
            "Knowledge 写入需要 approved 收据",
            path="$.approval_receipt.decision",
        )
    if receipt.operator_id != operator.operator_id:
        raise HumanControlContractError(
            "approval_operator_mismatch",
            "审批收据与 operator identity 不一致",
            path="$.approval_receipt.operator_id",
        )
    expected = knowledge_write_subject_sha256(
        candidate,
        operator=operator,
    )
    if receipt.subject_sha256 != expected:
        raise HumanControlContractError(
            "approval_subject_mismatch",
            "审批收据未绑定当前 Knowledge candidate",
            path="$.approval_receipt.subject_sha256",
        )


def _validate_revoke_receipt(
    entry: KnowledgeEntry,
    *,
    revoked_at: str,
    operator: OperatorIdentity,
    receipt: ApprovalReceipt,
) -> None:
    if not isinstance(receipt, ApprovalReceipt):
        raise HumanControlContractError(
            "approval_receipt_invalid",
            "approval_receipt 必须是 ApprovalReceipt",
        )
    if receipt.operation is not ApprovalOperation.KNOWLEDGE_REVOKE:
        raise HumanControlContractError(
            "approval_operation_mismatch",
            "Knowledge 撤销必须使用 knowledge_revoke 收据",
            path="$.approval_receipt.operation",
        )
    if receipt.decision is not HumanDecision.APPROVED:
        raise HumanControlContractError(
            "approval_required",
            "Knowledge 撤销需要 approved 收据",
            path="$.approval_receipt.decision",
        )
    if receipt.operator_id != operator.operator_id:
        raise HumanControlContractError(
            "approval_operator_mismatch",
            "审批收据与 operator identity 不一致",
            path="$.approval_receipt.operator_id",
        )
    expected = knowledge_revoke_subject_sha256(
        entry,
        operator=operator,
    )
    if receipt.subject_sha256 != expected:
        raise HumanControlContractError(
            "approval_subject_mismatch",
            "审批收据未绑定当前 Knowledge entry/revocation",
            path="$.approval_receipt.subject_sha256",
        )


def _schema_version(value: Any) -> None:
    if value != KNOWLEDGE_SCHEMA_VERSION:
        raise HumanControlContractError(
            "schema_version_unsupported",
            (
                "schema_version 必须等于 "
                f"{KNOWLEDGE_SCHEMA_VERSION}"
            ),
            path="$.schema_version",
        )


def _strict_object(
    value: Mapping[str, Any],
    *,
    required: set[str],
    optional: set[str] | None = None,
    path: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise HumanControlContractError(
            "object_required",
            "值必须是 JSON object",
            path=path,
        )
    if any(not isinstance(key, str) for key in value):
        raise HumanControlContractError(
            "json_key_invalid",
            "JSON object key 必须是字符串",
            path=path,
        )
    payload = dict(value)
    allowed = required | (optional or set())
    unknown = sorted(set(payload) - allowed)
    missing = sorted(required - set(payload))
    if unknown:
        raise HumanControlContractError(
            "fields_unknown",
            f"包含未知字段：{', '.join(unknown)}",
            path=path,
        )
    if missing:
        raise HumanControlContractError(
            "fields_missing",
            f"缺少字段：{', '.join(missing)}",
            path=path,
        )
    return payload


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


def _scope_tuple(values: tuple[str, ...]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise HumanControlContractError(
            "scope_invalid",
            "scope 必须是字符串 array",
            path="$.scope",
        )
    try:
        result = tuple(values)
    except TypeError as exc:
        raise HumanControlContractError(
            "scope_invalid",
            "scope 必须是字符串 array",
            path="$.scope",
        ) from exc
    for item in result:
        if (
            not isinstance(item, str)
            or _SCOPE_PATTERN.fullmatch(item) is None
        ):
            raise HumanControlContractError(
                "scope_token_invalid",
                "scope token 不是合法规范值",
                path="$.scope",
            )
    if len(result) != len(set(result)):
        raise HumanControlContractError(
            "scope_duplicate",
            "scope token 不得重复",
            path="$.scope",
        )
    dimensions = [item.split(":", 1)[0] for item in result]
    if len(dimensions) != len(set(dimensions)):
        raise HumanControlContractError(
            "scope_dimension_conflict",
            "同一 scope dimension 只能声明一个值",
            path="$.scope",
        )
    return tuple(sorted(result))


def _provenance_tuple(
    values: tuple[KnowledgeProvenance, ...],
) -> tuple[KnowledgeProvenance, ...]:
    if isinstance(values, (str, bytes)):
        raise HumanControlContractError(
            "provenance_invalid",
            "provenance 必须是 array",
            path="$.provenance",
        )
    try:
        result = tuple(values)
    except TypeError as exc:
        raise HumanControlContractError(
            "provenance_invalid",
            "provenance 必须是 array",
            path="$.provenance",
        ) from exc
    if any(
        not isinstance(item, KnowledgeProvenance)
        for item in result
    ):
        raise HumanControlContractError(
            "provenance_item_invalid",
            "provenance item 必须是 KnowledgeProvenance",
            path="$.provenance",
        )
    source_ids = [item.source_id for item in result]
    if len(source_ids) != len(set(source_ids)):
        raise HumanControlContractError(
            "provenance_duplicate",
            "provenance source_id 不得重复",
            path="$.provenance",
        )
    return tuple(sorted(result, key=lambda item: item.source_id))
