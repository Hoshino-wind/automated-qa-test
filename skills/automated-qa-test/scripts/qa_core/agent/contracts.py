"""定义模型可提交但不能自行授权的 Agent 提案契约。"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Self

from qa_core.tools import ToolContractError, ToolInvocation, ToolRegistry

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_FORBIDDEN_MODEL_TOKENS = frozenset(
    {
        "authorization",
        "signature",
        "shell",
    },
)
_PLAN_FIELDS = frozenset(
    {
        "proposal_id",
        "context_sha256",
        "state_sha256",
        "tool_registry_sha256",
        "model_id",
        "objective",
        "hypotheses",
        "evidence_refs",
        "probes",
    },
)
_HYPOTHESIS_FIELDS = frozenset(
    {
        "hypothesis_id",
        "statement",
        "evidence_refs",
    },
)
_PROBE_FIELDS = frozenset(
    {
        "probe_id",
        "context_sha256",
        "state_sha256",
        "tool_registry_sha256",
        "model_id",
        "hypothesis_ids",
        "evidence_refs",
        "rationale",
        "invocation",
        "timeout_seconds",
        "output_limit_bytes",
    },
)
_CRITIC_FIELDS = frozenset(
    {
        "review_id",
        "plan_sha256",
        "context_sha256",
        "state_sha256",
        "tool_registry_sha256",
        "model_id",
        "recommendation",
        "hypothesis_ids",
        "evidence_refs",
        "findings",
    },
)
_DIAGNOSIS_FIELDS = frozenset(
    {
        "diagnosis_id",
        "plan_sha256",
        "context_sha256",
        "state_sha256",
        "tool_registry_sha256",
        "trace_sha256",
        "model_id",
        "findings",
        "unknowns",
    },
)
_DIAGNOSIS_FINDING_FIELDS = frozenset(
    {
        "hypothesis_id",
        "status",
        "explanation",
        "evidence_refs",
        "recommended_probe_ids",
    },
)


class AgentContractError(ValueError):
    """模型提案不完整、越权或与当前输入不一致。"""

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
        """返回可写入 handoff 的结构化错误。"""

        return {
            "schema_version": 1,
            "error": "agent_contract_error",
            "code": self.code,
            "path": self.path,
            "message": str(self),
        }


class CriticRecommendation(StrEnum):
    """Critic 只能给出建议，不能表示策略批准。"""

    ACCEPT = "accept"
    REVISE = "revise"
    STOP = "stop"


class DiagnosisStatus(StrEnum):
    """Diagnostician 对既有假设的受约束状态更新。"""

    SUPPORTED = "supported"
    REFUTED = "refuted"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Hypothesis:
    """计划中带来源引用的可验证假设。"""

    hypothesis_id: str
    statement: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "hypothesis_id",
            _text("hypothesis_id", self.hypothesis_id),
        )
        object.__setattr__(
            self,
            "statement",
            _text("statement", self.statement),
        )
        object.__setattr__(
            self,
            "evidence_refs",
            _text_tuple("evidence_refs", self.evidence_refs),
        )

    @classmethod
    def from_model_input(
        cls,
        value: Mapping[str, Any],
        *,
        path: str = "$.hypothesis",
    ) -> Self:
        """严格解析模型给出的假设。"""

        payload = _model_object(
            value,
            allowed=_HYPOTHESIS_FIELDS,
            required=_HYPOTHESIS_FIELDS,
            unknown_code="hypothesis_fields_unknown",
            missing_code="hypothesis_fields_missing",
            path=path,
        )
        return cls(
            hypothesis_id=payload["hypothesis_id"],
            statement=payload["statement"],
            evidence_refs=_model_text_array(
                payload["evidence_refs"],
                name="evidence_refs",
                path=f"{path}.evidence_refs",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "statement": self.statement,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True, slots=True)
class ProbeProposal:
    """绑定当前输入、假设和证据来源的单个工具调用提案。"""

    probe_id: str
    context_sha256: str
    state_sha256: str
    tool_registry_sha256: str
    model_id: str
    hypothesis_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    rationale: str
    invocation: ToolInvocation
    timeout_seconds: float
    output_limit_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "probe_id",
            _text("probe_id", self.probe_id),
        )
        for field_name in (
            "context_sha256",
            "state_sha256",
            "tool_registry_sha256",
        ):
            object.__setattr__(
                self,
                field_name,
                _sha256(field_name, getattr(self, field_name)),
            )
        object.__setattr__(
            self,
            "model_id",
            _text("model_id", self.model_id),
        )
        hypothesis_ids = _text_tuple(
            "hypothesis_ids",
            self.hypothesis_ids,
        )
        if not hypothesis_ids:
            raise AgentContractError(
                "hypothesis_refs_missing",
                "ProbeProposal 至少需要一个 hypothesis_id",
                path="$.hypothesis_ids",
            )
        object.__setattr__(self, "hypothesis_ids", hypothesis_ids)
        object.__setattr__(
            self,
            "evidence_refs",
            _text_tuple("evidence_refs", self.evidence_refs),
        )
        object.__setattr__(
            self,
            "rationale",
            _text("rationale", self.rationale),
        )
        if not isinstance(self.invocation, ToolInvocation):
            raise AgentContractError(
                "invocation_type_invalid",
                "invocation 必须是 ToolInvocation",
                path="$.invocation",
            )
        _reject_forbidden_model_fields(
            self.invocation.to_dict(),
            path="$.invocation",
        )
        object.__setattr__(
            self,
            "timeout_seconds",
            _positive_number(
                "timeout_seconds",
                self.timeout_seconds,
            ),
        )
        object.__setattr__(
            self,
            "output_limit_bytes",
            _positive_integer(
                "output_limit_bytes",
                self.output_limit_bytes,
            ),
        )

    @classmethod
    def from_model_input(
        cls,
        value: Mapping[str, Any],
        *,
        registry: ToolRegistry,
        path: str = "$.probe",
    ) -> Self:
        """严格解析模型探针，并由 registry 形成 ToolInvocation。"""

        payload = _model_object(
            value,
            allowed=_PROBE_FIELDS,
            required=_PROBE_FIELDS,
            unknown_code="probe_fields_unknown",
            missing_code="probe_fields_missing",
            path=path,
        )
        if not isinstance(registry, ToolRegistry):
            raise AgentContractError(
                "tool_registry_invalid",
                "registry 必须是 ToolRegistry",
                path="$.registry",
            )
        try:
            invocation = registry.invocation_from_model(
                payload["invocation"],
            )
        except ToolContractError as exc:
            raise AgentContractError(
                exc.code,
                str(exc),
                path=f"{path}.invocation{exc.path[1:]}",
            ) from exc
        return cls(
            probe_id=payload["probe_id"],
            context_sha256=payload["context_sha256"],
            state_sha256=payload["state_sha256"],
            tool_registry_sha256=payload["tool_registry_sha256"],
            model_id=payload["model_id"],
            hypothesis_ids=_model_text_array(
                payload["hypothesis_ids"],
                name="hypothesis_ids",
                path=f"{path}.hypothesis_ids",
            ),
            evidence_refs=_model_text_array(
                payload["evidence_refs"],
                name="evidence_refs",
                path=f"{path}.evidence_refs",
            ),
            rationale=payload["rationale"],
            invocation=invocation,
            timeout_seconds=payload["timeout_seconds"],
            output_limit_bytes=payload["output_limit_bytes"],
        )

    @property
    def canonical_sha256(self) -> str:
        """返回用于授权绑定的规范哈希。"""

        return _canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "context_sha256": self.context_sha256,
            "state_sha256": self.state_sha256,
            "tool_registry_sha256": self.tool_registry_sha256,
            "model_id": self.model_id,
            "hypothesis_ids": list(self.hypothesis_ids),
            "evidence_refs": list(self.evidence_refs),
            "rationale": self.rationale,
            "invocation": self.invocation.to_dict(),
            "timeout_seconds": self.timeout_seconds,
            "output_limit_bytes": self.output_limit_bytes,
        }


@dataclass(frozen=True, slots=True)
class PlanProposal:
    """模型规划输出；该对象不包含任何执行授权。"""

    proposal_id: str
    context_sha256: str
    state_sha256: str
    tool_registry_sha256: str
    model_id: str
    objective: str
    hypotheses: tuple[Hypothesis, ...]
    evidence_refs: tuple[str, ...]
    probes: tuple[ProbeProposal, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "proposal_id",
            _text("proposal_id", self.proposal_id),
        )
        for field_name in (
            "context_sha256",
            "state_sha256",
            "tool_registry_sha256",
        ):
            object.__setattr__(
                self,
                field_name,
                _sha256(field_name, getattr(self, field_name)),
            )
        object.__setattr__(
            self,
            "model_id",
            _text("model_id", self.model_id),
        )
        object.__setattr__(
            self,
            "objective",
            _text("objective", self.objective),
        )
        hypotheses = tuple(self.hypotheses)
        if not hypotheses or any(
            not isinstance(item, Hypothesis)
            for item in hypotheses
        ):
            raise AgentContractError(
                "hypotheses_invalid",
                "PlanProposal 至少需要一个 Hypothesis",
                path="$.hypotheses",
            )
        hypothesis_ids = [item.hypothesis_id for item in hypotheses]
        _unique_ids(
            "hypothesis_id",
            hypothesis_ids,
            path="$.hypotheses",
        )
        object.__setattr__(self, "hypotheses", hypotheses)
        object.__setattr__(
            self,
            "evidence_refs",
            _text_tuple("evidence_refs", self.evidence_refs),
        )
        probes = tuple(self.probes)
        if not probes or any(
            not isinstance(item, ProbeProposal)
            for item in probes
        ):
            raise AgentContractError(
                "probes_invalid",
                "PlanProposal 至少需要一个 ProbeProposal",
                path="$.probes",
            )
        _unique_ids(
            "probe_id",
            [item.probe_id for item in probes],
            path="$.probes",
        )
        known_hypotheses = set(hypothesis_ids)
        for index, probe in enumerate(probes):
            self._validate_probe_binding(
                probe,
                index=index,
                known_hypotheses=known_hypotheses,
            )
        object.__setattr__(self, "probes", probes)

    @classmethod
    def from_model_input(
        cls,
        value: Mapping[str, Any],
        *,
        registry: ToolRegistry,
        expected_model_id: str,
        allowed_evidence_refs: Iterable[str],
    ) -> Self:
        """严格解析计划并绑定 Registry、模型与可信来源集合。"""

        payload = _model_object(
            value,
            allowed=_PLAN_FIELDS,
            required=_PLAN_FIELDS,
            unknown_code="proposal_fields_unknown",
            missing_code="proposal_fields_missing",
            path="$.proposal",
        )
        if not isinstance(registry, ToolRegistry):
            raise AgentContractError(
                "tool_registry_invalid",
                "registry 必须是 ToolRegistry",
                path="$.registry",
            )
        registry_sha256 = _sha256(
            "tool_registry_sha256",
            payload["tool_registry_sha256"],
        )
        if registry_sha256 != registry.canonical_sha256:
            raise AgentContractError(
                "tool_registry_hash_drift",
                "模型计划绑定的 Tool Registry 不是当前版本",
                path="$.proposal.tool_registry_sha256",
            )
        hypotheses_value = payload["hypotheses"]
        probes_value = payload["probes"]
        if not isinstance(hypotheses_value, list):
            raise AgentContractError(
                "hypotheses_invalid",
                "hypotheses 必须是 array",
                path="$.proposal.hypotheses",
            )
        if not isinstance(probes_value, list):
            raise AgentContractError(
                "probes_invalid",
                "probes 必须是 array",
                path="$.proposal.probes",
            )
        hypotheses = tuple(
            Hypothesis.from_model_input(
                item,
                path=f"$.proposal.hypotheses[{index}]",
            )
            for index, item in enumerate(hypotheses_value)
        )
        probes = tuple(
            ProbeProposal.from_model_input(
                item,
                registry=registry,
                path=f"$.proposal.probes[{index}]",
            )
            for index, item in enumerate(probes_value)
        )
        proposal = cls(
            proposal_id=payload["proposal_id"],
            context_sha256=payload["context_sha256"],
            state_sha256=payload["state_sha256"],
            tool_registry_sha256=registry_sha256,
            model_id=payload["model_id"],
            objective=payload["objective"],
            hypotheses=hypotheses,
            evidence_refs=_model_text_array(
                payload["evidence_refs"],
                name="evidence_refs",
                path="$.proposal.evidence_refs",
            ),
            probes=probes,
        )
        expected_model = _text(
            "expected_model_id",
            expected_model_id,
        )
        if proposal.model_id != expected_model:
            raise AgentContractError(
                "proposal_model_id_drift",
                "模型计划的 model_id 与受信调用边界不一致",
                path="$.proposal.model_id",
            )
        allowed_refs = _trusted_evidence_refs(
            allowed_evidence_refs,
            path="$.allowed_evidence_refs",
        )
        _require_evidence_subset(
            proposal.evidence_refs,
            allowed=allowed_refs,
            path="$.proposal.evidence_refs",
        )
        declared_refs = frozenset(proposal.evidence_refs)
        if not declared_refs:
            raise AgentContractError(
                "proposal_evidence_missing",
                "PlanProposal 至少需要一个受信证据引用",
                path="$.proposal.evidence_refs",
            )
        for index, hypothesis in enumerate(proposal.hypotheses):
            if not hypothesis.evidence_refs:
                raise AgentContractError(
                    "hypothesis_evidence_missing",
                    "每个 hypothesis 至少需要一个受信证据引用",
                    path=(
                        "$.proposal.hypotheses"
                        f"[{index}].evidence_refs"
                    ),
                )
            _require_evidence_subset(
                hypothesis.evidence_refs,
                allowed=declared_refs,
                path=(
                    "$.proposal.hypotheses"
                    f"[{index}].evidence_refs"
                ),
            )
        for index, probe in enumerate(proposal.probes):
            if not probe.evidence_refs:
                raise AgentContractError(
                    "probe_evidence_missing",
                    "每个 probe 至少需要一个受信证据引用",
                    path=f"$.proposal.probes[{index}].evidence_refs",
                )
            _require_evidence_subset(
                probe.evidence_refs,
                allowed=declared_refs,
                path=f"$.proposal.probes[{index}].evidence_refs",
            )
        return proposal

    @property
    def canonical_sha256(self) -> str:
        """返回用于 Critic 和 Policy 绑定的规范哈希。"""

        return _canonical_sha256(self.to_dict())

    def find_probe(self, probe_id: str) -> ProbeProposal:
        """按稳定 id 查找探针。"""

        normalized = _text("probe_id", probe_id)
        for probe in self.probes:
            if probe.probe_id == normalized:
                return probe
        raise AgentContractError(
            "probe_unknown",
            f"计划中不存在 probe：{normalized}",
            path="$.probe_id",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "qa_plan_proposal",
            "not_authorization": True,
            "proposal_id": self.proposal_id,
            "context_sha256": self.context_sha256,
            "state_sha256": self.state_sha256,
            "tool_registry_sha256": self.tool_registry_sha256,
            "model_id": self.model_id,
            "objective": self.objective,
            "hypotheses": [
                item.to_dict()
                for item in self.hypotheses
            ],
            "evidence_refs": list(self.evidence_refs),
            "probes": [
                item.to_dict()
                for item in self.probes
            ],
        }

    def _validate_probe_binding(
        self,
        probe: ProbeProposal,
        *,
        index: int,
        known_hypotheses: set[str],
    ) -> None:
        bindings = {
            "context_sha256": self.context_sha256,
            "state_sha256": self.state_sha256,
            "tool_registry_sha256": self.tool_registry_sha256,
            "model_id": self.model_id,
        }
        for field_name, expected in bindings.items():
            if getattr(probe, field_name) != expected:
                raise AgentContractError(
                    "probe_binding_drift",
                    f"probe 的 {field_name} 与计划不一致",
                    path=f"$.probes[{index}].{field_name}",
                )
        unknown = sorted(
            set(probe.hypothesis_ids) - known_hypotheses,
        )
        if unknown:
            raise AgentContractError(
                "hypothesis_ref_unknown",
                f"probe 引用了未知假设：{', '.join(unknown)}",
                path=f"$.probes[{index}].hypothesis_ids",
            )


@dataclass(frozen=True, slots=True)
class CriticReview:
    """绑定计划与证据的 Critic 建议，不具备授权语义。"""

    review_id: str
    plan_sha256: str
    context_sha256: str
    state_sha256: str
    tool_registry_sha256: str
    model_id: str
    recommendation: CriticRecommendation | str
    hypothesis_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    findings: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "review_id",
            _text("review_id", self.review_id),
        )
        for field_name in (
            "plan_sha256",
            "context_sha256",
            "state_sha256",
            "tool_registry_sha256",
        ):
            object.__setattr__(
                self,
                field_name,
                _sha256(field_name, getattr(self, field_name)),
            )
        object.__setattr__(
            self,
            "model_id",
            _text("model_id", self.model_id),
        )
        try:
            recommendation = CriticRecommendation(
                self.recommendation,
            )
        except (TypeError, ValueError) as exc:
            raise AgentContractError(
                "critic_recommendation_invalid",
                "recommendation 必须是 accept、revise 或 stop",
                path="$.recommendation",
            ) from exc
        object.__setattr__(
            self,
            "recommendation",
            recommendation,
        )
        object.__setattr__(
            self,
            "hypothesis_ids",
            _text_tuple("hypothesis_ids", self.hypothesis_ids),
        )
        object.__setattr__(
            self,
            "evidence_refs",
            _text_tuple("evidence_refs", self.evidence_refs),
        )
        findings = _text_tuple("findings", self.findings)
        if not findings:
            raise AgentContractError(
                "critic_findings_missing",
                "CriticReview 至少需要一条 finding",
                path="$.findings",
            )
        object.__setattr__(self, "findings", findings)

    @classmethod
    def from_model_input(
        cls,
        value: Mapping[str, Any],
        *,
        plan: PlanProposal,
        expected_model_id: str,
        allowed_evidence_refs: Iterable[str],
    ) -> Self:
        """解析 Critic 建议并绑定当前计划、模型与证据集合。"""

        if not isinstance(plan, PlanProposal):
            raise AgentContractError(
                "critic_plan_invalid",
                "plan 必须是 PlanProposal",
                path="$.plan",
            )
        payload = _model_object(
            value,
            allowed=_CRITIC_FIELDS,
            required=_CRITIC_FIELDS,
            unknown_code="critic_fields_unknown",
            missing_code="critic_fields_missing",
            path="$.critic",
        )
        bindings = {
            "plan_sha256": plan.canonical_sha256,
            "context_sha256": plan.context_sha256,
            "state_sha256": plan.state_sha256,
            "tool_registry_sha256": plan.tool_registry_sha256,
        }
        for field_name, expected in bindings.items():
            if _sha256(field_name, payload[field_name]) != expected:
                raise AgentContractError(
                    "critic_binding_drift",
                    f"critic 的 {field_name} 与当前计划不一致",
                    path=f"$.critic.{field_name}",
                )
        if _text("model_id", payload["model_id"]) != _text(
            "expected_model_id",
            expected_model_id,
        ):
            raise AgentContractError(
                "critic_model_id_drift",
                "critic model_id 与受信调用边界不一致",
                path="$.critic.model_id",
            )
        review = cls(
            review_id=payload["review_id"],
            plan_sha256=payload["plan_sha256"],
            context_sha256=payload["context_sha256"],
            state_sha256=payload["state_sha256"],
            tool_registry_sha256=payload[
                "tool_registry_sha256"
            ],
            model_id=payload["model_id"],
            recommendation=payload["recommendation"],
            hypothesis_ids=_model_text_array(
                payload["hypothesis_ids"],
                name="hypothesis_ids",
                path="$.critic.hypothesis_ids",
            ),
            evidence_refs=_model_text_array(
                payload["evidence_refs"],
                name="evidence_refs",
                path="$.critic.evidence_refs",
            ),
            findings=_model_text_array(
                payload["findings"],
                name="findings",
                path="$.critic.findings",
            ),
        )
        unknown_hypotheses = sorted(
            set(review.hypothesis_ids)
            - {
                hypothesis.hypothesis_id
                for hypothesis in plan.hypotheses
            }
        )
        if unknown_hypotheses:
            raise AgentContractError(
                "critic_hypothesis_unknown",
                (
                    "critic 引用了未知假设："
                    + ", ".join(unknown_hypotheses)
                ),
                path="$.critic.hypothesis_ids",
            )
        _require_evidence_subset(
            review.evidence_refs,
            allowed=_trusted_evidence_refs(
                allowed_evidence_refs,
                path="$.allowed_evidence_refs",
            ),
            path="$.critic.evidence_refs",
        )
        return review

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "qa_critic_review",
            "not_authorization": True,
            "review_id": self.review_id,
            "plan_sha256": self.plan_sha256,
            "context_sha256": self.context_sha256,
            "state_sha256": self.state_sha256,
            "tool_registry_sha256": self.tool_registry_sha256,
            "model_id": self.model_id,
            "recommendation": self.recommendation.value,
            "hypothesis_ids": list(self.hypothesis_ids),
            "evidence_refs": list(self.evidence_refs),
            "findings": list(self.findings),
        }


@dataclass(frozen=True, slots=True)
class DiagnosisFinding:
    """只引用既有假设/探针和观察证据的诊断结论。"""

    hypothesis_id: str
    status: DiagnosisStatus | str
    explanation: str
    evidence_refs: tuple[str, ...]
    recommended_probe_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "hypothesis_id",
            _text("hypothesis_id", self.hypothesis_id),
        )
        try:
            normalized_status = DiagnosisStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise AgentContractError(
                "diagnosis_status_invalid",
                "status 必须是 supported、refuted 或 unknown",
                path="$.status",
            ) from exc
        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(
            self,
            "explanation",
            _text("explanation", self.explanation),
        )
        evidence_refs = _text_tuple(
            "evidence_refs",
            self.evidence_refs,
        )
        if not evidence_refs:
            raise AgentContractError(
                "diagnosis_evidence_missing",
                "每条 diagnosis finding 至少需要一个观察证据引用",
                path="$.evidence_refs",
            )
        object.__setattr__(self, "evidence_refs", evidence_refs)
        object.__setattr__(
            self,
            "recommended_probe_ids",
            _text_tuple(
                "recommended_probe_ids",
                self.recommended_probe_ids,
            ),
        )

    @classmethod
    def from_model_input(
        cls,
        value: Mapping[str, Any],
        *,
        path: str,
    ) -> Self:
        payload = _model_object(
            value,
            allowed=_DIAGNOSIS_FINDING_FIELDS,
            required=_DIAGNOSIS_FINDING_FIELDS,
            unknown_code="diagnosis_finding_fields_unknown",
            missing_code="diagnosis_finding_fields_missing",
            path=path,
        )
        return cls(
            hypothesis_id=payload["hypothesis_id"],
            status=payload["status"],
            explanation=payload["explanation"],
            evidence_refs=_model_text_array(
                payload["evidence_refs"],
                name="evidence_refs",
                path=f"{path}.evidence_refs",
            ),
            recommended_probe_ids=_model_text_array(
                payload["recommended_probe_ids"],
                name="recommended_probe_ids",
                path=f"{path}.recommended_probe_ids",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "status": self.status.value,
            "explanation": self.explanation,
            "evidence_refs": list(self.evidence_refs),
            "recommended_probe_ids": list(
                self.recommended_probe_ids
            ),
        }


@dataclass(frozen=True, slots=True)
class DiagnosisProposal:
    """绑定当前 plan/state/trace 的诊断建议，不携带工具调用或授权。"""

    diagnosis_id: str
    plan_sha256: str
    context_sha256: str
    state_sha256: str
    tool_registry_sha256: str
    trace_sha256: str
    model_id: str
    findings: tuple[DiagnosisFinding, ...]
    unknowns: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "diagnosis_id",
            _text("diagnosis_id", self.diagnosis_id),
        )
        for field_name in (
            "plan_sha256",
            "context_sha256",
            "state_sha256",
            "tool_registry_sha256",
            "trace_sha256",
        ):
            object.__setattr__(
                self,
                field_name,
                _sha256(field_name, getattr(self, field_name)),
            )
        object.__setattr__(
            self,
            "model_id",
            _text("model_id", self.model_id),
        )
        findings = tuple(self.findings)
        if not findings or any(
            not isinstance(item, DiagnosisFinding)
            for item in findings
        ):
            raise AgentContractError(
                "diagnosis_findings_invalid",
                "DiagnosisProposal 至少需要一条 DiagnosisFinding",
                path="$.findings",
            )
        _unique_ids(
            "hypothesis_id",
            [item.hypothesis_id for item in findings],
            path="$.findings",
        )
        object.__setattr__(self, "findings", findings)
        object.__setattr__(
            self,
            "unknowns",
            _text_tuple("unknowns", self.unknowns),
        )

    @classmethod
    def from_model_input(
        cls,
        value: Mapping[str, Any],
        *,
        plan: PlanProposal,
        expected_trace_sha256: str,
        expected_model_id: str,
        allowed_evidence_refs: Iterable[str],
    ) -> Self:
        """解析诊断并证明它只引用当前计划中的假设和探针。"""

        if not isinstance(plan, PlanProposal):
            raise AgentContractError(
                "diagnosis_plan_invalid",
                "plan 必须是 PlanProposal",
                path="$.plan",
            )
        payload = _model_object(
            value,
            allowed=_DIAGNOSIS_FIELDS,
            required=_DIAGNOSIS_FIELDS,
            unknown_code="diagnosis_fields_unknown",
            missing_code="diagnosis_fields_missing",
            path="$.diagnosis",
        )
        bindings = {
            "plan_sha256": plan.canonical_sha256,
            "context_sha256": plan.context_sha256,
            "state_sha256": plan.state_sha256,
            "tool_registry_sha256": plan.tool_registry_sha256,
            "trace_sha256": _sha256(
                "expected_trace_sha256",
                expected_trace_sha256,
            ),
        }
        for field_name, expected in bindings.items():
            if _sha256(field_name, payload[field_name]) != expected:
                raise AgentContractError(
                    "diagnosis_binding_drift",
                    f"diagnosis 的 {field_name} 与当前计划不一致",
                    path=f"$.diagnosis.{field_name}",
                )
        if _text("model_id", payload["model_id"]) != _text(
            "expected_model_id",
            expected_model_id,
        ):
            raise AgentContractError(
                "diagnosis_model_id_drift",
                "diagnosis model_id 与受信调用边界不一致",
                path="$.diagnosis.model_id",
            )
        findings_value = payload["findings"]
        if not isinstance(findings_value, list):
            raise AgentContractError(
                "diagnosis_findings_invalid",
                "findings 必须是 JSON array",
                path="$.diagnosis.findings",
            )
        findings = tuple(
            DiagnosisFinding.from_model_input(
                item,
                path=f"$.diagnosis.findings[{index}]",
            )
            for index, item in enumerate(findings_value)
        )
        known_hypotheses = {
            item.hypothesis_id for item in plan.hypotheses
        }
        probes = {
            item.probe_id: item for item in plan.probes
        }
        allowed_refs = _trusted_evidence_refs(
            allowed_evidence_refs,
            path="$.allowed_evidence_refs",
        )
        for index, finding in enumerate(findings):
            if finding.hypothesis_id not in known_hypotheses:
                raise AgentContractError(
                    "diagnosis_hypothesis_unknown",
                    (
                        "diagnosis 引用了未知假设："
                        f"{finding.hypothesis_id}"
                    ),
                    path=(
                        f"$.diagnosis.findings[{index}].hypothesis_id"
                    ),
                )
            for probe_id in finding.recommended_probe_ids:
                probe = probes.get(probe_id)
                if probe is None:
                    raise AgentContractError(
                        "diagnosis_probe_unknown",
                        f"diagnosis 引用了未知探针：{probe_id}",
                        path=(
                            "$.diagnosis.findings"
                            f"[{index}].recommended_probe_ids"
                        ),
                    )
                if finding.hypothesis_id not in probe.hypothesis_ids:
                    raise AgentContractError(
                        "diagnosis_probe_hypothesis_mismatch",
                        (
                            f"探针 {probe_id} 未绑定假设 "
                            f"{finding.hypothesis_id}"
                        ),
                        path=(
                            "$.diagnosis.findings"
                            f"[{index}].recommended_probe_ids"
                        ),
                    )
            _require_evidence_subset(
                finding.evidence_refs,
                allowed=allowed_refs,
                path=(
                    f"$.diagnosis.findings[{index}].evidence_refs"
                ),
            )
        return cls(
            diagnosis_id=payload["diagnosis_id"],
            plan_sha256=payload["plan_sha256"],
            context_sha256=payload["context_sha256"],
            state_sha256=payload["state_sha256"],
            tool_registry_sha256=payload[
                "tool_registry_sha256"
            ],
            trace_sha256=payload["trace_sha256"],
            model_id=payload["model_id"],
            findings=findings,
            unknowns=_model_text_array(
                payload["unknowns"],
                name="unknowns",
                path="$.diagnosis.unknowns",
            ),
        )

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "qa_diagnosis_proposal",
            "not_authorization": True,
            "diagnosis_id": self.diagnosis_id,
            "plan_sha256": self.plan_sha256,
            "context_sha256": self.context_sha256,
            "state_sha256": self.state_sha256,
            "tool_registry_sha256": self.tool_registry_sha256,
            "trace_sha256": self.trace_sha256,
            "model_id": self.model_id,
            "findings": [
                item.to_dict() for item in self.findings
            ],
            "unknowns": list(self.unknowns),
        }


def _model_object(
    value: Mapping[str, Any],
    *,
    allowed: frozenset[str],
    required: frozenset[str],
    unknown_code: str,
    missing_code: str,
    path: str,
) -> dict[str, Any]:
    payload = _plain_json(value, path=path)
    if not isinstance(payload, dict):
        raise AgentContractError(
            "model_object_invalid",
            "模型输出必须是 JSON object",
            path=path,
        )
    _reject_forbidden_model_fields(payload, path=path)
    fields = set(payload)
    unknown = sorted(fields - allowed)
    if unknown:
        raise AgentContractError(
            unknown_code,
            f"模型输出包含未知字段：{', '.join(unknown)}",
            path=path,
        )
    missing = sorted(required - fields)
    if missing:
        raise AgentContractError(
            missing_code,
            f"模型输出缺少字段：{', '.join(missing)}",
            path=path,
        )
    return payload


def _reject_forbidden_model_fields(
    value: Any,
    *,
    path: str,
) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            tokens = {
                token.rstrip("s")
                for token in re.split(r"[._-]+", key.lower())
                if token
            }
            forbidden = sorted(tokens & _FORBIDDEN_MODEL_TOKENS)
            if forbidden:
                raise AgentContractError(
                    "model_field_forbidden",
                    (
                        "模型 proposal 不得包含字段："
                        f"{key}"
                    ),
                    path=f"{path}.{key}",
                )
            _reject_forbidden_model_fields(
                item,
                path=f"{path}.{key}",
            )
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_forbidden_model_fields(
                item,
                path=f"{path}[{index}]",
            )


def _plain_json(value: Any, *, path: str) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise AgentContractError(
                    "json_key_invalid",
                    "JSON object 的 key 必须是字符串",
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
    raise AgentContractError(
        "json_value_invalid",
        "值必须能无损表示为标准 JSON",
        path=path,
    )


def _text_tuple(
    name: str,
    values: tuple[str, ...],
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise AgentContractError(
            "text_list_invalid",
            f"{name} 必须是字符串 array",
            path=f"$.{name}",
        )
    try:
        normalized = tuple(
            _text(name, item)
            for item in values
        )
    except TypeError as exc:
        raise AgentContractError(
            "text_list_invalid",
            f"{name} 必须是字符串 array",
            path=f"$.{name}",
        ) from exc
    if len(normalized) != len(set(normalized)):
        raise AgentContractError(
            "text_list_duplicate",
            f"{name} 不得包含重复值",
            path=f"$.{name}",
        )
    return normalized


def _model_text_array(
    value: Any,
    *,
    name: str,
    path: str,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AgentContractError(
            "model_array_invalid",
            f"{name} 必须是 JSON array",
            path=path,
        )
    return _text_tuple(name, tuple(value))


def _trusted_evidence_refs(
    values: Iterable[str],
    *,
    path: str,
) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise AgentContractError(
            "evidence_allowlist_invalid",
            "allowed_evidence_refs 必须是字符串集合",
            path=path,
        )
    try:
        normalized = _text_tuple(
            "allowed_evidence_refs",
            tuple(values),
        )
    except TypeError as exc:
        raise AgentContractError(
            "evidence_allowlist_invalid",
            "allowed_evidence_refs 必须是字符串集合",
            path=path,
        ) from exc
    if not normalized:
        raise AgentContractError(
            "evidence_allowlist_empty",
            "allowed_evidence_refs 不得为空",
            path=path,
        )
    return frozenset(normalized)


def _require_evidence_subset(
    values: Iterable[str],
    *,
    allowed: frozenset[str],
    path: str,
) -> None:
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise AgentContractError(
            "evidence_ref_untrusted",
            "模型引用了未注入的证据来源：" + ", ".join(unknown),
            path=path,
        )


def _unique_ids(
    name: str,
    values: list[str],
    *,
    path: str,
) -> None:
    if len(values) != len(set(values)):
        raise AgentContractError(
            "id_duplicate",
            f"{name} 不得重复",
            path=path,
        )


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AgentContractError(
            "text_invalid",
            f"{name} 必须是非空字符串",
            path=f"$.{name}",
        )
    return value.strip()


def _sha256(name: str, value: str) -> str:
    normalized = _text(name, value).lower()
    if _SHA256_PATTERN.fullmatch(normalized) is None:
        raise AgentContractError(
            "sha256_invalid",
            f"{name} 必须是 64 位十六进制 SHA-256",
            path=f"$.{name}",
        )
    return normalized


def _positive_number(name: str, value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise AgentContractError(
            "positive_number_invalid",
            f"{name} 必须是有限正数",
            path=f"$.{name}",
        )
    return float(value)


def _positive_integer(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise AgentContractError(
            "positive_integer_invalid",
            f"{name} 必须是正整数",
            path=f"$.{name}",
        )
    return value


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
