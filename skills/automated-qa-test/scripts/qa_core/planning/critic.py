"""按信息增益确定性排序探针；该模块不签发执行授权。"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Self

from qa_core.tools import (
    ToolContractError,
    ToolInvocation,
    build_default_tool_registry,
)

CRITIC_SCHEMA_VERSION = 1
CRITIC_VERSION = "deterministic-probe-critic@1"
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_PROBABILITY_TOLERANCE = 1e-9
_ROUND_DIGITS = 12
_MAX_ITEMS = 512
_MAX_TEXT_LENGTH = 8_192
_MAX_DURATION_SECONDS = 86_400.0
_MAX_REMAINING_SECONDS = 604_800.0
_MAX_OUTPUT_BYTES = 1_073_741_824
_MAX_REMAINING_OUTPUT_BYTES = 17_179_869_184
_MAX_ATTEMPTS = 1_000_000
_UNTRUSTED_DUPLICATE_FLOOR = 1.0
_UNTRUSTED_NO_PROGRESS_FLOOR = 1.0
_WEIGHTS = {
    "information_gain": 0.40,
    "defect_risk": 0.25,
    "conflict_resolution": 0.20,
    "cost_efficiency": 0.15,
    "duplicate_penalty": 0.15,
    "no_progress_penalty": 0.25,
}
_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "plan_sha256",
        "context_sha256",
        "state_sha256",
        "tool_registry_sha256",
        "hypotheses",
        "evidence_gaps",
        "candidates",
        "history",
        "budget",
    }
)
_HYPOTHESIS_FIELDS = frozenset(
    {
        "hypothesis_id",
        "statement",
        "prior_defect_probability",
        "defect_impact",
    }
)
_GAP_FIELDS = frozenset(
    {
        "gap_id",
        "hypothesis_id",
        "statement",
        "evidence_refs",
        "conflict_level",
    }
)
_CANDIDATE_FIELDS = frozenset(
    {
        "probe_id",
        "action",
        "arguments",
        "tool_version",
        "tool_spec_sha256",
        "hypothesis_ids",
        "evidence_gap_ids",
        "expected_observations",
        "estimated_cost",
    }
)
_OBSERVATION_FIELDS = frozenset(
    {
        "observation_id",
        "probability",
        "posteriors",
    }
)
_POSTERIOR_FIELDS = frozenset(
    {
        "hypothesis_id",
        "defect_probability",
    }
)
_COST_FIELDS = frozenset(
    {
        "duration_seconds",
        "output_bytes",
    }
)
_HISTORY_FIELDS = frozenset(
    {
        "probe_fingerprint_sha256",
        "attempts",
        "no_progress_attempts",
    }
)
_BUDGET_FIELDS = frozenset(
    {
        "remaining_seconds",
        "remaining_probes",
        "remaining_output_bytes",
    }
)


class CriticContractError(ValueError):
    """Critic 输入不完整、数值不安全或引用关系不闭合。"""

    def __init__(self, code: str, message: str, *, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(message)

    def to_dict(self) -> dict[str, str | int]:
        """返回稳定的失败关闭错误。"""

        return {
            "schema_version": CRITIC_SCHEMA_VERSION,
            "error": "critic_contract_error",
            "code": self.code,
            "path": self.path,
            "message": str(self),
        }


@dataclass(frozen=True, slots=True)
class HypothesisSignal:
    """用于计算风险和先验熵的假设信号。"""

    hypothesis_id: str
    statement: str
    prior_defect_probability: float
    defect_impact: float

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], *, path: str) -> Self:
        payload = _strict_object(value, fields=_HYPOTHESIS_FIELDS, path=path)
        return cls(
            hypothesis_id=_text(
                payload["hypothesis_id"],
                path=f"{path}.hypothesis_id",
            ),
            statement=_text(payload["statement"], path=f"{path}.statement"),
            prior_defect_probability=_bounded_number(
                payload["prior_defect_probability"],
                minimum=0.0,
                maximum=1.0,
                path=f"{path}.prior_defect_probability",
            ),
            defect_impact=_bounded_number(
                payload["defect_impact"],
                minimum=0.0,
                maximum=1.0,
                path=f"{path}.defect_impact",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "statement": self.statement,
            "prior_defect_probability": self.prior_defect_probability,
            "defect_impact": self.defect_impact,
        }


@dataclass(frozen=True, slots=True)
class EvidenceGap:
    """与一个假设绑定、尚待探针消解的证据缺口。"""

    gap_id: str
    hypothesis_id: str
    statement: str
    evidence_refs: tuple[str, ...]
    conflict_level: float

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], *, path: str) -> Self:
        payload = _strict_object(value, fields=_GAP_FIELDS, path=path)
        return cls(
            gap_id=_text(payload["gap_id"], path=f"{path}.gap_id"),
            hypothesis_id=_text(
                payload["hypothesis_id"],
                path=f"{path}.hypothesis_id",
            ),
            statement=_text(payload["statement"], path=f"{path}.statement"),
            evidence_refs=_text_array(
                payload["evidence_refs"],
                path=f"{path}.evidence_refs",
                allow_empty=False,
            ),
            conflict_level=_bounded_number(
                payload["conflict_level"],
                minimum=0.0,
                maximum=1.0,
                path=f"{path}.conflict_level",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "gap_id": self.gap_id,
            "hypothesis_id": self.hypothesis_id,
            "statement": self.statement,
            "evidence_refs": list(self.evidence_refs),
            "conflict_level": self.conflict_level,
        }


@dataclass(frozen=True, slots=True)
class PosteriorEstimate:
    """某个观察结果下的假设后验概率。"""

    hypothesis_id: str
    defect_probability: float

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], *, path: str) -> Self:
        payload = _strict_object(value, fields=_POSTERIOR_FIELDS, path=path)
        return cls(
            hypothesis_id=_text(
                payload["hypothesis_id"],
                path=f"{path}.hypothesis_id",
            ),
            defect_probability=_bounded_number(
                payload["defect_probability"],
                minimum=0.0,
                maximum=1.0,
                path=f"{path}.defect_probability",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "defect_probability": self.defect_probability,
        }


@dataclass(frozen=True, slots=True)
class ExpectedObservation:
    """探针可能观察到的结果及其假设后验。"""

    observation_id: str
    probability: float
    posteriors: tuple[PosteriorEstimate, ...]

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], *, path: str) -> Self:
        payload = _strict_object(value, fields=_OBSERVATION_FIELDS, path=path)
        posteriors_value = _array(
            payload["posteriors"],
            path=f"{path}.posteriors",
            minimum_length=1,
        )
        posteriors = tuple(
            PosteriorEstimate.from_dict(
                item,
                path=f"{path}.posteriors[{index}]",
            )
            for index, item in enumerate(posteriors_value)
        )
        _unique(
            [item.hypothesis_id for item in posteriors],
            code="posterior_hypothesis_duplicate",
            path=f"{path}.posteriors",
        )
        return cls(
            observation_id=_text(
                payload["observation_id"],
                path=f"{path}.observation_id",
            ),
            probability=_bounded_number(
                payload["probability"],
                minimum=0.0,
                maximum=1.0,
                path=f"{path}.probability",
                minimum_exclusive=True,
            ),
            posteriors=tuple(
                sorted(posteriors, key=lambda item: item.hypothesis_id)
            ),
        )

    def posterior_for(self, hypothesis_id: str) -> float:
        for posterior in self.posteriors:
            if posterior.hypothesis_id == hypothesis_id:
                return posterior.defect_probability
        raise CriticContractError(
            "posterior_hypothesis_missing",
            f"观察 {self.observation_id} 缺少假设 {hypothesis_id} 的后验",
            path="$.candidates.expected_observations",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "probability": self.probability,
            "posteriors": [item.to_dict() for item in self.posteriors],
        }


@dataclass(frozen=True, slots=True)
class EstimatedCost:
    """单次探针预计消耗。"""

    duration_seconds: float
    output_bytes: int

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], *, path: str) -> Self:
        payload = _strict_object(value, fields=_COST_FIELDS, path=path)
        return cls(
            duration_seconds=_bounded_number(
                payload["duration_seconds"],
                minimum=0.0,
                maximum=_MAX_DURATION_SECONDS,
                path=f"{path}.duration_seconds",
                minimum_exclusive=True,
            ),
            output_bytes=_integer(
                payload["output_bytes"],
                minimum=1,
                maximum=_MAX_OUTPUT_BYTES,
                path=f"{path}.output_bytes",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "duration_seconds": self.duration_seconds,
            "output_bytes": self.output_bytes,
        }


@dataclass(frozen=True, slots=True)
class ProbeCandidate:
    """带概率预测和成本估计的候选探针。"""

    probe_id: str
    action: str
    arguments: Mapping[str, Any]
    tool_version: str
    tool_spec_sha256: str
    hypothesis_ids: tuple[str, ...]
    evidence_gap_ids: tuple[str, ...]
    expected_observations: tuple[ExpectedObservation, ...]
    estimated_cost: EstimatedCost
    probe_fingerprint_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        try:
            invocation = ToolInvocation(
                action=self.action,
                version=self.tool_version,
                arguments=self.arguments,
                spec_sha256=self.tool_spec_sha256,
            )
            build_default_tool_registry().validate_invocation(invocation)
        except ToolContractError as exc:
            raise CriticContractError(
                "tool_invocation_invalid",
                f"candidate 未绑定可信 ToolSpec：{exc.code}",
                path="$.candidate",
            ) from exc
        object.__setattr__(self, "action", invocation.action)
        object.__setattr__(self, "tool_version", invocation.version)
        object.__setattr__(
            self,
            "tool_spec_sha256",
            invocation.spec_sha256,
        )
        object.__setattr__(self, "arguments", invocation.arguments)
        object.__setattr__(
            self,
            "probe_fingerprint_sha256",
            _canonical_sha256(
                {
                    "action": invocation.action,
                    "arguments": invocation.to_dict()["arguments"],
                    "tool_version": invocation.version,
                    "tool_spec_sha256": invocation.spec_sha256,
                }
            ),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], *, path: str) -> Self:
        payload = _strict_object(value, fields=_CANDIDATE_FIELDS, path=path)
        observations_value = _array(
            payload["expected_observations"],
            path=f"{path}.expected_observations",
            minimum_length=2,
        )
        observations = tuple(
            ExpectedObservation.from_dict(
                item,
                path=f"{path}.expected_observations[{index}]",
            )
            for index, item in enumerate(observations_value)
        )
        _unique(
            [item.observation_id for item in observations],
            code="observation_id_duplicate",
            path=f"{path}.expected_observations",
        )
        probability_sum = _checked_fsum(
            (item.probability for item in observations),
            path=f"{path}.expected_observations",
        )
        if not math.isclose(
            probability_sum,
            1.0,
            rel_tol=0.0,
            abs_tol=_PROBABILITY_TOLERANCE,
        ):
            raise CriticContractError(
                "observation_probability_sum_invalid",
                "expected_observations 的 probability 总和必须等于 1",
                path=f"{path}.expected_observations",
            )
        hypothesis_ids = _text_array(
            payload["hypothesis_ids"],
            path=f"{path}.hypothesis_ids",
            allow_empty=False,
        )
        evidence_gap_ids = _text_array(
            payload["evidence_gap_ids"],
            path=f"{path}.evidence_gap_ids",
            allow_empty=False,
        )
        return cls(
            probe_id=_text(payload["probe_id"], path=f"{path}.probe_id"),
            action=_text(payload["action"], path=f"{path}.action"),
            arguments=payload["arguments"],
            tool_version=_text(
                payload["tool_version"],
                path=f"{path}.tool_version",
            ),
            tool_spec_sha256=_sha256(
                payload["tool_spec_sha256"],
                path=f"{path}.tool_spec_sha256",
            ),
            hypothesis_ids=tuple(sorted(hypothesis_ids)),
            evidence_gap_ids=tuple(sorted(evidence_gap_ids)),
            expected_observations=tuple(
                sorted(observations, key=lambda item: item.observation_id)
            ),
            estimated_cost=EstimatedCost.from_dict(
                payload["estimated_cost"],
                path=f"{path}.estimated_cost",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "action": self.action,
            "arguments": ToolInvocation(
                action=self.action,
                version=self.tool_version,
                arguments=self.arguments,
                spec_sha256=self.tool_spec_sha256,
            ).to_dict()["arguments"],
            "tool_version": self.tool_version,
            "tool_spec_sha256": self.tool_spec_sha256,
            "hypothesis_ids": list(self.hypothesis_ids),
            "evidence_gap_ids": list(self.evidence_gap_ids),
            "expected_observations": [
                item.to_dict() for item in self.expected_observations
            ],
            "estimated_cost": self.estimated_cost.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ProbeHistory:
    """同一探针指纹的重复与无进展记录。"""

    probe_fingerprint_sha256: str
    attempts: int
    no_progress_attempts: int

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], *, path: str) -> Self:
        payload = _strict_object(value, fields=_HISTORY_FIELDS, path=path)
        attempts = _integer(
            payload["attempts"],
            minimum=1,
            maximum=_MAX_ATTEMPTS,
            path=f"{path}.attempts",
        )
        no_progress_attempts = _integer(
            payload["no_progress_attempts"],
            minimum=0,
            maximum=_MAX_ATTEMPTS,
            path=f"{path}.no_progress_attempts",
        )
        if no_progress_attempts > attempts:
            raise CriticContractError(
                "no_progress_exceeds_attempts",
                "no_progress_attempts 不得大于 attempts",
                path=f"{path}.no_progress_attempts",
            )
        return cls(
            probe_fingerprint_sha256=_sha256(
                payload["probe_fingerprint_sha256"],
                path=f"{path}.probe_fingerprint_sha256",
            ),
            attempts=attempts,
            no_progress_attempts=no_progress_attempts,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_fingerprint_sha256": self.probe_fingerprint_sha256,
            "attempts": self.attempts,
            "no_progress_attempts": self.no_progress_attempts,
        }


@dataclass(frozen=True, slots=True)
class RemainingBudget:
    """Critic 可用于建议的剩余预算快照。"""

    remaining_seconds: float
    remaining_probes: int
    remaining_output_bytes: int

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], *, path: str) -> Self:
        payload = _strict_object(value, fields=_BUDGET_FIELDS, path=path)
        return cls(
            remaining_seconds=_bounded_number(
                payload["remaining_seconds"],
                minimum=0.0,
                maximum=_MAX_REMAINING_SECONDS,
                path=f"{path}.remaining_seconds",
            ),
            remaining_probes=_integer(
                payload["remaining_probes"],
                minimum=0,
                maximum=_MAX_ITEMS,
                path=f"{path}.remaining_probes",
            ),
            remaining_output_bytes=_integer(
                payload["remaining_output_bytes"],
                minimum=0,
                maximum=_MAX_REMAINING_OUTPUT_BYTES,
                path=f"{path}.remaining_output_bytes",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "remaining_seconds": self.remaining_seconds,
            "remaining_probes": self.remaining_probes,
            "remaining_output_bytes": self.remaining_output_bytes,
        }


@dataclass(frozen=True, slots=True)
class CriticRequest:
    """完全绑定当前计划、状态、缺口、候选与预算的评审请求。"""

    request_id: str
    plan_sha256: str
    context_sha256: str
    state_sha256: str
    tool_registry_sha256: str
    hypotheses: tuple[HypothesisSignal, ...]
    evidence_gaps: tuple[EvidenceGap, ...]
    candidates: tuple[ProbeCandidate, ...]
    history: tuple[ProbeHistory, ...]
    budget: RemainingBudget
    schema_version: int = CRITIC_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Self:
        payload = _strict_object(value, fields=_REQUEST_FIELDS, path="$")
        if payload["schema_version"] != CRITIC_SCHEMA_VERSION:
            raise CriticContractError(
                "schema_version_unsupported",
                f"schema_version 必须等于 {CRITIC_SCHEMA_VERSION}",
                path="$.schema_version",
            )
        hypotheses = _parse_objects(
            payload["hypotheses"],
            path="$.hypotheses",
            parser=HypothesisSignal.from_dict,
        )
        gaps = _parse_objects(
            payload["evidence_gaps"],
            path="$.evidence_gaps",
            parser=EvidenceGap.from_dict,
        )
        candidates = _parse_objects(
            payload["candidates"],
            path="$.candidates",
            parser=ProbeCandidate.from_dict,
        )
        history = _parse_objects(
            payload["history"],
            path="$.history",
            parser=ProbeHistory.from_dict,
            allow_empty=True,
        )
        _unique(
            [item.hypothesis_id for item in hypotheses],
            code="hypothesis_id_duplicate",
            path="$.hypotheses",
        )
        _unique(
            [item.gap_id for item in gaps],
            code="gap_id_duplicate",
            path="$.evidence_gaps",
        )
        _unique(
            [item.probe_id for item in candidates],
            code="probe_id_duplicate",
            path="$.candidates",
        )
        _unique(
            [item.probe_fingerprint_sha256 for item in candidates],
            code="probe_fingerprint_duplicate",
            path="$.candidates",
        )
        _unique(
            [item.probe_fingerprint_sha256 for item in history],
            code="history_fingerprint_duplicate",
            path="$.history",
        )
        request = cls(
            schema_version=payload["schema_version"],
            request_id=_text(payload["request_id"], path="$.request_id"),
            plan_sha256=_sha256(
                payload["plan_sha256"],
                path="$.plan_sha256",
            ),
            context_sha256=_sha256(
                payload["context_sha256"],
                path="$.context_sha256",
            ),
            state_sha256=_sha256(
                payload["state_sha256"],
                path="$.state_sha256",
            ),
            tool_registry_sha256=_sha256(
                payload["tool_registry_sha256"],
                path="$.tool_registry_sha256",
            ),
            hypotheses=tuple(
                sorted(hypotheses, key=lambda item: item.hypothesis_id)
            ),
            evidence_gaps=tuple(
                sorted(gaps, key=lambda item: item.gap_id)
            ),
            candidates=tuple(
                sorted(candidates, key=lambda item: item.probe_id)
            ),
            history=tuple(
                sorted(
                    history,
                    key=lambda item: item.probe_fingerprint_sha256,
                )
            ),
            budget=RemainingBudget.from_dict(
                payload["budget"],
                path="$.budget",
            ),
        )
        request._validate_reference_graph()
        trusted_registry_sha256 = (
            build_default_tool_registry().canonical_sha256
        )
        if not hmac.compare_digest(
            request.tool_registry_sha256,
            trusted_registry_sha256,
        ):
            raise CriticContractError(
                "tool_registry_drift",
                "tool_registry_sha256 与可信默认 ToolRegistry 不一致",
                path="$.tool_registry_sha256",
            )
        return request

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "plan_sha256": self.plan_sha256,
            "context_sha256": self.context_sha256,
            "state_sha256": self.state_sha256,
            "tool_registry_sha256": self.tool_registry_sha256,
            "hypotheses": [item.to_dict() for item in self.hypotheses],
            "evidence_gaps": [item.to_dict() for item in self.evidence_gaps],
            "candidates": [item.to_dict() for item in self.candidates],
            "history": [item.to_dict() for item in self.history],
            "budget": self.budget.to_dict(),
        }

    def _validate_reference_graph(self) -> None:
        hypotheses = {
            item.hypothesis_id: item for item in self.hypotheses
        }
        gaps = {item.gap_id: item for item in self.evidence_gaps}
        for index, gap in enumerate(self.evidence_gaps):
            if gap.hypothesis_id not in hypotheses:
                raise CriticContractError(
                    "gap_hypothesis_unknown",
                    f"证据缺口 {gap.gap_id} 引用了未知假设",
                    path=f"$.evidence_gaps[{index}].hypothesis_id",
                )
        for index, candidate in enumerate(self.candidates):
            candidate_path = f"$.candidates[{index}]"
            unknown_hypotheses = sorted(
                set(candidate.hypothesis_ids) - set(hypotheses)
            )
            if unknown_hypotheses:
                raise CriticContractError(
                    "candidate_hypothesis_unknown",
                    (
                        "候选探针引用了未知假设："
                        f"{', '.join(unknown_hypotheses)}"
                    ),
                    path=f"{candidate_path}.hypothesis_ids",
                )
            unknown_gaps = sorted(
                set(candidate.evidence_gap_ids) - set(gaps)
            )
            if unknown_gaps:
                raise CriticContractError(
                    "candidate_gap_unknown",
                    (
                        "候选探针引用了未知证据缺口："
                        f"{', '.join(unknown_gaps)}"
                    ),
                    path=f"{candidate_path}.evidence_gap_ids",
                )
            gap_hypotheses = {
                gaps[gap_id].hypothesis_id
                for gap_id in candidate.evidence_gap_ids
            }
            missing_gap_links = sorted(
                set(candidate.hypothesis_ids) - gap_hypotheses
            )
            if missing_gap_links:
                raise CriticContractError(
                    "candidate_gap_link_missing",
                    "每个候选 hypothesis_id 都必须有对应 evidence_gap_id",
                    path=f"{candidate_path}.evidence_gap_ids",
                )
            unrelated_gaps = sorted(
                gap_hypotheses - set(candidate.hypothesis_ids)
            )
            if unrelated_gaps:
                raise CriticContractError(
                    "candidate_gap_unrelated",
                    "候选探针不能引用其他假设的证据缺口",
                    path=f"{candidate_path}.evidence_gap_ids",
                )
            expected_ids = set(candidate.hypothesis_ids)
            for observation_index, observation in enumerate(
                candidate.expected_observations
            ):
                posterior_ids = {
                    item.hypothesis_id for item in observation.posteriors
                }
                if posterior_ids != expected_ids:
                    raise CriticContractError(
                        "posterior_hypothesis_set_mismatch",
                        "每个观察结果必须恰好覆盖候选的 hypothesis_ids",
                        path=(
                            f"{candidate_path}.expected_observations"
                            f"[{observation_index}].posteriors"
                        ),
                    )
            for hypothesis_id in candidate.hypothesis_ids:
                expected_prior = _checked_fsum(
                    (
                        observation.probability
                        * observation.posterior_for(hypothesis_id)
                        for observation in (
                            candidate.expected_observations
                        )
                    ),
                    path=(
                        f"{candidate_path}.expected_observations"
                    ),
                )
                actual_prior = hypotheses[
                    hypothesis_id
                ].prior_defect_probability
                if not math.isclose(
                    expected_prior,
                    actual_prior,
                    rel_tol=0.0,
                    abs_tol=_PROBABILITY_TOLERANCE,
                ):
                    raise CriticContractError(
                        "posterior_prior_inconsistent",
                        (
                            f"候选 {candidate.probe_id} 对 {hypothesis_id} "
                            "的期望后验必须等于先验"
                        ),
                        path=f"{candidate_path}.expected_observations",
                    )


@dataclass(frozen=True, slots=True)
class RankedProbe:
    """单个候选的可解释评分。"""

    rank: int
    probe_id: str
    probe_fingerprint_sha256: str
    suggestion: str
    budget_feasible: bool
    score: float
    signals: Mapping[str, float]
    weighted_contributions: Mapping[str, float]
    budget_checks: Mapping[str, bool]
    hypothesis_ids: tuple[str, ...]
    evidence_gap_ids: tuple[str, ...]
    explanation: tuple[str, ...]
    not_authorization: bool = True
    history_authoritative: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "rank": self.rank,
            "probe_id": self.probe_id,
            "probe_fingerprint_sha256": self.probe_fingerprint_sha256,
            "suggestion": self.suggestion,
            "budget_feasible": self.budget_feasible,
            "score": self.score,
            "signals": dict(self.signals),
            "weighted_contributions": dict(
                self.weighted_contributions
            ),
            "budget_checks": dict(self.budget_checks),
            "hypothesis_ids": list(self.hypothesis_ids),
            "evidence_gap_ids": list(self.evidence_gap_ids),
            "explanation": list(self.explanation),
            "not_authorization": self.not_authorization,
            "history_authoritative": self.history_authoritative,
        }


@dataclass(frozen=True, slots=True)
class CriticResult:
    """稳定可哈希的排序结果，明确不具备授权语义。"""

    request_sha256: str
    ranked_probes: tuple[RankedProbe, ...]
    critic_version: str = CRITIC_VERSION
    schema_version: int = CRITIC_SCHEMA_VERSION
    not_authorization: bool = True
    history_authoritative: bool = False
    admission_allowed: bool = False
    policy_boundary: str = "candidate_requires_separate_policy_decision"

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self._content_dict())

    def _content_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "critic_version": self.critic_version,
            "request_sha256": self.request_sha256,
            "not_authorization": self.not_authorization,
            "admission_allowed": self.admission_allowed,
            "history_authoritative": self.history_authoritative,
            "anti_repeat_policy": (
                "conservative_floor_for_unverified_history"
            ),
            "policy_boundary": self.policy_boundary,
            "weights": dict(_WEIGHTS),
            "ranked_probes": [
                item.to_dict() for item in self.ranked_probes
            ],
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._content_dict()
        payload["result_sha256"] = self.canonical_sha256
        return payload


class DeterministicProbeCritic:
    """使用固定、版本化权重生成建议，不调用 Policy 或执行器。"""

    def rank(self, request: CriticRequest) -> CriticResult:
        if not isinstance(request, CriticRequest):
            raise CriticContractError(
                "request_type_invalid",
                "request 必须是 CriticRequest",
            )
        hypotheses = {
            item.hypothesis_id: item for item in request.hypotheses
        }
        gaps = {item.gap_id: item for item in request.evidence_gaps}
        history = {
            item.probe_fingerprint_sha256: item
            for item in request.history
        }
        scored = [
            self._score(
                candidate,
                request=request,
                hypotheses=hypotheses,
                gaps=gaps,
                history=history.get(candidate.probe_fingerprint_sha256),
            )
            for candidate in request.candidates
        ]
        scored.sort(key=self._sort_key)
        ranked = tuple(
            RankedProbe(rank=index, **item)
            for index, item in enumerate(scored, start=1)
        )
        return CriticResult(
            request_sha256=request.canonical_sha256,
            ranked_probes=ranked,
        )

    def _score(
        self,
        candidate: ProbeCandidate,
        *,
        request: CriticRequest,
        hypotheses: Mapping[str, HypothesisSignal],
        gaps: Mapping[str, EvidenceGap],
        history: ProbeHistory | None,
    ) -> dict[str, Any]:
        information_gain = _mean(
            [
                self._hypothesis_information_gain(
                    candidate,
                    hypotheses[hypothesis_id],
                )
                for hypothesis_id in candidate.hypothesis_ids
            ]
        )
        defect_risk = _mean(
            [
                hypotheses[hypothesis_id].prior_defect_probability
                * hypotheses[hypothesis_id].defect_impact
                for hypothesis_id in candidate.hypothesis_ids
            ]
        )
        conflict_value = _mean(
            [
                gaps[gap_id].conflict_level
                for gap_id in candidate.evidence_gap_ids
            ]
        )
        budget_checks, cost_pressure = self._budget_signals(
            candidate.estimated_cost,
            request.budget,
        )
        budget_feasible = all(budget_checks.values())
        cost_efficiency = max(0.0, 1.0 - cost_pressure)
        attempts = history.attempts if history is not None else 0
        no_progress_attempts = (
            history.no_progress_attempts if history is not None else 0
        )
        duplicate_level = max(
            min(attempts / 3.0, 1.0),
            _UNTRUSTED_DUPLICATE_FLOOR,
        )
        no_progress_rate = (
            no_progress_attempts / attempts if attempts else 0.0
        )
        no_progress_rate = max(
            no_progress_rate,
            _UNTRUSTED_NO_PROGRESS_FLOOR,
        )
        signals = {
            "normalized_information_gain": _round(information_gain),
            "defect_risk": _round(defect_risk),
            "conflict_resolution_value": _round(conflict_value),
            "cost_pressure": _round(cost_pressure),
            "cost_efficiency": _round(cost_efficiency),
            "duplicate_level": _round(duplicate_level),
            "no_progress_rate": _round(no_progress_rate),
        }
        contributions = {
            "information_gain": _round(
                _WEIGHTS["information_gain"] * information_gain
            ),
            "defect_risk": _round(
                _WEIGHTS["defect_risk"] * defect_risk
            ),
            "conflict_resolution": _round(
                _WEIGHTS["conflict_resolution"] * conflict_value
            ),
            "cost_efficiency": _round(
                _WEIGHTS["cost_efficiency"] * cost_efficiency
            ),
            "duplicate_penalty": _round(
                -_WEIGHTS["duplicate_penalty"] * duplicate_level
            ),
            "no_progress_penalty": _round(
                -_WEIGHTS["no_progress_penalty"] * no_progress_rate
            ),
        }
        score = _round(
            _checked_fsum(
                contributions.values(),
                path="$.critic.score",
            )
        )
        suggestion = (
            "consider_with_unverified_history"
            if budget_feasible
            else "defer_budget_exceeded"
        )
        explanation = (
            (
                "normalized_information_gain="
                f"{signals['normalized_information_gain']:.6f}"
            ),
            f"defect_risk={signals['defect_risk']:.6f}",
            (
                "conflict_resolution_value="
                f"{signals['conflict_resolution_value']:.6f}"
            ),
            f"cost_pressure={signals['cost_pressure']:.6f}",
            (
                f"duplicate_level={signals['duplicate_level']:.6f}; "
                f"no_progress_rate={signals['no_progress_rate']:.6f}"
            ),
            (
                "history=not_authoritative; conservative anti-repeat "
                "floor applied"
            ),
            (
                "budget=fit"
                if budget_feasible
                else "budget=exceeded; suggestion is deferred"
            ),
            "Policy must independently authorize any execution.",
        )
        return {
            "probe_id": candidate.probe_id,
            "probe_fingerprint_sha256": (
                candidate.probe_fingerprint_sha256
            ),
            "suggestion": suggestion,
            "budget_feasible": budget_feasible,
            "score": score,
            "signals": signals,
            "weighted_contributions": contributions,
            "budget_checks": budget_checks,
            "hypothesis_ids": candidate.hypothesis_ids,
            "evidence_gap_ids": candidate.evidence_gap_ids,
            "explanation": explanation,
            "not_authorization": True,
            "history_authoritative": False,
        }

    @staticmethod
    def _hypothesis_information_gain(
        candidate: ProbeCandidate,
        hypothesis: HypothesisSignal,
    ) -> float:
        prior_entropy = _binary_entropy(
            hypothesis.prior_defect_probability
        )
        posterior_entropy = _checked_fsum(
            (
                observation.probability
                * _binary_entropy(
                    observation.posterior_for(hypothesis.hypothesis_id)
                )
                for observation in candidate.expected_observations
            ),
            path="$.candidates.expected_observations",
        )
        gain_bits = max(0.0, prior_entropy - posterior_entropy)
        return min(gain_bits, 1.0)

    @staticmethod
    def _budget_signals(
        cost: EstimatedCost,
        budget: RemainingBudget,
    ) -> tuple[dict[str, bool], float]:
        checks = {
            "time_fits": (
                budget.remaining_seconds > 0
                and cost.duration_seconds <= budget.remaining_seconds
            ),
            "probe_slot_available": budget.remaining_probes >= 1,
            "output_fits": (
                budget.remaining_output_bytes > 0
                and cost.output_bytes <= budget.remaining_output_bytes
            ),
        }
        ratios = [
            _safe_ratio(
                cost.duration_seconds,
                budget.remaining_seconds,
            ),
            _safe_ratio(1, budget.remaining_probes),
            _safe_ratio(
                cost.output_bytes,
                budget.remaining_output_bytes,
            ),
        ]
        return checks, min(max(ratios), 1.0)

    @staticmethod
    def _sort_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
        signals = item["signals"]
        return (
            not item["budget_feasible"],
            -item["score"],
            -signals["normalized_information_gain"],
            -signals["defect_risk"],
            -signals["conflict_resolution_value"],
            signals["cost_pressure"],
            signals["duplicate_level"],
            signals["no_progress_rate"],
            item["probe_id"],
        )


def _strict_object(
    value: Any,
    *,
    fields: frozenset[str],
    path: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CriticContractError(
            "object_required",
            "值必须是 JSON object",
            path=path,
        )
    actual = set(value)
    unknown = sorted(actual - fields)
    if unknown:
        raise CriticContractError(
            "fields_unknown",
            f"包含未知字段：{', '.join(unknown)}",
            path=path,
        )
    missing = sorted(fields - actual)
    if missing:
        raise CriticContractError(
            "fields_missing",
            f"缺少字段：{', '.join(missing)}",
            path=path,
        )
    return value


def _parse_objects(
    value: Any,
    *,
    path: str,
    parser: Any,
    allow_empty: bool = False,
) -> tuple[Any, ...]:
    values = _array(
        value,
        path=path,
        minimum_length=0 if allow_empty else 1,
    )
    return tuple(
        parser(item, path=f"{path}[{index}]")
        for index, item in enumerate(values)
    )


def _array(
    value: Any,
    *,
    path: str,
    minimum_length: int,
) -> Sequence[Any]:
    if not isinstance(value, list):
        raise CriticContractError(
            "array_required",
            "值必须是 JSON array",
            path=path,
        )
    if len(value) < minimum_length:
        raise CriticContractError(
            "array_too_short",
            f"array 至少需要 {minimum_length} 项",
            path=path,
        )
    if len(value) > _MAX_ITEMS:
        raise CriticContractError(
            "array_too_long",
            f"array 不得超过 {_MAX_ITEMS} 项",
            path=path,
        )
    return value


def _text(value: Any, *, path: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > _MAX_TEXT_LENGTH
    ):
        raise CriticContractError(
            "text_invalid",
            (
                "值必须是非空字符串且不得超过 "
                f"{_MAX_TEXT_LENGTH} 个字符"
            ),
            path=path,
        )
    return value.strip()


def _text_array(
    value: Any,
    *,
    path: str,
    allow_empty: bool,
) -> tuple[str, ...]:
    values = _array(
        value,
        path=path,
        minimum_length=0 if allow_empty else 1,
    )
    normalized = tuple(
        _text(item, path=f"{path}[{index}]")
        for index, item in enumerate(values)
    )
    _unique(
        normalized,
        code="array_value_duplicate",
        path=path,
    )
    return normalized


def _sha256(value: Any, *, path: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise CriticContractError(
            "sha256_invalid",
            "值必须是 64 位小写 SHA-256",
            path=path,
        )
    return value


def _bounded_number(
    value: Any,
    *,
    minimum: float,
    maximum: float | None,
    path: str,
    minimum_exclusive: bool = False,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CriticContractError(
            "number_invalid",
            "值必须是有限数字",
            path=path,
        )
    normalized = float(value)
    if not math.isfinite(normalized):
        raise CriticContractError(
            "number_not_finite",
            "值必须是有限数字，NaN 和 Infinity 被拒绝",
            path=path,
        )
    below_minimum = (
        normalized <= minimum
        if minimum_exclusive
        else normalized < minimum
    )
    if below_minimum or (
        maximum is not None and normalized > maximum
    ):
        boundary = f"{minimum}..{maximum}" if maximum is not None else f">={minimum}"
        raise CriticContractError(
            "number_out_of_range",
            f"值超出允许范围 {boundary}",
            path=path,
        )
    return normalized


def _integer(
    value: Any,
    *,
    minimum: int,
    maximum: int,
    path: str,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CriticContractError(
            "integer_invalid",
            "值必须是整数",
            path=path,
        )
    if value < minimum or value > maximum:
        raise CriticContractError(
            "integer_out_of_range",
            f"值必须在 {minimum}..{maximum} 范围内",
            path=path,
        )
    return value


def _unique(values: Sequence[str], *, code: str, path: str) -> None:
    if len(values) != len(set(values)):
        raise CriticContractError(
            code,
            "值必须唯一",
            path=path,
        )


def _binary_entropy(probability: float) -> float:
    if probability <= 0.0 or probability >= 1.0:
        return 0.0
    return -(
        probability * math.log2(probability)
        + (1.0 - probability) * math.log2(1.0 - probability)
    )


def _safe_ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 1.0
    return min(float(numerator) / float(denominator), 1.0)


def _mean(values: Sequence[float]) -> float:
    return _checked_fsum(values, path="$.critic.mean") / len(values)


def _checked_fsum(values: Any, *, path: str) -> float:
    """将 fsum 的异常与非有限结果转为结构化契约错误。"""

    try:
        result = math.fsum(values)
    except (OverflowError, ValueError) as exc:
        raise CriticContractError(
            "numeric_sum_overflow",
            "数值累计超出安全范围",
            path=path,
        ) from exc
    if not math.isfinite(result):
        raise CriticContractError(
            "numeric_sum_nonfinite",
            "数值累计产生非有限结果",
            path=path,
        )
    return result


def _round(value: float) -> float:
    normalized = round(value, _ROUND_DIGITS)
    return 0.0 if normalized == 0 else normalized


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
