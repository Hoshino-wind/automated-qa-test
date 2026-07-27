"""定义安全探针组合与调度建议的严格契约。"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Self

from qa_core.tools import (
    RiskClass,
    ToolContractError,
    build_default_tool_registry,
)

SCHEDULE_SCHEMA_VERSION = 1
MAX_CANDIDATES = 512
MAX_PARALLELISM = 64
MAX_TOTAL_COST = 1_000_000_000_000.0
MAX_TOTAL_TIME_SECONDS = 604_800.0
MAX_CANDIDATE_TIME_SECONDS = 86_400.0
MAX_INFORMATION_GAIN = 1_000_000_000.0

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "tool_registry_sha256",
        "budget",
        "candidates",
    },
)
_BUDGET_FIELDS = frozenset(
    {
        "max_total_cost",
        "max_total_time_seconds",
        "max_actions",
        "max_parallelism",
    },
)
_CANDIDATE_FIELDS = frozenset(
    {
        "id",
        "action",
        "tool_version",
        "tool_spec_sha256",
        "estimated_cost",
        "estimated_time_seconds",
        "information_gain",
        "dependencies",
    },
)


class SchedulingContractError(ValueError):
    """调度输入或安全约束不满足失败关闭要求。"""

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
        """返回稳定的机器可读错误。"""

        return {
            "schema_version": SCHEDULE_SCHEMA_VERSION,
            "error": "scheduling_contract_error",
            "code": self.code,
            "path": self.path,
            "message": str(self),
        }


@dataclass(frozen=True, slots=True)
class ScheduleBudget:
    """一次调度建议可以占用的共享上限。"""

    max_total_cost: float
    max_total_time_seconds: float
    max_actions: int
    max_parallelism: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "max_total_cost",
            _positive_number(
                "max_total_cost",
                self.max_total_cost,
                maximum=MAX_TOTAL_COST,
                path="$.budget.max_total_cost",
            ),
        )
        object.__setattr__(
            self,
            "max_total_time_seconds",
            _positive_number(
                "max_total_time_seconds",
                self.max_total_time_seconds,
                maximum=MAX_TOTAL_TIME_SECONDS,
                path="$.budget.max_total_time_seconds",
            ),
        )
        object.__setattr__(
            self,
            "max_actions",
            _positive_integer(
                "max_actions",
                self.max_actions,
                maximum=MAX_CANDIDATES,
                path="$.budget.max_actions",
            ),
        )
        object.__setattr__(
            self,
            "max_parallelism",
            _positive_integer(
                "max_parallelism",
                self.max_parallelism,
                maximum=MAX_PARALLELISM,
                path="$.budget.max_parallelism",
            ),
        )
        if self.max_parallelism > self.max_actions:
            raise SchedulingContractError(
                "parallelism_exceeds_actions",
                "max_parallelism 不得大于 max_actions",
                path="$.budget.max_parallelism",
            )

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        path: str = "$.budget",
    ) -> Self:
        """严格解析预算对象。"""

        payload = _closed_object(
            value,
            allowed=_BUDGET_FIELDS,
            required=_BUDGET_FIELDS,
            unknown_code="budget_fields_unknown",
            missing_code="budget_fields_missing",
            path=path,
        )
        return cls(
            max_total_cost=payload["max_total_cost"],
            max_total_time_seconds=payload[
                "max_total_time_seconds"
            ],
            max_actions=payload["max_actions"],
            max_parallelism=payload["max_parallelism"],
        )

    def to_dict(self) -> dict[str, float | int]:
        """返回规范化预算。"""

        return {
            "max_total_cost": self.max_total_cost,
            "max_total_time_seconds": self.max_total_time_seconds,
            "max_actions": self.max_actions,
            "max_parallelism": self.max_parallelism,
        }


@dataclass(frozen=True, slots=True)
class ProbeCandidate:
    """一个绑定可信 ToolSpec、但仍未获得执行授权的候选动作。"""

    id: str
    action: str
    tool_version: str
    tool_spec_sha256: str
    estimated_cost: float
    estimated_time_seconds: float
    information_gain: float
    dependencies: tuple[str, ...]
    capabilities: tuple[str, ...] = field(init=False)
    read: tuple[str, ...] = field(init=False)
    write: tuple[str, ...] = field(init=False)
    side_effects: tuple[str, ...] = field(init=False)
    risk_class: RiskClass = field(init=False)
    idempotent: bool = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "id",
            _text("id", self.id, path="$.candidate.id"),
        )
        object.__setattr__(
            self,
            "action",
            _text("action", self.action, path="$.candidate.action"),
        )
        object.__setattr__(
            self,
            "tool_version",
            _text(
                "tool_version",
                self.tool_version,
                path="$.candidate.tool_version",
            ),
        )
        object.__setattr__(
            self,
            "tool_spec_sha256",
            _sha256(
                "tool_spec_sha256",
                self.tool_spec_sha256,
                path="$.candidate.tool_spec_sha256",
            ),
        )
        try:
            spec = build_default_tool_registry().get(self.action)
        except ToolContractError as exc:
            raise SchedulingContractError(
                "tool_action_unknown",
                f"action 不在可信默认 ToolRegistry 中：{self.action}",
                path="$.candidate.action",
            ) from exc
        if self.tool_version != spec.version:
            raise SchedulingContractError(
                "tool_version_drift",
                "candidate tool_version 与可信 ToolSpec 不一致",
                path="$.candidate.tool_version",
            )
        if not hmac.compare_digest(
            self.tool_spec_sha256,
            spec.canonical_sha256,
        ):
            raise SchedulingContractError(
                "tool_spec_drift",
                "candidate tool_spec_sha256 与可信 ToolSpec 不一致",
                path="$.candidate.tool_spec_sha256",
            )
        for field_name in (
            "capabilities",
            "read",
            "write",
            "side_effects",
            "risk_class",
            "idempotent",
        ):
            object.__setattr__(self, field_name, getattr(spec, field_name))
        object.__setattr__(
            self,
            "estimated_cost",
            _nonnegative_number(
                "estimated_cost",
                self.estimated_cost,
                maximum=MAX_TOTAL_COST,
                path="$.candidate.estimated_cost",
            ),
        )
        object.__setattr__(
            self,
            "estimated_time_seconds",
            _positive_number(
                "estimated_time_seconds",
                self.estimated_time_seconds,
                maximum=MAX_CANDIDATE_TIME_SECONDS,
                path="$.candidate.estimated_time_seconds",
            ),
        )
        object.__setattr__(
            self,
            "information_gain",
            _nonnegative_number(
                "information_gain",
                self.information_gain,
                maximum=MAX_INFORMATION_GAIN,
                path="$.candidate.information_gain",
            ),
        )
        object.__setattr__(
            self,
            "dependencies",
            _string_set(
                "dependencies",
                self.dependencies,
                path="$.candidate.dependencies",
            ),
        )
    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        path: str = "$.candidate",
    ) -> Self:
        """严格解析单个候选动作。"""

        payload = _closed_object(
            value,
            allowed=_CANDIDATE_FIELDS,
            required=_CANDIDATE_FIELDS,
            unknown_code="candidate_fields_unknown",
            missing_code="candidate_fields_missing",
            path=path,
        )
        return cls(
            id=payload["id"],
            action=payload["action"],
            tool_version=payload["tool_version"],
            tool_spec_sha256=payload["tool_spec_sha256"],
            estimated_cost=payload["estimated_cost"],
            estimated_time_seconds=payload[
                "estimated_time_seconds"
            ],
            information_gain=payload["information_gain"],
            dependencies=_text_array(
                payload["dependencies"],
                name="dependencies",
                path=f"{path}.dependencies",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """返回字段与集合均已规范化的候选动作。"""

        return {
            "id": self.id,
            "action": self.action,
            "tool_version": self.tool_version,
            "tool_spec_sha256": self.tool_spec_sha256,
            "estimated_cost": self.estimated_cost,
            "estimated_time_seconds": self.estimated_time_seconds,
            "information_gain": self.information_gain,
            "dependencies": list(self.dependencies),
        }

    def trusted_metadata(self) -> dict[str, Any]:
        """返回只由匹配的默认 ToolSpec 派生的调度元数据。"""

        return {
            "source": "default_tool_registry",
            "capabilities": list(self.capabilities),
            "read": list(self.read),
            "write": list(self.write),
            "side_effects": list(self.side_effects),
            "risk_class": self.risk_class.value,
            "idempotent": self.idempotent,
        }


@dataclass(frozen=True, slots=True)
class ScheduleRequest:
    """绑定预算与可信 ToolRegistry 的非授权调度请求。"""

    tool_registry_sha256: str
    budget: ScheduleBudget
    candidates: tuple[ProbeCandidate, ...]
    schema_version: int = SCHEDULE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != SCHEDULE_SCHEMA_VERSION
        ):
            raise SchedulingContractError(
                "schedule_schema_unsupported",
                (
                    "schema_version 必须等于 "
                    f"{SCHEDULE_SCHEMA_VERSION}"
                ),
                path="$.schema_version",
            )
        if not isinstance(self.budget, ScheduleBudget):
            raise SchedulingContractError(
                "budget_type_invalid",
                "budget 必须是 ScheduleBudget",
                path="$.budget",
            )
        registry_sha256 = _sha256(
            "tool_registry_sha256",
            self.tool_registry_sha256,
            path="$.tool_registry_sha256",
        )
        trusted_registry_sha256 = (
            build_default_tool_registry().canonical_sha256
        )
        if not hmac.compare_digest(
            registry_sha256,
            trusted_registry_sha256,
        ):
            raise SchedulingContractError(
                "tool_registry_drift",
                "tool_registry_sha256 与可信默认 ToolRegistry 不一致",
                path="$.tool_registry_sha256",
            )
        object.__setattr__(
            self,
            "tool_registry_sha256",
            registry_sha256,
        )
        candidates = tuple(self.candidates)
        if not candidates:
            raise SchedulingContractError(
                "candidates_empty",
                "candidates 至少需要一个候选动作",
                path="$.candidates",
            )
        if len(candidates) > MAX_CANDIDATES:
            raise SchedulingContractError(
                "candidates_limit_exceeded",
                f"candidates 不得超过 {MAX_CANDIDATES} 个",
                path="$.candidates",
            )
        if any(
            not isinstance(candidate, ProbeCandidate)
            for candidate in candidates
        ):
            raise SchedulingContractError(
                "candidate_type_invalid",
                "candidates 只能包含 ProbeCandidate",
                path="$.candidates",
            )
        sorted_candidates = tuple(
            sorted(candidates, key=lambda candidate: candidate.id),
        )
        _validate_candidate_graph(sorted_candidates)
        object.__setattr__(self, "candidates", sorted_candidates)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Self:
        """从闭合 JSON object 构造调度请求。"""

        payload = _closed_object(
            value,
            allowed=_REQUEST_FIELDS,
            required=_REQUEST_FIELDS,
            unknown_code="request_fields_unknown",
            missing_code="request_fields_missing",
            path="$",
        )
        raw_candidates = payload["candidates"]
        if not isinstance(raw_candidates, list):
            raise SchedulingContractError(
                "candidates_not_array",
                "candidates 必须是 JSON array",
                path="$.candidates",
            )
        return cls(
            schema_version=payload["schema_version"],
            tool_registry_sha256=payload[
                "tool_registry_sha256"
            ],
            budget=ScheduleBudget.from_dict(
                payload["budget"],
                path="$.budget",
            ),
            candidates=tuple(
                ProbeCandidate.from_dict(
                    candidate,
                    path=f"$.candidates[{index}]",
                )
                for index, candidate in enumerate(raw_candidates)
            ),
        )

    @property
    def canonical_sha256(self) -> str:
        """返回与候选输入顺序无关的请求哈希。"""

        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        """返回可持久化的规范请求。"""

        return {
            "schema_version": self.schema_version,
            "tool_registry_sha256": self.tool_registry_sha256,
            "budget": self.budget.to_dict(),
            "candidates": [
                candidate.to_dict() for candidate in self.candidates
            ],
        }


def canonical_sha256(value: Any) -> str:
    """对不含 NaN 的 JSON 值计算规范 SHA-256。"""

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validate_candidate_graph(
    candidates: tuple[ProbeCandidate, ...],
) -> None:
    by_id: dict[str, ProbeCandidate] = {}
    for index, candidate in enumerate(candidates):
        if candidate.id in by_id:
            raise SchedulingContractError(
                "candidate_id_duplicate",
                f"候选 id 重复：{candidate.id}",
                path=f"$.candidates[{index}].id",
            )
        by_id[candidate.id] = candidate

    for candidate in candidates:
        for dependency in candidate.dependencies:
            if dependency not in by_id:
                raise SchedulingContractError(
                    "dependency_unknown",
                    (
                        f"候选 {candidate.id} 引用了未知依赖："
                        f"{dependency}"
                    ),
                    path=f"$.candidates.{candidate.id}.dependencies",
                )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(candidate_id: str, trail: tuple[str, ...]) -> None:
        if candidate_id in visiting:
            cycle_start = trail.index(candidate_id)
            cycle = (*trail[cycle_start:], candidate_id)
            raise SchedulingContractError(
                "dependency_cycle",
                f"依赖图存在环：{' -> '.join(cycle)}",
                path=f"$.candidates.{candidate_id}.dependencies",
            )
        if candidate_id in visited:
            return
        visiting.add(candidate_id)
        for dependency in by_id[candidate_id].dependencies:
            visit(dependency, (*trail, candidate_id))
        visiting.remove(candidate_id)
        visited.add(candidate_id)

    for candidate_id in sorted(by_id):
        visit(candidate_id, ())


def _closed_object(
    value: Mapping[str, Any],
    *,
    allowed: frozenset[str],
    required: frozenset[str],
    unknown_code: str,
    missing_code: str,
    path: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchedulingContractError(
            "object_required",
            f"{path} 必须是 JSON object",
            path=path,
        )
    fields = set(value)
    unknown = sorted(fields - allowed)
    if unknown:
        raise SchedulingContractError(
            unknown_code,
            f"{path} 包含未知字段：{', '.join(unknown)}",
            path=path,
        )
    missing = sorted(required - fields)
    if missing:
        raise SchedulingContractError(
            missing_code,
            f"{path} 缺少字段：{', '.join(missing)}",
            path=path,
        )
    return value


def _text_array(
    value: Any,
    *,
    name: str,
    path: str,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise SchedulingContractError(
            "array_required",
            f"{name} 必须是 JSON array",
            path=path,
        )
    return tuple(
        _text(name, item, path=f"{path}[{index}]")
        for index, item in enumerate(value)
    )


def _string_set(
    name: str,
    value: tuple[str, ...],
    *,
    path: str,
) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, tuple):
        raise SchedulingContractError(
            "string_set_invalid",
            f"{name} 必须是字符串 tuple",
            path=path,
        )
    normalized = tuple(
        _text(name, item, path=f"{path}[{index}]")
        for index, item in enumerate(value)
    )
    if len(normalized) != len(set(normalized)):
        raise SchedulingContractError(
            "string_set_duplicate",
            f"{name} 不得包含重复值",
            path=path,
        )
    return tuple(sorted(normalized))


def _text(name: str, value: Any, *, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SchedulingContractError(
            "text_invalid",
            f"{name} 必须是非空字符串",
            path=path,
        )
    return value.strip()


def _sha256(name: str, value: Any, *, path: str) -> str:
    normalized = _text(name, value, path=path).lower()
    if _SHA256_PATTERN.fullmatch(normalized) is None:
        raise SchedulingContractError(
            "sha256_invalid",
            f"{name} 必须是 64 位十六进制 SHA-256",
            path=path,
        )
    return normalized


def _positive_number(
    name: str,
    value: Any,
    *,
    maximum: float,
    path: str,
) -> float:
    normalized = _finite_number(name, value, path=path)
    if normalized <= 0 or normalized > maximum:
        raise SchedulingContractError(
            "positive_number_invalid",
            f"{name} 必须大于 0 且不超过 {maximum:g}",
            path=path,
        )
    return normalized


def _nonnegative_number(
    name: str,
    value: Any,
    *,
    maximum: float,
    path: str,
) -> float:
    normalized = _finite_number(name, value, path=path)
    if normalized < 0 or normalized > maximum:
        raise SchedulingContractError(
            "nonnegative_number_invalid",
            f"{name} 必须在 0..{maximum:g} 范围内",
            path=path,
        )
    return normalized


def _finite_number(name: str, value: Any, *, path: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise SchedulingContractError(
            "finite_number_invalid",
            f"{name} 必须是有限数值",
            path=path,
        )
    return float(value)


def _positive_integer(
    name: str,
    value: Any,
    *,
    maximum: int,
    path: str,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > maximum
    ):
        raise SchedulingContractError(
            "positive_integer_invalid",
            f"{name} 必须是 1..{maximum} 范围内的整数",
            path=path,
        )
    return value
