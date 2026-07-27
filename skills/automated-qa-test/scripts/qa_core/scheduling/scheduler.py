"""在共享预算内生成确定性、非授权的安全调度建议。"""

from __future__ import annotations

import math
import posixpath
import re
from dataclasses import dataclass
from fractions import Fraction
from typing import Any
from urllib.parse import unquote, urlsplit

from qa_core.tools import RiskClass

from .contracts import (
    SCHEDULE_SCHEMA_VERSION,
    ProbeCandidate,
    ScheduleBudget,
    ScheduleRequest,
    SchedulingContractError,
    canonical_sha256,
)

SELECTION_STRATEGY = "deterministic_marginal_information_gain_v1"
_MUTATING_RISKS = frozenset({RiskClass.HIGH, RiskClass.CRITICAL})
_URL_SCHEME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")


@dataclass(frozen=True, slots=True)
class ScheduleBatch:
    """一批按顺序交付给外层执行器的候选引用。"""

    index: int
    mode: str
    candidates: tuple[ProbeCandidate, ...]

    def to_dict(self) -> dict[str, Any]:
        """返回不含调用参数、也不产生授权的批次建议。"""

        return {
            "index": self.index,
            "mode": self.mode,
            "not_authorization": True,
            "admission_allowed": False,
            "candidates": [
                {
                    "id": candidate.id,
                    "action": candidate.action,
                    "tool_spec_sha256": (
                        candidate.tool_spec_sha256
                    ),
                    "trusted_tool_metadata": (
                        candidate.trusted_metadata()
                    ),
                }
                for candidate in self.candidates
            ],
            "estimated_cost": _checked_fsum(
                (
                    candidate.estimated_cost
                    for candidate in self.candidates
                ),
                path="$.schedule.batches.estimated_cost",
            ),
            "estimated_time_seconds": max(
                candidate.estimated_time_seconds
                for candidate in self.candidates
            ),
            "information_gain": _checked_fsum(
                (
                    candidate.information_gain
                    for candidate in self.candidates
                ),
                path="$.schedule.batches.information_gain",
            ),
        }


@dataclass(frozen=True, slots=True)
class ProbeSchedule:
    """可哈希、可审计但不能当作执行授权的调度结果。"""

    request_sha256: str
    budget: ScheduleBudget
    selected: tuple[ProbeCandidate, ...]
    batches: tuple[ScheduleBatch, ...]
    unselected: tuple[tuple[str, str], ...]

    @property
    def canonical_sha256(self) -> str:
        """计算不包含自身哈希字段的规范摘要。"""

        return canonical_sha256(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        """返回完整调度建议，并显式声明它不是授权。"""

        return {
            **self._unsigned_dict(),
            "schedule_sha256": self.canonical_sha256,
        }

    def _unsigned_dict(self) -> dict[str, Any]:
        selected = tuple(
            sorted(self.selected, key=lambda candidate: candidate.id),
        )
        total_time = _checked_fsum(
            (
                candidate.estimated_time_seconds
                for candidate in selected
            ),
            path="$.schedule.budget_usage.total_time_seconds",
        )
        estimated_wall_time = _checked_fsum(
            (
                batch.to_dict()["estimated_time_seconds"]
                for batch in self.batches
            ),
            path="$.schedule.budget_usage.estimated_wall_time_seconds",
        )
        return {
            "schema_version": SCHEDULE_SCHEMA_VERSION,
            "not_authorization": True,
            "admission_allowed": False,
            "execution_authorization_verified": False,
            "parallel_execution_authorized": False,
            "policy_boundary": (
                "current_execution_authorization_must_be_verified_"
                "by_the_executor"
            ),
            "request_sha256": self.request_sha256,
            "selection_strategy": SELECTION_STRATEGY,
            "budget": self.budget.to_dict(),
            "budget_usage": {
                "total_cost": _checked_fsum(
                    (
                        candidate.estimated_cost
                        for candidate in selected
                    ),
                    path="$.schedule.budget_usage.total_cost",
                ),
                "total_time_seconds": total_time,
                "estimated_wall_time_seconds": estimated_wall_time,
                "actions": len(selected),
                "information_gain": _checked_fsum(
                    (
                        candidate.information_gain
                        for candidate in selected
                    ),
                    path="$.schedule.budget_usage.information_gain",
                ),
            },
            "selected_ids": [
                candidate.id for candidate in selected
            ],
            "batches": [
                batch.to_dict() for batch in self.batches
            ],
            "unselected": [
                {
                    "id": candidate_id,
                    "reason": reason,
                }
                for candidate_id, reason in self.unselected
            ],
        }


def build_probe_schedule(request: ScheduleRequest) -> ProbeSchedule:
    """选择依赖闭包完整的组合，并生成保守的安全批次。"""

    if not isinstance(request, ScheduleRequest):
        raise SchedulingContractError(
            "request_type_invalid",
            "request 必须是 ScheduleRequest",
            path="$",
        )
    by_id = {
        candidate.id: candidate for candidate in request.candidates
    }
    selected_ids = _select_portfolio(request, by_id)
    if not selected_ids:
        raise SchedulingContractError(
            "budget_insufficient",
            "共享预算无法容纳任何正信息增益的完整依赖闭包",
            path="$.budget",
        )
    batches = _build_batches(
        selected_ids,
        by_id,
        max_parallelism=request.budget.max_parallelism,
    )
    unselected = tuple(
        (
            candidate.id,
            (
                "no_marginal_information_gain"
                if candidate.information_gain == 0
                else "not_selected_within_budget"
            ),
        )
        for candidate in request.candidates
        if candidate.id not in selected_ids
    )
    return ProbeSchedule(
        request_sha256=request.canonical_sha256,
        budget=request.budget,
        selected=tuple(
            by_id[candidate_id]
            for candidate_id in sorted(selected_ids)
        ),
        batches=batches,
        unselected=unselected,
    )


def _select_portfolio(
    request: ScheduleRequest,
    by_id: dict[str, ProbeCandidate],
) -> set[str]:
    selected: set[str] = set()
    while True:
        choices: list[
            tuple[
                tuple[Any, ...],
                str,
                set[str],
            ]
        ] = []
        for candidate_id in sorted(by_id):
            if candidate_id in selected:
                continue
            marginal = _dependency_closure(candidate_id, by_id) - selected
            metrics = _metrics(marginal, by_id)
            if metrics["information_gain"] <= 0:
                continue
            if not _fits(
                request.budget,
                selected | marginal,
                by_id,
            ):
                continue
            choices.append(
                (
                    _priority(
                        candidate_id,
                        metrics,
                        request.budget,
                    ),
                    candidate_id,
                    marginal,
                ),
            )
        if not choices:
            break
        _, _, marginal = min(choices, key=lambda item: item[0])
        selected.update(marginal)
    return selected


def _dependency_closure(
    candidate_id: str,
    by_id: dict[str, ProbeCandidate],
) -> set[str]:
    closure: set[str] = set()
    pending = [candidate_id]
    while pending:
        current = pending.pop()
        if current in closure:
            continue
        closure.add(current)
        pending.extend(by_id[current].dependencies)
    return closure


def _metrics(
    candidate_ids: set[str],
    by_id: dict[str, ProbeCandidate],
) -> dict[str, float | int]:
    candidates = [
        by_id[candidate_id] for candidate_id in sorted(candidate_ids)
    ]
    return {
        "total_cost": _checked_fsum(
            (candidate.estimated_cost for candidate in candidates),
            path="$.candidates.estimated_cost",
        ),
        "total_time_seconds": _checked_fsum(
            (
                candidate.estimated_time_seconds
                for candidate in candidates
            ),
            path="$.candidates.estimated_time_seconds",
        ),
        "information_gain": _checked_fsum(
            (candidate.information_gain for candidate in candidates),
            path="$.candidates.information_gain",
        ),
        "actions": len(candidates),
    }


def _priority(
    candidate_id: str,
    metrics: dict[str, float | int],
    budget: ScheduleBudget,
) -> tuple[Any, ...]:
    gain = _fraction(metrics["information_gain"])
    cost = _fraction(metrics["total_cost"])
    duration = _fraction(metrics["total_time_seconds"])
    actions = int(metrics["actions"])
    burden = (
        cost / _fraction(budget.max_total_cost)
        + duration / _fraction(budget.max_total_time_seconds)
        + Fraction(actions, budget.max_actions)
    )
    density = gain / burden
    return (
        -density,
        -gain,
        cost,
        duration,
        actions,
        candidate_id,
    )


def _fraction(value: float | int) -> Fraction:
    return Fraction(str(value))


def _fits(
    budget: ScheduleBudget,
    candidate_ids: set[str],
    by_id: dict[str, ProbeCandidate],
) -> bool:
    metrics = _metrics(candidate_ids, by_id)
    return (
        metrics["total_cost"] <= budget.max_total_cost
        and metrics["total_time_seconds"]
        <= budget.max_total_time_seconds
        and metrics["actions"] <= budget.max_actions
    )


def _build_batches(
    selected_ids: set[str],
    by_id: dict[str, ProbeCandidate],
    *,
    max_parallelism: int,
) -> tuple[ScheduleBatch, ...]:
    completed: set[str] = set()
    remaining = set(selected_ids)
    batches: list[ScheduleBatch] = []
    while remaining:
        ready = [
            by_id[candidate_id]
            for candidate_id in sorted(remaining)
            if set(by_id[candidate_id].dependencies) <= completed
        ]
        if not ready:
            raise SchedulingContractError(
                "dependency_resolution_failed",
                "选中组合无法按依赖顺序生成批次",
                path="$.candidates",
            )
        parallel_roots = [
            candidate
            for candidate in ready
            if not candidate.dependencies and _parallel_safe(candidate)
        ]
        if parallel_roots:
            chosen: list[ProbeCandidate] = []
            for candidate in parallel_roots:
                if len(chosen) >= max_parallelism:
                    break
                if any(
                    _conflicts(candidate, existing)
                    for existing in chosen
                ):
                    continue
                chosen.append(candidate)
        else:
            chosen = [ready[0]]

        mode = (
            "parallel_suggestion"
            if len(chosen) > 1
            else "serial_suggestion"
        )
        batch = ScheduleBatch(
            index=len(batches),
            mode=mode,
            candidates=tuple(chosen),
        )
        batches.append(batch)
        completed.update(candidate.id for candidate in chosen)
        remaining.difference_update(candidate.id for candidate in chosen)
    return tuple(batches)


def _conflicts(
    left: ProbeCandidate,
    right: ProbeCandidate,
) -> bool:
    left_mutations = set(left.write) | set(left.side_effects)
    right_mutations = set(right.write) | set(right.side_effects)
    left_observed = set(left.read) | left_mutations
    right_observed = set(right.read) | right_mutations
    return _overlap(left_mutations, right_observed) or _overlap(
        right_mutations,
        left_observed,
    )


def _overlap(left: set[str], right: set[str]) -> bool:
    if not left or not right:
        return False
    if "*" in left or "*" in right:
        return True
    return any(
        _resource_is_same_or_ancestor(left_item, right_item)
        for left_item in left
        for right_item in right
    )


def _parallel_safe(candidate: ProbeCandidate) -> bool:
    """仅把可信 ToolSpec 明确为低风险幂等的动作放入并行建议。"""

    if not candidate.idempotent:
        return False
    mutations = candidate.write or candidate.side_effects
    if mutations and candidate.risk_class in _MUTATING_RISKS:
        return False
    return candidate.risk_class is not RiskClass.CRITICAL


def _resource_is_same_or_ancestor(left: str, right: str) -> bool:
    left_parts = _normalize_resource(left)
    right_parts = _normalize_resource(right)
    if left_parts == ("*",) or right_parts == ("*",):
        return True
    shared = min(len(left_parts), len(right_parts))
    return left_parts[:shared] == right_parts[:shared]


def _normalize_resource(value: str) -> tuple[str, ...]:
    """将路径、URL 与命名空间资源归一化为保守的祖先链。"""

    normalized = value.strip().replace("\\", "/")
    if normalized == "*":
        return ("*",)
    if _URL_SCHEME_PATTERN.match(normalized):
        parsed = urlsplit(normalized)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        default_port = (
            (scheme == "http" and port == 80)
            or (scheme == "https" and port == 443)
        )
        authority = hostname
        if port is not None and not default_port:
            authority = f"{hostname}:{port}"
        path = posixpath.normpath(unquote(parsed.path or "/"))
        path_parts = tuple(
            part for part in path.split("/") if part not in {"", "."}
        )
        return ("url", scheme, authority, *path_parts)
    if normalized.startswith("/"):
        path = posixpath.normpath(normalized)
        return (
            "path",
            *(
                part
                for part in path.split("/")
                if part not in {"", "."}
            ),
        )
    opaque = posixpath.normpath(normalized.strip("/"))
    return (
        "resource",
        *(
            part
            for part in opaque.split("/")
            if part not in {"", "."}
        ),
    )


def _checked_fsum(values: Any, *, path: str) -> float:
    """将浮点累计异常收敛为稳定的调度契约错误。"""

    try:
        result = math.fsum(values)
    except (OverflowError, ValueError) as exc:
        raise SchedulingContractError(
            "numeric_sum_overflow",
            "数值累计超出安全范围",
            path=path,
        ) from exc
    if not math.isfinite(result):
        raise SchedulingContractError(
            "numeric_sum_nonfinite",
            "数值累计产生非有限结果",
            path=path,
        )
    return result
