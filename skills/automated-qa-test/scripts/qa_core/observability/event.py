"""TraceEvent 判别式 schema 与跨字段约束。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Mapping

from ._validation import (
    ObservabilityError,
    boolean,
    choice,
    exact_object,
    integer,
    list_value,
    number,
    sha256,
    text,
    timestamp,
)
from .model import (
    EVENT_FIELDS,
    TRACE_KINDS,
    TRACE_SCHEMA_VERSION,
    TRACE_STATUSES,
    TraceArtifactRef,
    TraceBudget,
    TraceReason,
    attempt_id,
)


@dataclass(frozen=True, slots=True)
class TraceEvent:
    """一个完整 span；所有关联与测量字段都在提交前闭合。"""

    run_id: str
    generation: int
    iteration: int
    attempt_id: str | None
    kind: str
    stage: str
    action: str
    status: str
    started_at: str
    ended_at: str
    duration_seconds: float
    budget: TraceBudget
    reason: TraceReason
    artifact_refs: tuple[TraceArtifactRef, ...]
    attributes: Mapping[str, object]
    schema_version: int = TRACE_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, value: object, *, path: str = "event") -> "TraceEvent":
        payload = exact_object(path, value, required=EVENT_FIELDS)
        if payload["schema_version"] != TRACE_SCHEMA_VERSION:
            raise ObservabilityError(
                "trace_schema_unsupported",
                f"{path}.schema_version 必须等于 {TRACE_SCHEMA_VERSION}",
            )
        started_text, started = timestamp(f"{path}.started_at", payload["started_at"])
        ended_text, ended = timestamp(f"{path}.ended_at", payload["ended_at"])
        duration = number(f"{path}.duration_seconds", payload["duration_seconds"])
        observed_duration = (ended - started).total_seconds()
        if observed_duration < 0 or abs(observed_duration - duration) > 1e-6:
            raise ObservabilityError(
                "trace_duration_mismatch",
                f"{path}.duration_seconds 与 start/end 不一致",
            )
        refs = tuple(
            TraceArtifactRef.from_dict(
                item,
                path=f"{path}.artifact_refs[{index}]",
            )
            for index, item in enumerate(
                list_value(f"{path}.artifact_refs", payload["artifact_refs"])
            )
        )
        if len({(ref.attempt_id, ref.name) for ref in refs}) != len(refs):
            raise ObservabilityError(
                "trace_artifact_ref_duplicate",
                f"{path}.artifact_refs 不得重复",
            )
        kind = choice(f"{path}.kind", payload["kind"], set(TRACE_KINDS))
        budget = TraceBudget.from_dict(payload["budget"], path=f"{path}.budget")
        raw_attempt_id = payload["attempt_id"]
        normalized_attempt_id = (
            None
            if raw_attempt_id is None
            else attempt_id(f"{path}.attempt_id", raw_attempt_id)
        )
        if refs and normalized_attempt_id is None:
            raise ObservabilityError(
                "trace_attempt_id_missing",
                f"{path}.attempt_id 在引用 artifact 时不得为空",
            )
        if any(
            ref.attempt_id != normalized_attempt_id
            for ref in refs
        ):
            raise ObservabilityError(
                "trace_artifact_attempt_mismatch",
                f"{path}.artifact_refs 必须属于 event.attempt_id",
            )
        if kind == "artifact_validation" and normalized_attempt_id is None:
            raise ObservabilityError(
                "trace_attempt_id_missing",
                f"{path}.attempt_id 在 artifact_validation 中不得为空",
            )
        event = cls(
            run_id=text(f"{path}.run_id", payload["run_id"]),
            generation=integer(
                f"{path}.generation",
                payload["generation"],
                minimum=1,
            ),
            iteration=integer(
                f"{path}.iteration",
                payload["iteration"],
                minimum=1,
            ),
            attempt_id=normalized_attempt_id,
            kind=kind,
            stage=text(f"{path}.stage", payload["stage"]),
            action=text(f"{path}.action", payload["action"]),
            status=choice(f"{path}.status", payload["status"], set(TRACE_STATUSES)),
            started_at=started_text,
            ended_at=ended_text,
            duration_seconds=duration,
            budget=budget,
            reason=TraceReason.from_dict(payload["reason"], path=f"{path}.reason"),
            artifact_refs=refs,
            attributes=MappingProxyType(
                _attributes(
                    kind,
                    payload["attributes"],
                    refs=refs,
                    path=f"{path}.attributes",
                )
            ),
        )
        event._validate_run_budget(started)
        return event

    @property
    def started_datetime(self) -> datetime:
        return timestamp("event.started_at", self.started_at)[1]

    @property
    def ended_datetime(self) -> datetime:
        return timestamp("event.ended_at", self.ended_at)[1]

    @property
    def deadline_datetime(self) -> datetime | None:
        if self.budget.deadline_at is None:
            return None
        return timestamp("event.budget.deadline_at", self.budget.deadline_at)[1]

    @property
    def run_key(self) -> tuple[str, int, int]:
        return self.run_id, self.generation, self.iteration

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "generation": self.generation,
            "iteration": self.iteration,
            "attempt_id": self.attempt_id,
            "kind": self.kind,
            "stage": self.stage,
            "action": self.action,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_seconds": self.duration_seconds,
            "budget": self.budget.to_dict(),
            "reason": self.reason.to_dict(),
            "artifact_refs": [ref.to_dict() for ref in self.artifact_refs],
            "attributes": dict(self.attributes),
        }

    def _validate_run_budget(self, started: datetime) -> None:
        if self.kind != "run":
            return
        if self.budget.total_seconds is None or self.deadline_datetime is None:
            raise ObservabilityError(
                "trace_run_budget_incomplete",
                "run span 必须声明 total_seconds 和 deadline_at",
            )
        expected = (self.deadline_datetime - started).total_seconds()
        if abs(expected - self.budget.total_seconds) > 1e-6:
            raise ObservabilityError(
                "trace_run_deadline_mismatch",
                "run span 的 deadline_at 必须由 started_at + total_seconds 得到",
            )


def _attributes(
    kind: str,
    value: object,
    *,
    refs: tuple[TraceArtifactRef, ...],
    path: str,
) -> dict[str, object]:
    fields: dict[str, set[str]] = {
        "run": {
            "expected_stage_count",
            "expected_action_count",
            "state_start_sequence",
            "state_end_sequence",
            "cleanup_required",
            "handoff_required",
            "recovery_required",
            "converged",
        },
        "stage": {"command_sha256"},
        "action": set(),
        "cancellation": set(),
        "cleanup": {"managed_resources_remaining"},
        "handoff": {"structured"},
        "artifact_validation": {"required_ref_count", "valid_ref_count"},
        "recovery": {"resumed", "duplicate_committed_actions"},
        "plan_validation": {
            "valid_context",
            "executable",
            "plan_sha256",
            "context_sha256",
        },
    }
    payload = exact_object(path, value, required=fields[kind])
    if kind == "run":
        state_start = integer(
            f"{path}.state_start_sequence",
            payload["state_start_sequence"],
        )
        state_end = integer(
            f"{path}.state_end_sequence",
            payload["state_end_sequence"],
        )
        if state_end < state_start:
            raise ObservabilityError(
                "trace_state_window_invalid",
                "state_end_sequence 不得早于 state_start_sequence",
            )
        return {
            "expected_stage_count": integer(
                f"{path}.expected_stage_count",
                payload["expected_stage_count"],
            ),
            "expected_action_count": integer(
                f"{path}.expected_action_count",
                payload["expected_action_count"],
            ),
            "state_start_sequence": state_start,
            "state_end_sequence": state_end,
            "cleanup_required": boolean(
                f"{path}.cleanup_required",
                payload["cleanup_required"],
            ),
            "handoff_required": boolean(
                f"{path}.handoff_required",
                payload["handoff_required"],
            ),
            "recovery_required": boolean(
                f"{path}.recovery_required",
                payload["recovery_required"],
            ),
            "converged": boolean(f"{path}.converged", payload["converged"]),
        }
    if kind == "stage":
        return {
            "command_sha256": sha256(
                f"{path}.command_sha256",
                payload["command_sha256"],
            )
        }
    if kind == "cleanup":
        return {
            "managed_resources_remaining": integer(
                f"{path}.managed_resources_remaining",
                payload["managed_resources_remaining"],
            )
        }
    if kind == "handoff":
        return {"structured": boolean(f"{path}.structured", payload["structured"])}
    if kind == "artifact_validation":
        required = integer(f"{path}.required_ref_count", payload["required_ref_count"])
        valid = integer(f"{path}.valid_ref_count", payload["valid_ref_count"])
        if required != len(refs) or valid > required:
            raise ObservabilityError(
                "trace_artifact_counts_invalid",
                "artifact_validation 计数必须与 artifact_refs 闭合",
            )
        return {"required_ref_count": required, "valid_ref_count": valid}
    if kind == "recovery":
        return {
            "resumed": boolean(f"{path}.resumed", payload["resumed"]),
            "duplicate_committed_actions": integer(
                f"{path}.duplicate_committed_actions",
                payload["duplicate_committed_actions"],
            ),
        }
    if kind == "plan_validation":
        valid_context = boolean(f"{path}.valid_context", payload["valid_context"])
        executable = boolean(f"{path}.executable", payload["executable"])
        plan_hash = sha256(
            f"{path}.plan_sha256",
            payload["plan_sha256"],
        )
        raw_context_hash = payload["context_sha256"]
        context_hash = (
            None
            if raw_context_hash is None
            else sha256(
                f"{path}.context_sha256",
                raw_context_hash,
            )
        )
        if not valid_context and executable:
            raise ObservabilityError(
                "trace_plan_context_invalid",
                "无效 context 不能标记为 executable",
            )
        if executable and context_hash is None:
            raise ObservabilityError(
                "trace_plan_context_hash_missing",
                "executable plan_validation 必须绑定 context_sha256",
            )
        return {
            "valid_context": valid_context,
            "executable": executable,
            "plan_sha256": plan_hash,
            "context_sha256": context_hash,
        }
    return {}
