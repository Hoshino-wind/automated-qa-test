"""Trace 合同中的稳定值对象。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from ._validation import (
    ObservabilityError,
    boolean,
    exact_object,
    integer,
    nullable_text,
    optional_integer,
    optional_number,
    sha256,
    text,
    timestamp,
)

TRACE_SCHEMA_VERSION = 1
TRACE_KINDS = frozenset(
    {
        "run",
        "stage",
        "action",
        "cancellation",
        "cleanup",
        "handoff",
        "artifact_validation",
        "recovery",
        "plan_validation",
    }
)
TRACE_STATUSES = frozenset(
    {"succeeded", "failed", "cancelled", "blocked", "inconclusive"}
)
EVENT_FIELDS = {
    "schema_version",
    "run_id",
    "generation",
    "iteration",
    "attempt_id",
    "kind",
    "stage",
    "action",
    "status",
    "started_at",
    "ended_at",
    "duration_seconds",
    "budget",
    "reason",
    "artifact_refs",
    "attributes",
}
_ATTEMPT_ID_PATTERN = re.compile(r"att_[0-9a-f]{32}\Z")


@dataclass(frozen=True, slots=True)
class TraceBudget:
    """Span 开始和结束时的预算快照。"""

    total_seconds: float | None
    deadline_at: str | None
    remaining_seconds_at_start: float | None
    remaining_seconds_at_end: float | None
    probes_used: int
    max_probes: int | None
    output_bytes_used: int
    max_output_bytes: int | None
    cancelled: bool

    @classmethod
    def from_dict(cls, value: object, *, path: str = "event.budget") -> "TraceBudget":
        payload = exact_object(
            path,
            value,
            required={
                "total_seconds",
                "deadline_at",
                "remaining_seconds_at_start",
                "remaining_seconds_at_end",
                "probes_used",
                "max_probes",
                "output_bytes_used",
                "max_output_bytes",
                "cancelled",
            },
        )
        deadline = payload["deadline_at"]
        normalized_deadline = None
        if deadline is not None:
            normalized_deadline = timestamp(f"{path}.deadline_at", deadline)[0]
        return cls(
            total_seconds=optional_number(
                f"{path}.total_seconds",
                payload["total_seconds"],
            ),
            deadline_at=normalized_deadline,
            remaining_seconds_at_start=optional_number(
                f"{path}.remaining_seconds_at_start",
                payload["remaining_seconds_at_start"],
            ),
            remaining_seconds_at_end=optional_number(
                f"{path}.remaining_seconds_at_end",
                payload["remaining_seconds_at_end"],
            ),
            probes_used=integer(f"{path}.probes_used", payload["probes_used"]),
            max_probes=optional_integer(f"{path}.max_probes", payload["max_probes"]),
            output_bytes_used=integer(
                f"{path}.output_bytes_used",
                payload["output_bytes_used"],
            ),
            max_output_bytes=optional_integer(
                f"{path}.max_output_bytes",
                payload["max_output_bytes"],
            ),
            cancelled=boolean(f"{path}.cancelled", payload["cancelled"]),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "total_seconds": self.total_seconds,
            "deadline_at": self.deadline_at,
            "remaining_seconds_at_start": self.remaining_seconds_at_start,
            "remaining_seconds_at_end": self.remaining_seconds_at_end,
            "probes_used": self.probes_used,
            "max_probes": self.max_probes,
            "output_bytes_used": self.output_bytes_used,
            "max_output_bytes": self.max_output_bytes,
            "cancelled": self.cancelled,
        }


@dataclass(frozen=True, slots=True)
class TraceReason:
    """稳定原因码及其可选诊断。"""

    code: str
    detail: str | None

    @classmethod
    def from_dict(cls, value: object, *, path: str = "event.reason") -> "TraceReason":
        payload = exact_object(path, value, required={"code", "detail"})
        return cls(
            code=text(f"{path}.code", payload["code"]),
            detail=nullable_text(f"{path}.detail", payload["detail"]),
        )

    def to_dict(self) -> dict[str, object]:
        return {"code": self.code, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class TraceArtifactRef:
    """Trace 指向不可变 attempt artifact 的内容引用。"""

    attempt_id: str
    name: str
    path: str
    sha256: str
    size: int

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        path: str = "event.artifact_refs[]",
    ) -> "TraceArtifactRef":
        payload = exact_object(
            path,
            value,
            required={"attempt_id", "name", "path", "sha256", "size"},
        )
        return cls(
            attempt_id=attempt_id(f"{path}.attempt_id", payload["attempt_id"]),
            name=relative_path(f"{path}.name", payload["name"]),
            path=relative_path(f"{path}.path", payload["path"]),
            sha256=sha256(f"{path}.sha256", payload["sha256"]),
            size=integer(f"{path}.size", payload["size"]),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "attempt_id": self.attempt_id,
            "name": self.name,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
        }


def attempt_id(path: str, value: object) -> str:
    normalized = text(path, value)
    if not _ATTEMPT_ID_PATTERN.fullmatch(normalized):
        raise ObservabilityError(
            "trace_attempt_id_invalid",
            f"{path} 必须是 att_ 加 32 位小写十六进制",
        )
    return normalized


def relative_path(path: str, value: object) -> str:
    normalized = text(path, value)
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ObservabilityError(
            "trace_artifact_path_invalid",
            f"{path} 必须是无穿越的 POSIX 相对路径",
        )
    return candidate.as_posix()
