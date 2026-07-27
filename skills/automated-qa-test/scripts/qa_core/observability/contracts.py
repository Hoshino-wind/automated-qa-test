"""Trace event 与 journal record 的公开合同。"""

from __future__ import annotations

from dataclasses import dataclass

from ._validation import ObservabilityError, canonical_sha256, exact_object, integer, sha256
from .event import TraceEvent
from .model import (
    EVENT_FIELDS,
    TRACE_KINDS,
    TRACE_SCHEMA_VERSION,
    TRACE_STATUSES,
    TraceArtifactRef,
    TraceBudget,
    TraceReason,
)

_RECORD_FIELDS = EVENT_FIELDS | {
    "sequence",
    "previous_event_sha256",
    "event_sha256",
}


@dataclass(frozen=True, slots=True)
class TraceRecord:
    """带 sequence 和前向哈希的 journal 记录。"""

    event: TraceEvent
    sequence: int
    previous_event_sha256: str | None
    event_sha256: str

    @classmethod
    def create(
        cls,
        event: TraceEvent,
        *,
        sequence: int,
        previous_event_sha256: str | None,
    ) -> "TraceRecord":
        if not isinstance(event, TraceEvent):
            raise TypeError("event 必须是 TraceEvent")
        normalized_sequence = integer("record.sequence", sequence, minimum=1)
        previous = _previous_hash(normalized_sequence, previous_event_sha256)
        unsigned = {
            **event.to_dict(),
            "sequence": normalized_sequence,
            "previous_event_sha256": previous,
        }
        return cls(
            event=event,
            sequence=normalized_sequence,
            previous_event_sha256=previous,
            event_sha256=canonical_sha256(unsigned),
        )

    @classmethod
    def from_dict(cls, value: object, *, path: str = "record") -> "TraceRecord":
        payload = exact_object(path, value, required=_RECORD_FIELDS)
        event = TraceEvent.from_dict(
            {field: payload[field] for field in EVENT_FIELDS},
            path=path,
        )
        sequence = integer(f"{path}.sequence", payload["sequence"], minimum=1)
        previous = _previous_hash(sequence, payload["previous_event_sha256"])
        recorded_hash = sha256(f"{path}.event_sha256", payload["event_sha256"])
        expected_hash = canonical_sha256(
            {
                **event.to_dict(),
                "sequence": sequence,
                "previous_event_sha256": previous,
            }
        )
        if recorded_hash != expected_hash:
            raise ObservabilityError(
                "trace_event_hash_mismatch",
                f"{path}.event_sha256 与记录内容不匹配",
            )
        return cls(event, sequence, previous, recorded_hash)

    def to_dict(self) -> dict[str, object]:
        return {
            **self.event.to_dict(),
            "sequence": self.sequence,
            "previous_event_sha256": self.previous_event_sha256,
            "event_sha256": self.event_sha256,
        }


def _previous_hash(sequence: int, value: object) -> str | None:
    if sequence == 1:
        if value is not None:
            raise ObservabilityError(
                "trace_chain_origin_invalid",
                "首条记录的 previous_event_sha256 必须为 null",
            )
        return None
    if value is None:
        raise ObservabilityError(
            "trace_chain_link_missing",
            "非首条记录必须声明 previous_event_sha256",
        )
    return sha256("record.previous_event_sha256", value)


__all__ = [
    "TRACE_KINDS",
    "TRACE_SCHEMA_VERSION",
    "TRACE_STATUSES",
    "TraceArtifactRef",
    "TraceBudget",
    "TraceEvent",
    "TraceReason",
    "TraceRecord",
]
