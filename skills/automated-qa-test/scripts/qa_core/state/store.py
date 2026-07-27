"""用追加事件、哈希链和 reducer 持久化 QA Agent 状态。"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable, Mapping

from qa_common import atomic_write_json

EVENT_SCHEMA_VERSION = 1
STATE_SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
PASS_AUTHORITY = "deterministic_verdict"


class RunEventType(StrEnum):
    """受支持的状态变化类型；未注册类型默认拒绝。"""

    RUN_CREATED = "run_created"
    PHASE_CHANGED = "phase_changed"
    FACT_RECORDED = "fact_recorded"
    ASSUMPTION_RECORDED = "assumption_recorded"
    HYPOTHESIS_RECORDED = "hypothesis_recorded"
    HYPOTHESIS_UPDATED = "hypothesis_updated"
    UNKNOWN_RECORDED = "unknown_recorded"
    EVIDENCE_LINKED = "evidence_linked"
    APPROVAL_RECORDED = "approval_recorded"
    BUDGET_UPDATED = "budget_updated"
    COMPONENT_VERSIONS_RECORDED = "component_versions_recorded"
    STATUS_CHANGED = "status_changed"


class EventLogError(RuntimeError):
    """事件日志缺失、损坏或违反状态约束。"""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        sequence: int | None = None,
    ) -> None:
        self.code = code
        self.sequence = sequence
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "error": "event_log_error",
            "code": self.code,
            "sequence": self.sequence,
            "message": str(self),
        }


@dataclass(frozen=True, slots=True)
class RunEvent:
    """一个不可变、可校验的运行事件。"""

    run_id: str
    sequence: int
    event_id: str
    event_type: RunEventType
    occurred_at: str
    actor: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str
    schema_version: int = EVENT_SCHEMA_VERSION

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        sequence: int,
        event_type: RunEventType | str,
        payload: Mapping[str, Any],
        previous_hash: str,
        actor: str,
        occurred_at: str | None = None,
        event_id: str | None = None,
    ) -> "RunEvent":
        normalized_type = _event_type(event_type)
        normalized_payload = _validated_payload(normalized_type, payload)
        base = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "run_id": _non_empty_text("run_id", run_id),
            "sequence": _positive_int("sequence", sequence),
            "event_id": _non_empty_text("event_id", event_id or str(uuid.uuid4())),
            "event_type": normalized_type.value,
            "occurred_at": _non_empty_text("occurred_at", occurred_at or _utc_now()),
            "actor": _non_empty_text("actor", actor),
            "payload": normalized_payload,
            "previous_hash": _sha256_text("previous_hash", previous_hash),
        }
        return cls(
            run_id=base["run_id"],
            sequence=base["sequence"],
            event_id=base["event_id"],
            event_type=normalized_type,
            occurred_at=base["occurred_at"],
            actor=base["actor"],
            payload=normalized_payload,
            previous_hash=base["previous_hash"],
            event_hash=_hash_payload(base),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RunEvent":
        if value.get("schema_version") != EVENT_SCHEMA_VERSION:
            raise EventLogError(
                "unsupported_event_schema",
                f"event schema_version must equal {EVENT_SCHEMA_VERSION}",
                sequence=_optional_int(value.get("sequence")),
            )
        required = {
            "run_id",
            "sequence",
            "event_id",
            "event_type",
            "occurred_at",
            "actor",
            "payload",
            "previous_hash",
            "event_hash",
        }
        missing = sorted(required - set(value))
        if missing:
            raise EventLogError(
                "event_fields_missing",
                f"event is missing fields: {', '.join(missing)}",
                sequence=_optional_int(value.get("sequence")),
            )
        extra = sorted(set(value) - required - {"schema_version"})
        if extra:
            raise EventLogError(
                "event_fields_unknown",
                f"event contains unknown fields: {', '.join(extra)}",
                sequence=_optional_int(value.get("sequence")),
            )
        try:
            event = cls.create(
                run_id=value["run_id"],
                sequence=value["sequence"],
                event_type=value["event_type"],
                payload=value["payload"],
                previous_hash=value["previous_hash"],
                actor=value["actor"],
                occurred_at=value["occurred_at"],
                event_id=value["event_id"],
            )
        except (TypeError, ValueError) as exc:
            raise EventLogError(
                "event_invalid",
                str(exc),
                sequence=_optional_int(value.get("sequence")),
            ) from exc
        declared_hash = value.get("event_hash")
        if declared_hash != event.event_hash:
            raise EventLogError(
                "event_hash_mismatch",
                "event content does not match event_hash",
                sequence=event.sequence,
            )
        return event

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "sequence": self.sequence,
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "occurred_at": self.occurred_at,
            "actor": self.actor,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
        }


@dataclass(slots=True)
class RunState:
    """由事件日志唯一派生的可恢复状态投影。"""

    run_id: str
    goal: str
    scope: list[str]
    sequence: int = 0
    last_event_hash: str = GENESIS_HASH
    phase: str = "created"
    status: str = "running"
    facts: dict[str, dict[str, Any]] = field(default_factory=dict)
    assumptions: dict[str, dict[str, Any]] = field(default_factory=dict)
    hypotheses: dict[str, dict[str, Any]] = field(default_factory=dict)
    unknowns: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence: dict[str, dict[str, Any]] = field(default_factory=dict)
    approvals: dict[str, dict[str, Any]] = field(default_factory=dict)
    budget: dict[str, Any] = field(default_factory=dict)
    component_versions: dict[str, Any] = field(default_factory=dict)
    updated_at: str | None = None
    schema_version: int = STATE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "sequence": self.sequence,
            "last_event_hash": self.last_event_hash,
            "goal": self.goal,
            "scope": self.scope,
            "phase": self.phase,
            "status": self.status,
            "facts": self.facts,
            "assumptions": self.assumptions,
            "hypotheses": self.hypotheses,
            "unknowns": self.unknowns,
            "evidence": self.evidence,
            "approvals": self.approvals,
            "budget": self.budget,
            "component_versions": self.component_versions,
            "updated_at": self.updated_at,
        }


class RunStateStore:
    """在单写租约内追加事件，并原子发布状态投影。"""

    def __init__(
        self,
        run_dir: Path,
        *,
        events_name: str = "run-events.jsonl",
        state_name: str = "run-state.json",
    ) -> None:
        self.run_dir = run_dir.expanduser().resolve()
        self.events_path = self.run_dir / events_name
        self.state_path = self.run_dir / state_name

    def initialize(
        self,
        *,
        run_id: str,
        goal: str,
        scope: Iterable[str],
        actor: str,
        component_versions: Mapping[str, Any] | None = None,
    ) -> RunState:
        payload: dict[str, Any] = {
            "goal": _non_empty_text("goal", goal),
            "scope": _text_list("scope", list(scope)),
        }
        if component_versions is not None:
            payload["component_versions"] = _json_object(
                "component_versions",
                component_versions,
            )
        return self._append_new(
            run_id=run_id,
            event_type=RunEventType.RUN_CREATED,
            payload=payload,
            actor=actor,
            require_empty=True,
        )

    def append(
        self,
        event_type: RunEventType | str,
        payload: Mapping[str, Any],
        *,
        actor: str,
    ) -> RunState:
        events = self.load_events()
        if not events:
            raise EventLogError(
                "run_not_initialized",
                "initialize the run before appending events",
            )
        return self._append_new(
            run_id=events[0].run_id,
            event_type=event_type,
            payload=payload,
            actor=actor,
            require_empty=False,
        )

    def load_events(self) -> list[RunEvent]:
        if not self.events_path.exists():
            return []
        try:
            metadata = self.events_path.lstat()
        except OSError as exc:
            raise EventLogError("event_log_unreadable", str(exc)) from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise EventLogError(
                "event_log_not_file",
                f"event log is not a regular file: {self.events_path}",
            )
        try:
            raw = self.events_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise EventLogError("event_log_unreadable", str(exc)) from exc
        if raw and not raw.endswith("\n"):
            raise EventLogError(
                "event_log_truncated",
                "event log does not end with a complete newline",
            )
        raw_lines = raw.splitlines()
        events: list[RunEvent] = []
        for index, line in enumerate(raw_lines, 1):
            if not line.strip():
                raise EventLogError(
                    "event_line_empty",
                    "event log contains an empty line",
                    sequence=index,
                )
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise EventLogError(
                    "event_json_invalid",
                    f"invalid event JSON: {exc.msg}",
                    sequence=index,
                ) from exc
            if not isinstance(value, dict):
                raise EventLogError(
                    "event_not_object",
                    "event JSON root must be an object",
                    sequence=index,
                )
            events.append(RunEvent.from_dict(value))
        _validate_chain(events)
        return events

    def load_state(self) -> RunState:
        events = self.load_events()
        if not events:
            raise EventLogError("run_not_initialized", "event log is empty")
        return reduce_events(events)

    def _append_new(
        self,
        *,
        run_id: str,
        event_type: RunEventType | str,
        payload: Mapping[str, Any],
        actor: str,
        require_empty: bool,
    ) -> RunState:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.events_path, flags, 0o600)
        except OSError as exc:
            raise EventLogError("event_log_unwritable", str(exc)) from exc
        try:
            with os.fdopen(descriptor, "r+", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                handle.seek(0)
                events = _parse_locked_lines(handle.read())
                if require_empty and events:
                    raise EventLogError(
                        "run_already_initialized",
                        "event log already contains a run",
                    )
                if not require_empty and not events:
                    raise EventLogError(
                        "run_not_initialized",
                        "initialize the run before appending events",
                    )
                if events and events[0].run_id != run_id:
                    raise EventLogError(
                        "run_id_mismatch",
                        "event log belongs to a different run",
                    )
                previous_hash = events[-1].event_hash if events else GENESIS_HASH
                event = RunEvent.create(
                    run_id=run_id,
                    sequence=len(events) + 1,
                    event_type=event_type,
                    payload=payload,
                    previous_hash=previous_hash,
                    actor=actor,
                )
                projected = reduce_events([*events, event])
                handle.seek(0, os.SEEK_END)
                handle.write(
                    json.dumps(
                        event.to_dict(),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    + "\n"
                )
                handle.flush()
                os.fsync(handle.fileno())
                atomic_write_json(self.state_path, projected.to_dict())
                return projected
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise


def reduce_events(events: Iterable[RunEvent]) -> RunState:
    """严格按序重放事件，生成唯一状态。"""

    ordered = list(events)
    _validate_chain(ordered)
    first = ordered[0]
    if first.event_type is not RunEventType.RUN_CREATED:
        raise EventLogError(
            "first_event_invalid",
            "first event must be run_created",
            sequence=first.sequence,
        )
    state = RunState(
        run_id=first.run_id,
        goal=first.payload["goal"],
        scope=list(first.payload["scope"]),
        component_versions=dict(first.payload.get("component_versions") or {}),
    )
    for event in ordered:
        _apply_event(state, event)
        state.sequence = event.sequence
        state.last_event_hash = event.event_hash
        state.updated_at = event.occurred_at
    return state


def _apply_event(state: RunState, event: RunEvent) -> None:
    payload = event.payload
    if event.event_type is RunEventType.RUN_CREATED:
        return
    if event.event_type is RunEventType.PHASE_CHANGED:
        state.phase = payload["phase"]
        return
    if event.event_type is RunEventType.FACT_RECORDED:
        state.facts[payload["id"]] = payload
        return
    if event.event_type is RunEventType.ASSUMPTION_RECORDED:
        state.assumptions[payload["id"]] = payload
        return
    if event.event_type is RunEventType.HYPOTHESIS_RECORDED:
        state.hypotheses[payload["id"]] = payload
        return
    if event.event_type is RunEventType.HYPOTHESIS_UPDATED:
        hypothesis_id = payload["id"]
        if hypothesis_id not in state.hypotheses:
            raise EventLogError(
                "hypothesis_missing",
                f"cannot update unknown hypothesis {hypothesis_id!r}",
                sequence=event.sequence,
            )
        state.hypotheses[hypothesis_id] = {
            **state.hypotheses[hypothesis_id],
            **payload,
        }
        return
    if event.event_type is RunEventType.UNKNOWN_RECORDED:
        state.unknowns[payload["id"]] = payload
        return
    if event.event_type is RunEventType.EVIDENCE_LINKED:
        state.evidence[payload["id"]] = payload
        return
    if event.event_type is RunEventType.APPROVAL_RECORDED:
        state.approvals[payload["id"]] = payload
        return
    if event.event_type is RunEventType.BUDGET_UPDATED:
        state.budget = dict(payload["budget"])
        return
    if event.event_type is RunEventType.COMPONENT_VERSIONS_RECORDED:
        state.component_versions = {
            **state.component_versions,
            **payload["versions"],
        }
        return
    if event.event_type is RunEventType.STATUS_CHANGED:
        state.status = payload["status"]
        return
    raise EventLogError(
        "event_type_unhandled",
        f"no reducer for {event.event_type.value}",
        sequence=event.sequence,
    )


def _validated_payload(
    event_type: RunEventType,
    value: Mapping[str, Any],
) -> dict[str, Any]:
    payload = _json_object("payload", value)
    if event_type is RunEventType.RUN_CREATED:
        _reject_unknown_fields(
            payload,
            {"goal", "scope", "component_versions"},
        )
        result = {
            "goal": _non_empty_text("payload.goal", payload.get("goal")),
            "scope": _text_list("payload.scope", payload.get("scope")),
        }
        if "component_versions" in payload:
            result["component_versions"] = _json_object(
                "payload.component_versions",
                payload["component_versions"],
            )
        return result
    if event_type is RunEventType.PHASE_CHANGED:
        _reject_unknown_fields(
            payload,
            {"phase", "trace_required", "command_sha256"},
        )
        result = {
            "phase": _non_empty_text(
                "payload.phase",
                payload.get("phase"),
            )
        }
        if "trace_required" in payload:
            if type(payload["trace_required"]) is not bool:
                raise TypeError("payload.trace_required must be boolean")
            result["trace_required"] = payload["trace_required"]
        if "command_sha256" in payload:
            result["command_sha256"] = _sha256_text(
                "payload.command_sha256",
                payload["command_sha256"],
            )
        if result.get("trace_required") is True and "command_sha256" not in result:
            raise ValueError(
                "payload.command_sha256 is required when trace_required=true"
            )
        if "command_sha256" in result and result.get("trace_required") is not True:
            raise ValueError(
                "payload.command_sha256 requires trace_required=true"
            )
        return result
    if event_type in {
        RunEventType.FACT_RECORDED,
        RunEventType.ASSUMPTION_RECORDED,
        RunEventType.UNKNOWN_RECORDED,
    }:
        _reject_unknown_fields(
            payload,
            {"id", "statement", "source_refs", "confidence"},
        )
        return _statement_payload(payload)
    if event_type is RunEventType.HYPOTHESIS_RECORDED:
        _reject_unknown_fields(
            payload,
            {"id", "statement", "source_refs", "confidence", "status"},
        )
        result = _statement_payload(payload)
        result["status"] = _choice(
            "payload.status",
            payload.get("status", "open"),
            {"open", "supported", "rejected", "superseded"},
        )
        result["confidence"] = _confidence(payload.get("confidence", 0.5))
        return result
    if event_type is RunEventType.HYPOTHESIS_UPDATED:
        _reject_unknown_fields(
            payload,
            {"id", "status", "confidence", "reason"},
        )
        result = {
            "id": _non_empty_text("payload.id", payload.get("id")),
            "status": _choice(
                "payload.status",
                payload.get("status"),
                {"open", "supported", "rejected", "superseded"},
            ),
        }
        if "confidence" in payload:
            result["confidence"] = _confidence(payload["confidence"])
        if "reason" in payload:
            result["reason"] = _non_empty_text(
                "payload.reason",
                payload["reason"],
            )
        return result
    if event_type is RunEventType.EVIDENCE_LINKED:
        _reject_unknown_fields(
            payload,
            {"id", "path", "status", "proves", "sha256"},
        )
        result = {
            "id": _non_empty_text("payload.id", payload.get("id")),
            "path": _non_empty_text("payload.path", payload.get("path")),
            "status": _choice(
                "payload.status",
                payload.get("status"),
                {"passed", "failed", "blocked", "untested", "inconclusive"},
            ),
            "proves": _text_list("payload.proves", payload.get("proves", [])),
        }
        if "sha256" in payload:
            result["sha256"] = _sha256_text("payload.sha256", payload["sha256"])
        return result
    if event_type is RunEventType.APPROVAL_RECORDED:
        _reject_unknown_fields(
            payload,
            {"id", "decision", "scope", "decided_by"},
        )
        return {
            "id": _non_empty_text("payload.id", payload.get("id")),
            "decision": _choice(
                "payload.decision",
                payload.get("decision"),
                {"approved", "denied"},
            ),
            "scope": _text_list("payload.scope", payload.get("scope")),
            "decided_by": _non_empty_text(
                "payload.decided_by",
                payload.get("decided_by"),
            ),
        }
    if event_type is RunEventType.BUDGET_UPDATED:
        _reject_unknown_fields(payload, {"budget"})
        return {"budget": _json_object("payload.budget", payload.get("budget"))}
    if event_type is RunEventType.COMPONENT_VERSIONS_RECORDED:
        _reject_unknown_fields(payload, {"versions"})
        return {
            "versions": _json_object(
                "payload.versions",
                payload.get("versions"),
            )
        }
    if event_type is RunEventType.STATUS_CHANGED:
        _reject_unknown_fields(
            payload,
            {"status", "authority", "verdict_ref", "attempt_ref"},
        )
        status = _choice(
            "payload.status",
            payload.get("status"),
            {
                "running",
                "attention",
                "blocked",
                "passed",
                "failed",
                "inconclusive",
                "cancelled",
            },
        )
        result = {
            "status": status,
            "authority": _non_empty_text(
                "payload.authority",
                payload.get("authority"),
            ),
        }
        if status == "passed":
            if result["authority"] != PASS_AUTHORITY:
                raise ValueError(
                    "payload.authority must be deterministic_verdict for passed status"
                )
            result["verdict_ref"] = _json_object(
                "payload.verdict_ref",
                payload.get("verdict_ref"),
            )
            _non_empty_text(
                "payload.verdict_ref.path",
                result["verdict_ref"].get("path"),
            )
            _sha256_text(
                "payload.verdict_ref.sha256",
                result["verdict_ref"].get("sha256"),
            )
            if payload.get("attempt_ref") is None:
                raise ValueError(
                    "payload.attempt_ref is required for passed status"
                )
            result["attempt_ref"] = _attempt_ref(
                payload.get("attempt_ref"),
            )
        elif "verdict_ref" in payload:
            result["verdict_ref"] = _json_object(
                "payload.verdict_ref",
                payload["verdict_ref"],
            )
        if status != "passed" and "attempt_ref" in payload:
            result["attempt_ref"] = _attempt_ref(
                payload["attempt_ref"],
            )
        return result
    raise ValueError(f"unsupported event type: {event_type.value}")


def _statement_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        "id": _non_empty_text("payload.id", payload.get("id")),
        "statement": _non_empty_text(
            "payload.statement",
            payload.get("statement"),
        ),
        "source_refs": _text_list(
            "payload.source_refs",
            payload.get("source_refs", []),
        ),
    }
    if "confidence" in payload:
        result["confidence"] = _confidence(payload["confidence"])
    return result


def _attempt_ref(value: Any) -> dict[str, Any]:
    reference = _json_object("payload.attempt_ref", value)
    _reject_unknown_fields(
        reference,
        {
            "attempt_id",
            "attempt_manifest_sha256",
            "run_manifest_sequence",
            "run_manifest_sha256",
        },
    )
    return {
        "attempt_id": _non_empty_text(
            "payload.attempt_ref.attempt_id",
            reference.get("attempt_id"),
        ),
        "attempt_manifest_sha256": _sha256_text(
            "payload.attempt_ref.attempt_manifest_sha256",
            reference.get("attempt_manifest_sha256"),
        ),
        "run_manifest_sequence": _positive_int(
            "payload.attempt_ref.run_manifest_sequence",
            reference.get("run_manifest_sequence"),
        ),
        "run_manifest_sha256": _sha256_text(
            "payload.attempt_ref.run_manifest_sha256",
            reference.get("run_manifest_sha256"),
        ),
    }


def _validate_chain(events: list[RunEvent]) -> None:
    previous_hash = GENESIS_HASH
    run_id: str | None = None
    event_ids: set[str] = set()
    for expected_sequence, event in enumerate(events, 1):
        if event.sequence != expected_sequence:
            raise EventLogError(
                "event_sequence_gap",
                f"expected sequence {expected_sequence}, got {event.sequence}",
                sequence=event.sequence,
            )
        if run_id is None:
            run_id = event.run_id
        elif event.run_id != run_id:
            raise EventLogError(
                "run_id_mismatch",
                "event belongs to a different run",
                sequence=event.sequence,
            )
        if event.event_id in event_ids:
            raise EventLogError(
                "event_id_duplicate",
                f"duplicate event_id {event.event_id!r}",
                sequence=event.sequence,
            )
        if event.previous_hash != previous_hash:
            raise EventLogError(
                "event_chain_broken",
                "event previous_hash does not match prior event",
                sequence=event.sequence,
            )
        event_ids.add(event.event_id)
        previous_hash = event.event_hash


def _parse_locked_lines(raw: str) -> list[RunEvent]:
    if not raw:
        return []
    if not raw.endswith("\n"):
        raise EventLogError(
            "event_log_truncated",
            "event log does not end with a complete newline",
        )
    events: list[RunEvent] = []
    for index, line in enumerate(raw.splitlines(), 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EventLogError(
                "event_json_invalid",
                f"invalid event JSON: {exc.msg}",
                sequence=index,
            ) from exc
        if not isinstance(value, dict):
            raise EventLogError(
                "event_not_object",
                "event JSON root must be an object",
                sequence=index,
            )
        events.append(RunEvent.from_dict(value))
    _validate_chain(events)
    return events


def _event_type(value: RunEventType | str) -> RunEventType:
    try:
        return RunEventType(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"unsupported event type: {value!r}") from exc


def _hash_payload(value: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _reject_unknown_fields(
    value: Mapping[str, Any],
    allowed: set[str],
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(
            f"payload contains unknown fields: {', '.join(unknown)}"
        )


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _non_empty_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty text")
    return value.strip()


def _text_list(name: str, value: Any) -> list[str]:
    if not isinstance(value, list):
        raise TypeError(f"{name} must be a list")
    return [_non_empty_text(f"{name}[{index}]", item) for index, item in enumerate(value)]


def _json_object(name: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be an object")
    normalized = dict(value)
    try:
        json.dumps(normalized, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be JSON-compatible") from exc
    return normalized


def _choice(name: str, value: Any, choices: set[str]) -> str:
    normalized = _non_empty_text(name, value)
    if normalized not in choices:
        raise ValueError(f"{name} must be one of: {', '.join(sorted(choices))}")
    return normalized


def _confidence(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError("payload.confidence must be numeric")
    normalized = float(value)
    if not 0.0 <= normalized <= 1.0:
        raise ValueError("payload.confidence must be between 0 and 1")
    return normalized


def _positive_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _optional_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _sha256_text(name: str, value: Any) -> str:
    normalized = _non_empty_text(name, value)
    if len(normalized) != 64:
        raise ValueError(f"{name} must be a 64-character SHA-256 hex digest")
    try:
        int(normalized, 16)
    except ValueError as exc:
        raise ValueError(f"{name} must be a SHA-256 hex digest") from exc
    return normalized.lower()
