"""人工控制域共用的追加式 JSON journal。"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, Self

from qa_common import atomic_write_json

from .contracts import canonical_sha256, canonical_timestamp

JOURNAL_SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
MAX_EVENT_BYTES = 2 * 1024 * 1024
_EVENT_TYPE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,127}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class HumanControlJournalError(RuntimeError):
    """journal 损坏、冲突或无法安全持久化。"""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        sequence: int | None = None,
        covered_count: int | None = None,
        current_count: int | None = None,
        tail_count: int | None = None,
    ) -> None:
        self.code = code
        self.sequence = sequence
        self.covered_count = covered_count
        self.current_count = current_count
        self.tail_count = tail_count
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": JOURNAL_SCHEMA_VERSION,
            "error": "human_control_journal_error",
            "code": self.code,
            "message": str(self),
        }
        if self.sequence is not None:
            payload["sequence"] = self.sequence
        for field_name in (
            "covered_count",
            "current_count",
            "tail_count",
        ):
            value = getattr(self, field_name)
            if value is not None:
                payload[field_name] = value
        return payload


@dataclass(frozen=True, slots=True)
class JournalEvent:
    """带单调序号和前序哈希的不可变事件。"""

    sequence: int
    event_type: str
    occurred_at: str
    payload: Mapping[str, Any]
    previous_hash: str
    event_hash: str
    schema_version: int = JOURNAL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != JOURNAL_SCHEMA_VERSION:
            raise HumanControlJournalError(
                "event_schema_unsupported",
                (
                    "event schema_version 必须等于 "
                    f"{JOURNAL_SCHEMA_VERSION}"
                ),
                sequence=self.sequence,
            )
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
        ):
            raise HumanControlJournalError(
                "event_sequence_invalid",
                "event sequence 必须是正整数",
                sequence=self.sequence,
            )
        if (
            not isinstance(self.event_type, str)
            or _EVENT_TYPE_PATTERN.fullmatch(self.event_type) is None
        ):
            raise HumanControlJournalError(
                "event_type_invalid",
                "event_type 不是合法标识符",
                sequence=self.sequence,
            )
        canonical_timestamp(
            self.occurred_at,
            path="$.occurred_at",
        )
        payload = _json_object(self.payload)
        object.__setattr__(self, "payload", payload)
        for field_name in ("previous_hash", "event_hash"):
            value = getattr(self, field_name)
            if (
                not isinstance(value, str)
                or _SHA256_PATTERN.fullmatch(value) is None
            ):
                raise HumanControlJournalError(
                    "event_hash_invalid",
                    f"{field_name} 必须是 64 位小写 SHA-256",
                    sequence=self.sequence,
                )

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        event_type: str,
        occurred_at: str,
        payload: Mapping[str, Any],
        previous_hash: str,
    ) -> Self:
        body = {
            "schema_version": JOURNAL_SCHEMA_VERSION,
            "sequence": sequence,
            "event_type": event_type,
            "occurred_at": occurred_at,
            "payload": _json_object(payload),
            "previous_hash": previous_hash,
        }
        return cls(
            **body,
            event_hash=canonical_sha256(body),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Self:
        payload = _json_object(value)
        expected = {
            "schema_version",
            "sequence",
            "event_type",
            "occurred_at",
            "payload",
            "previous_hash",
            "event_hash",
        }
        unknown = sorted(set(payload) - expected)
        missing = sorted(expected - set(payload))
        if unknown:
            raise HumanControlJournalError(
                "event_fields_unknown",
                f"event 包含未知字段：{', '.join(unknown)}",
            )
        if missing:
            raise HumanControlJournalError(
                "event_fields_missing",
                f"event 缺少字段：{', '.join(missing)}",
            )
        return cls(
            schema_version=payload["schema_version"],
            sequence=payload["sequence"],
            event_type=payload["event_type"],
            occurred_at=payload["occurred_at"],
            payload=payload["payload"],
            previous_hash=payload["previous_hash"],
            event_hash=payload["event_hash"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "payload": dict(self.payload),
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
        }

    def verify_hash(self) -> None:
        expected = canonical_sha256(
            {
                "schema_version": self.schema_version,
                "sequence": self.sequence,
                "event_type": self.event_type,
                "occurred_at": self.occurred_at,
                "payload": dict(self.payload),
                "previous_hash": self.previous_hash,
            },
        )
        if self.event_hash != expected:
            raise HumanControlJournalError(
                "event_hash_mismatch",
                "event 内容与 event_hash 不一致",
                sequence=self.sequence,
            )


@dataclass(frozen=True, slots=True)
class JournalMutation:
    """一次准备追加的域事件。"""

    event_type: str
    occurred_at: str
    payload: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class JournalTransaction:
    """journal 事务结果；`appended=false` 表示幂等重放。"""

    events: tuple[JournalEvent, ...]
    projection: Mapping[str, Any]
    appended: bool


PrepareMutation = Callable[
    [tuple[JournalEvent, ...]],
    JournalMutation | None,
]
ProjectEvents = Callable[
    [tuple[JournalEvent, ...]],
    dict[str, Any],
]


class JournalCheckpointGuard(Protocol):
    """Structural protocol to avoid coupling the journal to one trust backend."""

    def verify(
        self,
        *,
        journal_kind: str,
        events_path: Path,
        projection_path: Path,
        events: Sequence[Any],
    ) -> Any: ...

    def note_append(self, *, current_count: int) -> None: ...


class AppendOnlyJsonJournal:
    """在文件锁内校验、追加、fsync 并原子更新 projection。"""

    def __init__(
        self,
        directory: Path,
        *,
        name: str,
        checkpoint_guard: JournalCheckpointGuard | None = None,
    ) -> None:
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name) is None
        ):
            raise HumanControlJournalError(
                "journal_name_invalid",
                "journal name 不是合法标识符",
            )
        self.directory = Path(directory)
        self.name = name
        self.events_path = self.directory / f"{name}-events.jsonl"
        self.projection_path = self.directory / f"{name}-snapshot.json"
        self._checkpoint_guard = checkpoint_guard

    def load_events(self) -> tuple[JournalEvent, ...]:
        """只信任并验证 journal；projection 不作为状态源。"""

        if not self._directory_exists_for_read():
            self._verify_checkpoint(())
            return ()
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.events_path, flags)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                self._verify_checkpoint(())
                return ()
            raise HumanControlJournalError(
                "journal_unreadable",
                str(exc),
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise HumanControlJournalError(
                    "journal_not_file",
                    f"journal 不是普通文件：{self.events_path}",
                )
            if opened.st_nlink != 1:
                raise HumanControlJournalError(
                    "journal_hardlink_unsafe",
                    "journal hard-link count 必须等于 1",
                )
            if opened.st_size > MAX_JOURNAL_BYTES:
                raise HumanControlJournalError(
                    "journal_size_exceeded",
                    f"journal 超过 {MAX_JOURNAL_BYTES} bytes",
                )
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
                raw = handle.read(MAX_JOURNAL_BYTES + 1)
                raw_size = len(raw.encode("utf-8"))
                if raw_size > MAX_JOURNAL_BYTES:
                    raise HumanControlJournalError(
                        "journal_size_exceeded",
                        f"journal 超过 {MAX_JOURNAL_BYTES} bytes",
                    )
                current_opened = os.fstat(handle.fileno())
                current = self.events_path.lstat()
                if (
                    current_opened.st_size != raw_size
                    or current.st_dev != opened.st_dev
                    or current.st_ino != opened.st_ino
                ):
                    raise HumanControlJournalError(
                        "journal_path_replaced",
                        "journal path 或内容在读取期间发生变化",
                    )
                events = _parse_lines(raw)
                self._verify_checkpoint(events)
                return events
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        raise AssertionError("unreachable")

    def transact(
        self,
        *,
        prepare: PrepareMutation,
        project: ProjectEvents,
    ) -> JournalTransaction:
        """在同一锁内完成幂等判断、追加和 projection 更新。"""

        self._ensure_directory()
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.events_path, flags, 0o600)
        except OSError as exc:
            raise HumanControlJournalError(
                "journal_unwritable",
                str(exc),
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise HumanControlJournalError(
                    "journal_not_file",
                    f"journal 不是普通文件：{self.events_path}",
                )
            if opened.st_nlink != 1:
                raise HumanControlJournalError(
                    "journal_hardlink_unsafe",
                    "journal hard-link count 必须等于 1",
                )
            if opened.st_size > MAX_JOURNAL_BYTES:
                raise HumanControlJournalError(
                    "journal_size_exceeded",
                    f"journal 超过 {MAX_JOURNAL_BYTES} bytes",
                )
            with os.fdopen(descriptor, "r+", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                handle.seek(0)
                raw = handle.read(MAX_JOURNAL_BYTES + 1)
                raw_size = len(raw.encode("utf-8"))
                if raw_size > MAX_JOURNAL_BYTES:
                    raise HumanControlJournalError(
                        "journal_size_exceeded",
                        f"journal 超过 {MAX_JOURNAL_BYTES} bytes",
                    )
                current_opened = os.fstat(handle.fileno())
                if current_opened.st_size != raw_size:
                    raise HumanControlJournalError(
                        "journal_changed_during_read",
                        "journal 内容在事务读取期间发生变化",
                    )
                events = _parse_lines(raw)
                self._verify_checkpoint(events)
                mutation = prepare(events)
                appended = mutation is not None
                updated = events
                if mutation is not None:
                    event = JournalEvent.create(
                        sequence=len(events) + 1,
                        event_type=mutation.event_type,
                        occurred_at=mutation.occurred_at,
                        payload=mutation.payload,
                        previous_hash=(
                            events[-1].event_hash
                            if events
                            else GENESIS_HASH
                        ),
                    )
                    updated = (*events, event)
                projection = _json_object(project(updated))
                if mutation is not None:
                    encoded_event = (
                        json.dumps(
                            event.to_dict(),
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
                    encoded_size = len(encoded_event.encode("utf-8"))
                    if encoded_size > MAX_EVENT_BYTES:
                        raise HumanControlJournalError(
                            "journal_event_size_exceeded",
                            f"journal event 超过 {MAX_EVENT_BYTES} bytes",
                            sequence=event.sequence,
                        )
                    if (
                        current_opened.st_size + encoded_size
                        > MAX_JOURNAL_BYTES
                    ):
                        raise HumanControlJournalError(
                            "journal_size_exceeded",
                            f"journal 超过 {MAX_JOURNAL_BYTES} bytes",
                        )
                    handle.seek(0, os.SEEK_END)
                    handle.write(encoded_event)
                    handle.flush()
                    os.fsync(handle.fileno())
                    if self._checkpoint_guard is not None:
                        self._checkpoint_guard.note_append(
                            current_count=len(updated),
                        )
                current = self.events_path.lstat()
                if (
                    current.st_dev != opened.st_dev
                    or current.st_ino != opened.st_ino
                ):
                    raise HumanControlJournalError(
                        "journal_path_replaced",
                        "journal path 在事务期间被替换",
                    )
                atomic_write_json(
                    self.projection_path,
                    projection,
                )
                return JournalTransaction(
                    events=updated,
                    projection=projection,
                    appended=appended,
                )
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise

    def project(
        self,
        project: ProjectEvents,
    ) -> dict[str, Any]:
        """从权威 journal 重建只读 projection。"""

        return _json_object(project(self.load_events()))

    def _ensure_directory(self) -> None:
        if self.directory.exists():
            try:
                metadata = self.directory.lstat()
            except OSError as exc:
                raise HumanControlJournalError(
                    "journal_directory_unreadable",
                    str(exc),
                ) from exc
            if not stat.S_ISDIR(metadata.st_mode):
                raise HumanControlJournalError(
                    "journal_directory_invalid",
                    f"journal directory 不是普通目录：{self.directory}",
                )
            return
        try:
            self.directory.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            self._ensure_directory()
        except OSError as exc:
            raise HumanControlJournalError(
                "journal_directory_unwritable",
                str(exc),
            ) from exc

    def _directory_exists_for_read(self) -> bool:
        try:
            metadata = self.directory.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise HumanControlJournalError(
                "journal_directory_unreadable",
                str(exc),
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise HumanControlJournalError(
                "journal_directory_invalid",
                f"journal directory 不是普通目录：{self.directory}",
            )
        return True

    def _verify_checkpoint(
        self,
        events: tuple[JournalEvent, ...],
    ) -> None:
        if self._checkpoint_guard is None:
            return
        self._checkpoint_guard.verify(
            journal_kind=self.name,
            events_path=self.events_path,
            projection_path=self.projection_path,
            events=events,
        )


def _parse_lines(raw: str) -> tuple[JournalEvent, ...]:
    if len(raw.encode("utf-8")) > MAX_JOURNAL_BYTES:
        raise HumanControlJournalError(
            "journal_size_exceeded",
            f"journal 超过 {MAX_JOURNAL_BYTES} bytes",
        )
    if raw and not raw.endswith("\n"):
        raise HumanControlJournalError(
            "journal_truncated",
            "journal 尾部不是完整换行记录",
        )
    events: list[JournalEvent] = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        if not line:
            raise HumanControlJournalError(
                "journal_line_empty",
                "journal 包含空行",
                sequence=line_number,
            )
        if len(line.encode("utf-8")) > MAX_EVENT_BYTES:
            raise HumanControlJournalError(
                "journal_event_size_exceeded",
                f"journal event 超过 {MAX_EVENT_BYTES} bytes",
                sequence=line_number,
            )
        value = _strict_json_line(line, line_number=line_number)
        if not isinstance(value, dict):
            raise HumanControlJournalError(
                "journal_event_not_object",
                "journal event 根必须是 object",
                sequence=line_number,
            )
        events.append(JournalEvent.from_dict(value))
    _validate_chain(events)
    return tuple(events)


def _strict_json_line(raw: str, *, line_number: int) -> Any:
    def object_pairs(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise HumanControlJournalError(
                    "journal_json_duplicate_key",
                    f"journal JSON 包含重复 key：{key}",
                    sequence=line_number,
                )
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise HumanControlJournalError(
            "journal_json_nonfinite",
            f"journal JSON 不允许非有限数：{value}",
            sequence=line_number,
        )

    try:
        return json.loads(
            raw,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        message = (
            exc.msg
            if isinstance(exc, json.JSONDecodeError)
            else "JSON nesting 过深"
        )
        raise HumanControlJournalError(
            "journal_json_invalid",
            f"journal JSON 非法：{message}",
            sequence=line_number,
        ) from exc


def _validate_chain(events: list[JournalEvent]) -> None:
    previous_hash = GENESIS_HASH
    for expected_sequence, event in enumerate(events, 1):
        if event.sequence != expected_sequence:
            raise HumanControlJournalError(
                "event_sequence_mismatch",
                (
                    f"期望 sequence={expected_sequence}，"
                    f"实际为 {event.sequence}"
                ),
                sequence=event.sequence,
            )
        if event.previous_hash != previous_hash:
            raise HumanControlJournalError(
                "event_chain_broken",
                "previous_hash 与前一事件不一致",
                sequence=event.sequence,
            )
        event.verify_hash()
        previous_hash = event.event_hash


def _json_object(value: Any) -> dict[str, Any]:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        decoded = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HumanControlJournalError(
            "json_value_invalid",
            "值必须能无损表示为标准 JSON",
        ) from exc
    if not isinstance(decoded, dict):
        raise HumanControlJournalError(
            "json_object_required",
            "值必须是 JSON object",
        )
    return decoded
