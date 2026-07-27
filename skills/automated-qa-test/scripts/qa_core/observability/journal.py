"""并发安全、追加式且读时验链的 trace journal。"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping

from ._validation import ObservabilityError, canonical_bytes
from .contracts import TraceEvent, TraceRecord

_MAX_JOURNAL_BYTES = 64 * 1024 * 1024
_MAX_LINE_BYTES = 1024 * 1024
_READ_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True, slots=True)
class TraceSnapshot:
    """一次共享锁内读取并验证的 journal 快照。"""

    records: tuple[TraceRecord, ...]
    sha256: str
    byte_size: int


class TraceJournal:
    """以 JSONL 保存完整 span，并让损坏阻断后续追加。"""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        candidate = Path(path).expanduser()
        if not candidate.name or candidate.name in {".", ".."}:
            raise ObservabilityError(
                "trace_journal_path_invalid",
                "trace journal 路径必须包含文件名",
            )
        parent = candidate.parent.resolve()
        self.path = parent / candidate.name
        self.guard_path = parent / f".{candidate.name}.guard"

    def append(self, event: TraceEvent | Mapping[str, object]) -> TraceRecord:
        """校验事件，在独占锁内连接前一哈希并持久化一行。"""
        normalized = (
            event
            if isinstance(event, TraceEvent)
            else TraceEvent.from_dict(dict(event))
        )
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._guard(exclusive=True):
            payload, records, identity = self._read_unlocked()
            previous = records[-1].event_sha256 if records else None
            record = TraceRecord.create(
                normalized,
                sequence=len(records) + 1,
                previous_event_sha256=previous,
            )
            line = canonical_bytes(record.to_dict()) + b"\n"
            if len(line) > _MAX_LINE_BYTES:
                raise ObservabilityError(
                    "trace_line_too_large",
                    f"trace 单行超过 {_MAX_LINE_BYTES} 字节",
                )
            descriptor = self._open_journal_for_append()
            try:
                metadata = os.fstat(descriptor)
                if identity is None:
                    if metadata.st_size != 0:
                        raise ObservabilityError(
                            "trace_journal_raced",
                            "journal 在校验与追加之间被替换",
                        )
                elif (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_size,
                ) != identity:
                    raise ObservabilityError(
                        "trace_journal_raced",
                        "journal 在校验与追加之间发生变化",
                    )
                if metadata.st_size != len(payload):
                    raise ObservabilityError(
                        "trace_journal_raced",
                        "journal 长度在追加前发生变化",
                    )
                _write_all(descriptor, line)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _fsync_directory(self.path.parent)
            return record

    def read(self) -> tuple[TraceRecord, ...]:
        return self.snapshot().records

    def snapshot(self) -> TraceSnapshot:
        """只读返回记录与原始字节哈希，不创建目录或 guard。"""
        with self._guard(exclusive=False) as guarded:
            payload, records, _ = self._read_unlocked()
        if not guarded and payload:
            self._require_read_only_unguarded_package()
        return TraceSnapshot(
            records=records,
            sha256=hashlib.sha256(payload).hexdigest(),
            byte_size=len(payload),
        )

    @contextmanager
    def _guard(self, *, exclusive: bool) -> Iterator[bool]:
        flags = (
            os.O_RDWR | os.O_CREAT
            if exclusive
            else os.O_RDONLY
        )
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.guard_path, flags, 0o600)
        except FileNotFoundError as error:
            if not exclusive:
                # 验证器可能收到不含写入端 guard 的不可变制品包。调用方固定读取后，
                # 再判断它是尚未创建的空写入日志，还是非空不可变制品包。
                yield False
                return
            raise ObservabilityError(
                "trace_guard_open_failed",
                f"无法打开 trace guard：{error}",
            ) from error
        except OSError as error:
            raise ObservabilityError(
                "trace_guard_open_failed",
                f"无法打开 trace guard：{error}",
            ) from error
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ObservabilityError(
                    "trace_guard_not_regular",
                    "trace guard 必须是普通文件",
                )
            if os.fstat(descriptor).st_nlink != 1:
                raise ObservabilityError(
                    "trace_guard_hardlink_rejected",
                    "trace guard 不得存在硬链接别名",
                )
            fcntl.flock(
                descriptor,
                fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH,
            )
            yield True
        finally:
            os.close(descriptor)

    def _require_read_only_unguarded_package(self) -> None:
        """Reject a non-empty guardless trace unless its package is read-only."""

        try:
            journal_mode = self.path.stat().st_mode
            parent_mode = self.path.parent.stat().st_mode
        except OSError as metadata_error:
            raise ObservabilityError(
                "trace_guard_missing_untrusted",
                (
                    "缺失 trace guard 时无法确认只读 artifact "
                    f"package：{metadata_error}"
                ),
            ) from metadata_error
        writable_bits = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
        if journal_mode & writable_bits or parent_mode & writable_bits:
            raise ObservabilityError(
                "trace_guard_missing_untrusted",
                (
                    "缺失 trace guard 的非空 snapshot 只允许来自"
                    "只读 journal 与只读目录"
                ),
            )

    def _read_unlocked(
        self,
    ) -> tuple[bytes, tuple[TraceRecord, ...], tuple[int, int, int] | None]:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(self.path, flags)
        except FileNotFoundError:
            return b"", (), None
        except OSError as error:
            raise ObservabilityError(
                "trace_journal_open_failed",
                f"无法安全读取 trace journal：{error}",
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ObservabilityError(
                    "trace_journal_not_regular",
                    "trace journal 必须是普通文件",
                )
            if metadata.st_nlink != 1:
                raise ObservabilityError(
                    "trace_journal_hardlink_rejected",
                    "trace journal 不得存在硬链接别名",
                )
            if metadata.st_size > _MAX_JOURNAL_BYTES:
                raise ObservabilityError(
                    "trace_journal_too_large",
                    f"trace journal 超过 {_MAX_JOURNAL_BYTES} 字节",
                )
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(descriptor, min(_READ_CHUNK_SIZE, remaining))
                if not chunk:
                    raise ObservabilityError(
                        "trace_journal_truncated",
                        "trace journal 读取时意外截断",
                    )
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
            identity = (metadata.st_dev, metadata.st_ino, metadata.st_size)
            try:
                current = self.path.lstat()
            except OSError as error:
                raise ObservabilityError(
                    "trace_journal_changed",
                    "trace journal 在读取期间消失或无法复核",
                ) from error
            opened_identity = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
            after_identity = (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            current_identity = (
                current.st_dev,
                current.st_ino,
                current.st_mode,
                current.st_nlink,
                current.st_size,
                current.st_mtime_ns,
                current.st_ctime_ns,
            )
            if (
                after_identity != opened_identity
                or current_identity != opened_identity
            ):
                raise ObservabilityError(
                    "trace_journal_changed",
                    "trace journal 路径或内容在读取期间发生变化",
                )
        finally:
            os.close(descriptor)
        return payload, _parse_records(payload), identity

    def _open_journal_for_append(self) -> int:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError as error:
            raise ObservabilityError(
                "trace_journal_open_failed",
                f"无法安全追加 trace journal：{error}",
            ) from error
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise ObservabilityError(
                "trace_journal_not_regular",
                "trace journal 必须是普通文件",
            )
        if metadata.st_nlink != 1:
            os.close(descriptor)
            raise ObservabilityError(
                "trace_journal_hardlink_rejected",
                "trace journal 不得存在硬链接别名",
            )
        return descriptor


def _parse_records(payload: bytes) -> tuple[TraceRecord, ...]:
    if not payload:
        return ()
    if not payload.endswith(b"\n"):
        raise ObservabilityError(
            "trace_partial_line",
            "trace journal 末行未完整提交",
        )
    records: list[TraceRecord] = []
    previous: str | None = None
    for line_number, raw_line in enumerate(payload.splitlines(), start=1):
        if not raw_line:
            raise ObservabilityError(
                "trace_blank_line",
                f"trace journal 第 {line_number} 行为空",
            )
        if len(raw_line) > _MAX_LINE_BYTES:
            raise ObservabilityError(
                "trace_line_too_large",
                f"trace journal 第 {line_number} 行过大",
            )
        try:
            value = json.loads(
                raw_line,
                object_pairs_hook=_reject_duplicate_keys,
            )
        except UnicodeDecodeError as error:
            raise ObservabilityError(
                "trace_utf8_invalid",
                f"trace journal 第 {line_number} 行不是 UTF-8",
            ) from error
        except json.JSONDecodeError as error:
            raise ObservabilityError(
                "trace_json_invalid",
                f"trace journal 第 {line_number} 行不是合法 JSON：{error}",
            ) from error
        record = TraceRecord.from_dict(value, path=f"records[{line_number - 1}]")
        if record.sequence != line_number:
            raise ObservabilityError(
                "trace_sequence_invalid",
                f"trace journal 第 {line_number} 行 sequence 不连续",
            )
        if record.previous_event_sha256 != previous:
            raise ObservabilityError(
                "trace_chain_broken",
                f"trace journal 第 {line_number} 行前向哈希断裂",
            )
        records.append(record)
        previous = record.event_sha256
    return tuple(records)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ObservabilityError(
                "trace_duplicate_json_key",
                f"trace JSON 对象包含重复键：{key}",
            )
        result[key] = value
    return result


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("trace journal 写入未取得进展")
        offset += written


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
