"""跨进程运行租约及其所有权围栏。"""

from __future__ import annotations

import fcntl
import json
import math
import os
import stat
import tempfile
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Callable, Iterator

__all__ = [
    "LeaseAlreadyHeldError",
    "LeaseClockError",
    "LeaseNotFoundError",
    "LeaseNotStaleError",
    "LeaseOwnershipError",
    "LeaseRecord",
    "LeaseRecordError",
    "RunLease",
    "RunLeaseError",
]

_LEASE_FIELDS = frozenset(
    {
        "run_id",
        "owner",
        "generation",
        "pid",
        "acquired_at",
        "heartbeat_at",
    }
)
_MAX_LEASE_BYTES = 64 * 1024


class RunLeaseError(RuntimeError):
    """运行租约基础异常。"""


class LeaseAlreadyHeldError(RunLeaseError):
    """租约已被其他执行者持有。"""

    def __init__(self, current: LeaseRecord) -> None:
        self.current = current
        super().__init__(
            f"运行 {current.run_id!r} 的租约已由 {current.owner!r} "
            f"持有（generation={current.generation}）"
        )


class LeaseNotFoundError(RunLeaseError):
    """租约文件不存在。"""


class LeaseOwnershipError(RunLeaseError):
    """调用者提交的租约身份与当前记录不一致。"""

    def __init__(
        self,
        current: LeaseRecord,
        *,
        run_id: str,
        owner: str,
        generation: int,
    ) -> None:
        self.current = current
        self.requested_run_id = run_id
        self.requested_owner = owner
        self.requested_generation = generation
        super().__init__(
            "租约身份不匹配："
            f"当前为 run_id={current.run_id!r}, owner={current.owner!r}, "
            f"generation={current.generation}；"
            f"请求为 run_id={run_id!r}, owner={owner!r}, generation={generation}"
        )


class LeaseNotStaleError(RunLeaseError):
    """租约尚未达到调用者声明的陈旧阈值。"""

    def __init__(self, current: LeaseRecord, *, age_seconds: float, stale_after_seconds: float) -> None:
        self.current = current
        self.age_seconds = age_seconds
        self.stale_after_seconds = stale_after_seconds
        super().__init__(
            f"租约尚未陈旧：age={age_seconds:.6f}s, "
            f"stale_after={stale_after_seconds:.6f}s"
        )


class LeaseRecordError(RunLeaseError):
    """磁盘租约记录损坏或不符合契约。"""


class LeaseClockError(RunLeaseError):
    """时钟回退会破坏心跳与陈旧判断。"""


@dataclass(frozen=True, slots=True)
class LeaseRecord:
    """持久化租约记录。"""

    run_id: str
    owner: str
    generation: int
    pid: int
    acquired_at: float
    heartbeat_at: float

    def to_dict(self) -> dict[str, str | int | float]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: object) -> LeaseRecord:
        if not isinstance(value, dict):
            raise LeaseRecordError("租约 JSON 必须是对象")
        if set(value) != _LEASE_FIELDS:
            missing = sorted(_LEASE_FIELDS - set(value))
            extra = sorted(set(value) - _LEASE_FIELDS)
            raise LeaseRecordError(f"租约字段不匹配：missing={missing}, extra={extra}")

        run_id = _required_text(value["run_id"], field="run_id", error_type=LeaseRecordError)
        owner = _required_text(value["owner"], field="owner", error_type=LeaseRecordError)
        generation = _positive_int(value["generation"], field="generation", error_type=LeaseRecordError)
        pid = _positive_int(value["pid"], field="pid", error_type=LeaseRecordError)
        acquired_at = _timestamp(value["acquired_at"], field="acquired_at", error_type=LeaseRecordError)
        heartbeat_at = _timestamp(value["heartbeat_at"], field="heartbeat_at", error_type=LeaseRecordError)
        if heartbeat_at < acquired_at:
            raise LeaseRecordError("heartbeat_at 不得早于 acquired_at")
        return cls(
            run_id=run_id,
            owner=owner,
            generation=generation,
            pid=pid,
            acquired_at=acquired_at,
            heartbeat_at=heartbeat_at,
        )


class RunLease:
    """通过文件系统提供单写租约、心跳和代际围栏。"""

    def __init__(self, path: str | os.PathLike[str], *, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        self._guard_path = self.path.with_name(f".{self.path.name}.guard")

    def read(self) -> LeaseRecord | None:
        """读取当前租约；不存在时返回 None。"""
        with self._exclusive_guard():
            return self._read_unlocked(required=False)

    def acquire(
        self,
        run_id: str,
        owner: str,
        *,
        pid: int | None = None,
    ) -> LeaseRecord:
        """仅在目标不存在时创建 generation=1 的租约。"""
        normalized_run_id = _required_text(run_id, field="run_id")
        normalized_owner = _required_text(owner, field="owner")
        normalized_pid = _positive_int(os.getpid() if pid is None else pid, field="pid")

        with self._exclusive_guard():
            now = self._now()
            record = LeaseRecord(
                run_id=normalized_run_id,
                owner=normalized_owner,
                generation=1,
                pid=normalized_pid,
                acquired_at=now,
                heartbeat_at=now,
            )
            try:
                self._create_exclusive(record)
            except FileExistsError:
                current = self._read_unlocked(required=True)
                raise LeaseAlreadyHeldError(current) from None
            return record

    def heartbeat(
        self,
        run_id: str,
        owner: str,
        generation: int,
    ) -> LeaseRecord:
        """仅由当前 run_id/owner/generation 身份推进心跳。"""
        identity = _validated_identity(run_id, owner, generation)
        with self._exclusive_guard():
            current = self._read_unlocked(required=True)
            self._require_identity(current, *identity)
            now = self._now()
            if now < current.heartbeat_at:
                raise LeaseClockError(
                    f"时钟从 {current.heartbeat_at:.6f} 回退到 {now:.6f}，拒绝覆盖心跳"
                )
            updated = replace(current, heartbeat_at=now)
            self._atomic_replace(updated)
            return updated

    def takeover(
        self,
        run_id: str,
        owner: str,
        *,
        expected_owner: str,
        expected_generation: int,
        stale_after_seconds: float,
        pid: int | None = None,
    ) -> LeaseRecord:
        """在身份仍匹配且租约明确陈旧时提升 generation 并接管。"""
        normalized_run_id = _required_text(run_id, field="run_id")
        normalized_owner = _required_text(owner, field="owner")
        normalized_expected_owner = _required_text(expected_owner, field="expected_owner")
        normalized_generation = _positive_int(expected_generation, field="expected_generation")
        normalized_pid = _positive_int(os.getpid() if pid is None else pid, field="pid")
        threshold = _positive_number(stale_after_seconds, field="stale_after_seconds")

        with self._exclusive_guard():
            current = self._read_unlocked(required=True)
            self._require_identity(
                current,
                normalized_run_id,
                normalized_expected_owner,
                normalized_generation,
            )
            now = self._now()
            age = now - current.heartbeat_at
            if age < threshold:
                raise LeaseNotStaleError(
                    current,
                    age_seconds=age,
                    stale_after_seconds=threshold,
                )
            updated = LeaseRecord(
                run_id=normalized_run_id,
                owner=normalized_owner,
                generation=current.generation + 1,
                pid=normalized_pid,
                acquired_at=now,
                heartbeat_at=now,
            )
            self._atomic_replace(updated)
            return updated

    def release(self, run_id: str, owner: str, generation: int) -> None:
        """仅由当前完整身份删除租约。"""
        identity = _validated_identity(run_id, owner, generation)
        with self._exclusive_guard():
            current = self._read_unlocked(required=True)
            self._require_identity(current, *identity)
            self.path.unlink()
            _fsync_directory(self.path.parent)

    @contextmanager
    def _exclusive_guard(self) -> Iterator[None]:
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self._guard_path, flags, 0o600)
        locked = False
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            locked = True
            yield
        finally:
            try:
                if locked:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        # 保护文件必须保留；删除已加锁 inode 会让并发者锁到不同文件。

    def _create_exclusive(self, record: LeaseRecord) -> None:
        payload = _serialize(record)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            owned_descriptor = descriptor
            descriptor = -1
            _write_descriptor(owned_descriptor, payload)
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            self.path.unlink(missing_ok=True)
            raise
        _fsync_directory(self.path.parent)

    def _atomic_replace(self, record: LeaseRecord) -> None:
        descriptor, raw_temporary_path = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=self.path.parent,
        )
        temporary_path = Path(raw_temporary_path)
        try:
            os.fchmod(descriptor, 0o600)
            owned_descriptor = descriptor
            descriptor = -1
            _write_descriptor(owned_descriptor, _serialize(record))
            os.replace(temporary_path, self.path)
            _fsync_directory(self.path.parent)
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            temporary_path.unlink(missing_ok=True)
            raise

    def _read_unlocked(self, *, required: bool) -> LeaseRecord | None:
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except FileNotFoundError:
            if required:
                raise LeaseNotFoundError(f"租约不存在：{self.path}") from None
            return None

        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise LeaseRecordError(f"租约路径不是普通文件：{self.path}")
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                payload = handle.read(_MAX_LEASE_BYTES + 1)
            if len(payload) > _MAX_LEASE_BYTES:
                raise LeaseRecordError(f"租约记录超过 {_MAX_LEASE_BYTES} 字节")
            try:
                value = json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise LeaseRecordError(f"租约 JSON 无效：{error}") from error
            return LeaseRecord.from_dict(value)
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _require_identity(
        current: LeaseRecord,
        run_id: str,
        owner: str,
        generation: int,
    ) -> None:
        if (
            current.run_id != run_id
            or current.owner != owner
            or current.generation != generation
        ):
            raise LeaseOwnershipError(
                current,
                run_id=run_id,
                owner=owner,
                generation=generation,
            )

    def _now(self) -> float:
        return _timestamp(self._clock(), field="clock")


def _validated_identity(run_id: str, owner: str, generation: int) -> tuple[str, str, int]:
    return (
        _required_text(run_id, field="run_id"),
        _required_text(owner, field="owner"),
        _positive_int(generation, field="generation"),
    )


def _required_text(
    value: object,
    *,
    field: str,
    error_type: type[Exception] = ValueError,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise error_type(f"{field} 必须是非空字符串")
    return value.strip()


def _positive_int(
    value: object,
    *,
    field: str,
    error_type: type[Exception] = ValueError,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise error_type(f"{field} 必须是正整数")
    return value


def _timestamp(
    value: object,
    *,
    field: str,
    error_type: type[Exception] = LeaseClockError,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise error_type(f"{field} 必须是有限的非负数")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0:
        raise error_type(f"{field} 必须是有限的非负数")
    return normalized


def _positive_number(value: object, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} 必须是有限正数")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized <= 0:
        raise ValueError(f"{field} 必须是有限正数")
    return normalized


def _serialize(record: LeaseRecord) -> bytes:
    payload = json.dumps(
        record.to_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"{payload}\n".encode()


def _write_descriptor(descriptor: int, payload: bytes) -> None:
    try:
        handle = os.fdopen(descriptor, "wb")
    except BaseException:
        os.close(descriptor)
        raise
    with handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
