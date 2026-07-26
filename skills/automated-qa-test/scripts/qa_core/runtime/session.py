"""把 run_id、单写租约与父子编排身份组合为一个会话边界。"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Self

from qa_core.state import RunStateStore

from .lease import LeaseAlreadyHeldError, LeaseRecord, RunLease

LEASE_FILENAME = ".qa-run-lease.json"
AGENT_OWNER_PREFIX = "qa-agent-loop"
CYCLE_OWNER_PREFIX = "qa-cycle"


@dataclass(slots=True)
class RunSession:
    """持有或校验一个 run 的单写者身份。"""

    run_dir: Path
    lease: RunLease
    record: LeaseRecord
    inherited: bool
    _closed: bool = False

    @classmethod
    def open(
        cls,
        run_dir: Path,
        *,
        owner_prefix: str,
        allow_parent_inheritance: bool = False,
        pid: int | None = None,
        parent_pid: int | None = None,
    ) -> Self:
        resolved_dir = run_dir.expanduser().resolve()
        resolved_dir.mkdir(parents=True, exist_ok=True)
        process_id = os.getpid() if pid is None else pid
        process_parent_id = os.getppid() if parent_pid is None else parent_pid
        normalized_prefix = _owner_prefix(owner_prefix)
        lease = RunLease(resolved_dir / LEASE_FILENAME)
        persisted_run_id = existing_run_id(resolved_dir)
        current = lease.read()
        if current is not None:
            state_matches = (
                persisted_run_id is None
                or persisted_run_id == current.run_id
            )
            if (
                allow_parent_inheritance
                and normalized_prefix == CYCLE_OWNER_PREFIX
                and current.owner.startswith(f"{AGENT_OWNER_PREFIX}:")
                and current.pid == process_parent_id
                and state_matches
            ):
                record = lease.heartbeat(
                    current.run_id,
                    current.owner,
                    current.generation,
                )
                return cls(
                    run_dir=resolved_dir,
                    lease=lease,
                    record=record,
                    inherited=True,
                )
            raise LeaseAlreadyHeldError(current)
        run_id = persisted_run_id or f"run_{uuid.uuid4().hex}"
        owner = f"{normalized_prefix}:{process_id}:{uuid.uuid4().hex}"
        record = lease.acquire(run_id, owner, pid=process_id)
        return cls(
            run_dir=resolved_dir,
            lease=lease,
            record=record,
            inherited=False,
        )

    @property
    def run_id(self) -> str:
        return self.record.run_id

    @property
    def owner(self) -> str:
        return self.record.owner

    @property
    def generation(self) -> int:
        return self.record.generation

    def heartbeat(self) -> LeaseRecord:
        """推进当前身份的心跳；关闭后拒绝继续写入。"""

        if self._closed:
            raise RuntimeError("run session is closed")
        self.record = self.lease.heartbeat(
            self.run_id,
            self.owner,
            self.generation,
        )
        return self.record

    def close(self) -> None:
        """释放自有租约；继承会话只停止使用，不删除父进程租约。"""

        if self._closed:
            return
        if not self.inherited:
            self.lease.release(
                self.run_id,
                self.owner,
                self.generation,
            )
        self._closed = True

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "owner": self.owner,
            "generation": self.generation,
            "pid": self.record.pid,
            "inherited": self.inherited,
            "lease_path": str(self.lease.path),
        }

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        self.close()
        return False


def resolve_run_id(run_dir: Path) -> str:
    """优先恢复事件日志中的 run_id，否则创建新的不透明标识。"""

    return existing_run_id(run_dir) or f"run_{uuid.uuid4().hex}"


def existing_run_id(run_dir: Path) -> str | None:
    """读取既有事件日志身份；没有日志时返回 None。"""

    events = RunStateStore(run_dir).load_events()
    if events:
        return events[0].run_id
    return None


def _owner_prefix(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("owner_prefix must be non-empty text")
    normalized = value.strip()
    if ":" in normalized:
        raise ValueError("owner_prefix must not contain ':'")
    return normalized
