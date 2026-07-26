"""确定且无外部依赖的 QA 运行预算。"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from enum import StrEnum
from threading import RLock
from types import TracebackType
from typing import Any, Self

Clock = Callable[[], float]
Number = int | float


class BudgetReason(StrEnum):
    """稳定的预算失败原因码。"""

    DEADLINE_EXCEEDED = "deadline_exceeded"
    STAGE_TIMEOUT = "stage_timeout"
    PROBE_LIMIT = "probe_limit"
    OUTPUT_BYTE_LIMIT = "output_byte_limit"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class BudgetSnapshot:
    """可 JSON 化的运行预算快照。"""

    started_at: float
    deadline: float | None
    remaining_time: float | None
    probes_used: int
    max_probes: int | None
    output_bytes_used: int
    max_output_bytes: int | None
    cancelled: bool
    cancel_detail: str | None
    cancelled_at: float | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BudgetExceeded(RuntimeError):
    """运行因预算限制无法继续时抛出的结构化异常。"""

    def __init__(
        self,
        reason: BudgetReason,
        *,
        snapshot: BudgetSnapshot,
        stage: str | None = None,
        limit: Number | None = None,
        observed: Number | None = None,
        detail: str | None = None,
    ) -> None:
        self.reason = reason
        self.snapshot = snapshot
        self.stage = stage
        self.limit = limit
        self.observed = observed
        self.detail = detail
        super().__init__(self._message())

    def _message(self) -> str:
        subject = f"stage {self.stage!r}" if self.stage else "run"
        message = f"{subject} budget exceeded: {self.reason.value}"
        if self.limit is not None:
            message += f" (limit={self.limit!r}, observed={self.observed!r})"
        if self.detail:
            message += f": {self.detail}"
        return message

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "error": "budget_exceeded",
            "reason": self.reason.value,
            "stage": self.stage,
            "limit": self.limit,
            "observed": self.observed,
            "detail": self.detail,
            "budget": self.snapshot.to_dict(),
        }


class RunBudget:
    """集中管理一次运行的时间、探针、输出和取消边界。

    ``deadline`` 是注入时钟域中的绝对值；``total_timeout`` 则从构造时刻
    计算 deadline。两者只能提供一个。
    """

    def __init__(
        self,
        *,
        deadline: float | None = None,
        total_timeout: float | None = None,
        default_stage_timeout: float | None = None,
        stage_timeouts: Mapping[str, float] | None = None,
        max_probes: int | None = None,
        max_output_bytes: int | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        if deadline is not None and total_timeout is not None:
            raise ValueError("deadline and total_timeout are mutually exclusive")
        if not callable(clock):
            raise TypeError("clock must be callable")

        self._clock = clock
        self._lock = RLock()
        self._started_at = self._now()
        if total_timeout is not None:
            total_timeout = _non_negative_float("total_timeout", total_timeout)
            deadline = self._started_at + total_timeout
        elif deadline is not None:
            deadline = _finite_float("deadline", deadline)

        self._deadline = deadline
        self._default_stage_timeout = (
            _non_negative_float(
                "default_stage_timeout",
                default_stage_timeout,
            )
            if default_stage_timeout is not None
            else None
        )
        self._stage_timeouts = _stage_timeout_map(stage_timeouts)
        self._max_probes = _non_negative_int("max_probes", max_probes)
        self._max_output_bytes = _non_negative_int(
            "max_output_bytes",
            max_output_bytes,
        )
        self._probes_used = 0
        self._output_bytes_used = 0
        self._cancelled = False
        self._cancel_detail: str | None = None
        self._cancelled_at: float | None = None

    @property
    def started_at(self) -> float:
        return self._started_at

    @property
    def deadline(self) -> float | None:
        return self._deadline

    @property
    def probes_used(self) -> int:
        with self._lock:
            return self._probes_used

    @property
    def output_bytes_used(self) -> int:
        with self._lock:
            return self._output_bytes_used

    @property
    def cancelled(self) -> bool:
        with self._lock:
            return self._cancelled

    def remaining_time(self) -> float | None:
        """返回剩余秒数；过期或取消后为零，无限制时为 ``None``。"""

        with self._lock:
            return self._remaining_at(self._now())

    def stage(self, name: str) -> StageBudget:
        """按配置的 timeout 开始一个阶段预算。"""

        if not isinstance(name, str) or not name.strip():
            raise ValueError("stage name must be a non-empty string")
        with self._lock:
            now = self._now()
            self._check_locked(now)
            return StageBudget(
                parent=self,
                name=name,
                started_at=now,
                timeout=self._stage_timeouts.get(
                    name,
                    self._default_stage_timeout,
                ),
            )

    def check(self) -> None:
        """取消或 deadline 到达时抛出 ``BudgetExceeded``。"""

        with self._lock:
            self._check_locked(self._now())

    def consume_probe(self, count: int = 1) -> int:
        """原子预留探针额度并返回累计用量。"""

        return self._consume_probe(count, stage=None)

    def consume_output(self, byte_count: int) -> int:
        """原子预留输出字节额度并返回累计用量。"""

        return self._consume_output(byte_count, stage=None)

    def cancel(self, detail: str | None = None) -> bool:
        """幂等取消运行，并保留第一次取消原因。"""

        if detail is not None and not isinstance(detail, str):
            raise TypeError("cancel detail must be a string or None")
        with self._lock:
            if self._cancelled:
                return False
            self._cancelled = True
            self._cancel_detail = detail
            self._cancelled_at = self._now()
            return True

    def snapshot(self) -> BudgetSnapshot:
        with self._lock:
            return self._snapshot_locked(self._now())

    def _now(self) -> float:
        try:
            value = float(self._clock())
        except (TypeError, ValueError) as exc:
            raise RuntimeError("clock must return a numeric value") from exc
        if not math.isfinite(value):
            raise RuntimeError("clock must return a finite value")
        return value

    def _remaining_at(self, now: float) -> float | None:
        if self._cancelled:
            return 0.0
        if self._deadline is None:
            return None
        return max(0.0, self._deadline - now)

    def _snapshot_locked(self, now: float) -> BudgetSnapshot:
        return BudgetSnapshot(
            started_at=self._started_at,
            deadline=self._deadline,
            remaining_time=self._remaining_at(now),
            probes_used=self._probes_used,
            max_probes=self._max_probes,
            output_bytes_used=self._output_bytes_used,
            max_output_bytes=self._max_output_bytes,
            cancelled=self._cancelled,
            cancel_detail=self._cancel_detail,
            cancelled_at=self._cancelled_at,
        )

    def _check_locked(
        self,
        now: float,
        stage: StageBudget | None = None,
    ) -> None:
        stage_name = stage.name if stage else None
        if self._cancelled:
            raise BudgetExceeded(
                BudgetReason.CANCELLED,
                snapshot=self._snapshot_locked(now),
                stage=stage_name,
                observed=self._cancelled_at,
                detail=self._cancel_detail,
            )
        if self._deadline is not None and now >= self._deadline:
            raise BudgetExceeded(
                BudgetReason.DEADLINE_EXCEEDED,
                snapshot=self._snapshot_locked(now),
                stage=stage_name,
                limit=self._deadline,
                observed=now,
            )
        if stage and stage.timeout is not None:
            stage_deadline = stage.started_at + stage.timeout
            if now >= stage_deadline:
                raise BudgetExceeded(
                    BudgetReason.STAGE_TIMEOUT,
                    snapshot=self._snapshot_locked(now),
                    stage=stage.name,
                    limit=stage.timeout,
                    observed=now - stage.started_at,
                )

    def _consume_probe(
        self,
        count: int,
        *,
        stage: StageBudget | None,
    ) -> int:
        count = _required_non_negative_int("probe count", count)
        with self._lock:
            now = self._now()
            self._check_locked(now, stage)
            attempted = self._probes_used + count
            if self._max_probes is not None and attempted > self._max_probes:
                raise BudgetExceeded(
                    BudgetReason.PROBE_LIMIT,
                    snapshot=self._snapshot_locked(now),
                    stage=stage.name if stage else None,
                    limit=self._max_probes,
                    observed=attempted,
                )
            self._probes_used = attempted
            return attempted

    def _consume_output(
        self,
        byte_count: int,
        *,
        stage: StageBudget | None,
    ) -> int:
        byte_count = _required_non_negative_int("output byte count", byte_count)
        with self._lock:
            now = self._now()
            self._check_locked(now, stage)
            attempted = self._output_bytes_used + byte_count
            if (
                self._max_output_bytes is not None
                and attempted > self._max_output_bytes
            ):
                raise BudgetExceeded(
                    BudgetReason.OUTPUT_BYTE_LIMIT,
                    snapshot=self._snapshot_locked(now),
                    stage=stage.name if stage else None,
                    limit=self._max_output_bytes,
                    observed=attempted,
                )
            self._output_bytes_used = attempted
            return attempted


@dataclass(frozen=True, slots=True)
class StageBudget:
    """与所属运行共享计数和取消状态的阶段预算视图。"""

    parent: RunBudget
    name: str
    started_at: float
    timeout: float | None

    @property
    def deadline(self) -> float | None:
        stage_deadline = (
            self.started_at + self.timeout
            if self.timeout is not None
            else None
        )
        run_deadline = self.parent.deadline
        if stage_deadline is None:
            return run_deadline
        if run_deadline is None:
            return stage_deadline
        return min(stage_deadline, run_deadline)

    def remaining_time(self) -> float | None:
        with self.parent._lock:
            now = self.parent._now()
            if self.parent._cancelled:
                return 0.0
            deadline = self.deadline
            if deadline is None:
                return None
            return max(0.0, deadline - now)

    def check(self) -> None:
        with self.parent._lock:
            self.parent._check_locked(self.parent._now(), self)

    def consume_probe(self, count: int = 1) -> int:
        return self.parent._consume_probe(count, stage=self)

    def consume_output(self, byte_count: int) -> int:
        return self.parent._consume_output(byte_count, stage=self)

    def __enter__(self) -> Self:
        self.check()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if exc_type is None:
            self.check()
        return False


def _finite_float(name: str, value: Number) -> float:
    if isinstance(value, bool):
        raise TypeError(f"{name} must be a number")
    try:
        normalized = float(value)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"{name} must be a number") from exc
    if not math.isfinite(normalized):
        raise ValueError(f"{name} must be finite")
    return normalized


def _non_negative_float(name: str, value: Number) -> float:
    normalized = _finite_float(name, value)
    if normalized < 0:
        raise ValueError(f"{name} must be >= 0")
    return normalized


def _required_non_negative_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be >= 0")
    return value


def _non_negative_int(name: str, value: int | None) -> int | None:
    if value is None:
        return None
    return _required_non_negative_int(name, value)


def _stage_timeout_map(
    values: Mapping[str, float] | None,
) -> dict[str, float]:
    if values is None:
        return {}
    if not isinstance(values, Mapping):
        raise TypeError("stage_timeouts must be a mapping")
    normalized: dict[str, float] = {}
    for name, timeout in values.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("stage timeout names must be non-empty strings")
        normalized[name] = _non_negative_float(
            f"stage timeout for {name!r}",
            timeout,
        )
    return normalized
