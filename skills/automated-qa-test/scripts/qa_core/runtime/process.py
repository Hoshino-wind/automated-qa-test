"""受运行预算约束的独立进程组执行器。"""

from __future__ import annotations

import math
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .budget import BudgetExceeded, BudgetReason, RunBudget, StageBudget

_TIMEOUT_REASONS = {
    BudgetReason.DEADLINE_EXCEEDED,
    BudgetReason.STAGE_TIMEOUT,
}
_TIMEOUT_EXIT_CODE = 124
_EXECUTION_BOUNDARY_EXIT_CODE = 125
_SPAWN_ERROR_EXIT_CODE = 127
_CANCELLED_EXIT_CODE = 130


class _TailBuffer:
    """只保留固定字节数尾部的缓冲区。"""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.total_bytes = 0

    def append(self, chunk: bytes) -> None:
        self.total_bytes += len(chunk)
        if self.limit == 0:
            return
        self.data.extend(chunk)
        overflow = len(self.data) - self.limit
        if overflow > 0:
            del self.data[:overflow]

    def text(self) -> str:
        return bytes(self.data).decode("utf-8", errors="replace")


class ProcessExecutor:
    """执行单个阶段命令，并把整个进程组限制在运行预算内。"""

    def __init__(
        self,
        budget: RunBudget,
        stage: str,
        *,
        tail_bytes: int = 4000,
        poll_interval: float = 0.05,
        termination_grace: float = 1.0,
        read_size: int = 16 * 1024,
    ) -> None:
        if not isinstance(budget, RunBudget):
            raise TypeError("budget must be a RunBudget")
        if not isinstance(stage, str) or not stage.strip():
            raise ValueError("stage must be a non-empty string")
        self.budget = budget
        self.stage = stage
        self.tail_bytes = _non_negative_int("tail_bytes", tail_bytes)
        self.poll_interval = _positive_float("poll_interval", poll_interval)
        self.termination_grace = _non_negative_float(
            "termination_grace",
            termination_grace,
        )
        self.read_size = _positive_int("read_size", read_size)

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: str | os.PathLike[str] | None = None,
        env: Mapping[str, str] | None = None,
        probe_count: int = 0,
    ) -> dict[str, Any]:
        """执行数组命令，仅为显式声明的探针计入预算。"""

        normalized_command = _command(command)
        normalized_cwd = str(Path(cwd).expanduser()) if cwd is not None else None
        normalized_probe_count = _non_negative_int("probe_count", probe_count)
        started_monotonic = time.monotonic()
        started_at = _iso_timestamp()
        try:
            stage_budget = self.budget.stage(self.stage)
            stage_budget.check()
            if normalized_probe_count > 0:
                stage_budget.consume_probe(normalized_probe_count)
        except BudgetExceeded as exc:
            return self._empty_result(
                normalized_command,
                normalized_cwd,
                started_monotonic,
                started_at,
                termination_reason=exc.reason.value,
                budget_error=exc,
            )

        popen_kwargs: dict[str, Any] = {}
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        elif os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            process = subprocess.Popen(
                normalized_command,
                cwd=normalized_cwd,
                env=dict(env) if env is not None else None,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                shell=False,
                **popen_kwargs,
            )
        except OSError as exc:
            return self._empty_result(
                normalized_command,
                normalized_cwd,
                started_monotonic,
                started_at,
                termination_reason="spawn_error",
                spawn_error={
                    "type": type(exc).__name__,
                    "message": str(exc),
                },
            )

        return self._collect(
            process,
            stage_budget,
            normalized_command,
            normalized_cwd,
            started_monotonic,
            started_at,
        )

    def _collect(
        self,
        process: subprocess.Popen[bytes],
        stage_budget: StageBudget,
        command: list[str],
        cwd: str | None,
        started_monotonic: float,
        started_at: str,
    ) -> dict[str, Any]:
        selector = selectors.DefaultSelector()
        stdout_tail = _TailBuffer(self.tail_bytes)
        stderr_tail = _TailBuffer(self.tail_bytes)
        tails = {"stdout": stdout_tail, "stderr": stderr_tail}
        budget_error: BudgetExceeded | None = None
        termination_reason: str | None = None
        executor_error: dict[str, str] | None = None
        term_sent_at: float | None = None
        kill_sent_at: float | None = None
        process_group_cleanup = False
        drain_cutoff: float | None = None

        assert process.stdout is not None
        assert process.stderr is not None
        streams = (("stdout", process.stdout), ("stderr", process.stderr))
        try:
            for name, stream in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)

            while True:
                if budget_error is None and termination_reason is None:
                    try:
                        stage_budget.check()
                    except BudgetExceeded as exc:
                        budget_error = exc
                        termination_reason = exc.reason.value
                        term_sent_at = self._send_term(process)

                wait = self.poll_interval
                if budget_error is None and termination_reason is None:
                    remaining = stage_budget.remaining_time()
                    if remaining is not None:
                        wait = min(wait, max(0.0, remaining))

                for key, _ in selector.select(wait):
                    stream = key.fileobj
                    try:
                        chunk = os.read(stream.fileno(), self.read_size)
                    except BlockingIOError:
                        continue
                    except OSError:
                        chunk = b""
                    if not chunk:
                        self._close_stream(selector, stream)
                        continue

                    tail = tails[str(key.data)]
                    tail.append(chunk)
                    if budget_error is None and termination_reason is None:
                        try:
                            stage_budget.consume_output(len(chunk))
                        except BudgetExceeded as exc:
                            budget_error = exc
                            termination_reason = exc.reason.value
                            term_sent_at = self._send_term(process)

                return_code = process.poll()
                now = time.monotonic()
                if (
                    return_code is not None
                    and termination_reason is None
                    and self._group_alive(process)
                ):
                    process_group_cleanup = True
                    termination_reason = "process_group_cleanup"
                    term_sent_at = self._send_term(process)

                if term_sent_at is not None and kill_sent_at is None:
                    if not self._group_alive(process):
                        kill_sent_at = 0.0
                    elif now - term_sent_at >= self.termination_grace:
                        kill_sent_at = self._send_kill(process)
                        drain_cutoff = now + max(
                            self.poll_interval * 2,
                            self.termination_grace,
                            0.1,
                        )

                group_alive = self._group_alive(process)
                streams_open = bool(selector.get_map())
                if return_code is not None and not streams_open and not group_alive:
                    break
                if (
                    kill_sent_at not in (None, 0.0)
                    and drain_cutoff is not None
                    and now >= drain_cutoff
                ):
                    break
        except Exception as exc:
            executor_error = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
            if termination_reason is None:
                termination_reason = "executor_error"
            if term_sent_at is None:
                term_sent_at = self._send_term(process)
            if self._group_alive(process):
                kill_sent_at = self._send_kill(process)
        finally:
            process.poll()
            if self._group_alive(process):
                if term_sent_at is None:
                    term_sent_at = self._send_term(process)
                if self._group_alive(process):
                    kill_sent_at = self._send_kill(process)
            try:
                process.wait(timeout=max(self.termination_grace, 0.1))
            except subprocess.TimeoutExpired:
                kill_sent_at = self._send_kill(process)
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
            for _, stream in streams:
                self._close_stream(selector, stream)
            selector.close()

        reason = budget_error.reason if budget_error else None
        raw_exit_code = process.returncode
        return {
            "schema_version": 1,
            "command": command,
            "cwd": cwd,
            "stage": self.stage,
            "started": True,
            "exit_code": _effective_exit_code(
                raw_exit_code,
                termination_reason,
                budget_error,
            ),
            "raw_exit_code": raw_exit_code,
            "timed_out": reason in _TIMEOUT_REASONS,
            "termination_reason": termination_reason,
            "budget_error": budget_error.to_dict() if budget_error else None,
            "stdout": stdout_tail.text(),
            "stderr": stderr_tail.text(),
            "stdout_bytes": stdout_tail.total_bytes,
            "stderr_bytes": stderr_tail.total_bytes,
            "output_bytes": stdout_tail.total_bytes + stderr_tail.total_bytes,
            "stdout_truncated": stdout_tail.total_bytes > len(stdout_tail.data),
            "stderr_truncated": stderr_tail.total_bytes > len(stderr_tail.data),
            "term_sent": term_sent_at is not None,
            "kill_sent": kill_sent_at not in (None, 0.0),
            "process_group_cleanup": process_group_cleanup,
            "spawn_error": None,
            "executor_error": executor_error,
            **_timing_fields(started_at, started_monotonic),
        }

    def _empty_result(
        self,
        command: list[str],
        cwd: str | None,
        started_monotonic: float,
        started_at: str,
        *,
        termination_reason: str,
        budget_error: BudgetExceeded | None = None,
        spawn_error: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        reason = budget_error.reason if budget_error else None
        return {
            "schema_version": 1,
            "command": command,
            "cwd": cwd,
            "stage": self.stage,
            "started": False,
            "exit_code": _effective_exit_code(
                None,
                termination_reason,
                budget_error,
            ),
            "raw_exit_code": None,
            "timed_out": reason in _TIMEOUT_REASONS,
            "termination_reason": termination_reason,
            "budget_error": budget_error.to_dict() if budget_error else None,
            "stdout": "",
            "stderr": "",
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "output_bytes": 0,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "term_sent": False,
            "kill_sent": False,
            "process_group_cleanup": False,
            "spawn_error": spawn_error,
            "executor_error": None,
            **_timing_fields(started_at, started_monotonic),
        }

    @staticmethod
    def _close_stream(
        selector: selectors.BaseSelector,
        stream: Any,
    ) -> None:
        try:
            selector.unregister(stream)
        except (KeyError, ValueError):
            pass
        try:
            stream.close()
        except OSError:
            pass

    @staticmethod
    def _group_alive(process: subprocess.Popen[bytes]) -> bool:
        if os.name != "posix":
            return process.poll() is None
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    @staticmethod
    def _send_term(process: subprocess.Popen[bytes]) -> float:
        sent_at = time.monotonic()
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            pass
        except OSError:
            try:
                process.terminate()
            except OSError:
                pass
        return sent_at

    @staticmethod
    def _send_kill(process: subprocess.Popen[bytes]) -> float:
        sent_at = time.monotonic()
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        except OSError:
            try:
                process.kill()
            except OSError:
                pass
        return sent_at


def _effective_exit_code(
    raw_exit_code: int | None,
    termination_reason: str | None,
    budget_error: BudgetExceeded | None,
) -> int:
    reason = (
        budget_error.reason.value
        if budget_error is not None
        else termination_reason
    )
    if reason in {
        BudgetReason.DEADLINE_EXCEEDED.value,
        BudgetReason.STAGE_TIMEOUT.value,
    }:
        return _TIMEOUT_EXIT_CODE
    if reason == BudgetReason.CANCELLED.value:
        return _CANCELLED_EXIT_CODE
    if reason == "spawn_error":
        return _SPAWN_ERROR_EXIT_CODE
    if budget_error is not None or termination_reason is not None:
        return _EXECUTION_BOUNDARY_EXIT_CODE
    if raw_exit_code is None:
        return _EXECUTION_BOUNDARY_EXIT_CODE
    return raw_exit_code


def _iso_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _timing_fields(
    started_at: str,
    started_monotonic: float,
) -> dict[str, str | float]:
    return {
        "started_at": started_at,
        "finished_at": _iso_timestamp(),
        "duration_seconds": round(
            time.monotonic() - started_monotonic,
            6,
        ),
    }


def _command(value: Sequence[str]) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TypeError("command must be a sequence of strings")
    command = list(value)
    if not command:
        raise ValueError("command must not be empty")
    if any(not isinstance(part, str) or not part for part in command):
        raise ValueError("command parts must be non-empty strings")
    return command


def _non_negative_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be >= 0")
    return value


def _positive_int(name: str, value: int) -> int:
    value = _non_negative_int(name, value)
    if value == 0:
        raise ValueError(f"{name} must be > 0")
    return value


def _non_negative_float(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number")
    normalized = float(value)
    if not math.isfinite(normalized):
        raise ValueError(f"{name} must be finite")
    if normalized < 0:
        raise ValueError(f"{name} must be >= 0")
    return normalized


def _positive_float(name: str, value: float) -> float:
    value = _non_negative_float(name, value)
    if value == 0:
        raise ValueError(f"{name} must be > 0")
    return value
