"""把 QA cycle 的真实运行结果闭合为可验链 TraceEvent。"""

from __future__ import annotations

import hashlib
import math
import os
import stat
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from qa_core.runtime.budget import BudgetSnapshot

from ._validation import (
    ObservabilityError,
    boolean,
    canonical_sha256,
    integer,
    nullable_text,
    number,
    sha256,
    text,
    timestamp,
)
from .contracts import TraceArtifactRef, TraceBudget, TraceEvent, TraceReason
from .journal import TraceJournal, TraceSnapshot

TRACE_JOURNAL_FILENAME = "agent-trace.jsonl"

_PROCESS_RESULT_FIELDS = {
    "schema_version",
    "command",
    "cwd",
    "stage",
    "started",
    "exit_code",
    "raw_exit_code",
    "timed_out",
    "termination_reason",
    "budget_error",
    "stdout",
    "stderr",
    "stdout_bytes",
    "stderr_bytes",
    "output_bytes",
    "stdout_truncated",
    "stderr_truncated",
    "term_sent",
    "kill_sent",
    "process_group_cleanup",
    "spawn_error",
    "executor_error",
    "started_at",
    "finished_at",
    "duration_seconds",
}
_BUDGET_FIELDS = {
    "started_at",
    "deadline",
    "remaining_time",
    "probes_used",
    "max_probes",
    "output_bytes_used",
    "max_output_bytes",
    "cancelled",
    "cancel_detail",
    "cancelled_at",
}
_STATUS_ALIASES = {
    "pass": "succeeded",
    "passed": "succeeded",
    "succeeded": "succeeded",
    "fail": "failed",
    "failed": "failed",
    "error": "failed",
    "cancelled": "cancelled",
    "blocked": "blocked",
    "skipped": "blocked",
    "inconclusive": "inconclusive",
}
_ACTION_STATUS = {
    "passed": ("succeeded", "action_completed"),
    "failed": ("failed", "action_failed"),
    "skipped": ("blocked", "action_skipped"),
}
_BUDGET_STOP_REASONS = {
    "deadline_exceeded",
    "stage_timeout",
    "probe_limit",
    "output_byte_limit",
}
_READ_CHUNK_SIZE = 1024 * 1024


class CycleTracer:
    """Cycle observability 的小接口；所有 journal 追加都先完整校验。

    pre-commit span 的 ``attempt_id`` 始终为空。只有调用方提交并传入真实
    attempt 后，artifact validation、handoff 与最终 run span 才会绑定它。
    """

    def __init__(
        self,
        journal: TraceJournal,
        *,
        run_id: str,
        generation: int,
        iteration: int,
        initial_budget: BudgetSnapshot | Mapping[str, object],
        started_at: str | datetime,
        state_start_sequence: int = 0,
        initial_snapshot: TraceSnapshot | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(journal, TraceJournal):
            raise TypeError("journal 必须是 TraceJournal")
        if clock is not None and not callable(clock):
            raise TypeError("clock 必须可调用")
        self.journal = journal
        self.run_id = text("runtime.run_id", run_id)
        self.generation = integer(
            "runtime.generation",
            generation,
            minimum=1,
        )
        self.iteration = integer(
            "runtime.iteration",
            iteration,
            minimum=1,
        )
        self._state_start_sequence = integer(
            "runtime.state_start_sequence",
            state_start_sequence,
        )
        self._clock = clock or (lambda: datetime.now(UTC))
        self._started_at, started = _runtime_timestamp(
            "runtime.started_at",
            started_at,
        )
        self._started_datetime = started
        self._initial_budget = _budget_snapshot(initial_budget)
        if self._initial_budget.deadline is None:
            raise ObservabilityError(
                "trace_run_budget_unbounded",
                "CycleTracer 要求 RunBudget 提供总 deadline",
            )
        total_seconds = (
            self._initial_budget.deadline
            - self._initial_budget.started_at
        )
        if total_seconds < 0 or not math.isfinite(total_seconds):
            raise ObservabilityError(
                "trace_run_budget_invalid",
                "RunBudget deadline 不得早于 started_at",
            )
        self._total_seconds = total_seconds
        self._deadline_at = _format_deadline(
            started + timedelta(seconds=total_seconds)
        )
        self._last_budget = self._initial_budget

        observed = journal.snapshot()
        if initial_snapshot is not None:
            if not isinstance(initial_snapshot, TraceSnapshot):
                raise TypeError("initial_snapshot 必须是 TraceSnapshot")
            if (
                initial_snapshot.sha256 != observed.sha256
                or initial_snapshot.byte_size != observed.byte_size
                or initial_snapshot.records != observed.records
            ):
                raise ObservabilityError(
                    "trace_initial_snapshot_stale",
                    "initial_snapshot 与当前 journal 不一致",
                )
        self._initial_snapshot = observed
        _validate_trace_history(observed)
        if any(
            record.event.run_id == self.run_id
            and (
                record.event.generation > self.generation
                or (
                    record.event.generation == self.generation
                    and record.event.iteration > self.iteration
                )
            )
            for record in observed.records
        ):
            raise ObservabilityError(
                "trace_runtime_stale",
                "journal 包含当前租约世代或迭代之后的事件",
            )
        if any(
            record.event.run_key
            == (self.run_id, self.generation, self.iteration)
            for record in observed.records
        ):
            raise ObservabilityError(
                "trace_run_key_reused",
                "run_id/generation/iteration 必须唯一",
            )
        self._recovered_keys = _incomplete_run_keys(
            observed,
            run_id=self.run_id,
            generation=self.generation,
            before_iteration=self.iteration,
        )
        self._recovered_actions = {
            (record.event.stage, record.event.action)
            for record in observed.records
            if record.event.run_key in self._recovered_keys
            and record.event.kind == "action"
            and record.event.status == "succeeded"
        }
        self._stage_count = 0
        self._action_count = 0
        self._current_succeeded_actions: set[tuple[str, str]] = set()
        self._plan_recorded = False
        self._actions_recorded = False
        self._recovery_recorded = False
        self._cleanup_recorded = False
        self._handoff_recorded = False
        self._artifact_recorded = False
        self._finalized = False
        self._max_ended_at = started

    @property
    def recovery_required(self) -> bool:
        return bool(self._recovered_keys)

    @property
    def finalized(self) -> bool:
        return self._finalized

    @property
    def stage_count(self) -> int:
        return self._stage_count

    @property
    def action_count(self) -> int:
        return self._action_count

    @property
    def plan_recorded(self) -> bool:
        return self._plan_recorded

    @property
    def actions_recorded(self) -> bool:
        return self._actions_recorded

    def record_stage(
        self,
        name: str,
        result: Mapping[str, object],
        before_budget: BudgetSnapshot | Mapping[str, object],
        after_budget: BudgetSnapshot | Mapping[str, object],
    ) -> TraceEvent:
        """记录一个 ProcessExecutor 阶段；失败同样产生完整 span。"""

        self._require_open()
        stage = text("stage.name", name)
        normalized = _process_result(result, expected_stage=stage)
        before, after = self._budget_window(before_budget, after_budget)
        status, reason = _process_outcome(normalized)
        event = self._build_timed_event(
            kind="stage",
            stage=stage,
            action="execute",
            status=status,
            started_at=normalized["started_at"],
            ended_at=normalized["finished_at"],
            budget=self._trace_budget(before, after),
            reason=reason,
            attributes={
                "command_sha256": canonical_sha256(
                    {
                        "command": normalized["command"],
                        "cwd": normalized["cwd"],
                    }
                )
            },
        )
        self.journal.append(event)
        self._stage_count += 1
        self._last_budget = after
        self._remember_end(event)
        return event

    def record_plan_validation(
        self,
        result: Mapping[str, object],
        before_budget: BudgetSnapshot | Mapping[str, object],
        after_budget: BudgetSnapshot | Mapping[str, object],
        *,
        plan_sha256: str,
        context_sha256: str | None,
        context_result: Mapping[str, object] | None = None,
        valid_context: bool | None = None,
        executable: bool | None = None,
    ) -> TraceEvent:
        """记录计划验证判定；默认仅把 exit 0 解释为有效且可执行。"""

        self._require_open()
        if self._plan_recorded:
            raise ObservabilityError(
                "trace_plan_validation_duplicate",
                "每个 run key 只能记录一次 plan_validation",
            )
        normalized = _process_result(
            result,
            expected_stage=str(result.get("stage", "")),
        )
        plan_hash = sha256("plan.plan_sha256", plan_sha256)
        context_hash = (
            None
            if context_sha256 is None
            else sha256("plan.context_sha256", context_sha256)
        )
        context_normalized = (
            None
            if context_result is None
            else _process_result(
                context_result,
                expected_stage="compile_agent_context",
            )
        )
        succeeded = normalized["exit_code"] == 0
        context_ok = (
            succeeded
            if valid_context is None
            else boolean("plan.valid_context", valid_context)
        )
        can_execute = (
            succeeded
            if executable is None
            else boolean("plan.executable", executable)
        )
        if can_execute and not context_ok:
            raise ObservabilityError(
                "trace_plan_context_invalid",
                "无效 context 不能标记为 executable",
            )
        if can_execute and (
            not succeeded
            or context_normalized is None
            or context_normalized["exit_code"] != 0
            or context_hash is None
        ):
            raise ObservabilityError(
                "trace_plan_execution_unproven",
                "executable plan 必须绑定成功的计划、context 阶段与内容 hash",
            )
        started_at = normalized["started_at"]
        ended_at = (
            normalized["finished_at"]
            if context_normalized is None
            else context_normalized["finished_at"]
        )
        if (
            context_normalized is not None
            and timestamp(
                "context.started_at",
                context_normalized["started_at"],
            )[1]
            < timestamp(
                "plan.finished_at",
                normalized["finished_at"],
            )[1]
        ):
            raise ObservabilityError(
                "trace_plan_context_order_invalid",
                "context validation 不得早于 plan validation 完成",
            )
        before, after = self._budget_window(
            before_budget,
            after_budget,
            replay_window=True,
        )
        if context_ok and can_execute:
            status = "succeeded"
            reason = TraceReason("plan_valid", None)
        elif context_ok:
            status = "blocked"
            reason = TraceReason("plan_not_executable", _process_detail(normalized))
        else:
            status = "failed"
            reason = TraceReason("plan_context_invalid", _process_detail(normalized))
        event = self._build_timed_event(
            kind="plan_validation",
            stage="planning",
            action="validate_plan_and_context",
            status=status,
            started_at=started_at,
            ended_at=ended_at,
            budget=self._trace_budget(before, after),
            reason=reason,
            attributes={
                "valid_context": context_ok,
                "executable": can_execute,
                "plan_sha256": plan_hash,
                "context_sha256": context_hash,
            },
        )
        self.journal.append(event)
        self._plan_recorded = True
        self._last_budget = after
        self._remember_end(event)
        return event

    def record_actions(
        self,
        results: Mapping[str, object],
        final_budget: BudgetSnapshot | Mapping[str, object],
    ) -> tuple[TraceEvent, ...]:
        """把 results.scenarios[].steps[] 原子校验后逐条记录为 action span。"""

        self._require_open()
        if self._actions_recorded:
            raise ObservabilityError(
                "trace_actions_duplicate",
                "每个 CycleTracer 只能导入一次 results action",
            )
        budget = self._budget_window(final_budget, final_budget)[0]
        events = self._action_events(results, budget)
        for event in events:
            self.journal.append(event)
            self._remember_end(event)
        self._actions_recorded = True
        self._action_count = len(events)
        self._current_succeeded_actions = {
            (event.stage, event.action)
            for event in events
            if event.status == "succeeded"
        }
        self._last_budget = budget
        return events

    def record_cleanup(
        self,
        *,
        started_at: str | datetime,
        ended_at: str | datetime,
        before_budget: BudgetSnapshot | Mapping[str, object],
        after_budget: BudgetSnapshot | Mapping[str, object],
        managed_resources_remaining: int,
        status: str,
        reason: str | TraceReason,
    ) -> TraceEvent:
        """仅根据调用方提供的真实清理结果记录 cleanup，不推断成功。"""

        self._require_open()
        if self._cleanup_recorded:
            raise ObservabilityError(
                "trace_cleanup_duplicate",
                "每个 run key 只能记录一次 cleanup",
            )
        before, after = self._budget_window(
            before_budget,
            after_budget,
            replay_window=True,
        )
        event = self._build_timed_event(
            kind="cleanup",
            stage="cleanup",
            action="cleanup",
            status=_trace_status(status),
            started_at=started_at,
            ended_at=ended_at,
            budget=self._trace_budget(before, after),
            reason=_trace_reason(reason),
            attributes={
                "managed_resources_remaining": integer(
                    "cleanup.managed_resources_remaining",
                    managed_resources_remaining,
                )
            },
        )
        self.journal.append(event)
        self._cleanup_recorded = True
        self._last_budget = after
        self._remember_end(event)
        return event

    def record_handoff(
        self,
        *,
        attempt: object,
        started_at: str | datetime,
        ended_at: str | datetime,
        before_budget: BudgetSnapshot | Mapping[str, object],
        after_budget: BudgetSnapshot | Mapping[str, object],
        structured: bool,
        status: str,
        reason: str | TraceReason,
    ) -> TraceEvent:
        """记录真实 handoff，并只引用已验证的不可变 attempt artifacts。"""

        self._require_open()
        if self._handoff_recorded:
            raise ObservabilityError(
                "trace_handoff_duplicate",
                "每个 run key 只能记录一次 handoff",
            )
        attempt_id, refs = self._validated_attempt(attempt)
        before, after = self._budget_window(before_budget, after_budget)
        event = self._build_timed_event(
            kind="handoff",
            stage="handoff",
            action="publish_handoff",
            status=_trace_status(status),
            started_at=started_at,
            ended_at=ended_at,
            budget=self._trace_budget(before, after),
            reason=_trace_reason(reason),
            artifact_refs=refs,
            attempt_id=attempt_id,
            attributes={"structured": boolean("handoff.structured", structured)},
        )
        self.journal.append(event)
        self._handoff_recorded = True
        self._last_budget = after
        self._remember_end(event)
        return event

    def finalize(
        self,
        *,
        attempt: object | None,
        status: str,
        reason: str | TraceReason,
        final_budget: BudgetSnapshot | Mapping[str, object],
        expected_actions: int,
        state_end_sequence: int | None = None,
        cleanup_required: bool = False,
        handoff_required: bool = False,
        converged: bool | None = None,
    ) -> TraceSnapshot:
        """追加真实 recovery/artifact validation，最后提交唯一 run span。"""

        self._require_open()
        run_status = _trace_status(status)
        expected_action_count = integer(
            "run.expected_actions",
            expected_actions,
        )
        normalized_state_end = integer(
            "run.state_end_sequence",
            (
                self._state_start_sequence
                if state_end_sequence is None
                else state_end_sequence
            ),
        )
        if normalized_state_end < self._state_start_sequence:
            raise ObservabilityError(
                "trace_state_window_invalid",
                "state_end_sequence 不得早于 state_start_sequence",
            )
        if expected_action_count != self._action_count:
            raise ObservabilityError(
                "trace_action_count_mismatch",
                "expected_actions 必须等于已校验并记录的 action span 数量",
                details={
                    "expected": expected_action_count,
                    "observed": self._action_count,
                },
            )
        cleanup_is_required = boolean(
            "run.cleanup_required",
            cleanup_required,
        )
        handoff_is_required = boolean(
            "run.handoff_required",
            handoff_required,
        )
        if cleanup_is_required and not self._cleanup_recorded:
            raise ObservabilityError(
                "trace_cleanup_missing",
                "cleanup_required=true 时必须先记录真实 cleanup span",
            )
        if handoff_is_required and not self._handoff_recorded:
            raise ObservabilityError(
                "trace_handoff_missing",
                "handoff_required=true 时必须先记录真实 handoff span",
            )
        if run_status == "succeeded" and attempt is None:
            raise ObservabilityError(
                "trace_attempt_required",
                "成功 run 必须绑定真实已提交 attempt",
            )
        if run_status == "succeeded" and not self._plan_recorded:
            raise ObservabilityError(
                "trace_plan_validation_missing",
                "成功 run 必须包含真实 plan_validation span",
            )
        if run_status == "succeeded" and not self._actions_recorded:
            raise ObservabilityError(
                "trace_actions_missing",
                "成功 run 必须从 results 导入 action spans",
            )
        final = self._budget_window(final_budget, final_budget)[0]
        terminal_at = self._now()
        if terminal_at < self._max_ended_at:
            raise ObservabilityError(
                "trace_terminal_time_invalid",
                "最终 run 结束时间早于已记录 span",
            )

        attempt_id: str | None = None
        refs: tuple[TraceArtifactRef, ...] = ()
        if attempt is not None:
            attempt_id, refs = self._validated_attempt(attempt)

        duplicate_actions = len(
            self._recovered_actions & self._current_succeeded_actions
        )
        if self.recovery_required and not self._recovery_recorded:
            recovery_status = (
                "succeeded" if duplicate_actions == 0 else "failed"
            )
            recovery = self._build_timed_event(
                kind="recovery",
                stage="recovery",
                action="resume_cycle",
                status=recovery_status,
                started_at=self._started_at,
                ended_at=terminal_at,
                budget=self._trace_budget(self._initial_budget, final),
                reason=TraceReason(
                    "recovery_completed"
                    if duplicate_actions == 0
                    else "recovery_duplicate_action",
                    None,
                ),
                attributes={
                    "resumed": True,
                    "duplicate_committed_actions": duplicate_actions,
                },
            )
            self.journal.append(recovery)
            self._recovery_recorded = True
            self._remember_end(recovery)
        if duplicate_actions and run_status == "succeeded":
            raise ObservabilityError(
                "trace_recovery_duplicate_action",
                "恢复运行重复执行了此前已成功的 action，不能闭合为成功",
                details={"duplicate_count": duplicate_actions},
            )

        if attempt_id is not None and not self._artifact_recorded:
            artifact_event = self._build_timed_event(
                kind="artifact_validation",
                stage="commit",
                action="validate_artifacts",
                status="succeeded",
                started_at=terminal_at,
                ended_at=terminal_at,
                budget=self._trace_budget(final, final),
                reason=TraceReason("artifacts_verified", None),
                artifact_refs=refs,
                attempt_id=attempt_id,
                attributes={
                    "required_ref_count": len(refs),
                    "valid_ref_count": len(refs),
                },
            )
            self.journal.append(artifact_event)
            self._artifact_recorded = True
            self._remember_end(artifact_event)

        did_converge = (
            run_status == "succeeded"
            if converged is None
            else boolean("run.converged", converged)
        )
        if did_converge and run_status != "succeeded":
            raise ObservabilityError(
                "trace_convergence_status_invalid",
                "只有 succeeded run 可以标记 converged=true",
            )
        run_event = self._build_timed_event(
            kind="run",
            stage="cycle",
            action="run_qa_cycle",
            status=run_status,
            started_at=self._started_at,
            ended_at=terminal_at,
            budget=self._trace_budget(self._initial_budget, final),
            reason=_trace_reason(reason),
            attempt_id=attempt_id,
            attributes={
                "expected_stage_count": self._stage_count,
                "expected_action_count": expected_action_count,
                "state_start_sequence": self._state_start_sequence,
                "state_end_sequence": normalized_state_end,
                "cleanup_required": cleanup_is_required,
                "handoff_required": handoff_is_required,
                "recovery_required": self.recovery_required,
                "converged": did_converge,
            },
        )
        self.journal.append(run_event)
        self._finalized = True
        self._last_budget = final
        self._remember_end(run_event)
        return self.journal.snapshot()

    def _action_events(
        self,
        results: Mapping[str, object],
        budget: BudgetSnapshot,
    ) -> tuple[TraceEvent, ...]:
        if not isinstance(results, Mapping):
            raise ObservabilityError(
                "trace_results_invalid",
                "results 必须是对象",
            )
        scenarios = results.get("scenarios")
        if not isinstance(scenarios, list):
            raise ObservabilityError(
                "trace_results_invalid",
                "results.scenarios 必须是数组",
            )
        events: list[TraceEvent] = []
        scenario_ids: set[str] = set()
        action_ids: set[tuple[str, str]] = set()
        for scenario_index, raw_scenario in enumerate(scenarios):
            if not isinstance(raw_scenario, Mapping):
                raise ObservabilityError(
                    "trace_results_invalid",
                    f"results.scenarios[{scenario_index}] 必须是对象",
                )
            scenario_id = text(
                f"results.scenarios[{scenario_index}].id",
                raw_scenario.get("id"),
            )
            if scenario_id in scenario_ids:
                raise ObservabilityError(
                    "trace_scenario_duplicate",
                    f"results 包含重复 scenario id：{scenario_id}",
                )
            scenario_ids.add(scenario_id)
            steps = raw_scenario.get("steps")
            if not isinstance(steps, list):
                raise ObservabilityError(
                    "trace_results_invalid",
                    f"results.scenarios[{scenario_index}].steps 必须是数组",
                )
            for step_index, raw_step in enumerate(steps):
                path = (
                    f"results.scenarios[{scenario_index}]"
                    f".steps[{step_index}]"
                )
                if not isinstance(raw_step, Mapping):
                    raise ObservabilityError(
                        "trace_results_invalid",
                        f"{path} 必须是对象",
                    )
                step_scenario = text(
                    f"{path}.scenarioId",
                    raw_step.get("scenarioId"),
                )
                if step_scenario != scenario_id:
                    raise ObservabilityError(
                        "trace_action_scenario_mismatch",
                        f"{path}.scenarioId 与父 scenario 不一致",
                    )
                step_id = text(f"{path}.stepId", raw_step.get("stepId"))
                identity = (scenario_id, step_id)
                if identity in action_ids:
                    raise ObservabilityError(
                        "trace_action_duplicate",
                        f"results 包含重复 action：{scenario_id}/{step_id}",
                    )
                action_ids.add(identity)
                action = text(f"{path}.action", raw_step.get("action"))
                raw_status = text(f"{path}.status", raw_step.get("status"))
                if raw_status not in _ACTION_STATUS:
                    raise ObservabilityError(
                        "trace_action_status_invalid",
                        f"{path}.status 不受支持：{raw_status}",
                    )
                event_status, reason_code = _ACTION_STATUS[raw_status]
                detail_key = (
                    "error" if raw_status == "failed" else "skipReason"
                )
                detail = _optional_detail(
                    f"{path}.{detail_key}",
                    raw_step.get(detail_key),
                )
                event = self._build_timed_event(
                    kind="action",
                    stage=f"probe:{scenario_id}",
                    action=f"{step_id}:{action}",
                    status=event_status,
                    started_at=raw_step.get("startedAt"),
                    ended_at=raw_step.get("finishedAt"),
                    budget=self._trace_budget(budget, budget),
                    reason=TraceReason(reason_code, detail),
                    attributes={},
                )
                events.append(event)
        return tuple(events)

    def _validated_attempt(
        self,
        attempt: object,
    ) -> tuple[str, tuple[TraceArtifactRef, ...]]:
        payload = _object_dict(attempt, path="attempt")
        attempt_id = text("attempt.attempt_id", payload.get("attempt_id"))
        raw_artifacts = payload.get("artifacts")
        if not isinstance(raw_artifacts, list):
            raise ObservabilityError(
                "trace_attempt_artifacts_invalid",
                "attempt.artifacts 必须是数组",
            )
        if not raw_artifacts:
            raise ObservabilityError(
                "trace_attempt_artifacts_empty",
                "attempt 必须包含至少一个已提交 artifact",
            )
        refs = tuple(
            sorted(
                (
                    TraceArtifactRef.from_dict(
                        dict(item)
                        if isinstance(item, Mapping)
                        else item,
                        path=f"attempt.artifacts[{index}]",
                    )
                    for index, item in enumerate(raw_artifacts)
                ),
                key=lambda ref: ref.name,
            )
        )
        if any(ref.attempt_id != attempt_id for ref in refs):
            raise ObservabilityError(
                "trace_artifact_attempt_mismatch",
                "attempt.artifacts 必须全部属于 attempt.attempt_id",
            )
        if len({ref.name for ref in refs}) != len(refs):
            raise ObservabilityError(
                "trace_artifact_ref_duplicate",
                "attempt.artifacts 不得包含重复 name",
            )
        for ref in refs:
            expected_path = (
                PurePosixPath("attempts")
                / attempt_id
                / "committed"
                / "artifacts"
                / PurePosixPath(ref.name)
            ).as_posix()
            if ref.path != expected_path:
                raise ObservabilityError(
                    "trace_artifact_path_mismatch",
                    f"artifact {ref.name!r} 未绑定到当前 attempt",
                )
            observed_hash, observed_size = _hash_regular_beneath(
                self.journal.path.parent,
                PurePosixPath(ref.path),
            )
            if observed_hash != ref.sha256 or observed_size != ref.size:
                raise ObservabilityError(
                    "trace_artifact_integrity_mismatch",
                    f"artifact {ref.name!r} 的 hash 或 size 不匹配",
                )
        return attempt_id, refs

    def _budget_window(
        self,
        before: BudgetSnapshot | Mapping[str, object],
        after: BudgetSnapshot | Mapping[str, object],
        *,
        replay_window: bool = False,
    ) -> tuple[BudgetSnapshot, BudgetSnapshot]:
        normalized_before = _budget_snapshot(before)
        normalized_after = _budget_snapshot(after)
        _same_budget(self._initial_budget, normalized_before)
        _same_budget(self._initial_budget, normalized_after)
        continuity_point = (
            normalized_after if replay_window else normalized_before
        )
        if (
            continuity_point.probes_used
            != self._last_budget.probes_used
            or continuity_point.output_bytes_used
            != self._last_budget.output_bytes_used
            or continuity_point.cancelled
            != self._last_budget.cancelled
        ):
            raise ObservabilityError(
                "trace_budget_discontinuous",
                "span budget 与上一条已提交 span 不连续",
            )
        if (
            continuity_point.remaining_time is not None
            and self._last_budget.remaining_time is not None
            and continuity_point.remaining_time
            > self._last_budget.remaining_time + 1e-6
        ):
            raise ObservabilityError(
                "trace_budget_time_regressed",
                "remaining_time 不得在相邻 span 之间增加",
            )
        if normalized_after.probes_used < normalized_before.probes_used:
            raise ObservabilityError(
                "trace_budget_regressed",
                "probes_used 不得倒退",
            )
        if (
            normalized_after.output_bytes_used
            < normalized_before.output_bytes_used
        ):
            raise ObservabilityError(
                "trace_budget_regressed",
                "output_bytes_used 不得倒退",
            )
        if (
            normalized_before.remaining_time is not None
            and normalized_after.remaining_time is not None
            and normalized_after.remaining_time
            > normalized_before.remaining_time + 1e-6
        ):
            raise ObservabilityError(
                "trace_budget_time_regressed",
                "remaining_time 不得在 span 内增加",
            )
        if normalized_before.cancelled and not normalized_after.cancelled:
            raise ObservabilityError(
                "trace_budget_regressed",
                "cancelled 不得从 true 回退为 false",
            )
        return normalized_before, normalized_after

    def _trace_budget(
        self,
        before: BudgetSnapshot,
        after: BudgetSnapshot,
    ) -> TraceBudget:
        return TraceBudget(
            total_seconds=self._total_seconds,
            deadline_at=self._deadline_at,
            remaining_seconds_at_start=before.remaining_time,
            remaining_seconds_at_end=after.remaining_time,
            probes_used=after.probes_used,
            max_probes=after.max_probes,
            output_bytes_used=after.output_bytes_used,
            max_output_bytes=after.max_output_bytes,
            cancelled=after.cancelled,
        )

    def _build_timed_event(
        self,
        *,
        kind: str,
        stage: str,
        action: str,
        status: str,
        started_at: object,
        ended_at: object,
        budget: TraceBudget,
        reason: TraceReason,
        attributes: Mapping[str, object],
        artifact_refs: tuple[TraceArtifactRef, ...] = (),
        attempt_id: str | None = None,
    ) -> TraceEvent:
        started_text, started = _runtime_timestamp(
            f"{kind}.started_at",
            started_at,
        )
        ended_text, ended = _runtime_timestamp(
            f"{kind}.ended_at",
            ended_at,
        )
        if started < self._started_datetime or ended < started:
            raise ObservabilityError(
                "trace_span_time_invalid",
                f"{kind} span 必须位于 run 开始时间之后且 start <= end",
            )
        return TraceEvent.from_dict(
            {
                "schema_version": 1,
                "run_id": self.run_id,
                "generation": self.generation,
                "iteration": self.iteration,
                "attempt_id": attempt_id,
                "kind": kind,
                "stage": stage,
                "action": action,
                "status": status,
                "started_at": started_text,
                "ended_at": ended_text,
                "duration_seconds": (ended - started).total_seconds(),
                "budget": budget.to_dict(),
                "reason": reason.to_dict(),
                "artifact_refs": [ref.to_dict() for ref in artifact_refs],
                "attributes": dict(attributes),
            }
        )

    def _remember_end(self, event: TraceEvent) -> None:
        self._max_ended_at = max(self._max_ended_at, event.ended_datetime)

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise ObservabilityError(
                "trace_clock_invalid",
                "clock 必须返回 datetime",
            )
        if value.tzinfo is None or value.utcoffset() is None:
            raise ObservabilityError(
                "trace_clock_invalid",
                "clock 返回值必须包含时区",
            )
        return value

    def _require_open(self) -> None:
        if self._finalized:
            raise ObservabilityError(
                "trace_run_finalized",
                "run span 已提交，不能再追加当前 run key",
            )


def _process_result(
    value: Mapping[str, object],
    *,
    expected_stage: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ObservabilityError(
            "trace_process_result_invalid",
            "ProcessExecutor result 必须是对象",
        )
    payload = dict(value)
    missing = sorted(_PROCESS_RESULT_FIELDS - set(payload))
    unknown = sorted(set(payload) - _PROCESS_RESULT_FIELDS)
    if missing or unknown:
        raise ObservabilityError(
            "trace_process_result_schema_invalid",
            "ProcessExecutor result 字段不闭合",
            details={"missing": missing, "unknown": unknown},
        )
    if payload["schema_version"] != 1:
        raise ObservabilityError(
            "trace_process_result_schema_invalid",
            "ProcessExecutor result schema_version 必须为 1",
        )
    stage = text("process_result.stage", payload["stage"])
    if expected_stage and stage != expected_stage:
        raise ObservabilityError(
            "trace_process_stage_mismatch",
            "ProcessExecutor result.stage 与调用阶段不一致",
        )
    command = payload["command"]
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(part, str) or not part for part in command)
    ):
        raise ObservabilityError(
            "trace_process_result_invalid",
            "process_result.command 必须是非空字符串数组",
        )
    cwd = payload["cwd"]
    if cwd is not None and not isinstance(cwd, str):
        raise ObservabilityError(
            "trace_process_result_invalid",
            "process_result.cwd 必须是字符串或 null",
        )
    for field in (
        "started",
        "timed_out",
        "stdout_truncated",
        "stderr_truncated",
        "term_sent",
        "kill_sent",
        "process_group_cleanup",
    ):
        boolean(f"process_result.{field}", payload[field])
    _signed_integer("process_result.exit_code", payload["exit_code"])
    for field in ("stdout_bytes", "stderr_bytes", "output_bytes"):
        integer(f"process_result.{field}", payload[field])
    raw_exit_code = payload["raw_exit_code"]
    if raw_exit_code is not None and (
        isinstance(raw_exit_code, bool) or not isinstance(raw_exit_code, int)
    ):
        raise ObservabilityError(
            "trace_process_result_invalid",
            "process_result.raw_exit_code 必须是整数或 null",
        )
    termination = nullable_text(
        "process_result.termination_reason",
        payload["termination_reason"],
    )
    for field in ("stdout", "stderr"):
        if not isinstance(payload[field], str):
            raise ObservabilityError(
                "trace_process_result_invalid",
                f"process_result.{field} 必须是字符串",
            )
    for field in ("budget_error", "spawn_error", "executor_error"):
        nested = payload[field]
        if nested is not None and not isinstance(nested, Mapping):
            raise ObservabilityError(
                "trace_process_result_invalid",
                f"process_result.{field} 必须是对象或 null",
            )
    if payload["output_bytes"] != (
        payload["stdout_bytes"] + payload["stderr_bytes"]
    ):
        raise ObservabilityError(
            "trace_process_output_mismatch",
            "output_bytes 必须等于 stdout_bytes + stderr_bytes",
        )
    started_text, started = _runtime_timestamp(
        "process_result.started_at",
        payload["started_at"],
    )
    ended_text, ended = _runtime_timestamp(
        "process_result.finished_at",
        payload["finished_at"],
    )
    if ended < started:
        raise ObservabilityError(
            "trace_process_time_invalid",
            "ProcessExecutor finished_at 不得早于 started_at",
        )
    measured = number(
        "process_result.duration_seconds",
        payload["duration_seconds"],
    )
    wall_duration = (ended - started).total_seconds()
    if abs(measured - wall_duration) > 0.01:
        raise ObservabilityError(
            "trace_process_duration_mismatch",
            "ProcessExecutor duration_seconds 与时间戳不一致",
        )
    if payload["started"] is False and raw_exit_code is not None:
        raise ObservabilityError(
            "trace_process_result_invalid",
            "未启动进程不得声明 raw_exit_code",
        )
    if payload["exit_code"] == 0 and termination is not None:
        raise ObservabilityError(
            "trace_process_result_invalid",
            "exit_code=0 时不得声明 termination_reason",
        )
    payload["started_at"] = started_text
    payload["finished_at"] = ended_text
    payload["termination_reason"] = termination
    return payload


def _process_outcome(
    result: Mapping[str, object],
) -> tuple[str, TraceReason]:
    exit_code = int(result["exit_code"])
    termination = result["termination_reason"]
    if exit_code == 0:
        return "succeeded", TraceReason("completed", None)
    if termination == "cancelled":
        return "cancelled", TraceReason("cancelled", _process_detail(result))
    if termination in _BUDGET_STOP_REASONS:
        return "blocked", TraceReason(str(termination), _process_detail(result))
    if termination:
        return "failed", TraceReason(str(termination), _process_detail(result))
    return "failed", TraceReason("nonzero_exit", _process_detail(result))


def _process_detail(result: Mapping[str, object]) -> str:
    return (
        f"exit_code={result['exit_code']};"
        f"raw_exit_code={result['raw_exit_code']}"
    )


def _budget_snapshot(
    value: BudgetSnapshot | Mapping[str, object],
) -> BudgetSnapshot:
    if isinstance(value, BudgetSnapshot):
        payload = value.to_dict()
    elif isinstance(value, Mapping):
        payload = dict(value)
    else:
        raise ObservabilityError(
            "trace_budget_invalid",
            "budget 必须是 BudgetSnapshot 或对象",
        )
    missing = sorted(_BUDGET_FIELDS - set(payload))
    unknown = sorted(set(payload) - _BUDGET_FIELDS)
    if missing or unknown:
        raise ObservabilityError(
            "trace_budget_schema_invalid",
            "budget snapshot 字段不闭合",
            details={"missing": missing, "unknown": unknown},
        )
    started_at = number("budget.started_at", payload["started_at"])
    deadline = _optional_number("budget.deadline", payload["deadline"])
    remaining = _optional_number(
        "budget.remaining_time",
        payload["remaining_time"],
    )
    probes_used = integer("budget.probes_used", payload["probes_used"])
    max_probes = _optional_integer("budget.max_probes", payload["max_probes"])
    output_used = integer(
        "budget.output_bytes_used",
        payload["output_bytes_used"],
    )
    max_output = _optional_integer(
        "budget.max_output_bytes",
        payload["max_output_bytes"],
    )
    cancelled = boolean("budget.cancelled", payload["cancelled"])
    detail = payload["cancel_detail"]
    if detail is not None and not isinstance(detail, str):
        raise ObservabilityError(
            "trace_budget_invalid",
            "budget.cancel_detail 必须是字符串或 null",
        )
    cancelled_at = _optional_number(
        "budget.cancelled_at",
        payload["cancelled_at"],
    )
    if deadline is not None and deadline < started_at:
        raise ObservabilityError(
            "trace_budget_invalid",
            "budget.deadline 不得早于 started_at",
        )
    if max_probes is not None and probes_used > max_probes:
        raise ObservabilityError(
            "trace_budget_invalid",
            "budget.probes_used 不得超过 max_probes",
        )
    if max_output is not None and output_used > max_output:
        raise ObservabilityError(
            "trace_budget_invalid",
            "budget.output_bytes_used 不得超过 max_output_bytes",
        )
    if cancelled != (cancelled_at is not None):
        raise ObservabilityError(
            "trace_budget_invalid",
            "budget.cancelled 与 cancelled_at 必须同时闭合",
        )
    return BudgetSnapshot(
        started_at=started_at,
        deadline=deadline,
        remaining_time=remaining,
        probes_used=probes_used,
        max_probes=max_probes,
        output_bytes_used=output_used,
        max_output_bytes=max_output,
        cancelled=cancelled,
        cancel_detail=detail,
        cancelled_at=cancelled_at,
    )


def _same_budget(
    initial: BudgetSnapshot,
    candidate: BudgetSnapshot,
) -> None:
    for field in (
        "started_at",
        "deadline",
        "max_probes",
        "max_output_bytes",
    ):
        if getattr(initial, field) != getattr(candidate, field):
            raise ObservabilityError(
                "trace_budget_identity_mismatch",
                f"budget.{field} 与初始 RunBudget 不一致",
            )


def _optional_number(path: str, value: object) -> float | None:
    return None if value is None else number(path, value)


def _optional_integer(path: str, value: object) -> int | None:
    return None if value is None else integer(path, value)


def _signed_integer(path: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ObservabilityError(
            "schema_integer_invalid",
            f"{path} 必须是整数",
        )
    return value


def _trace_status(value: str) -> str:
    normalized = text("trace.status", value).lower()
    try:
        return _STATUS_ALIASES[normalized]
    except KeyError as error:
        raise ObservabilityError(
            "trace_status_invalid",
            f"不支持的 runtime status：{normalized}",
        ) from error


def _trace_reason(value: str | TraceReason) -> TraceReason:
    if isinstance(value, TraceReason):
        return TraceReason.from_dict(value.to_dict())
    return TraceReason(text("trace.reason", value), None)


def _optional_detail(path: str, value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ObservabilityError(
            "trace_results_invalid",
            f"{path} 必须是字符串或 null",
        )
    normalized = value.strip()
    return normalized[:4000] or None


def _runtime_timestamp(
    path: str,
    value: object,
) -> tuple[str, datetime]:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ObservabilityError(
                "schema_timestamp_invalid",
                f"{path} 必须包含时区",
            )
        normalized = _format_timestamp(value)
        return timestamp(path, normalized)
    return timestamp(path, value)


def _format_timestamp(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _format_deadline(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _object_dict(value: object, *, path: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if not callable(to_dict):
        raise ObservabilityError(
            "trace_attempt_invalid",
            f"{path} 必须是 attempt 对象或映射",
        )
    payload = to_dict()
    if not isinstance(payload, Mapping):
        raise ObservabilityError(
            "trace_attempt_invalid",
            f"{path}.to_dict() 必须返回对象",
        )
    return dict(payload)


def _incomplete_run_keys(
    snapshot: TraceSnapshot,
    *,
    run_id: str,
    generation: int,
    before_iteration: int,
) -> frozenset[tuple[str, int, int]]:
    observed = {
        record.event.run_key
        for record in snapshot.records
        if record.event.run_id == run_id
        and (
            record.event.generation < generation
            or (
                record.event.generation == generation
                and record.event.iteration < before_iteration
            )
        )
    }
    completed = {
        record.event.run_key
        for record in snapshot.records
        if record.event.kind == "run"
    }
    return frozenset(observed - completed)


def _validate_trace_history(snapshot: TraceSnapshot) -> None:
    completed: set[tuple[str, int, int]] = set()
    for record in snapshot.records:
        key = record.event.run_key
        if key in completed:
            raise ObservabilityError(
                "trace_event_after_terminal_run",
                f"run key {key!r} 在终局 run span 后仍有事件",
            )
        if record.event.kind == "run":
            completed.add(key)


def _hash_regular_beneath(
    root: Path,
    relative: PurePosixPath,
) -> tuple[str, int]:
    root_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    root_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_descriptor = os.open(root, root_flags)
    except OSError as error:
        raise ObservabilityError(
            "trace_artifact_root_invalid",
            f"无法安全打开 artifact root：{error}",
        ) from error
    descriptors = [parent_descriptor]
    try:
        parts = relative.parts
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        for part in parts[:-1]:
            descriptor = os.open(
                part,
                directory_flags,
                dir_fd=descriptors[-1],
            )
            descriptors.append(descriptor)
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        file_flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(
            parts[-1],
            file_flags,
            dir_fd=descriptors[-1],
        )
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ObservabilityError(
                "trace_artifact_not_regular",
                f"artifact 必须是无硬链接的普通文件：{relative}",
            )
        digest = hashlib.sha256()
        observed_size = 0
        while True:
            chunk = os.read(descriptor, _READ_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            observed_size += len(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ObservabilityError(
                "trace_artifact_changed",
                f"artifact 在 hash 期间变化：{relative}",
            )
        return digest.hexdigest(), observed_size
    except ObservabilityError:
        raise
    except OSError as error:
        raise ObservabilityError(
            "trace_artifact_open_failed",
            f"无法安全读取 artifact {relative}：{error}",
        ) from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


__all__ = ["TRACE_JOURNAL_FILENAME", "CycleTracer"]
