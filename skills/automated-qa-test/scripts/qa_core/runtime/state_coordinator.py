"""把运行租约、预算快照与事件化状态连接成单一写入边界。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from qa_common import file_sha256

from qa_core.state import EventLogError, RunEventType, RunState, RunStateStore

from .session import RunSession

_NON_PASS_STATUSES = {
    "attention": "inconclusive",
    "blocked": "blocked",
    "cancelled": "cancelled",
    "failed": "failed",
    "inconclusive": "inconclusive",
    "untested": "inconclusive",
}


@dataclass(slots=True)
class RunStateCoordinator:
    """只允许持有当前租约的编排器推进可恢复状态。"""

    session: RunSession
    store: RunStateStore
    actor: str
    state: RunState
    _finished: bool = False

    @classmethod
    def open(
        cls,
        session: RunSession,
        *,
        goal: str,
        scope: Iterable[str],
        component_versions: Mapping[str, Any],
        initial_budget: Mapping[str, Any],
    ) -> "RunStateCoordinator":
        """初始化或恢复 run，并立即撤销旧的终态声明。"""

        store = RunStateStore(session.run_dir)
        session.heartbeat()
        events = store.load_events()
        actor = session.owner
        if events:
            state = store.load_state()
            if state.run_id != session.run_id:
                raise EventLogError(
                    "run_id_mismatch",
                    "run state and active lease belong to different runs",
                )
        else:
            state = store.initialize(
                run_id=session.run_id,
                goal=goal,
                scope=scope,
                actor=actor,
                component_versions=component_versions,
            )
        coordinator = cls(
            session=session,
            store=store,
            actor=actor,
            state=state,
        )
        coordinator._append(
            RunEventType.COMPONENT_VERSIONS_RECORDED,
            {"versions": dict(component_versions)},
        )
        coordinator._append(
            RunEventType.STATUS_CHANGED,
            {
                "status": "running",
                "authority": "qa-cycle-orchestrator",
            },
        )
        coordinator._append(
            RunEventType.BUDGET_UPDATED,
            {"budget": dict(initial_budget)},
        )
        return coordinator

    def before_stage(
        self,
        stage: str,
        *,
        command_sha256: str | None = None,
    ) -> None:
        """先验证租约并记录阶段，再允许子进程启动。"""

        self._require_open()
        payload: dict[str, Any] = {
            "phase": _non_empty_text("stage", stage)
        }
        if command_sha256 is not None:
            payload.update(
                {
                    "trace_required": True,
                    "command_sha256": _sha256(
                        "command_sha256",
                        command_sha256,
                    ),
                }
            )
        self._append(
            RunEventType.PHASE_CHANGED,
            payload,
        )

    def update_budget(self, budget: Mapping[str, Any]) -> None:
        """把最新预算用量追加到事件日志。"""

        self._require_open()
        self._append(
            RunEventType.BUDGET_UPDATED,
            {"budget": dict(budget)},
        )

    def record_component_versions(
        self,
        versions: Mapping[str, Any],
    ) -> None:
        """把本轮生成的内容哈希绑定到可恢复状态链。"""

        self._require_open()
        self._append(
            RunEventType.COMPONENT_VERSIONS_RECORDED,
            {"versions": dict(versions)},
        )

    def finish(
        self,
        *,
        exit_code: int,
        verdict_path: Path,
        verdict_is_current: bool,
        final_budget: Mapping[str, Any],
        attempt_ref: Mapping[str, Any] | None,
        verdict_committed: bool,
    ) -> RunState:
        """仅由当前、可读取且哈希绑定的确定性裁决发布 PASS。"""

        self._require_open()
        self.session.heartbeat()
        self.update_budget(final_budget)
        verdict, verdict_hash = _read_verdict(verdict_path)
        status = _final_status(
            exit_code=exit_code,
            verdict=verdict,
            verdict_is_current=verdict_is_current,
            verdict_hash=verdict_hash,
            attempt_ref=attempt_ref,
            verdict_committed=verdict_committed,
        )
        verdict_ref = None
        if verdict_hash is not None:
            verdict_ref = {
                "path": str(verdict_path),
                "sha256": verdict_hash,
            }
            evidence_status = (
                "passed"
                if status == "passed"
                else status
                if status in {"failed", "blocked", "inconclusive"}
                else "inconclusive"
            )
            self._append(
                RunEventType.EVIDENCE_LINKED,
                {
                    "id": f"qa-verdict-{self.state.sequence + 1}",
                    "path": str(verdict_path),
                    "sha256": verdict_hash,
                    "status": evidence_status,
                    "proves": ["run_status"],
                },
            )
        payload: dict[str, Any] = {
            "status": status,
            "authority": (
                "deterministic_verdict"
                if status == "passed"
                else "qa-cycle-orchestrator"
            ),
        }
        if verdict_ref is not None:
            payload["verdict_ref"] = verdict_ref
        if attempt_ref is not None:
            payload["attempt_ref"] = dict(attempt_ref)
        self._append(RunEventType.STATUS_CHANGED, payload)
        self._finished = True
        return self.state

    def projection(self) -> dict[str, Any]:
        """返回摘要所需的最小、可核验状态指针。"""

        return {
            "run_id": self.state.run_id,
            "sequence": self.state.sequence,
            "last_event_hash": self.state.last_event_hash,
            "phase": self.state.phase,
            "status": self.state.status,
            "events_path": str(self.store.events_path),
            "state_path": str(self.store.state_path),
        }

    def invalidate_pass(self, *, reason: str) -> RunState:
        """只允许 proof verifier 把已发布 PASS 降级为非通过。"""

        if not self._finished:
            raise RuntimeError(
                "run state must be finished before proof invalidation"
            )
        self.session.heartbeat()
        self.state = self.store.append(
            RunEventType.STATUS_CHANGED,
            {
                "status": "inconclusive",
                "authority": "proof_verifier",
                "verdict_ref": {
                    "reason": _non_empty_text("reason", reason),
                },
            },
            actor=self.actor,
        )
        return self.state

    def _append(
        self,
        event_type: RunEventType,
        payload: Mapping[str, Any],
    ) -> None:
        self.session.heartbeat()
        self.state = self.store.append(
            event_type,
            payload,
            actor=self.actor,
        )

    def _require_open(self) -> None:
        if self._finished:
            raise RuntimeError("run state coordinator is already finished")


def _read_verdict(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    digest = file_sha256(path)
    if digest is None:
        return None, None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, digest
    return (value if isinstance(value, dict) else None), digest


def _sha256(name: str, value: Any) -> str:
    normalized = _non_empty_text(name, value)
    if len(normalized) != 64:
        raise ValueError(f"{name} must be a SHA-256 digest")
    try:
        int(normalized, 16)
    except ValueError as error:
        raise ValueError(f"{name} must be a SHA-256 digest") from error
    return normalized.lower()


def _final_status(
    *,
    exit_code: int,
    verdict: Mapping[str, Any] | None,
    verdict_is_current: bool,
    verdict_hash: str | None,
    attempt_ref: Mapping[str, Any] | None,
    verdict_committed: bool,
) -> str:
    if (
        exit_code == 0
        and verdict_is_current
        and verdict_hash is not None
        and verdict is not None
        and verdict.get("schema_version") == 1
        and verdict.get("verdict") == "passed"
        and verdict.get("can_claim_pass") is True
        and attempt_ref is not None
        and verdict_committed
    ):
        return "passed"
    if verdict is None:
        return "inconclusive"
    declared = verdict.get("verdict")
    if not isinstance(declared, str):
        return "inconclusive"
    return _NON_PASS_STATUSES.get(declared.strip().lower(), "inconclusive")


def _non_empty_text(field: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be non-empty text")
    return value.strip()
