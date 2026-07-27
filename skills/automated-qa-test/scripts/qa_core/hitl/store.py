"""可恢复、幂等且 currentness 绑定的 HITL 请求/决策存储。"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ._journal import (
    GENESIS_HASH,
    AppendOnlyJsonJournal,
    HumanControlJournalError,
    JournalEvent,
    JournalMutation,
)
from .auth import ApprovalVerifier
from .checkpoint import JournalCheckpointVerifier
from .contracts import (
    HUMAN_CONTROL_SCHEMA_VERSION,
    HITLConsumption,
    HITLDecision,
    HITLRequest,
    HumanControlContractError,
    HumanDecision,
    OperatorIdentity,
    canonical_sha256,
    canonical_timestamp,
    hitl_decision_subject_sha256,
    parse_timestamp,
    validate_hitl_decision,
)

REQUEST_EVENT = "hitl_request_created"
DECISION_EVENT = "hitl_decision_recorded"
CONSUMPTION_EVENT = "hitl_decision_consumed"
DISPATCH_REDEMPTION_EVENT = "human_dispatch_redeemed"
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class HITLStoreError(RuntimeError):
    """HITL 状态冲突、陈旧或不可恢复。"""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        request_id: str | None = None,
    ) -> None:
        self.code = code
        self.request_id = request_id
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": HUMAN_CONTROL_SCHEMA_VERSION,
            "error": "hitl_store_error",
            "code": self.code,
            "message": str(self),
        }
        if self.request_id is not None:
            payload["request_id"] = self.request_id
        return payload


@dataclass(frozen=True, slots=True)
class HITLState:
    """一个请求及其至多一个终局决策。"""

    request: HITLRequest
    decision: HITLDecision | None
    consumption: HITLConsumption | None = None

    @property
    def status(self) -> str:
        if self.consumption is not None:
            return "consumed"
        return "decided" if self.decision is not None else "pending"

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "decision": (
                self.decision.to_dict()
                if self.decision is not None
                else None
            ),
            "consumption": (
                self.consumption.to_dict()
                if self.consumption is not None
                else None
            ),
            "status": self.status,
        }


class HITLStore:
    """通过 request_id 和三重哈希绑定恢复人工确认流程。"""

    def __init__(
        self,
        directory: Path,
        *,
        trusted_authority_keys: (
            Mapping[str, Mapping[str, bytes | str]] | None
        ) = None,
        journal_mode: str = "local-test",
        checkpoint_path: Path | None = None,
        trusted_checkpoint_keys: (
            Mapping[str, Mapping[str, bytes | str]] | None
        ) = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.directory = Path(directory)
        self._verifier = ApprovalVerifier.configured(
            trusted_authority_keys=trusted_authority_keys,
        )
        self._clock = clock or (lambda: datetime.now(UTC))
        self._checkpoint_verifier = JournalCheckpointVerifier.configured(
            mode=journal_mode,
            checkpoint_path=checkpoint_path,
            trusted_authority_keys=trusted_checkpoint_keys,
            clock=self._clock,
        )
        self._journal = AppendOnlyJsonJournal(
            self.directory,
            name="hitl",
            checkpoint_guard=self._checkpoint_verifier,
        )
        self.events_path = self._journal.events_path
        self.snapshot_path = self._journal.projection_path
        if journal_mode == "production":
            self._journal.load_events()

    @property
    def journal_assurance(self) -> dict[str, Any]:
        """Describe whether reads are externally anchored or local-only."""

        return self._checkpoint_verifier.assurance

    def create_request(
        self,
        request: HITLRequest | Mapping[str, Any],
    ) -> HITLState:
        """创建可恢复请求；相同 request_id/内容的重试是 no-op。"""

        normalized = _request(request)
        now = self._trusted_now()
        if parse_timestamp(normalized.created_at) > now:
            raise HITLStoreError(
                "request_not_current",
                "request.created_at 晚于可信当前时间",
                request_id=normalized.request_id,
            )
        if now >= parse_timestamp(normalized.expires_at):
            raise HITLStoreError(
                "request_expired",
                "不能创建已过期 HITL request",
                request_id=normalized.request_id,
            )

        def prepare(
            events: tuple[JournalEvent, ...],
        ) -> JournalMutation | None:
            states = _reduce_states(
                events,
                verifier=self._verifier,
            )
            existing = states.get(normalized.request_id)
            if existing is not None:
                if (
                    existing.request.canonical_sha256
                    == normalized.canonical_sha256
                ):
                    return None
                raise HITLStoreError(
                    "request_conflict",
                    "同一 request_id 已绑定不同请求",
                    request_id=normalized.request_id,
                )
            return JournalMutation(
                event_type=REQUEST_EVENT,
                occurred_at=normalized.created_at,
                payload={"request": normalized.to_dict()},
            )

        transaction = self._journal.transact(
            prepare=prepare,
            project=lambda events: _project(
                events,
                verifier=self._verifier,
            ),
        )
        return _state_from_projection(
            transaction.projection,
            normalized.request_id,
        )

    def decision_subject_sha256(
        self,
        request_id: str,
        *,
        decision_id: str,
        decision: HumanDecision | str,
        reason: str,
        decided_at: str,
        operator: OperatorIdentity | Mapping[str, Any],
        expected_run_id: str,
        expected_lease_generation: int,
        expected_context_sha256: str,
        expected_action_sha256: str,
        expected_policy_sha256: str,
        expected_authorization_sha256: str,
    ) -> str:
        """在 currentness 校验后生成外部决策审批 subject。"""

        state = self._bound_state(
            request_id,
            expected_run_id=expected_run_id,
            expected_lease_generation=expected_lease_generation,
            expected_context_sha256=expected_context_sha256,
            expected_action_sha256=expected_action_sha256,
            expected_policy_sha256=expected_policy_sha256,
            expected_authorization_sha256=expected_authorization_sha256,
        )
        if state.decision is not None:
            raise HITLStoreError(
                "request_already_decided",
                "请求已有终局 decision",
                request_id=request_id,
            )
        normalized_time = canonical_timestamp(
            decided_at,
            path="$.decided_at",
        )
        now = self._trusted_now()
        if now >= parse_timestamp(state.request.expires_at):
            raise HITLStoreError(
                "request_expired",
                "HITL request 已超过可信当前时间",
                request_id=request_id,
            )
        if parse_timestamp(normalized_time) > now:
            raise HITLStoreError(
                "decision_time_in_future",
                "decided_at 不得晚于可信当前时间",
                request_id=request_id,
            )
        if parse_timestamp(normalized_time) < parse_timestamp(
            state.request.created_at,
        ) or parse_timestamp(normalized_time) >= parse_timestamp(
            state.request.expires_at,
        ):
            raise HITLStoreError(
                "request_expired",
                "decided_at 不在请求有效窗口内",
                request_id=request_id,
            )
        return hitl_decision_subject_sha256(
            state.request,
            decision_id=decision_id,
            decision=decision,
            reason=reason,
            decided_at=normalized_time,
            operator=_operator(operator),
        )

    def record_decision(
        self,
        decision: HITLDecision | Mapping[str, Any],
        *,
        expected_run_id: str,
        expected_lease_generation: int,
        expected_context_sha256: str,
        expected_action_sha256: str,
        expected_policy_sha256: str,
        expected_authorization_sha256: str,
    ) -> HITLState:
        """原子记录终局决策；完全相同重试幂等，任意差异均冲突。"""

        normalized = _decision(decision)
        self._verifier.verify(normalized.approval_receipt)
        now = self._trusted_now()
        if parse_timestamp(normalized.approval_receipt.approved_at) > now:
            raise HITLStoreError(
                "approval_time_in_future",
                "approval receipt 时间晚于可信当前时间",
                request_id=normalized.request_id,
            )
        expected = _expected_bindings(
            expected_run_id=expected_run_id,
            expected_lease_generation=expected_lease_generation,
            expected_context_sha256=expected_context_sha256,
            expected_action_sha256=expected_action_sha256,
            expected_policy_sha256=expected_policy_sha256,
            expected_authorization_sha256=expected_authorization_sha256,
        )

        def prepare(
            events: tuple[JournalEvent, ...],
        ) -> JournalMutation | None:
            states = _reduce_states(
                events,
                verifier=self._verifier,
            )
            state = states.get(normalized.request_id)
            if state is None:
                raise HITLStoreError(
                    "request_missing",
                    "decision 指向的请求不存在",
                    request_id=normalized.request_id,
                )
            _assert_current(
                state.request,
                expected,
            )
            validate_hitl_decision(state.request, normalized)
            if state.decision is not None:
                if (
                    state.decision.canonical_sha256
                    == normalized.canonical_sha256
                ):
                    return None
                raise HITLStoreError(
                    "decision_conflict",
                    "请求已有不同终局 decision",
                    request_id=normalized.request_id,
                )
            if now >= parse_timestamp(state.request.expires_at):
                raise HITLStoreError(
                    "request_expired",
                    "不能在 HITL request 过期后记录新 decision",
                    request_id=normalized.request_id,
                )
            _reject_reused_receipt(
                states,
                normalized,
            )
            return JournalMutation(
                event_type=DECISION_EVENT,
                occurred_at=normalized.decided_at,
                payload={"decision": normalized.to_dict()},
            )

        transaction = self._journal.transact(
            prepare=prepare,
            project=lambda events: _project(
                events,
                verifier=self._verifier,
            ),
        )
        return _state_from_projection(
            transaction.projection,
            normalized.request_id,
        )

    def consume_approved(
        self,
        request_id: str,
        *,
        consumption_id: str,
        expected_run_id: str,
        expected_lease_generation: int,
        expected_context_sha256: str,
        expected_action_sha256: str,
        expected_policy_sha256: str,
        expected_authorization_sha256: str,
    ) -> HITLState:
        """原子消费一次 approved decision；任何重放都失败关闭。"""

        normalized_id = _identifier("request_id", request_id)
        normalized_consumption_id = _identifier(
            "consumption_id",
            consumption_id,
        )
        expected = _expected_bindings(
            expected_run_id=expected_run_id,
            expected_lease_generation=expected_lease_generation,
            expected_context_sha256=expected_context_sha256,
            expected_action_sha256=expected_action_sha256,
            expected_policy_sha256=expected_policy_sha256,
            expected_authorization_sha256=expected_authorization_sha256,
        )
        now = self._trusted_now()
        consumed_at = now.isoformat().replace("+00:00", "Z")

        def prepare(
            events: tuple[JournalEvent, ...],
        ) -> JournalMutation:
            states = _reduce_states(
                events,
                verifier=self._verifier,
            )
            state = states.get(normalized_id)
            if state is None:
                raise HITLStoreError(
                    "request_missing",
                    "待消费 HITL request 不存在",
                    request_id=normalized_id,
                )
            _assert_current(state.request, expected)
            if state.consumption is not None:
                raise HITLStoreError(
                    "decision_already_consumed",
                    "approved decision 已被消费，禁止重放",
                    request_id=normalized_id,
                )
            if state.decision is None:
                raise HITLStoreError(
                    "decision_missing",
                    "HITL request 尚无终局 decision",
                    request_id=normalized_id,
                )
            if state.decision.decision is not HumanDecision.APPROVED:
                raise HITLStoreError(
                    "decision_not_approved",
                    "只有 approved decision 可以消费",
                    request_id=normalized_id,
                )
            if now >= parse_timestamp(state.request.expires_at):
                raise HITLStoreError(
                    "request_expired",
                    "approved decision 未在 request 有效期内消费",
                    request_id=normalized_id,
                )
            for prior in states.values():
                if (
                    prior.consumption is not None
                    and prior.consumption.consumption_id
                    == normalized_consumption_id
                ):
                    raise HITLStoreError(
                        "consumption_id_reused",
                        "consumption_id 已用于其他 decision",
                        request_id=normalized_id,
                    )
            consumption = HITLConsumption(
                consumption_id=normalized_consumption_id,
                request_id=state.request.request_id,
                decision_id=state.decision.decision_id,
                run_id=state.request.run_id,
                lease_generation=state.request.lease_generation,
                context_sha256=state.request.context_sha256,
                action_sha256=state.request.action_sha256,
                policy_sha256=state.request.policy_sha256,
                authorization_sha256=(
                    state.request.authorization_sha256
                ),
                consumed_at=consumed_at,
            )
            return JournalMutation(
                event_type=CONSUMPTION_EVENT,
                occurred_at=consumed_at,
                payload={"consumption": consumption.to_dict()},
            )

        transaction = self._journal.transact(
            prepare=prepare,
            project=lambda events: _project(
                events,
                verifier=self._verifier,
            ),
        )
        if (
            transaction.appended
            and self._checkpoint_verifier.mode == "production"
        ):
            assurance = self._checkpoint_verifier.assurance
            raise HumanControlJournalError(
                "checkpoint_refresh_required",
                (
                    "consumption 已持久化但尚未被外部 checkpoint 覆盖；"
                    "在刷新 checkpoint 并通过 hitl-resume 确认前不得执行 action"
                ),
                covered_count=assurance["covered_count"],
                current_count=assurance["current_count"],
                tail_count=assurance["tail_count"],
            )
        return _state_from_projection(
            transaction.projection,
            normalized_id,
        )

    def resume(
        self,
        request_id: str,
        *,
        expected_run_id: str,
        expected_lease_generation: int,
        expected_context_sha256: str,
        expected_action_sha256: str,
        expected_policy_sha256: str,
        expected_authorization_sha256: str,
    ) -> HITLState:
        """恢复请求；陈旧绑定失败关闭，未决过期请求不得继续。"""

        state = self._bound_state(
            request_id,
            expected_run_id=expected_run_id,
            expected_lease_generation=expected_lease_generation,
            expected_context_sha256=expected_context_sha256,
            expected_action_sha256=expected_action_sha256,
            expected_policy_sha256=expected_policy_sha256,
            expected_authorization_sha256=expected_authorization_sha256,
        )
        if (
            state.consumption is None
            and self._trusted_now()
            >= parse_timestamp(state.request.expires_at)
        ):
            raise HITLStoreError(
                "request_expired",
                "未决 HITL request 已过期",
                request_id=request_id,
            )
        return state

    def redeem_dispatch(
        self,
        redemption: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], bool]:
        """Atomically redeem one consumed approval for one execution intent.

        The append intentionally makes the checkpoint used to authorize the
        redemption stale.  The caller may dispatch exactly once from the
        transaction that reports ``appended=True``; every later read requires
        a refreshed checkpoint and observes the durable redemption.
        """

        normalized = _dispatch_redemption(redemption)
        now = self._trusted_now()
        redeemed_at = parse_timestamp(normalized["redeemed_at"])
        if redeemed_at > now:
            raise HITLStoreError(
                "redemption_time_in_future",
                "dispatch redemption time is later than trusted time",
                request_id=normalized["request_id"],
            )

        def prepare(
            events: tuple[JournalEvent, ...],
        ) -> JournalMutation | None:
            states = _reduce_states(
                events,
                verifier=self._verifier,
            )
            state = states.get(normalized["request_id"])
            if (
                state is None
                or state.decision is None
                or state.consumption is None
            ):
                raise HITLStoreError(
                    "redemption_consumption_missing",
                    "dispatch redemption requires a consumed approved decision",
                    request_id=normalized["request_id"],
                )
            _assert_redemption_matches_state(normalized, state)
            prior = next(
                (
                    item
                    for item in _redemptions(events)
                    if item["consumption_id"]
                    == normalized["consumption_id"]
                ),
                None,
            )
            if prior is None:
                return JournalMutation(
                    event_type=DISPATCH_REDEMPTION_EVENT,
                    occurred_at=normalized["redeemed_at"],
                    payload={"redemption": normalized},
                )
            stable_fields = set(normalized) - {"redeemed_at"}
            if any(
                prior.get(name) != normalized.get(name)
                for name in stable_fields
            ):
                raise HITLStoreError(
                    "redemption_conflict",
                    "consumption is already bound to another execution intent",
                    request_id=normalized["request_id"],
                )
            return None

        transaction = self._journal.transact(
            prepare=prepare,
            project=lambda events: _project(
                events,
                verifier=self._verifier,
            ),
        )
        projected = next(
            (
                dict(item)
                for item in transaction.projection.get(
                    "redemptions",
                    [],
                )
                if item.get("redemption_id")
                == normalized["redemption_id"]
            ),
            None,
        )
        if projected is None:
            raise HITLStoreError(
                "redemption_projection_missing",
                "durable projection lacks the dispatch redemption",
                request_id=normalized["request_id"],
            )
        return (
            projected,
            dict(transaction.projection),
            transaction.appended,
        )

    def pending(
        self,
        *,
        expected_run_id: str,
        expected_lease_generation: int,
        expected_context_sha256: str,
        expected_policy_sha256: str,
        expected_authorization_sha256: str,
    ) -> tuple[HITLState, ...]:
        """列出当前 run/context 下仍有效的未决请求。"""

        run_id = _identifier("expected_run_id", expected_run_id)
        lease_generation = _generation(
            "expected_lease_generation",
            expected_lease_generation,
        )
        context_sha256 = _sha256(
            "expected_context_sha256",
            expected_context_sha256,
        )
        policy_sha256 = _sha256(
            "expected_policy_sha256",
            expected_policy_sha256,
        )
        authorization_sha256 = _sha256(
            "expected_authorization_sha256",
            expected_authorization_sha256,
        )
        now = self._trusted_now()
        states = _reduce_states(
            self._journal.load_events(),
            verifier=self._verifier,
        )
        result = []
        for state in states.values():
            request = state.request
            if request.run_id != run_id:
                continue
            if request.lease_generation != lease_generation:
                continue
            if request.context_sha256 != context_sha256:
                continue
            if request.policy_sha256 != policy_sha256:
                continue
            if request.authorization_sha256 != authorization_sha256:
                continue
            if state.decision is not None:
                continue
            if now >= parse_timestamp(request.expires_at):
                continue
            result.append(state)
        return tuple(
            sorted(result, key=lambda item: item.request.request_id),
        )

    def projection(self) -> dict[str, Any]:
        """从 journal 重建完整请求/决策 projection。"""

        return _project(
            self._journal.load_events(),
            verifier=self._verifier,
        )

    def _bound_state(
        self,
        request_id: str,
        *,
        expected_run_id: str,
        expected_lease_generation: int,
        expected_context_sha256: str,
        expected_action_sha256: str,
        expected_policy_sha256: str,
        expected_authorization_sha256: str,
    ) -> HITLState:
        normalized_id = _identifier("request_id", request_id)
        states = _reduce_states(
            self._journal.load_events(),
            verifier=self._verifier,
        )
        state = states.get(normalized_id)
        if state is None:
            raise HITLStoreError(
                "request_missing",
                "HITL request 不存在",
                request_id=normalized_id,
            )
        _assert_current(
            state.request,
            _expected_bindings(
                expected_run_id=expected_run_id,
                expected_lease_generation=expected_lease_generation,
                expected_context_sha256=expected_context_sha256,
                expected_action_sha256=expected_action_sha256,
                expected_policy_sha256=expected_policy_sha256,
                expected_authorization_sha256=expected_authorization_sha256,
            ),
        )
        return state

    def _trusted_now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise HITLStoreError(
                "trusted_clock_invalid",
                "trusted clock 必须返回 timezone-aware datetime",
            )
        return value.astimezone(UTC)


def _project(
    events: tuple[JournalEvent, ...],
    *,
    verifier: ApprovalVerifier,
) -> dict[str, Any]:
    states = _reduce_states(events, verifier=verifier)
    body = {
        "schema_version": HUMAN_CONTROL_SCHEMA_VERSION,
        "sequence": len(events),
        "last_event_hash": (
            events[-1].event_hash
            if events
            else GENESIS_HASH
        ),
        "requests": [
            states[key].to_dict()
            for key in sorted(states)
        ],
        "redemptions": _redemptions(events),
    }
    return {
        **body,
        "projection_sha256": canonical_sha256(body),
    }


def _reduce_states(
    events: tuple[JournalEvent, ...],
    *,
    verifier: ApprovalVerifier,
) -> dict[str, HITLState]:
    states: dict[str, HITLState] = {}
    for event in events:
        if event.event_type == REQUEST_EVENT:
            payload = _strict_payload(
                event.payload,
                {"request"},
                event=event,
            )
            request = HITLRequest.from_dict(payload["request"])
            if event.occurred_at != request.created_at:
                raise HITLStoreError(
                    "request_event_time_mismatch",
                    "request event 时间与 request.created_at 不一致",
                    request_id=request.request_id,
                )
            if request.request_id in states:
                raise HITLStoreError(
                    "request_duplicate",
                    "journal 包含重复 request_id",
                    request_id=request.request_id,
                )
            states[request.request_id] = HITLState(
                request=request,
                decision=None,
                consumption=None,
            )
            continue
        if event.event_type == DECISION_EVENT:
            payload = _strict_payload(
                event.payload,
                {"decision"},
                event=event,
            )
            decision = HITLDecision.from_dict(payload["decision"])
            verifier.verify(decision.approval_receipt)
            state = states.get(decision.request_id)
            if state is None:
                raise HITLStoreError(
                    "decision_orphan",
                    "decision event 指向不存在的 request",
                    request_id=decision.request_id,
                )
            if state.decision is not None:
                raise HITLStoreError(
                    "decision_duplicate",
                    "journal 中一个 request 存在多个 decision",
                    request_id=decision.request_id,
                )
            if event.occurred_at != decision.decided_at:
                raise HITLStoreError(
                    "decision_event_time_mismatch",
                    "decision event 时间与 decided_at 不一致",
                    request_id=decision.request_id,
                )
            validate_hitl_decision(state.request, decision)
            states[decision.request_id] = HITLState(
                request=state.request,
                decision=decision,
                consumption=None,
            )
            continue
        if event.event_type == CONSUMPTION_EVENT:
            payload = _strict_payload(
                event.payload,
                {"consumption"},
                event=event,
            )
            consumption = HITLConsumption.from_dict(
                payload["consumption"],
            )
            state = states.get(consumption.request_id)
            if state is None or state.decision is None:
                raise HITLStoreError(
                    "consumption_orphan",
                    "consumption event 缺少对应 decision",
                    request_id=consumption.request_id,
                )
            if state.consumption is not None:
                raise HITLStoreError(
                    "consumption_duplicate",
                    "journal 中一个 decision 存在多个 consumption",
                    request_id=consumption.request_id,
                )
            if state.decision.decision is not HumanDecision.APPROVED:
                raise HITLStoreError(
                    "consumption_not_approved",
                    "rejected decision 不得出现 consumption event",
                    request_id=consumption.request_id,
                )
            expected = {
                "request_id": state.request.request_id,
                "decision_id": state.decision.decision_id,
                "run_id": state.request.run_id,
                "lease_generation": state.request.lease_generation,
                "context_sha256": state.request.context_sha256,
                "action_sha256": state.request.action_sha256,
                "policy_sha256": state.request.policy_sha256,
                "authorization_sha256": (
                    state.request.authorization_sha256
                ),
            }
            for field_name, expected_value in expected.items():
                if getattr(consumption, field_name) != expected_value:
                    raise HITLStoreError(
                        "consumption_binding_mismatch",
                        (
                            f"consumption.{field_name} "
                            "与 request/decision 不一致"
                        ),
                        request_id=consumption.request_id,
                    )
            if event.occurred_at != consumption.consumed_at:
                raise HITLStoreError(
                    "consumption_event_time_mismatch",
                    "consumption event 时间不一致",
                    request_id=consumption.request_id,
                )
            if parse_timestamp(consumption.consumed_at) >= parse_timestamp(
                state.request.expires_at,
            ):
                raise HITLStoreError(
                    "consumption_after_expiry",
                    "consumption 必须早于 request.expires_at",
                    request_id=consumption.request_id,
                )
            states[consumption.request_id] = HITLState(
                request=state.request,
                decision=state.decision,
                consumption=consumption,
            )
            continue
        if event.event_type == DISPATCH_REDEMPTION_EVENT:
            payload = _strict_payload(
                event.payload,
                {"redemption"},
                event=event,
            )
            redemption = _dispatch_redemption(
                payload["redemption"]
            )
            state = states.get(redemption["request_id"])
            if (
                state is None
                or state.decision is None
                or state.consumption is None
            ):
                raise HITLStoreError(
                    "redemption_orphan",
                    "dispatch redemption lacks a consumed approved decision",
                    request_id=redemption["request_id"],
                )
            _assert_redemption_matches_state(redemption, state)
            if event.occurred_at != redemption["redeemed_at"]:
                raise HITLStoreError(
                    "redemption_event_time_mismatch",
                    "redemption event time does not match its payload",
                    request_id=redemption["request_id"],
                )
            for prior in _redemptions(events[: event.sequence - 1]):
                if (
                    prior["redemption_id"]
                    == redemption["redemption_id"]
                    or prior["consumption_id"]
                    == redemption["consumption_id"]
                ):
                    raise HITLStoreError(
                        "redemption_duplicate",
                        "journal contains a repeated redemption",
                        request_id=redemption["request_id"],
                    )
            continue
        raise HITLStoreError(
            "hitl_event_unknown",
            f"未知 HITL event_type：{event.event_type}",
        )
    return states


def _assert_current(
    request: HITLRequest,
    expected: Mapping[str, Any],
) -> None:
    for field_name, expected_value in expected.items():
        if getattr(request, field_name) != expected_value:
            raise HITLStoreError(
                f"{field_name}_stale",
                (
                    f"HITL request.{field_name} 与当前值不一致；"
                    "必须创建新请求"
                ),
                request_id=request.request_id,
            )


def _expected_bindings(
    *,
    expected_run_id: str,
    expected_lease_generation: int,
    expected_context_sha256: str,
    expected_action_sha256: str,
    expected_policy_sha256: str,
    expected_authorization_sha256: str,
) -> dict[str, Any]:
    return {
        "run_id": _identifier("expected_run_id", expected_run_id),
        "lease_generation": _generation(
            "expected_lease_generation",
            expected_lease_generation,
        ),
        "context_sha256": _sha256(
            "expected_context_sha256",
            expected_context_sha256,
        ),
        "action_sha256": _sha256(
            "expected_action_sha256",
            expected_action_sha256,
        ),
        "policy_sha256": _sha256(
            "expected_policy_sha256",
            expected_policy_sha256,
        ),
        "authorization_sha256": _sha256(
            "expected_authorization_sha256",
            expected_authorization_sha256,
        ),
    }


def _strict_payload(
    value: Mapping[str, Any],
    expected: set[str],
    *,
    event: JournalEvent,
) -> dict[str, Any]:
    payload = dict(value)
    unknown = sorted(set(payload) - expected)
    missing = sorted(expected - set(payload))
    if unknown:
        raise HITLStoreError(
            "hitl_event_fields_unknown",
            (
                f"event {event.sequence} 包含未知字段："
                f"{', '.join(unknown)}"
            ),
        )
    if missing:
        raise HITLStoreError(
            "hitl_event_fields_missing",
            (
                f"event {event.sequence} 缺少字段："
                f"{', '.join(missing)}"
            ),
        )
    return payload


_DISPATCH_REDEMPTION_FIELDS = {
    "schema_version",
    "kind",
    "not_evidence",
    "redemption_id",
    "request_id",
    "decision_id",
    "consumption_id",
    "run_id",
    "lease_generation",
    "plan_sha256",
    "context_sha256",
    "plan_audit_sha256",
    "tool_registry_sha256",
    "action_sha256",
    "policy_sha256",
    "authorization_sha256",
    "execution_intent_sha256",
    "approval_chain_sha256",
    "hitl_checkpoint_file_sha256",
    "hitl_checkpoint_event_count",
    "hitl_checkpoint_terminal_event_hash",
    "redeemed_at",
}


def _dispatch_redemption(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    payload = dict(value)
    if set(payload) != _DISPATCH_REDEMPTION_FIELDS:
        raise HITLStoreError(
            "redemption_schema_invalid",
            "dispatch redemption has unknown or missing fields",
            request_id=(
                payload.get("request_id")
                if isinstance(payload.get("request_id"), str)
                else None
            ),
        )
    if (
        payload["schema_version"] != 1
        or payload["kind"] != "qa_human_dispatch_redemption"
        or payload["not_evidence"] is not True
    ):
        raise HITLStoreError(
            "redemption_schema_invalid",
            "dispatch redemption kind/schema/not_evidence is invalid",
            request_id=payload.get("request_id"),
        )
    for field in (
        "redemption_id",
        "request_id",
        "decision_id",
        "consumption_id",
        "run_id",
    ):
        payload[field] = _identifier(field, payload[field])
    payload["lease_generation"] = _generation(
        "lease_generation",
        payload["lease_generation"],
    )
    if (
        isinstance(payload["hitl_checkpoint_event_count"], bool)
        or not isinstance(
            payload["hitl_checkpoint_event_count"],
            int,
        )
        or payload["hitl_checkpoint_event_count"] < 0
    ):
        raise HITLStoreError(
            "redemption_checkpoint_count_invalid",
            "dispatch redemption checkpoint count must be non-negative",
            request_id=payload["request_id"],
        )
    for field in (
        "plan_sha256",
        "context_sha256",
        "plan_audit_sha256",
        "tool_registry_sha256",
        "action_sha256",
        "policy_sha256",
        "authorization_sha256",
        "execution_intent_sha256",
        "approval_chain_sha256",
        "hitl_checkpoint_file_sha256",
        "hitl_checkpoint_terminal_event_hash",
    ):
        payload[field] = _sha256(field, payload[field])
    payload["redeemed_at"] = canonical_timestamp(
        payload["redeemed_at"],
        path="$.redeemed_at",
    )
    return payload


def _assert_redemption_matches_state(
    redemption: Mapping[str, Any],
    state: HITLState,
) -> None:
    assert state.decision is not None
    assert state.consumption is not None
    expected = {
        "request_id": state.request.request_id,
        "decision_id": state.decision.decision_id,
        "consumption_id": state.consumption.consumption_id,
        "run_id": state.request.run_id,
        "lease_generation": state.request.lease_generation,
        "context_sha256": state.request.context_sha256,
        "action_sha256": state.request.action_sha256,
        "policy_sha256": state.request.policy_sha256,
        "authorization_sha256": (
            state.request.authorization_sha256
        ),
    }
    for field, expected_value in expected.items():
        if redemption.get(field) != expected_value:
            raise HITLStoreError(
                "redemption_binding_mismatch",
                f"dispatch redemption {field} does not match consumption",
                request_id=state.request.request_id,
            )
    if state.decision.decision is not HumanDecision.APPROVED:
        raise HITLStoreError(
            "redemption_not_approved",
            "dispatch redemption requires an approved decision",
            request_id=state.request.request_id,
        )
    if parse_timestamp(redemption["redeemed_at"]) < parse_timestamp(
        state.consumption.consumed_at
    ):
        raise HITLStoreError(
            "redemption_before_consumption",
            "dispatch redemption cannot predate approval consumption",
            request_id=state.request.request_id,
        )


def _redemptions(
    events: tuple[JournalEvent, ...],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for event in events:
        if event.event_type != DISPATCH_REDEMPTION_EVENT:
            continue
        payload = _strict_payload(
            event.payload,
            {"redemption"},
            event=event,
        )
        redemption = _dispatch_redemption(
            payload["redemption"]
        )
        if event.occurred_at != redemption["redeemed_at"]:
            raise HITLStoreError(
                "redemption_event_time_mismatch",
                "redemption event time does not match its payload",
                request_id=redemption["request_id"],
            )
        result.append(
            {
                **redemption,
                "journal_event_sequence": event.sequence,
                "journal_event_sha256": event.event_hash,
            }
        )
    return result


def _request(
    value: HITLRequest | Mapping[str, Any],
) -> HITLRequest:
    if isinstance(value, HITLRequest):
        return value
    return HITLRequest.from_dict(value)


def _decision(
    value: HITLDecision | Mapping[str, Any],
) -> HITLDecision:
    if isinstance(value, HITLDecision):
        return value
    return HITLDecision.from_dict(value)


def _operator(
    value: OperatorIdentity | Mapping[str, Any],
) -> OperatorIdentity:
    if isinstance(value, OperatorIdentity):
        return value
    return OperatorIdentity.from_dict(value)


def _identifier(name: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or _IDENTIFIER_PATTERN.fullmatch(value) is None
    ):
        raise HumanControlContractError(
            "identifier_invalid",
            f"{name} 不是合法标识符",
            path=f"$.{name}",
        )
    return value


def _sha256(name: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or _SHA256_PATTERN.fullmatch(value) is None
    ):
        raise HumanControlContractError(
            "sha256_invalid",
            f"{name} 必须是 64 位小写 SHA-256",
            path=f"$.{name}",
        )
    return value


def _generation(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise HumanControlContractError(
            "lease_generation_invalid",
            f"{name} 必须是正整数",
            path=f"$.{name}",
        )
    return value


def _state_from_projection(
    projection: Mapping[str, Any],
    request_id: str,
) -> HITLState:
    for raw in projection.get("requests", []):
        request = raw.get("request")
        if (
            isinstance(request, dict)
            and request.get("request_id") == request_id
        ):
            decision = raw.get("decision")
            consumption = raw.get("consumption")
            return HITLState(
                request=HITLRequest.from_dict(request),
                decision=(
                    HITLDecision.from_dict(decision)
                    if decision is not None
                    else None
                ),
                consumption=(
                    HITLConsumption.from_dict(consumption)
                    if consumption is not None
                    else None
                ),
            )
    raise HITLStoreError(
        "hitl_projection_missing",
        "projection 未包含已提交 HITL request",
        request_id=request_id,
    )


def _reject_reused_receipt(
    states: Mapping[str, HITLState],
    decision: HITLDecision,
) -> None:
    for state in states.values():
        prior = state.decision
        if (
            prior is not None
            and (
                prior.approval_receipt.receipt_id
                == decision.approval_receipt.receipt_id
                or prior.approval_receipt.external_receipt_sha256
                == decision.approval_receipt.external_receipt_sha256
            )
        ):
            raise HITLStoreError(
                "approval_receipt_reused",
                "approval receipt 已绑定其他 HITL decision",
                request_id=decision.request_id,
            )
