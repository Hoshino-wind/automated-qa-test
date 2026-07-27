"""人工确认 Knowledge Store：journal 是状态源，snapshot 只是投影。"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from qa_core.hitl._journal import (
    GENESIS_HASH,
    AppendOnlyJsonJournal,
    JournalEvent,
    JournalMutation,
)
from qa_core.hitl.auth import ApprovalVerifier
from qa_core.hitl.checkpoint import JournalCheckpointVerifier
from qa_core.hitl.contracts import (
    ApprovalReceipt,
    OperatorIdentity,
    canonical_sha256,
    parse_timestamp,
)

from .contracts import (
    KNOWLEDGE_SCHEMA_VERSION,
    KnowledgeCandidate,
    KnowledgeEntry,
    build_knowledge_entry,
    knowledge_revoke_subject_sha256,
    knowledge_write_subject_sha256,
    normalize_knowledge_scope,
    revoke_knowledge_entry,
)

WRITE_EVENT = "knowledge_written"
REVOKE_EVENT = "knowledge_revoked"


class KnowledgeStoreError(RuntimeError):
    """Knowledge Store 状态冲突或完整性错误。"""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        entry_id: str | None = None,
        version: int | None = None,
    ) -> None:
        self.code = code
        self.entry_id = entry_id
        self.version = version
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": KNOWLEDGE_SCHEMA_VERSION,
            "error": "knowledge_store_error",
            "code": self.code,
            "message": str(self),
        }
        if self.entry_id is not None:
            payload["entry_id"] = self.entry_id
        if self.version is not None:
            payload["version"] = self.version
        return payload


class KnowledgeStore:
    """只暴露已确认知识的版本化写入、撤销与安全检索。"""

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
            name="knowledge",
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

    def write(
        self,
        candidate: KnowledgeCandidate | Mapping[str, Any],
        *,
        operator: OperatorIdentity | Mapping[str, Any],
        approval_receipt: ApprovalReceipt | Mapping[str, Any],
    ) -> KnowledgeEntry:
        """写入一个连续版本；完全相同的重试是幂等 no-op。"""

        normalized_candidate = _candidate(candidate)
        normalized_operator = _operator(operator)
        normalized_receipt = _receipt(approval_receipt)
        self._verifier.verify(normalized_receipt)
        now = self._trusted_now()
        if parse_timestamp(normalized_receipt.approved_at) > now:
            raise KnowledgeStoreError(
                "approval_time_in_future",
                "approval receipt 时间晚于可信当前时间",
                entry_id=normalized_candidate.entry_id,
                version=normalized_candidate.version,
            )
        committed_at = now.isoformat().replace("+00:00", "Z")
        entry = build_knowledge_entry(
            normalized_candidate,
            operator=normalized_operator,
            approval_receipt=normalized_receipt,
            committed_at=committed_at,
        )

        def prepare(
            events: tuple[JournalEvent, ...],
        ) -> JournalMutation | None:
            entries = _reduce_entries(
                events,
                verifier=self._verifier,
            )
            key = (entry.entry_id, entry.version)
            existing = entries.get(key)
            if existing is not None:
                if (
                    existing.candidate.canonical_sha256
                    == normalized_candidate.canonical_sha256
                    and existing.created_by == normalized_operator
                    and existing.approval_receipt
                    == normalized_receipt
                ):
                    return None
                raise KnowledgeStoreError(
                    "knowledge_write_conflict",
                    "同一 entry/version 已存在不同内容",
                    entry_id=entry.entry_id,
                    version=entry.version,
                )
            _reject_reused_receipt(
                entries,
                entry.approval_receipt,
            )
            prior_versions = [
                version
                for candidate_id, version in entries
                if candidate_id == entry.entry_id
            ]
            expected_version = (
                max(prior_versions) + 1
                if prior_versions
                else 1
            )
            if entry.version != expected_version:
                raise KnowledgeStoreError(
                    "knowledge_version_conflict",
                    (
                        f"期望 version={expected_version}，"
                        f"实际为 {entry.version}"
                    ),
                    entry_id=entry.entry_id,
                    version=entry.version,
                )
            if prior_versions:
                prior = entries[
                    (entry.entry_id, max(prior_versions))
                ]
                if parse_timestamp(entry.committed_at) < parse_timestamp(
                    prior.committed_at,
                ):
                    raise KnowledgeStoreError(
                        "knowledge_time_regression",
                        "新版本 committed_at 不得早于前一版本",
                        entry_id=entry.entry_id,
                        version=entry.version,
                    )
            return JournalMutation(
                event_type=WRITE_EVENT,
                occurred_at=entry.committed_at,
                payload={"entry": entry.to_dict()},
            )

        transaction = self._journal.transact(
            prepare=prepare,
            project=lambda events: _project(
                events,
                verifier=self._verifier,
            ),
        )
        return _entry_from_projection(
            transaction.projection,
            entry.entry_id,
            entry.version,
        )

    def write_subject_sha256(
        self,
        candidate: KnowledgeCandidate | Mapping[str, Any],
        *,
        operator: OperatorIdentity | Mapping[str, Any],
    ) -> str:
        """为外部审批系统生成 write subject hash。"""

        return knowledge_write_subject_sha256(
            _candidate(candidate),
            operator=_operator(operator),
        )

    def revoke_subject_sha256(
        self,
        entry_id: str,
        version: int,
        *,
        operator: OperatorIdentity | Mapping[str, Any],
    ) -> str:
        """为指定活动版本生成 revoke subject hash。"""

        entry_id = _event_entry_id(entry_id)
        version = _event_version(version)
        entry = self.get_history_entry(entry_id, version)
        if entry.revoked_at is not None:
            raise KnowledgeStoreError(
                "knowledge_already_revoked",
                "Knowledge entry 已撤销",
                entry_id=entry_id,
                version=version,
            )
        return knowledge_revoke_subject_sha256(
            entry,
            operator=_operator(operator),
        )

    def revoke(
        self,
        entry_id: str,
        version: int,
        *,
        operator: OperatorIdentity | Mapping[str, Any],
        approval_receipt: ApprovalReceipt | Mapping[str, Any],
    ) -> KnowledgeEntry:
        """撤销一个明确版本；相同撤销重试幂等，冲突撤销失败关闭。"""

        entry_id = _event_entry_id(entry_id)
        version = _event_version(version)
        now = self._trusted_now()
        normalized_time = now.isoformat().replace("+00:00", "Z")
        normalized_operator = _operator(operator)
        normalized_receipt = _receipt(approval_receipt)
        self._verifier.verify(normalized_receipt)
        if parse_timestamp(normalized_receipt.approved_at) > now:
            raise KnowledgeStoreError(
                "approval_time_in_future",
                "approval receipt 时间晚于可信当前时间",
                entry_id=entry_id,
                version=version,
            )

        def prepare(
            events: tuple[JournalEvent, ...],
        ) -> JournalMutation | None:
            entries = _reduce_entries(
                events,
                verifier=self._verifier,
            )
            key = (entry_id, version)
            existing = entries.get(key)
            if existing is None:
                raise KnowledgeStoreError(
                    "knowledge_entry_missing",
                    "待撤销 Knowledge entry 不存在",
                    entry_id=entry_id,
                    version=version,
                )
            active = (
                existing.without_revocation()
                if existing.revoked_at is not None
                else existing
            )
            revoke_knowledge_entry(
                active,
                revoked_at=normalized_time,
                operator=normalized_operator,
                approval_receipt=normalized_receipt,
            )
            if existing.revoked_at is not None:
                if (
                    existing.revoked_by == normalized_operator
                    and existing.revocation_receipt
                    == normalized_receipt
                ):
                    return None
                raise KnowledgeStoreError(
                    "knowledge_revocation_conflict",
                    "同一 Knowledge entry 已有不同撤销决定",
                    entry_id=entry_id,
                    version=version,
                )
            _reject_reused_receipt(
                entries,
                normalized_receipt,
            )
            return JournalMutation(
                event_type=REVOKE_EVENT,
                occurred_at=normalized_time,
                payload={
                    "entry_id": entry_id,
                    "version": version,
                    "entry_sha256": existing.canonical_sha256,
                    "revoked_at": normalized_time,
                    "operator": normalized_operator.to_dict(),
                    "approval_receipt": normalized_receipt.to_dict(),
                },
            )

        transaction = self._journal.transact(
            prepare=prepare,
            project=lambda events: _project(
                events,
                verifier=self._verifier,
            ),
        )
        return _entry_from_projection(
            transaction.projection,
            entry_id,
            version,
        )

    def query(
        self,
        *,
        scope: tuple[str, ...] | list[str],
    ) -> tuple[KnowledgeEntry, ...]:
        """返回安全可用的最新版本，过滤 future/expired/revoked/out-of-scope。"""

        requested_scope = set(normalize_knowledge_scope(scope))
        query_time = self._trusted_now()
        entries = _reduce_entries(
            self._journal.load_events(),
            verifier=self._verifier,
        )
        latest: dict[str, KnowledgeEntry] = {}
        for entry in entries.values():
            prior = latest.get(entry.entry_id)
            if prior is None or entry.version > prior.version:
                latest[entry.entry_id] = entry
        result = []
        for entry in latest.values():
            if entry.revoked_at is not None:
                continue
            if parse_timestamp(entry.committed_at) > query_time:
                continue
            if (
                entry.expires_at is not None
                and parse_timestamp(entry.expires_at) <= query_time
            ):
                continue
            if set(entry.scope) != requested_scope:
                continue
            result.append(entry)
        return tuple(
            sorted(
                result,
                key=lambda item: (item.entry_id, item.version),
            ),
        )

    def get_history_entry(
        self,
        entry_id: str,
        version: int,
    ) -> KnowledgeEntry:
        """审计接口：读取历史版本，不代表其当前可用于 Context。"""

        entry_id = _event_entry_id(entry_id)
        version = _event_version(version)
        entries = _reduce_entries(
            self._journal.load_events(),
            verifier=self._verifier,
        )
        try:
            return entries[(entry_id, version)]
        except KeyError as exc:
            raise KnowledgeStoreError(
                "knowledge_entry_missing",
                "Knowledge entry 不存在",
                entry_id=entry_id,
                version=version,
            ) from exc

    def history(self) -> tuple[KnowledgeEntry, ...]:
        """返回全部版本用于审计；调用方不得把它当安全检索接口。"""

        entries = _reduce_entries(
            self._journal.load_events(),
            verifier=self._verifier,
        )
        return tuple(
            entries[key]
            for key in sorted(entries)
        )

    def projection(self) -> dict[str, Any]:
        """从 journal 重建 projection，拒绝使用孤立 snapshot。"""

        return _project(
            self._journal.load_events(),
            verifier=self._verifier,
        )

    def _trusted_now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise KnowledgeStoreError(
                "trusted_clock_invalid",
                "trusted clock 必须返回 timezone-aware datetime",
            )
        return value.astimezone(UTC)


def _project(
    events: tuple[JournalEvent, ...],
    *,
    verifier: ApprovalVerifier,
) -> dict[str, Any]:
    entries = _reduce_entries(events, verifier=verifier)
    body = {
        "schema_version": KNOWLEDGE_SCHEMA_VERSION,
        "sequence": len(events),
        "last_event_hash": (
            events[-1].event_hash
            if events
            else GENESIS_HASH
        ),
        "entries": [
            entries[key].to_dict()
            for key in sorted(entries)
        ],
    }
    return {
        **body,
        "projection_sha256": canonical_sha256(body),
    }


def _reduce_entries(
    events: tuple[JournalEvent, ...],
    *,
    verifier: ApprovalVerifier,
) -> dict[tuple[str, int], KnowledgeEntry]:
    entries: dict[tuple[str, int], KnowledgeEntry] = {}
    for event in events:
        if event.event_type == WRITE_EVENT:
            payload = _strict_payload(
                event.payload,
                {"entry"},
                event=event,
            )
            entry = KnowledgeEntry.from_dict(
                payload["entry"],
                path=f"$.events[{event.sequence}].payload.entry",
            )
            verifier.verify(entry.approval_receipt)
            if entry.revoked_at is not None:
                raise KnowledgeStoreError(
                    "knowledge_write_pre_revoked",
                    "write event 不得直接写入已撤销条目",
                    entry_id=entry.entry_id,
                    version=entry.version,
                )
            if event.occurred_at != entry.committed_at:
                raise KnowledgeStoreError(
                    "knowledge_event_time_mismatch",
                    "write event occurred_at 与 entry.committed_at 不一致",
                    entry_id=entry.entry_id,
                    version=entry.version,
                )
            key = (entry.entry_id, entry.version)
            if key in entries:
                raise KnowledgeStoreError(
                    "knowledge_duplicate_version",
                    "journal 包含重复 Knowledge version",
                    entry_id=entry.entry_id,
                    version=entry.version,
                )
            prior_versions = [
                version
                for candidate_id, version in entries
                if candidate_id == entry.entry_id
            ]
            expected = max(prior_versions) + 1 if prior_versions else 1
            if entry.version != expected:
                raise KnowledgeStoreError(
                    "knowledge_version_chain_broken",
                    "journal 中 Knowledge version 不连续",
                    entry_id=entry.entry_id,
                    version=entry.version,
                )
            entries[key] = entry
            continue
        if event.event_type == REVOKE_EVENT:
            payload = _strict_payload(
                event.payload,
                {
                    "entry_id",
                    "version",
                    "entry_sha256",
                    "revoked_at",
                    "operator",
                    "approval_receipt",
                },
                event=event,
            )
            event_entry_id = _event_entry_id(payload["entry_id"])
            event_version = _event_version(payload["version"])
            key = (event_entry_id, event_version)
            existing = entries.get(key)
            if existing is None:
                raise KnowledgeStoreError(
                    "knowledge_revocation_orphan",
                    "revoke event 指向不存在的 Knowledge entry",
                    entry_id=event_entry_id,
                    version=event_version,
                )
            if existing.revoked_at is not None:
                raise KnowledgeStoreError(
                    "knowledge_duplicate_revocation",
                    "journal 包含重复撤销事件",
                    entry_id=existing.entry_id,
                    version=existing.version,
                )
            if payload["entry_sha256"] != existing.canonical_sha256:
                raise KnowledgeStoreError(
                    "knowledge_revocation_hash_drift",
                    "revoke event 绑定的 entry hash 已漂移",
                    entry_id=existing.entry_id,
                    version=existing.version,
                )
            if event.occurred_at != payload["revoked_at"]:
                raise KnowledgeStoreError(
                    "knowledge_event_time_mismatch",
                    "revoke event 时间不一致",
                    entry_id=existing.entry_id,
                    version=existing.version,
                )
            revocation_receipt = ApprovalReceipt.from_dict(
                payload["approval_receipt"],
            )
            verifier.verify(revocation_receipt)
            entries[key] = revoke_knowledge_entry(
                existing,
                revoked_at=payload["revoked_at"],
                operator=OperatorIdentity.from_dict(
                    payload["operator"],
                ),
                approval_receipt=revocation_receipt,
            )
            continue
        raise KnowledgeStoreError(
            "knowledge_event_unknown",
            f"未知 Knowledge event_type：{event.event_type}",
        )
    return entries


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
        raise KnowledgeStoreError(
            "knowledge_event_fields_unknown",
            (
                f"event {event.sequence} 包含未知字段："
                f"{', '.join(unknown)}"
            ),
        )
    if missing:
        raise KnowledgeStoreError(
            "knowledge_event_fields_missing",
            (
                f"event {event.sequence} 缺少字段："
                f"{', '.join(missing)}"
            ),
        )
    return payload


def _candidate(
    value: KnowledgeCandidate | Mapping[str, Any],
) -> KnowledgeCandidate:
    if isinstance(value, KnowledgeCandidate):
        return value
    return KnowledgeCandidate.from_dict(value)


def _operator(
    value: OperatorIdentity | Mapping[str, Any],
) -> OperatorIdentity:
    if isinstance(value, OperatorIdentity):
        return value
    return OperatorIdentity.from_dict(value)


def _receipt(
    value: ApprovalReceipt | Mapping[str, Any],
) -> ApprovalReceipt:
    if isinstance(value, ApprovalReceipt):
        return value
    return ApprovalReceipt.from_dict(value)


def _entry_from_projection(
    projection: Mapping[str, Any],
    entry_id: str,
    version: int,
) -> KnowledgeEntry:
    for raw in projection.get("entries", []):
        if (
            raw.get("entry_id") == entry_id
            and raw.get("version") == version
        ):
            return KnowledgeEntry.from_dict(raw)
    raise KnowledgeStoreError(
        "knowledge_projection_missing",
        "projection 未包含已提交 Knowledge entry",
        entry_id=entry_id,
        version=version,
    )


def _reject_reused_receipt(
    entries: Mapping[tuple[str, int], KnowledgeEntry],
    receipt: ApprovalReceipt,
) -> None:
    for entry in entries.values():
        prior_receipts = [entry.approval_receipt]
        if entry.revocation_receipt is not None:
            prior_receipts.append(entry.revocation_receipt)
        for prior in prior_receipts:
            if (
                prior.receipt_id == receipt.receipt_id
                or prior.external_receipt_sha256
                == receipt.external_receipt_sha256
            ):
                raise KnowledgeStoreError(
                    "approval_receipt_reused",
                    "approval receipt 已绑定其他 Knowledge 操作",
                    entry_id=entry.entry_id,
                    version=entry.version,
                )


def _event_entry_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or value != value.strip()
    ):
        raise KnowledgeStoreError(
            "knowledge_event_entry_id_invalid",
            "revoke event.entry_id 非法",
        )
    return value


def _event_version(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise KnowledgeStoreError(
            "knowledge_event_version_invalid",
            "revoke event.version 必须是正整数",
        )
    return value
