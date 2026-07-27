"""Runtime integration for curated knowledge and high-risk human control.

The stores in :mod:`qa_core.knowledge` and :mod:`qa_core.hitl` own durable
state.  This module is deliberately a narrow orchestration adapter: it turns a
current store projection into a deterministic, ``not_evidence`` context
snapshot and enforces the three-run HITL protocol required before a high-risk
probe may be dispatched.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from qa_common import file_sha256, read_stable_regular_file

from qa_core.hitl import (
    HITLConsumption,
    HITLDecision,
    HITLRequest,
    HITLStore,
    HITLStoreError,
    HumanControlJournalError,
    HumanDecision,
    JournalCheckpoint,
    canonical_journal_path_sha256,
    canonical_sha256,
    validate_hitl_decision,
)
from qa_core.knowledge import KnowledgeStore, normalize_knowledge_scope

_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_CONTEXT_BYTES = 4 * 1024 * 1024
_MAX_KNOWLEDGE_ENTRIES = 256
_SHA256 = frozenset("0123456789abcdef")


class HumanRuntimeError(RuntimeError):
    """A public trust, knowledge, or human-gate boundary failed closed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "error": "human_runtime_error",
            "code": self.code,
            "message": str(self),
        }


@dataclass(frozen=True, slots=True)
class PublicTrustConfig:
    """Strict public-key allowlists plus stable source commitments."""

    approval_keys: dict[str, dict[str, str]]
    checkpoint_keys: dict[str, dict[str, str]]
    file_sha256: str
    semantic_sha256: str


@dataclass(frozen=True, slots=True)
class KnowledgeRuntimeConfig:
    """Inputs required to replay one exact-scope KnowledgeStore query."""

    store_dir: Path
    scope: tuple[str, ...]
    trust_config_path: Path
    journal_mode: str = "local-test"
    checkpoint_path: Path | None = None


@dataclass(frozen=True, slots=True)
class HumanGateConfig:
    """Inputs for the high-risk HITL dispatch gate."""

    store_dir: Path
    trust_config_path: Path
    journal_mode: str
    checkpoint_path: Path | None
    request_ttl_seconds: float = 24 * 60 * 60
    human_execution_epoch: int = 1


@dataclass(frozen=True, slots=True)
class HumanGateResult:
    """One deterministic gate transition and its public artifact."""

    status: str
    code: str
    message: str
    dispatch_authorized: bool
    artifact: dict[str, Any]
    mutated: bool = False


def load_public_trust_config(path: Path) -> PublicTrustConfig:
    """Read the CLI-compatible public trust config through a stable FD."""

    source = Path(path).expanduser()
    try:
        raw = read_stable_regular_file(
            source,
            max_bytes=_MAX_CONFIG_BYTES,
        )
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise HumanRuntimeError(
            "trust_config_invalid",
            f"public trust config is not a stable strict JSON object: {error}",
        ) from error
    if not isinstance(value, dict):
        raise HumanRuntimeError(
            "trust_config_invalid",
            "public trust config root must be an object",
        )
    required = {"schema_version", "authorities"}
    allowed = {*required, "checkpoint_authorities"}
    if (
        not required.issubset(value)
        or not set(value).issubset(allowed)
        or value.get("schema_version") != 1
    ):
        raise HumanRuntimeError(
            "trust_config_schema_invalid",
            "trust config must be schema v1 with authorities and optional checkpoint_authorities",
        )
    approval = _parse_authorities(
        value["authorities"],
        field="authorities",
        allow_empty=False,
    )
    checkpoint = _parse_authorities(
        value.get("checkpoint_authorities", []),
        field="checkpoint_authorities",
        allow_empty=True,
    )
    semantic = {
        "schema_version": 1,
        "authorities": approval,
        "checkpoint_authorities": checkpoint,
    }
    return PublicTrustConfig(
        approval_keys=approval,
        checkpoint_keys=checkpoint,
        file_sha256=hashlib.sha256(raw).hexdigest(),
        semantic_sha256=canonical_sha256(semantic),
    )


def empty_knowledge_snapshot() -> dict[str, Any]:
    """Return the one canonical snapshot used when no store is configured."""

    unsigned = {
        "schema_version": 1,
        "kind": "qa_confirmed_knowledge_context",
        "not_evidence": True,
        "requested": False,
        "complete": True,
        "scope": [],
        "store": None,
        "trust": None,
        "checkpoint": None,
        "currentness": {
            "query_replayed": False,
            "rules_sha256": _knowledge_query_rules_sha256(),
        },
        "entries": [],
        "entries_sha256": canonical_sha256([]),
    }
    return {
        **unsigned,
        "knowledge_snapshot_sha256": canonical_sha256(unsigned),
    }


def compile_knowledge_snapshot(
    config: KnowledgeRuntimeConfig | None,
) -> dict[str, Any]:
    """Replay a KnowledgeStore query and bind every trust/currentness input."""

    if config is None:
        return empty_knowledge_snapshot()
    scope = normalize_knowledge_scope(config.scope)
    if not scope:
        raise HumanRuntimeError(
            "knowledge_scope_empty",
            "configured knowledge query requires a non-empty exact scope",
        )
    trust = load_public_trust_config(config.trust_config_path)
    checkpoint = _load_checkpoint(
        config.checkpoint_path,
        mode=config.journal_mode,
    )
    try:
        store = KnowledgeStore(
            config.store_dir,
            trusted_authority_keys=trust.approval_keys,
            journal_mode=config.journal_mode,
            checkpoint_path=config.checkpoint_path,
            trusted_checkpoint_keys=trust.checkpoint_keys,
        )
        entries = store.query(scope=scope)
        projection = store.projection()
    except Exception as error:
        raise HumanRuntimeError(
            getattr(error, "code", "knowledge_store_invalid"),
            f"knowledge store replay/query failed closed: {error}",
        ) from error
    if len(entries) > _MAX_KNOWLEDGE_ENTRIES:
        raise HumanRuntimeError(
            "knowledge_result_too_large",
            f"knowledge query returned more than {_MAX_KNOWLEDGE_ENTRIES} entries",
        )
    event_count = _projection_sequence(projection)
    checkpoint_payload = _checkpoint_binding(
        checkpoint,
        mode=config.journal_mode,
        checkpoint_path=config.checkpoint_path,
        projection=projection,
    )
    if (
        config.journal_mode == "production"
        and checkpoint_payload["complete"] is not True
    ):
        raise HumanRuntimeError(
            "knowledge_checkpoint_not_current",
            "production knowledge context requires a checkpoint covering the complete current journal",
        )
    serialized_entries = [entry.to_dict() for entry in entries]
    events_path = store.events_path
    unsigned = {
        "schema_version": 1,
        "kind": "qa_confirmed_knowledge_context",
        "not_evidence": True,
        "requested": True,
        "complete": True,
        "scope": list(scope),
        "store": {
            "journal_path_sha256": canonical_journal_path_sha256(
                events_path
            ),
            "journal_sha256": _journal_sha256(
                events_path,
                event_count=event_count,
            ),
            "projection_sha256": _required_sha256(
                "projection_sha256",
                projection.get("projection_sha256"),
            ),
            "sequence": event_count,
            "terminal_event_hash": _required_sha256(
                "last_event_hash",
                projection.get("last_event_hash"),
            ),
        },
        "trust": {
            "config_file_sha256": trust.file_sha256,
            "allowlist_sha256": trust.semantic_sha256,
        },
        "checkpoint": checkpoint_payload,
        "currentness": {
            "query_replayed": True,
            "rules_sha256": _knowledge_query_rules_sha256(),
        },
        "entries": serialized_entries,
        "entries_sha256": canonical_sha256(serialized_entries),
    }
    encoded = _canonical_bytes(unsigned)
    if len(encoded) > _MAX_CONTEXT_BYTES:
        raise HumanRuntimeError(
            "knowledge_snapshot_too_large",
            f"knowledge context exceeds {_MAX_CONTEXT_BYTES} bytes",
        )
    return {
        **unsigned,
        "knowledge_snapshot_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def evaluate_high_risk_human_gate(
    config: HumanGateConfig,
    *,
    contracts: Mapping[str, Any],
    run_id: str,
    lease_generation: int,
    context_sha256: str,
    now: datetime | None = None,
) -> HumanGateResult:
    """Advance or verify the three-checkpoint high-risk authorization flow.

    A first call creates a request and returns a handoff.  A later call may
    consume a fully checkpointed approved decision, but still returns a
    handoff.  Only a subsequent call with a new full checkpoint covering that
    consumption returns ``dispatch_authorized=True``.
    """

    current_time = _aware_utc(now)
    normalized_contracts = _contracts_object(contracts)
    high_risk = [
        dict(item)
        for item in normalized_contracts["actions"]
        if item.get("risk_class") == "high"
    ]
    trust = load_public_trust_config(config.trust_config_path)
    bindings = _human_bindings(
        normalized_contracts,
        high_risk=high_risk,
        run_id=run_id,
        lease_generation=lease_generation,
        context_sha256=context_sha256,
        trust=trust,
        human_execution_epoch=config.human_execution_epoch,
    )
    if not high_risk:
        artifact = _human_artifact(
            status="not_required",
            bindings=bindings,
            trust=trust,
            checkpoint=None,
            projection=None,
            request=None,
            decision=None,
            consumption=None,
            checkpoint_complete=False,
        )
        return HumanGateResult(
            status="not_required",
            code="human_authorization_not_required",
            message="the current plan contains no high-risk ToolSpec action",
            dispatch_authorized=True,
            artifact=artifact,
        )
    if config.journal_mode != "production":
        artifact = _human_artifact(
            status="production_checkpoint_required",
            bindings=bindings,
            trust=trust,
            checkpoint=None,
            projection=None,
            request=None,
            decision=None,
            consumption=None,
            checkpoint_complete=False,
        )
        return HumanGateResult(
            status="production_checkpoint_required",
            code="human_control_production_required",
            message="a configured high-risk gate cannot dispatch from local-test journal mode",
            dispatch_authorized=False,
            artifact=artifact,
        )
    checkpoint = _load_checkpoint(
        config.checkpoint_path,
        mode=config.journal_mode,
    )
    try:
        store = HITLStore(
            config.store_dir,
            trusted_authority_keys=trust.approval_keys,
            journal_mode=config.journal_mode,
            checkpoint_path=config.checkpoint_path,
            trusted_checkpoint_keys=trust.checkpoint_keys,
            clock=lambda: current_time,
        )
        projection = store.projection()
    except HumanControlJournalError as error:
        if error.code == "checkpoint_tail_uncovered":
            return _gate_handoff(
                status="checkpoint_refresh_required",
                code="human_checkpoint_not_current",
                message=(
                    "the supplied checkpoint does not cover the complete "
                    "current HITL journal"
                ),
                bindings=bindings,
                trust=trust,
                checkpoint=_checkpoint_without_projection(
                    checkpoint,
                    mode=config.journal_mode,
                    checkpoint_path=config.checkpoint_path,
                    current_count=error.current_count,
                ),
                projection=None,
            )
        raise HumanRuntimeError(
            error.code,
            f"HITL store replay failed closed: {error}",
        ) from error
    except Exception as error:
        raise HumanRuntimeError(
            getattr(error, "code", "human_control_store_invalid"),
            f"HITL store replay failed closed: {error}",
        ) from error
    checkpoint_binding = _checkpoint_binding(
        checkpoint,
        mode=config.journal_mode,
        checkpoint_path=config.checkpoint_path,
        projection=projection,
    )
    request_id = _request_id(bindings)
    raw_state = next(
        (
            item
            for item in projection.get("requests", [])
            if isinstance(item, dict)
            and isinstance(item.get("request"), dict)
            and item["request"].get("request_id") == request_id
        ),
        None,
    )
    if raw_state is None:
        if checkpoint_binding["complete"] is not True:
            return _gate_handoff(
                status="checkpoint_refresh_required",
                code="human_checkpoint_not_current",
                message="the checkpoint must cover the complete journal before creating a request",
                bindings=bindings,
                trust=trust,
                checkpoint=checkpoint_binding,
                projection=projection,
            )
        request = HITLRequest(
            request_id=request_id,
            run_id=bindings["run_id"],
            lease_generation=bindings["lease_generation"],
            context_sha256=bindings["context_sha256"],
            action_sha256=bindings["action_sha256"],
            policy_sha256=bindings["policy_sha256"],
            authorization_sha256=bindings["authorization_sha256"],
            action_summary=_action_summary(high_risk),
            question=(
                "Approve this exact high-risk QA action set for one "
                "checkpointed consumption?"
            ),
            allowed_decisions=(
                HumanDecision.APPROVED,
                HumanDecision.REJECTED,
            ),
            created_at=_timestamp(current_time),
            expires_at=_timestamp(
                current_time
                + timedelta(
                    seconds=_positive_ttl(
                        config.request_ttl_seconds
                    )
                )
            ),
        )
        try:
            state = store.create_request(request)
            projection = _read_projection(store.snapshot_path)
        except Exception as error:
            raise HumanRuntimeError(
                getattr(error, "code", "human_request_create_failed"),
                f"HITL request creation failed closed: {error}",
            ) from error
        checkpoint_binding = _checkpoint_binding(
            checkpoint,
            mode=config.journal_mode,
            checkpoint_path=config.checkpoint_path,
            projection=projection,
        )
        return _gate_handoff(
            status="pending_approval",
            code="human_approval_required",
            message="a hash-bound HITL request was created; obtain a signed decision and fresh checkpoint",
            bindings=bindings,
            trust=trust,
            checkpoint=checkpoint_binding,
            projection=projection,
            request=state.request.to_dict(),
            mutated=True,
        )

    request = raw_state.get("request")
    decision = raw_state.get("decision")
    consumption = raw_state.get("consumption")
    if checkpoint_binding["complete"] is not True:
        return _gate_handoff(
            status="checkpoint_refresh_required",
            code="human_checkpoint_not_current",
            message="the supplied checkpoint does not cover the complete current HITL journal",
            bindings=bindings,
            trust=trust,
            checkpoint=checkpoint_binding,
            projection=projection,
            request=request,
            decision=decision,
            consumption=consumption,
        )
    expected = {
        "expected_run_id": bindings["run_id"],
        "expected_lease_generation": bindings["lease_generation"],
        "expected_context_sha256": bindings["context_sha256"],
        "expected_action_sha256": bindings["action_sha256"],
        "expected_policy_sha256": bindings["policy_sha256"],
        "expected_authorization_sha256": bindings[
            "authorization_sha256"
        ],
    }
    try:
        state = store.resume(request_id, **expected)
    except Exception as error:
        raise HumanRuntimeError(
            getattr(error, "code", "human_request_not_current"),
            f"HITL request currentness failed closed: {error}",
        ) from error
    if state.decision is None:
        return _gate_handoff(
            status="pending_approval",
            code="human_approval_required",
            message="the HITL request has no signed terminal decision",
            bindings=bindings,
            trust=trust,
            checkpoint=checkpoint_binding,
            projection=projection,
            request=state.request.to_dict(),
        )
    if state.decision.decision is HumanDecision.REJECTED:
        return _gate_handoff(
            status="rejected",
            code="human_approval_rejected",
            message="the signed human decision rejected this action set",
            bindings=bindings,
            trust=trust,
            checkpoint=checkpoint_binding,
            projection=projection,
            request=state.request.to_dict(),
            decision=state.decision.to_dict(),
        )
    if state.consumption is None:
        consumption_id = _consumption_id(
            bindings,
            decision_id=state.decision.decision_id,
        )
        try:
            state = store.consume_approved(
                request_id,
                consumption_id=consumption_id,
                **expected,
            )
            projection = _read_projection(store.snapshot_path)
        except HumanControlJournalError as error:
            if error.code != "checkpoint_refresh_required":
                raise HumanRuntimeError(
                    error.code,
                    f"HITL approval consumption failed closed: {error}",
                ) from error
            projection = _read_projection(store.snapshot_path)
            raw_after = next(
                (
                    item
                    for item in projection.get("requests", [])
                    if isinstance(item, dict)
                    and isinstance(item.get("request"), dict)
                    and item["request"].get("request_id") == request_id
                ),
                None,
            )
            if raw_after is None or not isinstance(
                raw_after.get("consumption"),
                dict,
            ):
                raise HumanRuntimeError(
                    "human_consumption_persistence_unverifiable",
                    "consumption refresh was requested but the durable projection lacks consumption",
                )
            state_request = raw_after["request"]
            state_decision = raw_after.get("decision")
            state_consumption = raw_after["consumption"]
            checkpoint_binding = _checkpoint_binding(
                checkpoint,
                mode=config.journal_mode,
                checkpoint_path=config.checkpoint_path,
                projection=projection,
            )
            return _gate_handoff(
                status="awaiting_consumption_checkpoint",
                code="human_consumption_checkpoint_required",
                message="the approval was consumed once; obtain a new full checkpoint covering consumption",
                bindings=bindings,
                trust=trust,
                checkpoint=checkpoint_binding,
                projection=projection,
                request=state_request,
                decision=state_decision,
                consumption=state_consumption,
                mutated=True,
            )
        except HITLStoreError as error:
            raise HumanRuntimeError(
                error.code,
                f"HITL approval consumption failed closed: {error}",
            ) from error
        checkpoint_binding = _checkpoint_binding(
            checkpoint,
            mode=config.journal_mode,
            checkpoint_path=config.checkpoint_path,
            projection=projection,
        )
        return _gate_handoff(
            status="awaiting_consumption_checkpoint",
            code="human_consumption_checkpoint_required",
            message="the approval was consumed once; obtain a new full checkpoint covering consumption",
            bindings=bindings,
            trust=trust,
            checkpoint=checkpoint_binding,
            projection=projection,
            request=state.request.to_dict(),
            decision=state.decision.to_dict(),
            consumption=(
                state.consumption.to_dict()
                if state.consumption is not None
                else None
            ),
            mutated=True,
        )
    prior_redemption = next(
        (
            dict(item)
            for item in projection.get("redemptions", [])
            if isinstance(item, dict)
            and item.get("consumption_id")
            == state.consumption.consumption_id
        ),
        None,
    )
    if prior_redemption is not None:
        artifact = _human_artifact(
            status="redeemed",
            bindings=bindings,
            trust=trust,
            checkpoint=checkpoint_binding,
            projection=projection,
            request=state.request.to_dict(),
            decision=state.decision.to_dict(),
            consumption=state.consumption.to_dict(),
            redemption=prior_redemption,
            checkpoint_complete=True,
        )
        return HumanGateResult(
            status="already_redeemed",
            code="human_dispatch_already_redeemed",
            message=(
                "this approval consumption already claimed its one allowed "
                "probe attempt; reconcile the immutable attempt without "
                "redispatch"
            ),
            dispatch_authorized=False,
            artifact=artifact,
        )
    redemption, redeemed_projection, redemption_appended = (
        _claim_dispatch_redemption(
            store,
            bindings=bindings,
            checkpoint=checkpoint_binding,
            request=state.request.to_dict(),
            decision=state.decision.to_dict(),
            consumption=state.consumption.to_dict(),
            redeemed_at=_timestamp(current_time),
        )
    )
    artifact = _human_artifact(
        status=(
            "authorized"
            if redemption_appended
            else "redeemed"
        ),
        bindings=bindings,
        trust=trust,
        checkpoint=checkpoint_binding,
        projection=redeemed_projection,
        request=state.request.to_dict(),
        decision=state.decision.to_dict(),
        consumption=state.consumption.to_dict(),
        redemption=redemption,
        checkpoint_complete=not redemption_appended,
    )
    if not redemption_appended:
        return HumanGateResult(
            status="already_redeemed",
            code="human_dispatch_already_redeemed",
            message=(
                "this approval consumption already claimed its one allowed "
                "probe attempt; reconcile the immutable attempt without "
                "redispatch"
            ),
            dispatch_authorized=False,
            artifact=artifact,
        )
    return HumanGateResult(
        status="authorized",
        code="human_authorization_current",
        message=(
            "signed approval, one-shot consumption, post-consumption "
            "checkpoint, and one-shot dispatch redemption are current"
        ),
        dispatch_authorized=True,
        artifact=artifact,
        mutated=True,
    )


def verify_human_authorization_artifact(
    value: Mapping[str, Any],
    *,
    expected_file_sha256: str | None = None,
    artifact_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Strictly verify the self-hash and terminal authorization shape."""

    payload = dict(value)
    expected_fields = {
        "schema_version",
        "kind",
        "not_evidence",
        "status",
        "bindings",
        "trust",
        "checkpoint",
        "store",
        "request",
        "decision",
        "consumption",
        "redemption",
        "human_authorization_sha256",
    }
    if set(payload) != expected_fields:
        raise HumanRuntimeError(
            "human_authorization_schema_invalid",
            "human authorization artifact has unknown or missing fields",
        )
    if (
        payload.get("schema_version") != 1
        or payload.get("kind") != "qa_human_authorization"
        or payload.get("not_evidence") is not True
        or payload.get("status") not in {"authorized", "not_required"}
    ):
        raise HumanRuntimeError(
            "human_authorization_not_terminal",
            "human authorization artifact is not an authorized terminal state",
        )
    unsigned = dict(payload)
    recorded = unsigned.pop("human_authorization_sha256")
    if (
        not _is_sha256(recorded)
        or recorded != canonical_sha256(unsigned)
    ):
        raise HumanRuntimeError(
            "human_authorization_hash_invalid",
            "human authorization semantic hash is invalid",
        )
    bindings = payload.get("bindings")
    binding_fields = {
        "run_id",
        "lease_generation",
        "human_execution_epoch",
        "context_sha256",
        "plan_sha256",
        "plan_audit_sha256",
        "tool_registry_sha256",
        "action_sha256",
        "policy_sha256",
        "authorization_sha256",
        "authorized_actions",
        "high_risk_action_count",
        "high_risk_actions",
        "execution_intent_sha256",
    }
    if (
        not isinstance(bindings, dict)
        or set(bindings) != binding_fields
    ):
        raise HumanRuntimeError(
            "human_authorization_bindings_invalid",
            "human authorization bindings have unknown or missing fields",
        )
    for name in (
        "context_sha256",
        "plan_sha256",
        "plan_audit_sha256",
        "tool_registry_sha256",
        "action_sha256",
        "policy_sha256",
        "authorization_sha256",
        "execution_intent_sha256",
    ):
        _required_sha256(name, bindings.get(name))
    authorized_actions = bindings["authorized_actions"]
    high_risk_actions = bindings["high_risk_actions"]
    if (
        isinstance(bindings["human_execution_epoch"], bool)
        or not isinstance(bindings["human_execution_epoch"], int)
        or bindings["human_execution_epoch"] < 1
        or not isinstance(authorized_actions, list)
        or any(not isinstance(item, dict) for item in authorized_actions)
        or not isinstance(high_risk_actions, list)
        or any(not isinstance(item, dict) for item in high_risk_actions)
        or isinstance(bindings["high_risk_action_count"], bool)
        or not isinstance(bindings["high_risk_action_count"], int)
        or bindings["high_risk_action_count"]
        != len(high_risk_actions)
        or high_risk_actions
        != [
            item
            for item in authorized_actions
            if item.get("risk_class") == "high"
        ]
    ):
        raise HumanRuntimeError(
            "human_authorization_action_set_invalid",
            "human authorization action projection is inconsistent",
        )
    if bindings["action_sha256"] != canonical_sha256(
        high_risk_actions
    ):
        raise HumanRuntimeError(
            "human_authorization_action_hash_invalid",
            "human action hash does not bind the high-risk action set",
        )
    expected_authorization = canonical_sha256(
        {
            "schema_version": 1,
            "kind": "qa_stable_human_action_authorization",
            "run_id": bindings["run_id"],
            "lease_generation": bindings["lease_generation"],
            "human_execution_epoch": bindings[
                "human_execution_epoch"
            ],
            "plan_sha256": bindings["plan_sha256"],
            "context_sha256": bindings["context_sha256"],
            "plan_audit_sha256": bindings[
                "plan_audit_sha256"
            ],
            "tool_registry_sha256": bindings[
                "tool_registry_sha256"
            ],
            "actions": authorized_actions,
        }
    )
    if bindings["authorization_sha256"] != expected_authorization:
        raise HumanRuntimeError(
            "human_authorization_policy_hash_invalid",
            "human authorization hash does not bind the stable action policy",
        )
    trust = payload.get("trust")
    if (
        not isinstance(trust, dict)
        or set(trust)
        != {"config_file_sha256", "allowlist_sha256"}
    ):
        raise HumanRuntimeError(
            "human_authorization_trust_invalid",
            "human authorization trust binding is invalid",
        )
    for name in ("config_file_sha256", "allowlist_sha256"):
        _required_sha256(name, trust.get(name))
    expected_policy = canonical_sha256(
        {
            "schema_version": 1,
            "kind": "qa_high_risk_human_gate_policy",
            "risk_classes": ["high"],
            "requires_production_checkpoint": True,
            "requires_full_pre_consumption_checkpoint": True,
            "requires_one_shot_consumption": True,
            "requires_full_post_consumption_checkpoint": True,
            "tool_registry_sha256": bindings[
                "tool_registry_sha256"
            ],
            "trust_allowlist_sha256": trust[
                "allowlist_sha256"
            ],
        }
    )
    if bindings["policy_sha256"] != expected_policy:
        raise HumanRuntimeError(
            "human_authorization_gate_policy_invalid",
            "human gate policy hash is invalid",
        )
    intent_bindings = dict(bindings)
    recorded_intent = intent_bindings.pop(
        "execution_intent_sha256"
    )
    if recorded_intent != canonical_sha256(
        {
            "schema_version": 1,
            "kind": "qa_human_execution_intent",
            **intent_bindings,
        }
    ):
        raise HumanRuntimeError(
            "human_execution_intent_invalid",
            "execution intent hash is invalid",
        )
    if payload["status"] == "not_required":
        if (
            bindings["high_risk_action_count"] != 0
            or any(
                payload.get(name) is not None
                for name in (
                    "checkpoint",
                    "store",
                    "request",
                    "decision",
                    "consumption",
                    "redemption",
                )
            )
        ):
            raise HumanRuntimeError(
                "human_authorization_not_required_invalid",
                "not_required is valid only for an empty high-risk action set",
            )
    if payload["status"] == "authorized":
        checkpoint = payload.get("checkpoint")
        store = payload.get("store")
        checkpoint_fields = {
            "mode",
            "production_ready",
            "file_sha256",
            "journal_path_sha256",
            "event_count",
            "terminal_event_hash",
            "issued_at",
            "expires_at",
            "authority",
            "key_id",
            "complete",
            "current_event_count",
            "tail_count",
            "authorization_prefix_complete",
        }
        store_fields = {
            "journal_path_sha256",
            "sequence",
            "terminal_event_hash",
            "projection_sha256",
        }
        if (
            not isinstance(checkpoint, dict)
            or set(checkpoint) != checkpoint_fields
            or checkpoint.get("mode") != "production"
            or checkpoint.get("production_ready") is not True
            or checkpoint.get(
                "authorization_prefix_complete"
            )
            is not True
            or checkpoint.get("tail_count") != 1
            or checkpoint.get("complete") is not False
            or not isinstance(payload.get("request"), dict)
            or not isinstance(payload.get("decision"), dict)
            or payload["decision"].get("decision") != "approved"
            or not isinstance(payload.get("consumption"), dict)
            or not isinstance(payload.get("redemption"), dict)
            or not isinstance(store, dict)
            or set(store) != store_fields
        ):
            raise HumanRuntimeError(
                "human_authorization_chain_incomplete",
                "authorized artifact lacks the full checkpointed approval/consumption chain",
            )
        if bindings["high_risk_action_count"] < 1:
            raise HumanRuntimeError(
                "human_authorization_high_risk_missing",
                "authorized status requires at least one high-risk action",
            )
        checkpoint_count = checkpoint.get("event_count")
        checkpoint_current_count = checkpoint.get(
            "current_event_count"
        )
        if (
            isinstance(checkpoint_count, bool)
            or not isinstance(checkpoint_count, int)
            or checkpoint_count < 0
            or isinstance(checkpoint_current_count, bool)
            or not isinstance(checkpoint_current_count, int)
            or checkpoint_current_count < 1
        ):
            raise HumanRuntimeError(
                "human_authorization_checkpoint_invalid",
                "authorization checkpoint counts are invalid",
            )
        for name in (
            "file_sha256",
            "journal_path_sha256",
            "terminal_event_hash",
        ):
            _required_sha256(name, checkpoint.get(name))
        checkpoint_issued_at = _parse_human_timestamp(
            checkpoint["issued_at"],
            field="checkpoint.issued_at",
        )
        checkpoint_expires_at = _parse_human_timestamp(
            checkpoint["expires_at"],
            field="checkpoint.expires_at",
        )
        if (
            checkpoint_issued_at >= checkpoint_expires_at
            or not isinstance(checkpoint.get("authority"), str)
            or not checkpoint["authority"]
            or not isinstance(checkpoint.get("key_id"), str)
            or not checkpoint["key_id"]
        ):
            raise HumanRuntimeError(
                "human_authorization_checkpoint_invalid",
                "authorization checkpoint time or signer identity is invalid",
            )
        try:
            request = HITLRequest.from_dict(payload["request"])
            decision = HITLDecision.from_dict(payload["decision"])
            consumption = HITLConsumption.from_dict(
                payload["consumption"]
            )
            validate_hitl_decision(request, decision)
        except Exception as error:
            raise HumanRuntimeError(
                getattr(error, "code", "human_authorization_chain_invalid"),
                f"human approval chain is invalid: {error}",
            ) from error
        expected_chain = {
            "run_id": bindings["run_id"],
            "lease_generation": bindings["lease_generation"],
            "context_sha256": bindings["context_sha256"],
            "action_sha256": bindings["action_sha256"],
            "policy_sha256": bindings["policy_sha256"],
            "authorization_sha256": bindings[
                "authorization_sha256"
            ],
        }
        for name, expected_value in expected_chain.items():
            if (
                getattr(request, name) != expected_value
                or getattr(decision, name) != expected_value
                or getattr(consumption, name) != expected_value
            ):
                raise HumanRuntimeError(
                    "human_authorization_chain_binding_mismatch",
                    f"request/decision/consumption {name} binding differs",
                )
        if (
            consumption.request_id != request.request_id
            or consumption.decision_id != decision.decision_id
            or decision.request_id != request.request_id
        ):
            raise HumanRuntimeError(
                "human_authorization_chain_identity_mismatch",
                "request, decision, and consumption identities differ",
            )
        request_created_at = _parse_human_timestamp(
            request.created_at,
            field="request.created_at",
        )
        request_expires_at = _parse_human_timestamp(
            request.expires_at,
            field="request.expires_at",
        )
        decision_decided_at = _parse_human_timestamp(
            decision.decided_at,
            field="decision.decided_at",
        )
        consumption_consumed_at = _parse_human_timestamp(
            consumption.consumed_at,
            field="consumption.consumed_at",
        )
        if not (
            request_created_at
            <= decision_decided_at
            <= consumption_consumed_at
            < request_expires_at
        ):
            raise HumanRuntimeError(
                "human_authorization_chain_time_invalid",
                "request, decision, consumption, and expiry order is invalid",
            )
        redemption_artifact = dict(payload["redemption"])
        redemption_event_sequence = redemption_artifact.pop(
            "journal_event_sequence",
            None,
        )
        redemption_event_sha256 = redemption_artifact.pop(
            "journal_event_sha256",
            None,
        )
        _validate_redemption(redemption_artifact)
        redemption_redeemed_at = _parse_human_timestamp(
            redemption_artifact["redeemed_at"],
            field="redemption.redeemed_at",
        )
        if redemption_redeemed_at < consumption_consumed_at:
            raise HumanRuntimeError(
                "human_redemption_time_invalid",
                "redemption cannot predate approval consumption",
            )
        if (
            redemption_artifact["request_id"]
            != request.request_id
            or redemption_artifact["decision_id"]
            != decision.decision_id
            or redemption_artifact["consumption_id"]
            != consumption.consumption_id
        ):
            raise HumanRuntimeError(
                "human_redemption_chain_mismatch",
                "redemption identities do not match the approval chain",
            )
        for name, expected_value in expected_chain.items():
            if redemption_artifact.get(name) != expected_value:
                raise HumanRuntimeError(
                    "human_redemption_binding_mismatch",
                    f"redemption {name} differs from the approved intent",
                )
        if (
            redemption_artifact["plan_sha256"]
            != bindings["plan_sha256"]
            or redemption_artifact["plan_audit_sha256"]
            != bindings["plan_audit_sha256"]
            or redemption_artifact["tool_registry_sha256"]
            != bindings["tool_registry_sha256"]
            or redemption_artifact["execution_intent_sha256"]
            != bindings["execution_intent_sha256"]
        ):
            raise HumanRuntimeError(
                "human_redemption_intent_mismatch",
                "redemption does not bind the approved execution intent",
            )
        authorization_checkpoint = {
            key: item
            for key, item in checkpoint.items()
            if key
            not in {
                "current_event_count",
                "tail_count",
                "authorization_prefix_complete",
            }
        }
        authorization_checkpoint["complete"] = True
        expected_chain_sha256 = canonical_sha256(
            {
                "schema_version": 1,
                "kind": "qa_human_approval_chain",
                "bindings": bindings,
                "checkpoint": authorization_checkpoint,
                "request": request.to_dict(),
                "decision": decision.to_dict(),
                "consumption": consumption.to_dict(),
            }
        )
        if (
            redemption_artifact["approval_chain_sha256"]
            != expected_chain_sha256
        ):
            raise HumanRuntimeError(
                "human_redemption_approval_chain_invalid",
                "redemption approval-chain hash is invalid",
            )
        expected_redemption_id = "redeem-" + canonical_sha256(
            {
                "schema_version": 1,
                "kind": "qa_human_dispatch_redemption_identity",
                "consumption_id": consumption.consumption_id,
                "execution_intent_sha256": bindings[
                    "execution_intent_sha256"
                ],
            }
        )[:40]
        if redemption_artifact["redemption_id"] != expected_redemption_id:
            raise HumanRuntimeError(
                "human_redemption_identity_invalid",
                "redemption id is not deterministically bound",
            )
        if (
            redemption_artifact["hitl_checkpoint_file_sha256"]
            != checkpoint.get("file_sha256")
            or redemption_artifact["hitl_checkpoint_event_count"]
            != checkpoint.get("event_count")
            or redemption_artifact[
                "hitl_checkpoint_terminal_event_hash"
            ]
            != checkpoint.get("terminal_event_hash")
        ):
            raise HumanRuntimeError(
                "human_redemption_checkpoint_mismatch",
                "redemption does not bind the post-consumption checkpoint",
            )
        if (
            not isinstance(store, dict)
            or store.get("journal_path_sha256")
            != checkpoint.get("journal_path_sha256")
            or store.get("sequence")
            != checkpoint.get("current_event_count")
            or store.get("sequence")
            != checkpoint_count + 1
            or redemption_event_sequence != store.get("sequence")
            or redemption_event_sha256
            != store.get("terminal_event_hash")
        ):
            raise HumanRuntimeError(
                "human_redemption_tail_invalid",
                "authorization must bind exactly one terminal redemption tail event",
            )
        expected_redemption_event_sha256 = canonical_sha256(
            {
                "schema_version": 1,
                "sequence": checkpoint_count + 1,
                "event_type": "human_dispatch_redeemed",
                "occurred_at": redemption_artifact["redeemed_at"],
                "payload": {
                    "redemption": redemption_artifact,
                },
                "previous_hash": checkpoint[
                    "terminal_event_hash"
                ],
            }
        )
        if redemption_event_sha256 != expected_redemption_event_sha256:
            raise HumanRuntimeError(
                "human_redemption_event_hash_invalid",
                "redemption event hash is not reproducible from the checkpoint tail",
            )
        _required_sha256(
            "store.projection_sha256",
            store.get("projection_sha256"),
        )
        _required_sha256(
            "redemption.journal_event_sha256",
            redemption_event_sha256,
        )
    if expected_file_sha256 is not None:
        expected_hash = _required_sha256(
            "expected_file_sha256",
            expected_file_sha256,
        )
        if (
            not isinstance(artifact_bytes, bytes)
            or hashlib.sha256(artifact_bytes).hexdigest()
            != expected_hash
        ):
            raise HumanRuntimeError(
                "human_authorization_file_hash_mismatch",
                "human authorization bytes do not match the expected file hash",
            )
        try:
            parsed = json.loads(
                artifact_bytes.decode("utf-8"),
                object_pairs_hook=_object_without_duplicates,
                parse_constant=_reject_constant,
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as error:
            raise HumanRuntimeError(
                "human_authorization_file_invalid",
                f"human authorization bytes are not strict JSON: {error}",
            ) from error
        if parsed != payload:
            raise HumanRuntimeError(
                "human_authorization_file_substituted",
                "verified human authorization object differs from the bound file bytes",
            )
    return payload


def human_execution_iteration(
    value: Mapping[str, Any],
) -> int:
    """Map one immutable human execution intent to a JS-safe iteration."""

    payload = dict(value)
    bindings = (
        payload.get("bindings")
        if isinstance(payload.get("bindings"), dict)
        else payload
    )
    intent_sha256 = _required_sha256(
        "execution_intent_sha256",
        bindings.get("execution_intent_sha256"),
    )
    # 十三位十六进制数低于 2**53，Python 和 Node 均可精确保留该正整数；
    # 加一同时排除无效的零值。
    return int(intent_sha256[:13], 16) + 1


def verify_human_authorization_for_contracts(
    value: Mapping[str, Any],
    contracts: Mapping[str, Any],
) -> None:
    """Require a terminal human artifact to bind these final contracts."""

    artifact = verify_human_authorization_artifact(value)
    normalized_contracts = _contracts_object(contracts)
    bindings = artifact["bindings"]
    if artifact["status"] != "authorized":
        raise HumanRuntimeError(
            "human_contract_authorization_not_terminal",
            "high-risk contracts require authorized human status",
        )
    expected = {
        "run_id": normalized_contracts.get("run_id"),
        "lease_generation": normalized_contracts.get("generation"),
        "context_sha256": normalized_contracts.get(
            "context_sha256"
        ),
        "plan_sha256": normalized_contracts.get("plan_sha256"),
        "plan_audit_sha256": normalized_contracts.get(
            "plan_audit_sha256"
        ),
        "tool_registry_sha256": normalized_contracts.get(
            "tool_registry_sha256"
        ),
    }
    for name, expected_value in expected.items():
        if bindings.get(name) != expected_value:
            raise HumanRuntimeError(
                "human_contract_binding_mismatch",
                f"human authorization {name} differs from final contracts",
            )
    stable_actions = [
        _stable_action_binding(item)
        for item in normalized_contracts["actions"]
    ]
    high_risk = [
        item
        for item in stable_actions
        if item.get("risk_class") == "high"
    ]
    if (
        not high_risk
        or bindings["authorized_actions"] != stable_actions
        or bindings["high_risk_actions"] != high_risk
        or bindings["high_risk_action_count"] != len(high_risk)
    ):
        raise HumanRuntimeError(
            "human_contract_action_set_mismatch",
            "human authorization does not bind the final high-risk action set",
        )
    if normalized_contracts.get(
        "iteration"
    ) != human_execution_iteration(artifact):
        raise HumanRuntimeError(
            "human_contract_execution_intent_mismatch",
            "final contract iteration does not derive from the approved execution intent",
        )


def _human_bindings(
    contracts: Mapping[str, Any],
    *,
    high_risk: list[dict[str, Any]],
    run_id: str,
    lease_generation: int,
    context_sha256: str,
    trust: PublicTrustConfig,
    human_execution_epoch: int,
) -> dict[str, Any]:
    if (
        not isinstance(run_id, str)
        or not run_id
        or isinstance(lease_generation, bool)
        or not isinstance(lease_generation, int)
        or lease_generation < 1
    ):
        raise HumanRuntimeError(
            "human_run_binding_invalid",
            "run id and lease generation are invalid",
        )
    if (
        isinstance(human_execution_epoch, bool)
        or not isinstance(human_execution_epoch, int)
        or human_execution_epoch < 1
    ):
        raise HumanRuntimeError(
            "human_execution_epoch_invalid",
            "human execution epoch must be a positive integer",
        )
    context_hash = _required_sha256(
        "context_sha256",
        context_sha256,
    )
    action_payload = [_stable_action_binding(item) for item in high_risk]
    action_sha256 = canonical_sha256(action_payload)
    policy_sha256 = canonical_sha256(
        {
            "schema_version": 1,
            "kind": "qa_high_risk_human_gate_policy",
            "risk_classes": ["high"],
            "requires_production_checkpoint": True,
            "requires_full_pre_consumption_checkpoint": True,
            "requires_one_shot_consumption": True,
            "requires_full_post_consumption_checkpoint": True,
            "tool_registry_sha256": contracts.get(
                "tool_registry_sha256"
            ),
            "trust_allowlist_sha256": trust.semantic_sha256,
        }
    )
    stable_actions = [
        _stable_action_binding(item)
        for item in contracts["actions"]
    ]
    authorization_sha256 = canonical_sha256(
        {
            "schema_version": 1,
            "kind": "qa_stable_human_action_authorization",
            "run_id": run_id,
            "lease_generation": lease_generation,
            "human_execution_epoch": human_execution_epoch,
            "plan_sha256": contracts.get("plan_sha256"),
            "context_sha256": context_hash,
            "plan_audit_sha256": contracts.get(
                "plan_audit_sha256"
            ),
            "tool_registry_sha256": contracts.get(
                "tool_registry_sha256"
            ),
            "actions": stable_actions,
        }
    )
    bindings = {
        "run_id": run_id,
        "lease_generation": lease_generation,
        "human_execution_epoch": human_execution_epoch,
        "context_sha256": context_hash,
        "plan_sha256": _required_sha256(
            "plan_sha256",
            contracts.get("plan_sha256"),
        ),
        "plan_audit_sha256": _required_sha256(
            "plan_audit_sha256",
            contracts.get("plan_audit_sha256"),
        ),
        "tool_registry_sha256": _required_sha256(
            "tool_registry_sha256",
            contracts.get("tool_registry_sha256"),
        ),
        "action_sha256": action_sha256,
        "policy_sha256": policy_sha256,
        "authorization_sha256": authorization_sha256,
        "authorized_actions": stable_actions,
        "high_risk_action_count": len(high_risk),
        "high_risk_actions": action_payload,
    }
    return {
        **bindings,
        "execution_intent_sha256": canonical_sha256(
            {
                "schema_version": 1,
                "kind": "qa_human_execution_intent",
                **bindings,
            }
        ),
    }


def _human_artifact(
    *,
    status: str,
    bindings: Mapping[str, Any],
    trust: PublicTrustConfig,
    checkpoint: Mapping[str, Any] | None,
    projection: Mapping[str, Any] | None,
    request: Mapping[str, Any] | None,
    decision: Mapping[str, Any] | None,
    consumption: Mapping[str, Any] | None,
    checkpoint_complete: bool,
    redemption: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    store_binding = None
    if projection is not None:
        store_binding = {
            "journal_path_sha256": (
                checkpoint.get("journal_path_sha256")
                if isinstance(checkpoint, Mapping)
                else None
            ),
            "sequence": _projection_sequence(projection),
            "terminal_event_hash": _required_sha256(
                "last_event_hash",
                projection.get("last_event_hash"),
            ),
            "projection_sha256": _required_sha256(
                "projection_sha256",
                projection.get("projection_sha256"),
            ),
        }
    normalized_checkpoint = (
        {
            **dict(checkpoint),
            "complete": checkpoint_complete,
            "current_event_count": (
                _projection_sequence(projection)
                if projection is not None
                else None
            ),
            "tail_count": (
                _projection_sequence(projection)
                - checkpoint.get("event_count")
                if (
                    projection is not None
                    and isinstance(
                        checkpoint.get("event_count"),
                        int,
                    )
                )
                else None
            ),
            "authorization_prefix_complete": bool(
                status == "authorized"
                and redemption is not None
                and projection is not None
                and isinstance(
                    checkpoint.get("event_count"),
                    int,
                )
                and _projection_sequence(projection)
                == checkpoint.get("event_count") + 1
            ),
        }
        if checkpoint is not None
        else None
    )
    unsigned = {
        "schema_version": 1,
        "kind": "qa_human_authorization",
        "not_evidence": True,
        "status": status,
        "bindings": dict(bindings),
        "trust": {
            "config_file_sha256": trust.file_sha256,
            "allowlist_sha256": trust.semantic_sha256,
        },
        "checkpoint": normalized_checkpoint,
        "store": store_binding,
        "request": dict(request) if request is not None else None,
        "decision": dict(decision) if decision is not None else None,
        "consumption": (
            dict(consumption)
            if consumption is not None
            else None
        ),
        "redemption": (
            dict(redemption)
            if redemption is not None
            else None
        ),
    }
    return {
        **unsigned,
        "human_authorization_sha256": canonical_sha256(unsigned),
    }


def _gate_handoff(
    *,
    status: str,
    code: str,
    message: str,
    bindings: Mapping[str, Any],
    trust: PublicTrustConfig,
    checkpoint: Mapping[str, Any] | None,
    projection: Mapping[str, Any] | None,
    request: Mapping[str, Any] | None = None,
    decision: Mapping[str, Any] | None = None,
    consumption: Mapping[str, Any] | None = None,
    mutated: bool = False,
) -> HumanGateResult:
    return HumanGateResult(
        status=status,
        code=code,
        message=message,
        dispatch_authorized=False,
        artifact=_human_artifact(
            status=status,
            bindings=bindings,
            trust=trust,
            checkpoint=checkpoint,
            projection=projection,
            request=request,
            decision=decision,
            consumption=consumption,
            checkpoint_complete=False,
        ),
        mutated=mutated,
    )


def _checkpoint_binding(
    checkpoint: JournalCheckpoint | None,
    *,
    mode: str,
    checkpoint_path: Path | None,
    projection: Mapping[str, Any],
) -> dict[str, Any]:
    sequence = _projection_sequence(projection)
    terminal = _required_sha256(
        "last_event_hash",
        projection.get("last_event_hash"),
    )
    if checkpoint is None:
        return {
            "mode": mode,
            "production_ready": False,
            "file_sha256": None,
            "event_count": None,
            "terminal_event_hash": None,
            "issued_at": None,
            "expires_at": None,
            "authority": None,
            "key_id": None,
            "complete": mode != "production",
        }
    checkpoint_hash = file_sha256(checkpoint_path)
    if checkpoint_hash is None:
        raise HumanRuntimeError(
            "checkpoint_file_unreadable",
            "checkpoint file cannot be hashed as a stable single-link input",
        )
    complete = (
        checkpoint.event_count == sequence
        and checkpoint.terminal_event_hash == terminal
    )
    return {
        "mode": mode,
        "production_ready": mode == "production",
        "file_sha256": checkpoint_hash,
        "journal_path_sha256": checkpoint.journal_path_sha256,
        "event_count": checkpoint.event_count,
        "terminal_event_hash": checkpoint.terminal_event_hash,
        "issued_at": checkpoint.issued_at,
        "expires_at": checkpoint.expires_at,
        "authority": checkpoint.authority,
        "key_id": checkpoint.key_id,
        "complete": complete,
    }


def _checkpoint_without_projection(
    checkpoint: JournalCheckpoint | None,
    *,
    mode: str,
    checkpoint_path: Path | None,
    current_count: int | None,
) -> dict[str, Any] | None:
    if checkpoint is None:
        return None
    checkpoint_hash = file_sha256(checkpoint_path)
    if checkpoint_hash is None:
        raise HumanRuntimeError(
            "checkpoint_file_unreadable",
            "checkpoint file cannot be hashed as a stable single-link input",
        )
    return {
        "mode": mode,
        "production_ready": False,
        "file_sha256": checkpoint_hash,
        "journal_path_sha256": checkpoint.journal_path_sha256,
        "event_count": checkpoint.event_count,
        "current_count": current_count,
        "terminal_event_hash": checkpoint.terminal_event_hash,
        "issued_at": checkpoint.issued_at,
        "expires_at": checkpoint.expires_at,
        "authority": checkpoint.authority,
        "key_id": checkpoint.key_id,
        "complete": False,
    }


def _read_projection(path: Path) -> dict[str, Any]:
    try:
        raw = read_stable_regular_file(
            path,
            max_bytes=_MAX_CONTEXT_BYTES,
        )
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise HumanRuntimeError(
            "human_projection_unreadable",
            f"durable HITL projection is unreadable: {error}",
        ) from error
    if not isinstance(value, dict):
        raise HumanRuntimeError(
            "human_projection_invalid",
            "durable HITL projection root must be an object",
        )
    _projection_sequence(value)
    _required_sha256(
        "projection_sha256",
        value.get("projection_sha256"),
    )
    return value


def _load_checkpoint(
    path: Path | None,
    *,
    mode: str,
) -> JournalCheckpoint | None:
    if mode not in {"local-test", "production"}:
        raise HumanRuntimeError(
            "journal_mode_invalid",
            "journal mode must be local-test or production",
        )
    if mode == "local-test":
        if path is not None:
            raise HumanRuntimeError(
                "checkpoint_mode_mismatch",
                "local-test mode must not accept a production checkpoint",
            )
        return None
    if path is None:
        raise HumanRuntimeError(
            "checkpoint_required",
            "production mode requires an external signed checkpoint",
        )
    try:
        raw = read_stable_regular_file(
            path,
            max_bytes=64 * 1024,
        )
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
        if not isinstance(value, dict):
            raise ValueError("checkpoint root must be an object")
        return JournalCheckpoint.from_dict(value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise HumanRuntimeError(
            getattr(error, "code", "checkpoint_invalid"),
            f"checkpoint is not a stable strict signed object: {error}",
        ) from error


def _contracts_object(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(value)
    if (
        payload.get("schema_version") != 1
        or payload.get("kind") != "qa_action_contracts"
        or not isinstance(payload.get("actions"), list)
        or any(not isinstance(item, dict) for item in payload["actions"])
    ):
        raise HumanRuntimeError(
            "human_action_contracts_invalid",
            "human gate requires normalized action contracts",
        )
    return payload


def _projection_sequence(value: Mapping[str, Any]) -> int:
    sequence = value.get("sequence")
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 0
    ):
        raise HumanRuntimeError(
            "human_projection_invalid",
            "journal projection sequence is invalid",
        )
    return sequence


def _journal_sha256(path: Path, *, event_count: int) -> str:
    digest = file_sha256(path)
    if digest is not None:
        return digest
    if event_count == 0 and not path.exists():
        return canonical_sha256(
            {
                "schema_version": 1,
                "kind": "qa_empty_journal",
                "journal_path_sha256": canonical_journal_path_sha256(
                    path
                ),
            }
        )
    raise HumanRuntimeError(
        "journal_file_unreadable",
        "journal cannot be hashed as a stable single-link file",
    )


def _request_id(bindings: Mapping[str, Any]) -> str:
    return "hitl-" + canonical_sha256(
        {
            "schema_version": 1,
            "kind": "qa_high_risk_human_request_identity",
            **{
                name: bindings[name]
                for name in (
                    "run_id",
                    "lease_generation",
                    "context_sha256",
                    "action_sha256",
                    "policy_sha256",
                    "authorization_sha256",
                )
            },
        }
    )[:40]


def _consumption_id(
    bindings: Mapping[str, Any],
    *,
    decision_id: str,
) -> str:
    return "consume-" + canonical_sha256(
        {
            "schema_version": 1,
            "kind": "qa_high_risk_human_consumption_identity",
            "request_id": _request_id(bindings),
            "decision_id": decision_id,
        }
    )[:40]


def _stable_action_binding(
    item: Mapping[str, Any],
) -> dict[str, Any]:
    """Keep human intent stable across trace/state sequence advancement."""

    return {
        "scenario_id": item.get("scenario_id"),
        "step_id": item.get("step_id"),
        "action": item.get("action"),
        "tool_version": item.get("tool_version"),
        "tool_spec_sha256": item.get("tool_spec_sha256"),
        "risk_class": item.get("risk_class"),
        "idempotent": item.get("idempotent"),
        "required_authorizations": item.get(
            "required_authorizations"
        ),
        "granted_authorizations": item.get(
            "granted_authorizations"
        ),
        "raw_step_sha256": item.get("raw_step_sha256"),
        "resolution_policy_sha256": item.get(
            "resolution_policy_sha256"
        ),
        "command_execution_binding": item.get(
            "command_execution_binding"
        ),
        "authorized": item.get("authorized"),
        "recovery_policy": item.get("recovery_policy"),
    }


def _claim_dispatch_redemption(
    store: HITLStore,
    *,
    bindings: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    request: Mapping[str, Any],
    decision: Mapping[str, Any],
    consumption: Mapping[str, Any],
    redeemed_at: str,
) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """Atomically append redemption to the checkpointed HITL journal."""

    approval_chain_sha256 = canonical_sha256(
        {
            "schema_version": 1,
            "kind": "qa_human_approval_chain",
            "bindings": dict(bindings),
            "checkpoint": dict(checkpoint),
            "request": dict(request),
            "decision": dict(decision),
            "consumption": dict(consumption),
        }
    )
    redemption_id = "redeem-" + canonical_sha256(
        {
            "schema_version": 1,
            "kind": "qa_human_dispatch_redemption_identity",
            "consumption_id": consumption.get("consumption_id"),
            "execution_intent_sha256": bindings.get(
                "execution_intent_sha256"
            ),
        }
    )[:40]
    expected = {
        "schema_version": 1,
        "kind": "qa_human_dispatch_redemption",
        "not_evidence": True,
        "redemption_id": redemption_id,
        "request_id": request.get("request_id"),
        "decision_id": decision.get("decision_id"),
        "consumption_id": consumption.get("consumption_id"),
        "run_id": bindings.get("run_id"),
        "lease_generation": bindings.get("lease_generation"),
        "plan_sha256": bindings.get("plan_sha256"),
        "context_sha256": bindings.get("context_sha256"),
        "plan_audit_sha256": bindings.get(
            "plan_audit_sha256"
        ),
        "tool_registry_sha256": bindings.get(
            "tool_registry_sha256"
        ),
        "action_sha256": bindings.get("action_sha256"),
        "policy_sha256": bindings.get("policy_sha256"),
        "authorization_sha256": bindings.get(
            "authorization_sha256"
        ),
        "execution_intent_sha256": bindings.get(
            "execution_intent_sha256"
        ),
        "approval_chain_sha256": approval_chain_sha256,
        "hitl_checkpoint_file_sha256": checkpoint.get(
            "file_sha256"
        ),
        "hitl_checkpoint_event_count": checkpoint.get(
            "event_count"
        ),
        "hitl_checkpoint_terminal_event_hash": checkpoint.get(
            "terminal_event_hash"
        ),
        "redeemed_at": redeemed_at,
    }
    _validate_redemption(expected)

    try:
        redemption, projection, appended = store.redeem_dispatch(
            expected,
        )
    except Exception as error:
        raise HumanRuntimeError(
            getattr(error, "code", "human_redemption_store_invalid"),
            f"human dispatch redemption failed closed: {error}",
        ) from error
    return (
        {
            **redemption,
            "journal_event_sequence": _projection_sequence(
                projection
            ),
            "journal_event_sha256": _required_sha256(
                "last_event_hash",
                projection.get("last_event_hash"),
            ),
        },
        projection,
        appended,
    )


def _validate_redemption(value: Mapping[str, Any]) -> None:
    fields = {
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
    if set(value) != fields:
        raise HumanRuntimeError(
            "human_redemption_schema_invalid",
            "redemption payload has unknown or missing fields",
        )
    if (
        value.get("schema_version") != 1
        or value.get("kind") != "qa_human_dispatch_redemption"
        or value.get("not_evidence") is not True
    ):
        raise HumanRuntimeError(
            "human_redemption_schema_invalid",
            "redemption kind/schema/not_evidence boundary is invalid",
        )
    for field in (
        "redemption_id",
        "request_id",
        "decision_id",
        "consumption_id",
        "run_id",
    ):
        if not isinstance(value.get(field), str) or not value[field]:
            raise HumanRuntimeError(
                "human_redemption_schema_invalid",
                f"redemption {field} must be non-empty text",
            )
    if (
        isinstance(value.get("lease_generation"), bool)
        or not isinstance(value.get("lease_generation"), int)
        or value["lease_generation"] < 1
        or isinstance(value.get("hitl_checkpoint_event_count"), bool)
        or not isinstance(
            value.get("hitl_checkpoint_event_count"),
            int,
        )
        or value["hitl_checkpoint_event_count"] < 0
    ):
        raise HumanRuntimeError(
            "human_redemption_schema_invalid",
            "redemption generation/checkpoint count is invalid",
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
        _required_sha256(field, value.get(field))
    try:
        parsed = datetime.fromisoformat(
            str(value.get("redeemed_at")).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise HumanRuntimeError(
            "human_redemption_time_invalid",
            "redemption time must be ISO 8601",
        ) from error
    if parsed.tzinfo is None:
        raise HumanRuntimeError(
            "human_redemption_time_invalid",
            "redemption time must include a timezone",
        )


def _action_summary(actions: list[dict[str, Any]]) -> str:
    labels = [
        f"{item.get('scenario_id')}/{item.get('step_id')}:{item.get('action')}"
        for item in actions
    ]
    return "High-risk QA actions: " + ", ".join(labels)


def _knowledge_query_rules_sha256() -> str:
    return canonical_sha256(
        {
            "schema_version": 1,
            "kind": "qa_knowledge_query_currentness_rules",
            "scope_match": "exact_canonical",
            "latest_version_only": True,
            "future_filtered": True,
            "expired_filtered": True,
            "revoked_filtered": True,
        }
    )


def _parse_authorities(
    raw: Any,
    *,
    field: str,
    allow_empty: bool,
) -> dict[str, dict[str, str]]:
    if not isinstance(raw, list) or (not raw and not allow_empty):
        raise HumanRuntimeError(
            "trust_config_authorities_invalid",
            f"trust config {field} must be a non-empty array",
        )
    result: dict[str, dict[str, str]] = {}
    for index, item in enumerate(raw):
        if (
            not isinstance(item, dict)
            or set(item) != {"authority", "keys"}
        ):
            raise HumanRuntimeError(
                "trust_config_authorities_invalid",
                f"trust config {field}[{index}] fields are invalid",
            )
        authority = item.get("authority")
        keys = item.get("keys")
        if (
            not isinstance(authority, str)
            or not authority
            or authority.strip() != authority
            or authority in result
            or not isinstance(keys, list)
            or not keys
        ):
            raise HumanRuntimeError(
                "trust_config_authorities_invalid",
                f"trust config {field}[{index}] identity/key ring is invalid",
            )
        ring: dict[str, str] = {}
        for key_index, key in enumerate(keys):
            if (
                not isinstance(key, dict)
                or set(key)
                != {"key_id", "algorithm", "public_key_pem"}
                or key.get("algorithm") != "Ed25519"
            ):
                raise HumanRuntimeError(
                    "trust_config_key_invalid",
                    f"trust config {field}[{index}].keys[{key_index}] is invalid",
                )
            key_id = key.get("key_id")
            public_key = key.get("public_key_pem")
            if (
                not isinstance(key_id, str)
                or not key_id
                or key_id.strip() != key_id
                or key_id in ring
                or not isinstance(public_key, str)
                or not public_key
                or "PRIVATE KEY" in public_key
            ):
                raise HumanRuntimeError(
                    "trust_config_key_invalid",
                    f"trust config {field}[{index}].keys[{key_index}] is unsafe",
                )
            ring[key_id] = public_key
        result[authority] = ring
    return dict(sorted(result.items()))


def _positive_ttl(value: Any) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or value <= 0
        or value > 7 * 24 * 60 * 60
    ):
        raise HumanRuntimeError(
            "human_request_ttl_invalid",
            "human request TTL must be positive and no greater than seven days",
        )
    return float(value)


def _aware_utc(value: datetime | None) -> datetime:
    observed = value or datetime.now(UTC)
    if not isinstance(observed, datetime) or observed.tzinfo is None:
        raise HumanRuntimeError(
            "human_clock_invalid",
            "human runtime clock must be timezone-aware",
        )
    return observed.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_human_timestamp(value: str, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except (AttributeError, ValueError) as error:
        raise HumanRuntimeError(
            "human_timestamp_invalid",
            f"{field} is not an ISO-8601 timestamp",
        ) from error
    if parsed.tzinfo is None:
        raise HumanRuntimeError(
            "human_timestamp_invalid",
            f"{field} must include a timezone",
        )
    return parsed.astimezone(UTC)


def _required_sha256(name: str, value: Any) -> str:
    if not _is_sha256(value):
        raise HumanRuntimeError(
            "human_hash_invalid",
            f"{name} must be a lowercase SHA-256",
        )
    return value


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value).issubset(_SHA256)
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _object_without_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")
