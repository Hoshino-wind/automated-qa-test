"""Durable dispatch contracts for probe actions.

The Python orchestrator derives immutable action metadata from the registered
ToolSpec set.  The Node probe runner appends an intent before dispatch and a
commit afterwards.  Recovery may automatically replay only ToolSpec-declared
idempotent actions with the same deterministic idempotency key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from qa_core.human_runtime import (
    verify_human_authorization_artifact,
    verify_human_authorization_for_contracts,
)
from qa_core.tools import ToolRegistry, build_default_tool_registry

ACTION_CONTRACTS_SCHEMA_VERSION = 1
ACTION_JOURNAL_SCHEMA_VERSION = 1
ACTION_AUTHORITY_KEY_ENV = "QA_ACTION_AUTHORITY_KEY"
ACTION_AUTHORIZATION_TICKET_ENV = "QA_ACTION_AUTHORIZATION_TICKET"
NO_HUMAN_AUTHORIZATION_SHA256 = hashlib.sha256(
    b"qa-human-authorization:not-configured:v1"
).hexdigest()
RESOLUTION_POLICY = {
    "schema_version": 4,
    "kind": "qa_runtime_reference_resolution_policy",
    "reference_kinds": ["env", "template", "var"],
    "strict_closed_reference_objects": True,
    "mutually_exclusive_reference_kinds": True,
    "immutable_identity_fields": ["scenario.id", "step.action", "step.id"],
    "forbidden_dynamic_command_fields": [
        "step.cmd",
        "step.command",
        "step.cwd",
        "step.env",
        "step.shell",
    ],
    "forbidden_dynamic_high_risk_network_target_fields": [
        "plan.baseUrl",
        "step.method",
        "step.path",
        "step.pathTemplate",
        "step.url",
        "step.urlTemplate",
    ],
    "high_risk_network_redirects_followed": False,
    "high_risk_target_identity_binding": "static_scheme_host_port_path_method",
    "high_risk_dynamic_values": "credential_headers_only",
    "high_risk_absolute_http_target_required": True,
    "high_risk_routing_overrides_forbidden": True,
    "resolved_command_boundary_revalidation": True,
    "command_default_cwd": "plan_directory",
    "command_environment_binding": "allowlisted_exact_sha256",
    "command_executable_binding": (
        "real_absolute_single_link_regular_identity_sha256"
    ),
    "command_direct_file_binding": (
        "existing_argv_regular_files_identity_sha256"
    ),
    "command_spawn_uses_bound_real_paths": True,
    "resolved_values_persisted": False,
    "persistent_commitment_mode": "structured_secret_redacted",
    "dynamic_reference_values_persisted": False,
    "low_entropy_secret_hashes_persisted": False,
    "raw_reference_identity_preserved": True,
}
_HIGH_RISK_NETWORK_ACTIONS = frozenset(
    {"api", "cleanupApi", "pollApi"}
)
_REFERENCE_DISCRIMINATORS = frozenset(
    {"env", "$env", "var", "$var", "template", "$template"}
)
_CREDENTIAL_HEADER_NAMES = frozenset(
    {
        "api-key",
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-access-token",
        "x-api-key",
        "x-auth-token",
    }
)
_ROUTING_HEADER_NAMES = frozenset(
    {
        ":authority",
        "forwarded",
        "host",
        "x-http-method-override",
        "x-method-override",
        "x-original-url",
        "x-rewrite-url",
    }
)
_ROUTING_LAUNCH_ARGUMENT_PREFIXES = (
    "--host-resolver-rules",
    "--host-rules",
    "--proxy-bypass-list",
    "--proxy-pac-url",
    "--proxy-server",
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_CONTRACT_BYTES = 4 * 1024 * 1024
_MAX_JOURNAL_BYTES = 32 * 1024 * 1024
_MAX_LINE_BYTES = 1024 * 1024
_MAX_COMMAND_FILE_BYTES = 256 * 1024 * 1024
_COMMAND_INHERITED_ENV_NAMES = (
    "CI",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "NODE_PATH",
    "PATH",
    "PYTHONPATH",
    "TERM",
    "TMPDIR",
)
_INTERPRETER_NAMES = frozenset(
    {
        "bash",
        "dash",
        "node",
        "nodejs",
        "perl",
        "php",
        "python",
        "ruby",
        "sh",
        "zsh",
    }
)
_CONTRACT_FIELDS = {
    "schema_version",
    "kind",
    "not_evidence",
    "run_id",
    "generation",
    "iteration",
    "plan_sha256",
    "context_sha256",
    "plan_audit_sha256",
    "tool_registry_sha256",
    "human_authorization_sha256",
    "actions",
    "contracts_sha256",
}
_ACTION_FIELDS = {
    "scenario_id",
    "step_id",
    "action",
    "tool_version",
    "tool_spec_sha256",
    "risk_class",
    "idempotent",
    "required_authorizations",
    "granted_authorizations",
    "authorization_sha256",
    "raw_step_sha256",
    "resolution_policy_sha256",
    "command_execution_binding",
    "authorized",
    "recovery_policy",
}
_EVENT_FIELDS = {
    "schema_version",
    "sequence",
    "previous_event_sha256",
    "event_sha256",
    "kind",
    "intent_sequence",
    "run_id",
    "generation",
    "iteration",
    "scenario_id",
    "step_id",
    "action",
    "invocation_sha256",
    "resolved_invocation_sha256",
    "execution_controls_sha256",
    "authorization_ticket_sha256",
    "execution_authorization_sha256",
    "human_authorization_sha256",
    "raw_step_sha256",
    "resolution_policy_sha256",
    "tool_spec_sha256",
    "idempotency_key",
    "idempotent",
    "status",
    "occurred_at",
}


class ActionProtocolError(ValueError):
    """Action contract or journal is malformed or incomplete."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "error": "action_protocol_error",
            "code": self.code,
            "message": str(self),
        }


RESOLUTION_POLICY_SHA256 = hashlib.sha256(
    json.dumps(
        RESOLUTION_POLICY,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
).hexdigest()


@dataclass(frozen=True, slots=True)
class ActionJournalVerification:
    valid: bool
    errors: tuple[dict[str, str], ...]
    sha256: str | None
    event_count: int
    current_action_count: int
    unresolved_intents: int

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "valid": self.valid,
            "sha256": self.sha256,
            "event_count": self.event_count,
            "current_action_count": self.current_action_count,
            "unresolved_intents": self.unresolved_intents,
            "errors": [dict(item) for item in self.errors],
        }


@dataclass(frozen=True, slots=True)
class ActionJournalPreflight:
    """Strict pre-dispatch view of an existing journal."""

    valid: bool
    errors: tuple[dict[str, str], ...]
    sha256: str | None
    event_count: int
    unresolved_idempotent: int
    unresolved_non_idempotent: int

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "valid": self.valid,
            "sha256": self.sha256,
            "event_count": self.event_count,
            "unresolved_idempotent": self.unresolved_idempotent,
            "unresolved_non_idempotent": (
                self.unresolved_non_idempotent
            ),
            "errors": [dict(item) for item in self.errors],
        }


def build_action_contracts(
    plan_path: Path,
    context_path: Path,
    plan_audit_path: Path,
    *,
    run_id: str,
    generation: int,
    iteration: int,
    registry: ToolRegistry | None = None,
    human_authorization_sha256: str = NO_HUMAN_AUTHORIZATION_SHA256,
    command_base_cwd: Path | None = None,
) -> dict[str, Any]:
    """Derive per-step ToolSpec and deterministic authorization bindings."""

    selected = registry or build_default_tool_registry()
    if not isinstance(selected, ToolRegistry):
        raise ActionProtocolError(
            "action_registry_invalid",
            "registry must be a ToolRegistry",
        )
    plan, plan_hash = _read_json_object_snapshot(
        plan_path,
        _MAX_CONTRACT_BYTES,
        single_link=True,
    )
    context, _context_file_hash = _read_json_object_snapshot(
        context_path,
        _MAX_CONTRACT_BYTES,
        single_link=True,
    )
    audit, audit_hash = _read_json_object_snapshot(
        plan_audit_path,
        _MAX_CONTRACT_BYTES,
        single_link=True,
    )
    plan_hash = _required_hash("plan", plan_hash)
    context_hash = _required_hash(
        "context",
        context.get("context_sha256"),
    )
    unsigned_context = dict(context)
    unsigned_context.pop("context_sha256", None)
    if context_hash != _canonical_sha256(unsigned_context):
        raise ActionProtocolError(
            "action_context_not_canonical",
            "context_sha256 does not bind the context input snapshot",
        )
    audit_hash = _required_hash("plan_audit", audit_hash)
    if audit.get("passed") is not True:
        raise ActionProtocolError(
            "action_plan_not_validated",
            "plan audit must pass before action contracts are issued",
        )
    audit_plan_hash = (
        audit.get("artifact_hashes", {}).get("plan_sha256")
        if isinstance(audit.get("artifact_hashes"), dict)
        else None
    )
    if audit_plan_hash != plan_hash:
        raise ActionProtocolError(
            "action_plan_audit_stale",
            "plan audit does not bind the current plan",
        )
    adapter = context.get("semantic_summary", {}).get("adapter", {})
    isolated = (
        isinstance(adapter, dict)
        and adapter.get("environment_boundary_confirmed") is True
        and str(adapter.get("runtime_mode", "")).lower()
        not in {"production", "prod", "live"}
    )
    policy_grants = {
        "browser_interaction",
        "browser_state_write",
        "cleanup_execution",
        "command_execution",
        "isolated_test_environment",
        "network_request",
    } if isolated else set()
    actions: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    sensitive_environment_names = _dynamic_environment_reference_names(
        plan
    )
    scenarios = plan.get("scenarios")
    if not isinstance(scenarios, list):
        raise ActionProtocolError(
            "action_plan_invalid",
            "plan.scenarios must be an array",
        )
    for scenario_index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            raise ActionProtocolError(
                "action_plan_invalid",
                f"scenario {scenario_index} must be an object",
            )
        scenario_id = _text("scenario.id", scenario.get("id"))
        steps = scenario.get("steps")
        if not isinstance(steps, list):
            raise ActionProtocolError(
                "action_plan_invalid",
                f"scenario {scenario_id!r} steps must be an array",
            )
        for step_index, step in enumerate(steps):
            if not isinstance(step, dict):
                raise ActionProtocolError(
                    "action_plan_invalid",
                    f"step {scenario_id}/{step_index} must be an object",
                )
            step_id = _text("step.id", step.get("id"))
            identity = (scenario_id, step_id)
            if identity in seen:
                raise ActionProtocolError(
                    "action_identity_duplicate",
                    f"duplicate action identity: {scenario_id}/{step_id}",
                )
            seen.add(identity)
            action_name = _text("step.action", step.get("action"))
            try:
                spec = selected.get(action_name)
            except Exception as error:
                raise ActionProtocolError(
                    "action_unknown",
                    f"unregistered action {action_name!r}: {error}",
                ) from error
            if action_name in _HIGH_RISK_NETWORK_ACTIONS:
                _require_static_high_risk_network_target(
                    plan,
                    step,
                    scenario_id=scenario_id,
                    step_id=step_id,
                )
            command_execution_binding = (
                _build_command_execution_binding(
                    step,
                    plan_path=plan_path,
                    sensitive_environment_names=(
                        sensitive_environment_names
                    ),
                    command_base_cwd=command_base_cwd,
                )
                if action_name == "command"
                else None
            )
            required = list(spec.required_authorizations)
            granted = sorted(set(required) & policy_grants)
            raw_step_sha256 = _canonical_sha256(step)
            authorization_payload = {
                "run_id": _text("run_id", run_id),
                "generation": _positive_int("generation", generation),
                "iteration": _positive_int("iteration", iteration),
                "scenario_id": scenario_id,
                "step_id": step_id,
                "action": action_name,
                "plan_sha256": plan_hash,
                "context_sha256": context_hash,
                "plan_audit_sha256": audit_hash,
                "human_authorization_sha256": _required_hash(
                    "human_authorization_sha256",
                    human_authorization_sha256,
                ),
                "tool_spec_sha256": spec.canonical_sha256,
                "raw_step_sha256": raw_step_sha256,
                "resolution_policy_sha256": RESOLUTION_POLICY_SHA256,
                "command_execution_binding_sha256": (
                    command_execution_binding["binding_sha256"]
                    if command_execution_binding is not None
                    else None
                ),
                "required_authorizations": required,
                "granted_authorizations": granted,
            }
            authorized = granted == required
            actions.append(
                {
                    "scenario_id": scenario_id,
                    "step_id": step_id,
                    "action": action_name,
                    "tool_version": spec.version,
                    "tool_spec_sha256": spec.canonical_sha256,
                    "risk_class": spec.risk_class.value,
                    "idempotent": spec.idempotent,
                    "required_authorizations": required,
                    "granted_authorizations": granted,
                    "authorization_sha256": _canonical_sha256(
                        authorization_payload
                    ),
                    "raw_step_sha256": raw_step_sha256,
                    "resolution_policy_sha256": (
                        RESOLUTION_POLICY_SHA256
                    ),
                    "command_execution_binding": (
                        command_execution_binding
                    ),
                    "authorized": authorized,
                    "recovery_policy": (
                        "automatic_same_key"
                        if spec.idempotent
                        else "human_reconciliation"
                    ),
                }
            )
    unsigned = {
        "schema_version": ACTION_CONTRACTS_SCHEMA_VERSION,
        "kind": "qa_action_contracts",
        "not_evidence": True,
        "run_id": _text("run_id", run_id),
        "generation": _positive_int("generation", generation),
        "iteration": _positive_int("iteration", iteration),
        "plan_sha256": plan_hash,
        "context_sha256": context_hash,
        "plan_audit_sha256": audit_hash,
        "tool_registry_sha256": selected.canonical_sha256,
        "human_authorization_sha256": _required_hash(
            "human_authorization_sha256",
            human_authorization_sha256,
        ),
        "actions": actions,
    }
    if any(item["authorized"] is not True for item in actions):
        missing = [
            f"{item['scenario_id']}/{item['step_id']}"
            for item in actions
            if item["authorized"] is not True
        ]
        raise ActionProtocolError(
            "action_authorization_missing",
            "action policy did not grant all required authorizations: "
            + ", ".join(missing),
        )
    return {
        **unsigned,
        "contracts_sha256": _canonical_sha256(unsigned),
    }


def issue_action_authorization_ticket(
    contracts: Mapping[str, Any],
    *,
    plan_path: Path,
    context_path: Path,
    plan_audit_path: Path,
    authority_key: bytes,
    human_authorization_path: Path | None = None,
    command_base_cwd: Path | None = None,
) -> str:
    """Issue an ephemeral pre-dispatch ticket from current trusted inputs."""

    if not isinstance(authority_key, bytes) or len(authority_key) < 32:
        raise ActionProtocolError(
            "action_authority_key_invalid",
            "action authority key must contain at least 32 bytes",
        )
    normalized = _validate_contracts(contracts)
    plan, plan_hash = _read_json_object_snapshot(
        plan_path,
        _MAX_CONTRACT_BYTES,
        single_link=True,
    )
    context, _context_file_hash = _read_json_object_snapshot(
        context_path,
        _MAX_CONTRACT_BYTES,
        single_link=True,
    )
    audit, audit_hash = _read_json_object_snapshot(
        plan_audit_path,
        _MAX_CONTRACT_BYTES,
        single_link=True,
    )
    if plan_hash != normalized["plan_sha256"]:
        raise ActionProtocolError(
            "action_ticket_plan_mismatch",
            "authorization ticket plan does not match contracts",
        )
    if audit_hash != normalized["plan_audit_sha256"]:
        raise ActionProtocolError(
            "action_ticket_audit_mismatch",
            "authorization ticket audit does not match contracts",
        )
    context_hash = _required_hash(
        "context_sha256",
        context.get("context_sha256"),
    )
    unsigned_context = dict(context)
    unsigned_context.pop("context_sha256", None)
    if (
        context_hash != _canonical_sha256(unsigned_context)
        or context_hash != normalized["context_sha256"]
    ):
        raise ActionProtocolError(
            "action_ticket_context_mismatch",
            "authorization ticket context is stale or not canonical",
        )
    adapter = context.get("semantic_summary", {}).get("adapter", {})
    capability_graph = context.get("capability_graph", {})
    if (
        context.get("ready") is not True
        or context.get("blockers") != []
        or not isinstance(adapter, dict)
        or adapter.get("environment_boundary_confirmed") is not True
        or str(adapter.get("runtime_mode", "")).lower()
        in {"production", "prod", "live"}
        or not isinstance(capability_graph, dict)
        or capability_graph.get("tool_registry_sha256")
        != normalized["tool_registry_sha256"]
    ):
        raise ActionProtocolError(
            "action_ticket_policy_denied",
            "current context does not authorize isolated QA dispatch",
        )
    audit_plan_hash = (
        audit.get("artifact_hashes", {}).get("plan_sha256")
        if isinstance(audit.get("artifact_hashes"), dict)
        else None
    )
    if audit.get("passed") is not True or audit_plan_hash != plan_hash:
        raise ActionProtocolError(
            "action_ticket_audit_denied",
            "current plan audit does not authorize dispatch",
        )
    _verify_current_command_execution_bindings(
        normalized,
        plan=plan,
        plan_path=plan_path,
        command_base_cwd=command_base_cwd,
    )
    human_hash = normalized["human_authorization_sha256"]
    if human_hash == NO_HUMAN_AUTHORIZATION_SHA256:
        if human_authorization_path is not None:
            raise ActionProtocolError(
                "action_ticket_human_authorization_unexpected",
                "ungated action contracts must not receive a human authorization artifact",
            )
    else:
        if human_authorization_path is None:
            raise ActionProtocolError(
                "action_ticket_human_authorization_missing",
                "gated action contracts require the final human authorization artifact",
            )
        human_bytes = _read_regular(
            human_authorization_path,
            max_bytes=_MAX_CONTRACT_BYTES,
            single_link=True,
        )
        observed_human_hash = hashlib.sha256(
            human_bytes
        ).hexdigest()
        if observed_human_hash != human_hash:
            raise ActionProtocolError(
                "action_ticket_human_authorization_mismatch",
                "human authorization artifact does not match action contracts",
            )
        try:
            human_payload = json.loads(
                human_bytes.decode("utf-8"),
                object_pairs_hook=_object_without_duplicates,
                parse_constant=_reject_constant,
            )
            if not isinstance(human_payload, dict):
                raise ValueError(
                    "human authorization root must be an object"
                )
            verify_human_authorization_artifact(
                human_payload,
                expected_file_sha256=observed_human_hash,
                artifact_bytes=human_bytes,
            )
            verify_human_authorization_for_contracts(
                human_payload,
                normalized,
            )
        except Exception as error:
            raise ActionProtocolError(
                getattr(
                    error,
                    "code",
                    "action_ticket_human_authorization_invalid",
                ),
                f"human authorization artifact failed closed: {error}",
            ) from error
    payload = _action_authorization_ticket_payload(normalized)
    return hmac.new(
        authority_key,
        _canonical_bytes(payload),
        hashlib.sha256,
    ).hexdigest()


def _action_authorization_ticket_payload(
    contracts: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "qa_action_authorization_ticket",
        "run_id": contracts["run_id"],
        "generation": contracts["generation"],
        "iteration": contracts["iteration"],
        "plan_sha256": contracts["plan_sha256"],
        "context_sha256": contracts["context_sha256"],
        "plan_audit_sha256": contracts["plan_audit_sha256"],
        "tool_registry_sha256": contracts["tool_registry_sha256"],
        "human_authorization_sha256": contracts[
            "human_authorization_sha256"
        ],
        "contracts_sha256": contracts["contracts_sha256"],
        "resolution_policy_sha256": RESOLUTION_POLICY_SHA256,
        "action_authorization_sha256": [
            item["authorization_sha256"]
            for item in contracts["actions"]
        ],
    }


def verify_action_journal(
    journal_path: Path,
    contracts: Mapping[str, Any],
    *,
    results: Mapping[str, Any] | None = None,
) -> ActionJournalVerification:
    """Strictly verify the append chain, intent/commit pairing and results."""

    errors: list[dict[str, str]] = []
    events: list[dict[str, Any]] = []
    current_commits: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    digest: str | None = None
    try:
        normalized_contracts = _validate_contracts(contracts)
        raw = _read_regular(
            journal_path,
            max_bytes=_MAX_JOURNAL_BYTES,
            single_link=True,
        )
        events = _parse_events(raw)
        _validate_event_chain(events)
        current_commits, unresolved = _inspect_event_pairs(
            events,
            normalized_contracts,
        )
        if unresolved:
            raise ActionProtocolError(
                "action_intent_unresolved",
                "action journal contains unresolved dispatch intents: "
                + ", ".join(
                    str(item["sequence"]) for item in unresolved
                ),
            )
        _require_complete_current_action_coverage(
            current_commits,
            normalized_contracts,
        )
        if results is not None:
            _match_results(current_commits, results)
        digest = hashlib.sha256(raw).hexdigest()
    except (ActionProtocolError, OSError) as error:
        code = (
            error.code
            if isinstance(error, ActionProtocolError)
            else "action_journal_unreadable"
        )
        errors.append({"code": code, "message": str(error)})
    return ActionJournalVerification(
        valid=not errors,
        errors=tuple(errors),
        sha256=digest,
        event_count=len(events),
        current_action_count=len(current_commits),
        unresolved_intents=len(unresolved),
    )


def preflight_action_journal(
    journal_path: Path,
    contracts: Mapping[str, Any],
) -> ActionJournalPreflight:
    """Validate recovery state before any probe side effect is dispatched.

    Missing and empty journals are valid.  An unresolved idempotent intent can
    be closed as ``abandoned_safe`` and replayed with its deterministic key.
    An unresolved non-idempotent intent always requires human reconciliation.
    """

    errors: list[dict[str, str]] = []
    events: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    digest: str | None = None
    try:
        normalized_contracts = _validate_contracts(contracts)
        try:
            raw = _read_regular(
                journal_path,
                max_bytes=_MAX_JOURNAL_BYTES,
                single_link=True,
            )
        except FileNotFoundError:
            raw = b""
        events = _parse_events(raw)
        _validate_event_chain(events)
        _, unresolved = _inspect_event_pairs(
            events,
            normalized_contracts,
        )
        current_key = (
            normalized_contracts["run_id"],
            normalized_contracts["generation"],
            normalized_contracts["iteration"],
        )
        current_events = [
            event
            for event in events
            if (
                event["run_id"],
                event["generation"],
                event["iteration"],
            )
            == current_key
        ]
        if (
            normalized_contracts["human_authorization_sha256"]
            != NO_HUMAN_AUTHORIZATION_SHA256
            and current_events
        ):
            raise ActionProtocolError(
                "human_dispatch_already_claimed",
                "this human-authorized execution intent already has a "
                "durable action intent/commit; reconcile without "
                "redispatch",
            )
        unsafe = [
            item for item in unresolved
            if item["idempotent"] is not True
        ]
        if unsafe:
            raise ActionProtocolError(
                "action_reconciliation_required",
                "unresolved non-idempotent dispatch intents require human "
                "reconciliation: "
                + ", ".join(str(item["sequence"]) for item in unsafe),
            )
        if journal_path.exists():
            digest = hashlib.sha256(raw).hexdigest()
    except (ActionProtocolError, OSError) as error:
        code = (
            error.code
            if isinstance(error, ActionProtocolError)
            else "action_journal_unreadable"
        )
        errors.append({"code": code, "message": str(error)})
    return ActionJournalPreflight(
        valid=not errors,
        errors=tuple(errors),
        sha256=digest,
        event_count=len(events),
        unresolved_idempotent=sum(
            item["idempotent"] is True for item in unresolved
        ),
        unresolved_non_idempotent=sum(
            item["idempotent"] is not True for item in unresolved
        ),
    )


def load_action_contracts(path: Path) -> dict[str, Any]:
    """Read and validate a contracts artifact."""

    return _validate_contracts(
        _read_json_object(path, _MAX_CONTRACT_BYTES)
    )


def _validate_contracts(
    value: Mapping[str, Any],
    *,
    registry: ToolRegistry | None = None,
) -> dict[str, Any]:
    payload = dict(value)
    trusted_registry = registry or build_default_tool_registry()
    if not isinstance(trusted_registry, ToolRegistry):
        raise ActionProtocolError(
            "action_registry_invalid",
            "trusted registry must be a ToolRegistry",
        )
    _exact_fields("contracts", payload, _CONTRACT_FIELDS)
    if payload["schema_version"] != ACTION_CONTRACTS_SCHEMA_VERSION:
        raise ActionProtocolError(
            "action_contracts_schema_invalid",
            "action contracts schema_version must equal 1",
        )
    if (
        payload["kind"] != "qa_action_contracts"
        or payload["not_evidence"] is not True
    ):
        raise ActionProtocolError(
            "action_contracts_kind_invalid",
            "action contracts kind/not_evidence boundary is invalid",
        )
    for field in (
        "plan_sha256",
        "context_sha256",
        "plan_audit_sha256",
        "tool_registry_sha256",
        "human_authorization_sha256",
        "contracts_sha256",
    ):
        _required_hash(field, payload[field])
    if (
        payload["tool_registry_sha256"]
        != trusted_registry.canonical_sha256
    ):
        raise ActionProtocolError(
            "action_registry_drift",
            "action contracts do not bind the current trusted ToolRegistry",
        )
    _text("run_id", payload["run_id"])
    _positive_int("generation", payload["generation"])
    _positive_int("iteration", payload["iteration"])
    if not isinstance(payload["actions"], list):
        raise ActionProtocolError(
            "action_contracts_actions_invalid",
            "contracts.actions must be an array",
        )
    identities: set[tuple[str, str]] = set()
    for index, item in enumerate(payload["actions"]):
        if not isinstance(item, dict):
            raise ActionProtocolError(
                "action_contract_invalid",
                f"contracts.actions[{index}] must be an object",
            )
        _exact_fields(f"actions[{index}]", item, _ACTION_FIELDS)
        identity = (
            _text("scenario_id", item["scenario_id"]),
            _text("step_id", item["step_id"]),
        )
        if identity in identities:
            raise ActionProtocolError(
                "action_identity_duplicate",
                f"duplicate action contract: {identity!r}",
            )
        identities.add(identity)
        action = _text("action", item["action"])
        try:
            trusted_spec = trusted_registry.get(action)
        except Exception as error:
            raise ActionProtocolError(
                "action_unknown",
                "action contract is not in the trusted registry: "
                f"{action}",
            ) from error
        _text("tool_version", item["tool_version"])
        _required_hash("tool_spec_sha256", item["tool_spec_sha256"])
        _required_hash(
            "authorization_sha256",
            item["authorization_sha256"],
        )
        _required_hash("raw_step_sha256", item["raw_step_sha256"])
        resolution_policy_hash = _required_hash(
            "resolution_policy_sha256",
            item["resolution_policy_sha256"],
        )
        if resolution_policy_hash != RESOLUTION_POLICY_SHA256:
            raise ActionProtocolError(
                "action_resolution_policy_invalid",
                "action contract does not bind the supported "
                "runtime reference resolution policy",
            )
        command_binding = _validate_command_execution_binding(
            item["command_execution_binding"],
            action=action,
        )
        if type(item["idempotent"]) is not bool or type(item["authorized"]) is not bool:
            raise ActionProtocolError(
                "action_contract_boolean_invalid",
                "idempotent and authorized must be booleans",
            )
        if (
            item["tool_version"] != trusted_spec.version
            or item["tool_spec_sha256"]
            != trusted_spec.canonical_sha256
            or item["risk_class"] != trusted_spec.risk_class.value
            or item["idempotent"] is not trusted_spec.idempotent
        ):
            raise ActionProtocolError(
                "action_tool_spec_drift",
                f"action {identity!r} does not match the trusted ToolSpec",
            )
        for field in ("required_authorizations", "granted_authorizations"):
            if (
                not isinstance(item[field], list)
                or any(not isinstance(entry, str) or not entry for entry in item[field])
                or item[field] != sorted(set(item[field]))
            ):
                raise ActionProtocolError(
                    "action_contract_authorizations_invalid",
                    f"{field} must be a sorted unique string array",
                )
        if item["required_authorizations"] != list(
            trusted_spec.required_authorizations
        ):
            raise ActionProtocolError(
                "action_required_authorizations_drift",
                f"action {identity!r} changed ToolSpec authorizations",
            )
        if item["granted_authorizations"] != item[
            "required_authorizations"
        ]:
            raise ActionProtocolError(
                "action_policy_grant_invalid",
                f"action {identity!r} is not fully granted by policy",
            )
        if item["authorized"] is not True:
            raise ActionProtocolError(
                "action_contract_not_authorized",
                f"action {identity!r} is not authorized",
            )
        expected_authorization = _canonical_sha256(
            {
                "run_id": payload["run_id"],
                "generation": payload["generation"],
                "iteration": payload["iteration"],
                "scenario_id": item["scenario_id"],
                "step_id": item["step_id"],
                "action": item["action"],
                "plan_sha256": payload["plan_sha256"],
                "context_sha256": payload["context_sha256"],
                "plan_audit_sha256": payload["plan_audit_sha256"],
                "human_authorization_sha256": payload[
                    "human_authorization_sha256"
                ],
                "tool_spec_sha256": item["tool_spec_sha256"],
                "raw_step_sha256": item["raw_step_sha256"],
                "resolution_policy_sha256": (
                    item["resolution_policy_sha256"]
                ),
                "command_execution_binding_sha256": (
                    command_binding["binding_sha256"]
                    if command_binding is not None
                    else None
                ),
                "required_authorizations": (
                    item["required_authorizations"]
                ),
                "granted_authorizations": (
                    item["granted_authorizations"]
                ),
            }
        )
        if item["authorization_sha256"] != expected_authorization:
            raise ActionProtocolError(
                "action_authorization_hash_invalid",
                f"action {identity!r} authorization hash is invalid",
            )
        expected_policy = (
            "automatic_same_key"
            if item["idempotent"]
            else "human_reconciliation"
        )
        if item["recovery_policy"] != expected_policy:
            raise ActionProtocolError(
                "action_recovery_policy_invalid",
                f"action {identity!r} recovery policy is inconsistent",
            )
    unsigned = dict(payload)
    recorded_hash = unsigned.pop("contracts_sha256")
    if recorded_hash != _canonical_sha256(unsigned):
        raise ActionProtocolError(
            "action_contracts_hash_mismatch",
            "contracts_sha256 does not match the canonical payload",
        )
    return payload


def _parse_events(raw: bytes) -> list[dict[str, Any]]:
    if raw and not raw.endswith(b"\n"):
        raise ActionProtocolError(
            "action_journal_partial_line",
            "action journal must end with a newline",
        )
    events: list[dict[str, Any]] = []
    for index, line in enumerate(raw.splitlines(), start=1):
        if len(line) > _MAX_LINE_BYTES:
            raise ActionProtocolError(
                "action_journal_line_too_large",
                f"action journal line {index} exceeds the size limit",
            )
        try:
            value = json.loads(
                line.decode("utf-8"),
                object_pairs_hook=_object_without_duplicates,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ActionProtocolError(
                "action_journal_json_invalid",
                f"invalid action journal line {index}: {error}",
            ) from error
        if not isinstance(value, dict):
            raise ActionProtocolError(
                "action_journal_event_invalid",
                f"action journal line {index} must be an object",
            )
        _exact_fields(f"event[{index}]", value, _EVENT_FIELDS)
        events.append(value)
    return events


def _validate_event_chain(events: list[dict[str, Any]]) -> None:
    previous: str | None = None
    for expected_sequence, event in enumerate(events, start=1):
        if event["schema_version"] != ACTION_JOURNAL_SCHEMA_VERSION:
            raise ActionProtocolError(
                "action_journal_schema_invalid",
                "action journal schema_version must equal 1",
            )
        if event["sequence"] != expected_sequence:
            raise ActionProtocolError(
                "action_journal_sequence_invalid",
                "action journal sequence must be contiguous",
            )
        if event["previous_event_sha256"] != previous:
            raise ActionProtocolError(
                "action_journal_chain_invalid",
                "action journal previous hash is invalid",
            )
        unsigned = dict(event)
        recorded = unsigned.pop("event_sha256")
        if (
            not _is_hash(recorded)
            or recorded != _canonical_sha256(unsigned)
        ):
            raise ActionProtocolError(
                "action_journal_hash_invalid",
                "action journal event hash is invalid",
            )
        for field in (
            "invocation_sha256",
            "resolved_invocation_sha256",
            "execution_controls_sha256",
            "authorization_ticket_sha256",
            "execution_authorization_sha256",
            "human_authorization_sha256",
            "raw_step_sha256",
            "resolution_policy_sha256",
            "tool_spec_sha256",
            "idempotency_key",
        ):
            _required_hash(field, event[field])
        _text("run_id", event["run_id"])
        _positive_int("generation", event["generation"])
        _positive_int("iteration", event["iteration"])
        for field in ("scenario_id", "step_id", "action", "status"):
            _text(field, event[field])
        if type(event["idempotent"]) is not bool:
            raise ActionProtocolError(
                "action_journal_boolean_invalid",
                "event.idempotent must be a boolean",
            )
        expected_invocation_hash = _canonical_sha256(
            {
                "schema_version": 1,
                "kind": "qa_secret_redacted_invocation_commitment",
                "resolved_invocation_sha256": (
                    event["resolved_invocation_sha256"]
                ),
            }
        )
        if event["invocation_sha256"] != expected_invocation_hash:
            raise ActionProtocolError(
                "action_invocation_hash_invalid",
                "event.invocation_sha256 does not bind the exact "
                "resolved invocation commitment",
            )
        expected_idempotency_key = _canonical_sha256(
            {
                "run_id": event["run_id"],
                "generation": event["generation"],
                "iteration": event["iteration"],
                "scenario_id": event["scenario_id"],
                "step_id": event["step_id"],
                "action": event["action"],
                "invocation_sha256": event["invocation_sha256"],
                "execution_authorization_sha256": (
                    event["execution_authorization_sha256"]
                ),
            }
        )
        if event["idempotency_key"] != expected_idempotency_key:
            raise ActionProtocolError(
                "action_idempotency_key_invalid",
                "event.idempotency_key does not bind the dispatch identity",
            )
        try:
            parsed = datetime.fromisoformat(
                str(event["occurred_at"]).replace("Z", "+00:00")
            )
        except ValueError as error:
            raise ActionProtocolError(
                "action_journal_time_invalid",
                "event.occurred_at must be ISO 8601",
            ) from error
        if parsed.tzinfo is None:
            raise ActionProtocolError(
                "action_journal_time_invalid",
                "event.occurred_at must include a timezone",
            )
        if event["kind"] == "intent":
            if event["intent_sequence"] is not None or event["status"] != "pending":
                raise ActionProtocolError(
                    "action_intent_invalid",
                    "intent must use intent_sequence=null and status=pending",
                )
        elif event["kind"] == "commit":
            if (
                isinstance(event["intent_sequence"], bool)
                or not isinstance(event["intent_sequence"], int)
                or event["intent_sequence"] < 1
                or event["status"]
                not in {"passed", "failed", "skipped", "abandoned_safe"}
            ):
                raise ActionProtocolError(
                    "action_commit_invalid",
                    "commit intent_sequence/status is invalid",
                )
        else:
            raise ActionProtocolError(
                "action_journal_kind_invalid",
                "event.kind must be intent or commit",
            )
        previous = recorded


def _inspect_event_pairs(
    events: list[dict[str, Any]],
    contracts: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    intents: dict[int, dict[str, Any]] = {}
    committed: set[int] = set()
    current_key = (
        contracts["run_id"],
        contracts["generation"],
        contracts["iteration"],
    )
    contract_by_identity = {
        (item["scenario_id"], item["step_id"]): item
        for item in contracts["actions"]
    }
    current_commits: list[dict[str, Any]] = []
    for event in events:
        if event["kind"] == "intent":
            identity = (event["scenario_id"], event["step_id"])
            contract = contract_by_identity.get(identity)
            if (
                event["run_id"],
                event["generation"],
                event["iteration"],
            ) == current_key:
                _match_contract_event(
                    event,
                    contract,
                    human_authorization_sha256=contracts[
                        "human_authorization_sha256"
                    ],
                )
            intents[event["sequence"]] = event
            continue
        intent_sequence = event["intent_sequence"]
        intent = intents.get(intent_sequence)
        if intent is None or intent_sequence in committed:
            raise ActionProtocolError(
                "action_commit_orphaned",
                "commit must reference one unresolved prior intent",
            )
        for field in (
            "run_id",
            "generation",
            "iteration",
            "scenario_id",
            "step_id",
            "action",
            "invocation_sha256",
            "resolved_invocation_sha256",
            "execution_controls_sha256",
            "authorization_ticket_sha256",
            "execution_authorization_sha256",
            "human_authorization_sha256",
            "raw_step_sha256",
            "resolution_policy_sha256",
            "tool_spec_sha256",
            "idempotency_key",
            "idempotent",
        ):
            if event[field] != intent[field]:
                raise ActionProtocolError(
                    "action_commit_mismatch",
                    f"commit does not match intent field {field}",
                )
        committed.add(intent_sequence)
        if (
            event["run_id"],
            event["generation"],
            event["iteration"],
        ) == current_key and event["status"] != "abandoned_safe":
            contract = contract_by_identity.get(
                (event["scenario_id"], event["step_id"])
            )
            _match_contract_event(
                event,
                contract,
                human_authorization_sha256=contracts[
                    "human_authorization_sha256"
                ],
            )
            current_commits.append(event)
    unresolved = sorted(set(intents) - committed)
    return current_commits, [intents[item] for item in unresolved]


def _require_complete_current_action_coverage(
    current_commits: list[dict[str, Any]],
    contracts: Mapping[str, Any],
) -> None:
    contract_by_identity = {
        (item["scenario_id"], item["step_id"]): item
        for item in contracts["actions"]
    }
    if len(current_commits) != len(contract_by_identity):
        raise ActionProtocolError(
            "action_commit_coverage_incomplete",
            "current action commits do not exactly cover contracts",
        )
    identities = [
        (event["scenario_id"], event["step_id"])
        for event in current_commits
    ]
    if identities != list(contract_by_identity):
        raise ActionProtocolError(
            "action_commit_order_invalid",
            "current action commit order does not match contracts",
        )


def _match_contract_event(
    event: Mapping[str, Any],
    contract: Mapping[str, Any] | None,
    *,
    human_authorization_sha256: str,
) -> None:
    if contract is None:
        raise ActionProtocolError(
            "action_contract_missing",
            "journal event has no current action contract",
        )
    if (
        event["action"] != contract["action"]
        or event["tool_spec_sha256"] != contract["tool_spec_sha256"]
        or event["raw_step_sha256"] != contract["raw_step_sha256"]
        or event["resolution_policy_sha256"]
        != contract["resolution_policy_sha256"]
        or event["human_authorization_sha256"]
        != human_authorization_sha256
        or event["idempotent"] is not contract["idempotent"]
    ):
        raise ActionProtocolError(
            "action_contract_mismatch",
            "journal event does not match ToolSpec-derived contract",
        )
    expected_execution_authorization = _canonical_sha256(
        {
            "schema_version": 1,
            "kind": "qa_execution_authorization",
            "run_id": event["run_id"],
            "generation": event["generation"],
            "iteration": event["iteration"],
            "scenario_id": event["scenario_id"],
            "step_id": event["step_id"],
            "action": event["action"],
            "raw_step_sha256": event["raw_step_sha256"],
            "resolution_policy_sha256": (
                event["resolution_policy_sha256"]
            ),
            "resolved_invocation_sha256": (
                event["resolved_invocation_sha256"]
            ),
            "execution_controls_sha256": (
                event["execution_controls_sha256"]
            ),
            "authorization_ticket_sha256": (
                event["authorization_ticket_sha256"]
            ),
            "human_authorization_sha256": (
                event["human_authorization_sha256"]
            ),
            "invocation_sha256": event["invocation_sha256"],
            "tool_spec_sha256": event["tool_spec_sha256"],
            "contract_authorization_sha256": (
                contract["authorization_sha256"]
            ),
        }
    )
    if (
        event["execution_authorization_sha256"]
        != expected_execution_authorization
    ):
        raise ActionProtocolError(
            "action_execution_authorization_invalid",
            "journal event execution authorization does not bind the "
            "contract and resolved invocation",
        )


def _match_results(
    commits: list[dict[str, Any]],
    results: Mapping[str, Any],
) -> None:
    observed: list[tuple[str, str, str, str]] = []
    scenarios = results.get("scenarios")
    if not isinstance(scenarios, list):
        raise ActionProtocolError(
            "action_results_invalid",
            "results.scenarios must be an array",
        )
    for scenario in scenarios:
        if not isinstance(scenario, dict) or not isinstance(
            scenario.get("steps"),
            list,
        ):
            raise ActionProtocolError(
                "action_results_invalid",
                "results scenarios and steps must be objects/arrays",
            )
        for step in scenario["steps"]:
            if not isinstance(step, dict):
                raise ActionProtocolError(
                    "action_results_invalid",
                    "results step must be an object",
                )
            observed.append(
                (
                    _text("scenarioId", step.get("scenarioId")),
                    _text("stepId", step.get("stepId")),
                    _text("action", step.get("action")),
                    _text("status", step.get("status")),
                )
            )
    expected = [
        (
            event["scenario_id"],
            event["step_id"],
            event["action"],
            event["status"],
        )
        for event in commits
    ]
    if observed != expected:
        raise ActionProtocolError(
            "action_results_mismatch",
            "results steps do not exactly match committed action dispatches",
        )


def _read_json_object(path: Path, max_bytes: int) -> dict[str, Any]:
    value, _sha256 = _read_json_object_snapshot(
        path,
        max_bytes,
        single_link=False,
    )
    return value


def _read_json_object_snapshot(
    path: Path,
    max_bytes: int,
    *,
    single_link: bool,
) -> tuple[dict[str, Any], str]:
    """Parse and hash the exact bytes read from one stable descriptor."""

    raw = _read_regular(
        path,
        max_bytes=max_bytes,
        single_link=single_link,
    )
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ActionProtocolError(
            "action_json_invalid",
            f"invalid JSON input {path}: {error}",
        ) from error
    if not isinstance(value, dict):
        raise ActionProtocolError(
            "action_json_invalid",
            f"JSON input root must be an object: {path}",
        )
    return value, hashlib.sha256(raw).hexdigest()


def _read_regular(
    path: Path,
    *,
    max_bytes: int,
    single_link: bool,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ActionProtocolError(
                "action_input_not_regular",
                f"input is not a regular file: {path}",
            )
        if single_link and before.st_nlink != 1:
            raise ActionProtocolError(
                "action_input_hardlinked",
                f"hard-linked input is not allowed: {path}",
            )
        if before.st_size > max_bytes:
            raise ActionProtocolError(
                "action_input_too_large",
                f"input exceeds {max_bytes} bytes: {path}",
            )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, max_bytes + 1 - size),
            )
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise ActionProtocolError(
                    "action_input_too_large",
                    f"input exceeds {max_bytes} bytes: {path}",
                )
        raw = b"".join(chunks)
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
            raise ActionProtocolError(
                "action_input_changed",
                f"input changed while reading: {path}",
            )
        try:
            current = os.stat(path, follow_symlinks=False)
        except OSError as error:
            raise ActionProtocolError(
                "action_input_changed",
                f"input path changed while reading: {path}",
            ) from error
        if (
            not stat.S_ISREG(current.st_mode)
            or (
                current.st_dev,
                current.st_ino,
                current.st_size,
                current.st_mtime_ns,
            )
            != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
        ):
            raise ActionProtocolError(
                "action_input_changed",
                f"input path changed while reading: {path}",
            )
        return raw
    finally:
        os.close(descriptor)


def _exact_fields(
    label: str,
    value: Mapping[str, Any],
    expected: set[str],
) -> None:
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing or unknown:
        raise ActionProtocolError(
            "action_schema_fields_invalid",
            f"{label} fields invalid; missing={missing}, unknown={unknown}",
        )


def _object_without_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number: {value}")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ActionProtocolError(
            "action_json_not_canonical",
            str(error),
        ) from error


def _text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ActionProtocolError(
            "action_text_invalid",
            f"{name} must be non-empty trimmed text",
        )
    return value


def _positive_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ActionProtocolError(
            "action_integer_invalid",
            f"{name} must be a positive integer",
        )
    return value


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256.fullmatch(value))


def _required_hash(name: str, value: Any) -> str:
    if not _is_hash(value):
        raise ActionProtocolError(
            "action_hash_invalid",
            f"{name} must be a lowercase SHA-256",
        )
    return value


_COMMAND_BINDING_FIELDS = {
    "schema_version",
    "kind",
    "base_cwd",
    "cwd",
    "environment_sha256",
    "inherited_environment_names",
    "executable",
    "direct_files",
    "binding_sha256",
}
_COMMAND_FILE_IDENTITY_FIELDS = {
    "schema_version",
    "kind",
    "real_path",
    "device",
    "inode",
    "size",
    "mtime_ns",
    "mode",
    "sha256",
}
_COMMAND_DIRECT_FILE_FIELDS = {
    "argv_index",
    "argument_path",
    "identity",
}


def _build_command_execution_binding(
    step: Mapping[str, Any],
    *,
    plan_path: Path,
    sensitive_environment_names: set[str],
    command_base_cwd: Path | None,
) -> dict[str, Any]:
    """Bind the concrete command entry point before human authorization."""

    _require_static_command_controls(step)
    command_value = step.get("command", step.get("cmd"))
    if (
        not isinstance(command_value, list)
        or not command_value
        or any(
            not isinstance(part, str) or not part
            for part in command_value
        )
    ):
        raise ActionProtocolError(
            "action_command_argv_invalid",
            "command actions require a non-empty static string argv array",
        )
    if step.get("shell") is True:
        raise ActionProtocolError(
            "action_command_shell_forbidden",
            "command actions cannot enable a shell",
        )
    plan_directory = _command_base_directory(
        plan_path,
        command_base_cwd=command_base_cwd,
    )
    raw_cwd = step.get("cwd")
    if raw_cwd is None:
        cwd = plan_directory
    elif isinstance(raw_cwd, str) and raw_cwd:
        candidate_cwd = Path(raw_cwd)
        if not candidate_cwd.is_absolute():
            candidate_cwd = plan_directory / candidate_cwd
        try:
            cwd = candidate_cwd.resolve(strict=True)
        except OSError as error:
            raise ActionProtocolError(
                "action_command_cwd_invalid",
                f"command cwd is unavailable: {candidate_cwd}",
            ) from error
    else:
        raise ActionProtocolError(
            "action_command_cwd_invalid",
            "command cwd must be static non-empty text",
        )
    if not cwd.is_dir():
        raise ActionProtocolError(
            "action_command_cwd_invalid",
            f"command cwd is not a directory: {cwd}",
        )
    environment = _command_environment(
        step,
        sensitive_environment_names=sensitive_environment_names,
    )
    executable_path = _resolve_command_executable(
        command_value[0],
        cwd=cwd,
        environment=environment,
    )
    executable = _stable_command_file_identity(
        executable_path,
        kind="executable",
        require_executable=True,
    )
    direct_files = _command_direct_files(
        command_value,
        cwd=cwd,
        executable_name=Path(executable_path).name,
    )
    unsigned = {
        "schema_version": 1,
        "kind": "qa_command_execution_binding",
        "base_cwd": str(plan_directory),
        "cwd": str(cwd),
        "environment_sha256": _canonical_sha256(environment),
        "inherited_environment_names": list(
            _COMMAND_INHERITED_ENV_NAMES
        ),
        "executable": executable,
        "direct_files": direct_files,
    }
    return {
        **unsigned,
        "binding_sha256": _canonical_sha256(unsigned),
    }


def _require_static_command_controls(
    step: Mapping[str, Any],
) -> None:
    for field in ("command", "cmd", "cwd", "shell", "env"):
        if field in step and _contains_dynamic_reference(step[field]):
            raise ActionProtocolError(
                "action_command_control_dynamic",
                f"command control step.{field} cannot be dynamic",
            )


def _command_base_directory(
    plan_path: Path,
    *,
    command_base_cwd: Path | None,
) -> Path:
    selected = (
        command_base_cwd
        if command_base_cwd is not None
        else plan_path.parent
    )
    try:
        resolved = selected.resolve(strict=True)
    except OSError as error:
        raise ActionProtocolError(
            "action_command_base_cwd_invalid",
            f"command base cwd is unavailable: {selected}",
        ) from error
    if not resolved.is_dir():
        raise ActionProtocolError(
            "action_command_base_cwd_invalid",
            f"command base cwd is not a directory: {resolved}",
        )
    return resolved


def _contains_dynamic_reference(value: Any) -> bool:
    if isinstance(value, list):
        return any(_contains_dynamic_reference(item) for item in value)
    if not isinstance(value, dict):
        return False
    if _looks_like_dynamic_reference(value):
        return True
    return any(
        _contains_dynamic_reference(item)
        for item in value.values()
    )


def _dynamic_environment_reference_names(
    value: Any,
) -> set[str]:
    names: set[str] = set()
    if isinstance(value, list):
        for item in value:
            names.update(_dynamic_environment_reference_names(item))
        return names
    if not isinstance(value, dict):
        return names
    for field in ("env", "$env"):
        candidate = value.get(field)
        if isinstance(candidate, str) and candidate:
            names.add(candidate)
    for item in value.values():
        names.update(_dynamic_environment_reference_names(item))
    return names


def _command_environment(
    step: Mapping[str, Any],
    *,
    sensitive_environment_names: set[str],
) -> dict[str, str]:
    explicit = step.get("env", {})
    if (
        not isinstance(explicit, dict)
        or any(
            not isinstance(name, str)
            or not name
            or not isinstance(value, str)
            for name, value in explicit.items()
        )
    ):
        raise ActionProtocolError(
            "action_command_environment_invalid",
            "command env must be a static string-to-string object",
        )
    environment = {
        name: os.environ[name]
        for name in _COMMAND_INHERITED_ENV_NAMES
        if isinstance(os.environ.get(name), str)
    }
    environment.update(explicit)
    for name in sensitive_environment_names:
        environment.pop(name, None)
    return dict(sorted(environment.items()))


def _resolve_command_executable(
    argv0: str,
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> Path:
    if os.path.isabs(argv0) or os.sep in argv0 or (
        os.altsep is not None and os.altsep in argv0
    ):
        candidate = Path(argv0)
        if not candidate.is_absolute():
            candidate = cwd / candidate
    else:
        located = shutil.which(
            argv0,
            path=environment.get("PATH", ""),
        )
        if located is None:
            raise ActionProtocolError(
                "action_command_executable_missing",
                f"command executable is unavailable on the bound PATH: {argv0}",
            )
        candidate = Path(located)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ActionProtocolError(
            "action_command_executable_missing",
            f"command executable is unavailable: {candidate}",
        ) from error
    return resolved


def _command_direct_files(
    argv: list[str],
    *,
    cwd: Path,
    executable_name: str,
) -> list[dict[str, Any]]:
    primary_script = _interpreter_script_index(
        argv,
        executable_name=executable_name,
    )
    direct_files: list[dict[str, Any]] = []
    observed_indices: set[int] = set()
    for index, argument in enumerate(argv[1:], start=1):
        argument_path = Path(argument)
        if not argument_path.is_absolute():
            argument_path = cwd / argument_path
        lexical_path = Path(os.path.abspath(argument_path))
        try:
            info = lexical_path.stat()
        except OSError:
            if index == primary_script:
                raise ActionProtocolError(
                    "action_command_script_missing",
                    (
                        "interpreter script is unavailable during "
                        f"authorization: {lexical_path}"
                    ),
                )
            continue
        if not stat.S_ISREG(info.st_mode):
            if index == primary_script:
                raise ActionProtocolError(
                    "action_command_script_invalid",
                    f"interpreter script is not a regular file: {lexical_path}",
                )
            continue
        try:
            real_path = lexical_path.resolve(strict=True)
        except OSError as error:
            raise ActionProtocolError(
                "action_command_direct_file_invalid",
                f"direct command input is unavailable: {lexical_path}",
            ) from error
        direct_files.append(
            {
                "argv_index": index,
                "argument_path": str(lexical_path),
                "identity": _stable_command_file_identity(
                    real_path,
                    kind="direct_input",
                    require_executable=False,
                ),
            }
        )
        observed_indices.add(index)
    if (
        primary_script is not None
        and primary_script not in observed_indices
    ):
        raise ActionProtocolError(
            "action_command_script_missing",
            "interpreter script was not bound as a direct regular input",
        )
    return direct_files


def _interpreter_script_index(
    argv: list[str],
    *,
    executable_name: str,
) -> int | None:
    normalized = executable_name.lower()
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", normalized):
        inline = {"-c", "-m"}
        consumes_next = {"-W", "-X"}
    elif normalized in {"node", "nodejs"}:
        inline = {"-e", "--eval", "-p", "--print"}
        consumes_next = {
            "--conditions",
            "--diagnostic-dir",
            "--icu-data-dir",
            "--import",
            "--input-type",
            "--loader",
            "--openssl-config",
            "--require",
            "-r",
        }
    elif normalized in {"bash", "dash", "sh", "zsh"}:
        for argument in argv[1:]:
            if (
                argument.startswith("-")
                and "c" in argument.lstrip("-")
            ):
                return None
        inline = set()
        consumes_next = set()
    elif normalized in {"ruby", "perl", "php"}:
        inline = {"-e", "-E", "-r"}
        consumes_next = {"-I", "-M"}
    else:
        return None
    index = 1
    while index < len(argv):
        argument = argv[index]
        if argument in inline or argument == "-":
            return None
        if argument in consumes_next:
            index += 2
            continue
        if any(
            argument.startswith(f"{option}=")
            for option in consumes_next
            if option.startswith("--")
        ):
            index += 1
            continue
        if argument.startswith("-"):
            index += 1
            continue
        return index
    return None


def _stable_command_file_identity(
    path: Path,
    *,
    kind: str,
    require_executable: bool,
) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(
        os,
        "O_NONBLOCK",
        0,
    )
    descriptor = os.open(resolved, flags)
    try:
        before = os.fstat(descriptor)
        current_before = os.lstat(resolved)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise ActionProtocolError(
                "action_command_file_invalid",
                f"command {kind} must be a single-link regular file: {resolved}",
            )
        if before.st_size > _MAX_COMMAND_FILE_BYTES:
            raise ActionProtocolError(
                "action_command_file_too_large",
                (
                    f"command {kind} exceeds "
                    f"{_MAX_COMMAND_FILE_BYTES} bytes: {resolved}"
                ),
            )
        if require_executable and (
            before.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ) == 0:
            raise ActionProtocolError(
                "action_command_executable_invalid",
                f"command executable has no execute bit: {resolved}",
            )
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_COMMAND_FILE_BYTES:
                raise ActionProtocolError(
                    "action_command_file_too_large",
                    f"command {kind} grew while hashing: {resolved}",
                )
            digest.update(chunk)
        after = os.fstat(descriptor)
        current_after = os.lstat(resolved)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_mode,
            before.st_nlink,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_mode,
            after.st_nlink,
        )
        path_before = (
            current_before.st_dev,
            current_before.st_ino,
            current_before.st_size,
            current_before.st_mtime_ns,
            current_before.st_mode,
            current_before.st_nlink,
        )
        path_after = (
            current_after.st_dev,
            current_after.st_ino,
            current_after.st_size,
            current_after.st_mtime_ns,
            current_after.st_mode,
            current_after.st_nlink,
        )
        if (
            identity_before != identity_after
            or path_before != identity_before
            or path_after != identity_before
        ):
            raise ActionProtocolError(
                "action_command_file_changed",
                f"command {kind} changed while hashing: {resolved}",
            )
        return {
            "schema_version": 1,
            "kind": kind,
            "real_path": str(resolved),
            "device": str(before.st_dev),
            "inode": str(before.st_ino),
            "size": str(before.st_size),
            "mtime_ns": str(before.st_mtime_ns),
            "mode": str(before.st_mode),
            "sha256": digest.hexdigest(),
        }
    finally:
        os.close(descriptor)


def _validate_command_execution_binding(
    value: Any,
    *,
    action: str,
) -> dict[str, Any] | None:
    if action != "command":
        if value is not None:
            raise ActionProtocolError(
                "action_command_binding_unexpected",
                "non-command action cannot carry a command execution binding",
            )
        return None
    if not isinstance(value, dict):
        raise ActionProtocolError(
            "action_command_binding_missing",
            "command action requires a concrete execution binding",
        )
    binding = dict(value)
    _exact_fields(
        "command_execution_binding",
        binding,
        _COMMAND_BINDING_FIELDS,
    )
    if (
        binding["schema_version"] != 1
        or binding["kind"] != "qa_command_execution_binding"
    ):
        raise ActionProtocolError(
            "action_command_binding_invalid",
            "command execution binding kind/schema is invalid",
        )
    for field in ("base_cwd", "cwd"):
        selected_cwd = _text(
            f"command_execution_binding.{field}",
            binding[field],
        )
        if Path(selected_cwd).is_absolute():
            continue
        raise ActionProtocolError(
            "action_command_binding_invalid",
            f"bound command {field} must be absolute",
        )
    _required_hash(
        "command_execution_binding.environment_sha256",
        binding["environment_sha256"],
    )
    if binding["inherited_environment_names"] != list(
        _COMMAND_INHERITED_ENV_NAMES
    ):
        raise ActionProtocolError(
            "action_command_binding_invalid",
            "command inherited environment allowlist is unsupported",
        )
    _validate_command_file_identity(
        binding["executable"],
        expected_kind="executable",
    )
    if not isinstance(binding["direct_files"], list):
        raise ActionProtocolError(
            "action_command_binding_invalid",
            "command direct_files must be an array",
        )
    previous_index = 0
    for index, item in enumerate(binding["direct_files"]):
        if not isinstance(item, dict):
            raise ActionProtocolError(
                "action_command_binding_invalid",
                f"command direct_files[{index}] must be an object",
            )
        _exact_fields(
            f"command direct_files[{index}]",
            item,
            _COMMAND_DIRECT_FILE_FIELDS,
        )
        argv_index = item["argv_index"]
        if (
            isinstance(argv_index, bool)
            or not isinstance(argv_index, int)
            or argv_index <= previous_index
        ):
            raise ActionProtocolError(
                "action_command_binding_invalid",
                "command direct file argv indices must be strictly increasing",
            )
        previous_index = argv_index
        argument_path = _text(
            "command direct file argument_path",
            item["argument_path"],
        )
        if not Path(argument_path).is_absolute():
            raise ActionProtocolError(
                "action_command_binding_invalid",
                "command direct input argument path must be absolute",
            )
        _validate_command_file_identity(
            item["identity"],
            expected_kind="direct_input",
        )
    recorded = _required_hash(
        "command_execution_binding.binding_sha256",
        binding["binding_sha256"],
    )
    unsigned = dict(binding)
    unsigned.pop("binding_sha256")
    if recorded != _canonical_sha256(unsigned):
        raise ActionProtocolError(
            "action_command_binding_hash_invalid",
            "command execution binding hash is invalid",
        )
    return binding


def _validate_command_file_identity(
    value: Any,
    *,
    expected_kind: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ActionProtocolError(
            "action_command_file_identity_invalid",
            "command file identity must be an object",
        )
    identity = dict(value)
    _exact_fields(
        "command file identity",
        identity,
        _COMMAND_FILE_IDENTITY_FIELDS,
    )
    if (
        identity["schema_version"] != 1
        or identity["kind"] != expected_kind
    ):
        raise ActionProtocolError(
            "action_command_file_identity_invalid",
            "command file identity kind/schema is invalid",
        )
    real_path = _text(
        "command file identity real_path",
        identity["real_path"],
    )
    if not Path(real_path).is_absolute():
        raise ActionProtocolError(
            "action_command_file_identity_invalid",
            "command file identity path must be absolute",
        )
    for field in ("device", "inode", "size", "mtime_ns", "mode"):
        text = _text(f"command file identity {field}", identity[field])
        if not text.isdigit():
            raise ActionProtocolError(
                "action_command_file_identity_invalid",
                f"command file identity {field} must be decimal text",
            )
    _required_hash(
        "command file identity sha256",
        identity["sha256"],
    )
    return identity


def _verify_current_command_execution_bindings(
    contracts: Mapping[str, Any],
    *,
    plan: Mapping[str, Any],
    plan_path: Path,
    command_base_cwd: Path | None,
) -> None:
    steps: dict[tuple[str, str], Mapping[str, Any]] = {}
    for scenario in plan.get("scenarios", []):
        if not isinstance(scenario, dict):
            continue
        for step in scenario.get("steps", []):
            if isinstance(step, dict):
                steps[(scenario.get("id"), step.get("id"))] = step
    sensitive_names = _dynamic_environment_reference_names(plan)
    for item in contracts["actions"]:
        if item["action"] != "command":
            continue
        identity = (item["scenario_id"], item["step_id"])
        step = steps.get(identity)
        if step is None:
            raise ActionProtocolError(
                "action_command_binding_plan_mismatch",
                f"bound command is absent from current plan: {identity!r}",
            )
        current = _build_command_execution_binding(
            step,
            plan_path=plan_path,
            sensitive_environment_names=sensitive_names,
            command_base_cwd=command_base_cwd,
        )
        if current != item["command_execution_binding"]:
            raise ActionProtocolError(
                "action_command_binding_stale",
                (
                    "command executable, direct file input, cwd, or "
                    f"environment changed after authorization: {identity!r}"
                ),
            )


def _require_static_high_risk_network_target(
    plan: Mapping[str, Any],
    step: Mapping[str, Any],
    *,
    scenario_id: str,
    step_id: str,
) -> None:
    """Keep a human-approved network target stable through dispatch.

    Secrets may still be supplied dynamically in headers or bodies, but the
    request method and scheme/host/port/path identity must already be literal
    plan data.  Redirects are separately disabled by the Node executor.
    """

    location = f"{scenario_id}/{step_id}"
    base_url = plan.get("baseUrl")
    if "baseUrl" in plan and not isinstance(base_url, str):
        raise ActionProtocolError(
            "action_high_risk_target_dynamic",
            (
                "high-risk network action "
                f"{location} requires static plan.baseUrl"
            ),
        )
    for field in ("method", "url", "path"):
        if field in step and not isinstance(step[field], str):
            raise ActionProtocolError(
                "action_high_risk_target_dynamic",
                (
                    "high-risk network action "
                    f"{location} requires static step.{field}"
                ),
            )
    for field in ("urlTemplate", "pathTemplate"):
        if field in step:
            raise ActionProtocolError(
                "action_high_risk_target_dynamic",
                (
                    "high-risk network action "
                    f"{location} forbids dynamic step.{field}"
                ),
            )
    raw_url = step.get("url")
    if isinstance(raw_url, str) and raw_url:
        target = raw_url
    else:
        if not isinstance(base_url, str) or not base_url:
            raise ActionProtocolError(
                "action_high_risk_target_not_absolute",
                (
                    "high-risk network action "
                    f"{location} requires an absolute step.url or plan.baseUrl"
                ),
            )
        path_value = step.get("path", "/")
        if not isinstance(path_value, str):
            raise ActionProtocolError(
                "action_high_risk_target_dynamic",
                (
                    "high-risk network action "
                    f"{location} requires static step.path"
                ),
            )
        target = (
            base_url[:-1]
            if base_url.endswith("/")
            else base_url
        ) + (
            path_value
            if path_value.startswith("/")
            else f"/{path_value}"
        )
    _validate_absolute_http_target(
        target,
        location=location,
    )
    if isinstance(base_url, str) and base_url:
        parsed_base = _parse_http_target(
            base_url,
            location="plan.baseUrl",
        )
        if parsed_base.query or parsed_base.fragment:
            raise ActionProtocolError(
                "action_high_risk_base_url_ambiguous",
                "high-risk plan.baseUrl cannot contain a query or fragment",
            )

    context_options = plan.get("contextOptions")
    if context_options is not None:
        if not isinstance(context_options, dict):
            raise ActionProtocolError(
                "action_high_risk_routing_control_invalid",
                "plan.contextOptions must be an object",
            )
        for field in ("baseURL", "proxy"):
            if field in context_options:
                raise ActionProtocolError(
                    "action_high_risk_routing_override",
                    (
                        "high-risk network actions forbid "
                        f"plan.contextOptions.{field}"
                    ),
                )
        for field, value in context_options.items():
            if field == "extraHTTPHeaders":
                _validate_high_risk_headers(
                    value,
                    location="plan.contextOptions.extraHTTPHeaders",
                )
            else:
                _reject_dynamic_references(
                    value,
                    location=f"plan.contextOptions.{field}",
                )

    launch_options = plan.get("launchOptions")
    if launch_options is not None:
        if not isinstance(launch_options, dict):
            raise ActionProtocolError(
                "action_high_risk_routing_control_invalid",
                "plan.launchOptions must be an object",
            )
        if "proxy" in launch_options:
            raise ActionProtocolError(
                "action_high_risk_routing_override",
                "high-risk network actions forbid plan.launchOptions.proxy",
            )
        _reject_dynamic_references(
            launch_options,
            location="plan.launchOptions",
        )
        arguments = launch_options.get("args", [])
        if isinstance(arguments, list) and any(
            isinstance(argument, str)
            and argument.startswith(_ROUTING_LAUNCH_ARGUMENT_PREFIXES)
            for argument in arguments
        ):
            raise ActionProtocolError(
                "action_high_risk_routing_override",
                "high-risk network actions forbid browser routing arguments",
            )

    for field in ("defaultHeaders", "extraHTTPHeaders"):
        if field in plan:
            _validate_high_risk_headers(
                plan[field],
                location=f"plan.{field}",
            )
    if "headers" in step:
        _validate_high_risk_headers(
            step["headers"],
            location=f"{location}.headers",
        )
    for field, value in step.items():
        if field != "headers":
            _reject_dynamic_references(
                value,
                location=f"{location}.{field}",
            )


def _validate_absolute_http_target(
    target: str,
    *,
    location: str,
) -> None:
    parsed = _parse_http_target(target, location=location)
    if parsed.fragment:
        raise ActionProtocolError(
            "action_high_risk_target_fragment",
            f"high-risk network target {location} cannot contain a fragment",
        )


def _parse_http_target(
    target: str,
    *,
    location: str,
) -> Any:
    if not target or target.strip() != target:
        raise ActionProtocolError(
            "action_high_risk_target_not_absolute",
            f"high-risk network target {location} must be trimmed",
        )
    try:
        parsed = urlsplit(target)
        _ = parsed.port
    except ValueError as error:
        raise ActionProtocolError(
            "action_high_risk_target_not_absolute",
            f"high-risk network target {location} is invalid: {error}",
        ) from error
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ActionProtocolError(
            "action_high_risk_target_not_absolute",
            (
                f"high-risk network target {location} must be an "
                "absolute credential-free HTTP(S) URL"
            ),
        )
    return parsed


def _validate_high_risk_headers(
    value: Any,
    *,
    location: str,
) -> None:
    if not isinstance(value, dict):
        raise ActionProtocolError(
            "action_high_risk_headers_invalid",
            f"{location} must be an object",
        )
    for raw_name, header_value in value.items():
        name = raw_name.strip().lower()
        if (
            name in _ROUTING_HEADER_NAMES
            or name.startswith("x-forwarded-")
        ):
            raise ActionProtocolError(
                "action_high_risk_routing_override",
                f"high-risk network actions forbid routing header {raw_name}",
            )
        if name in _CREDENTIAL_HEADER_NAMES:
            continue
        _reject_dynamic_references(
            header_value,
            location=f"{location}.{raw_name}",
        )


def _reject_dynamic_references(
    value: Any,
    *,
    location: str,
) -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_dynamic_references(
                item,
                location=f"{location}[{index}]",
            )
        return
    if not isinstance(value, dict):
        return
    if _looks_like_dynamic_reference(value):
        raise ActionProtocolError(
            "action_high_risk_dynamic_value",
            (
                "high-risk network actions allow dynamic values only in "
                f"credential headers; found {location}"
            ),
        )
    for field, item in value.items():
        _reject_dynamic_references(
            item,
            location=f"{location}.{field}",
        )


def _looks_like_dynamic_reference(
    value: Mapping[str, Any],
) -> bool:
    return any(
        field in value
        and (
            field.startswith("$")
            or isinstance(value[field], str)
        )
        for field in _REFERENCE_DISCRIMINATORS
    )


__all__ = [
    "ACTION_CONTRACTS_SCHEMA_VERSION",
    "ACTION_JOURNAL_SCHEMA_VERSION",
    "ACTION_AUTHORITY_KEY_ENV",
    "ACTION_AUTHORIZATION_TICKET_ENV",
    "RESOLUTION_POLICY",
    "RESOLUTION_POLICY_SHA256",
    "ActionJournalPreflight",
    "ActionJournalVerification",
    "ActionProtocolError",
    "build_action_contracts",
    "issue_action_authorization_ticket",
    "load_action_contracts",
    "preflight_action_journal",
    "verify_action_journal",
]
