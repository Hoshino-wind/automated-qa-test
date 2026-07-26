#!/usr/bin/env python3
import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any

from qa_common import atomic_write_json, file_sha256, schema_version_error
from qa_core.contracts.schema import validate_artifact_schema
from qa_core.tools import DEFAULT_EVIDENCE_ACTIONS, DEFAULT_TOOL_ACTIONS
from qa_scaffold import command_secret_boundary_violation

ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
PACKAGE_CROSS_ENV_EXEC_SUBCOMMANDS = {"exec", "dlx", "x"}
PACKAGE_RUNNER_OPTIONS_WITH_VALUE = {
    "--cache", "--call", "-c", "--cwd", "-C", "--dir", "--filter", "-F",
    "--package", "-p", "--registry", "--userconfig",
}

EVIDENCE_ACTIONS = DEFAULT_EVIDENCE_ACTIONS
HTTP_REQUEST_ACTIONS = {"api", "pollApi", "cleanupApi", "clickAndWaitForResponse", "waitForResponse"}
ALLOWED_NON_EXECUTED_STATUSES = {"Blocked", "Untested", "Inconclusive"}
SECRET_PATTERNS = [
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
    re.compile(r"(?:access[_-]?token|auth[_-]?token|session[_-]?token|api[_-]?key|secret)\s*[:=]\s*[^\s\"',}]{8,}", re.IGNORECASE),
]
AUTH_SECRET_NAME_RE = re.compile(r"(?:authorization|auth|token|secret|api[_-]?key|jwt|cookie)", re.IGNORECASE)
SESSION_COOKIE_NAME_RE = re.compile(r"(?:^|[_-])(?:sid|session|sessionid)(?:$|[_-])", re.IGNORECASE)
AUTH_HEADER_NAME_RE = re.compile(r"(?:^authorization$|^cookie$|api[-_]?key|auth|token|jwt|secret|session)", re.IGNORECASE)
AUTH_RUNTIME_VAR_NAME_RE = re.compile(
    r"(?:authorization|auth|access[_-]?token|id[_-]?token|refresh[_-]?token|session[_-]?token|api[_-]?key|secret|jwt|cookie|password|^sid$)",
    re.IGNORECASE,
)
DESTRUCTIVE_COMMAND_RE = re.compile(
    r"\b(rm\s+-rf|drop\s+table|truncate\s+table|delete\s+from|update\s+\w+\s+set|insert\s+into|gh\s+repo\s+delete|kubectl\s+delete)\b",
    re.IGNORECASE,
)
TEMPLATE_FIELDS = {"pathTemplate", "urlTemplate", "responsePathTemplate"}
RUNTIME_TEMPLATE_FIELDS = {"template", "$template"}
DEFAULT_RUNTIME_VARS = {"qa_run_id", "qa_marker", "qa_started_at"}
TEMPLATE_VAR_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
VAR_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
STRATEGY_DIMENSION_ORDER = [
    "logic",
    "calculation",
    "ui",
    "interaction",
    "optimistic_ui",
    "schema_migration",
    "authorization_policy",
    "financial_ledger",
    "quota_metering",
    "transaction_integrity",
    "subscription_billing",
    "agent_tool",
    "artifact_generation",
    "analytics",
    "offline_sync",
    "background_sync",
    "service_worker",
    "local_storage",
    "conflict_resolution",
    "cache_consistency",
    "webhook_security",
    "accessibility",
    "localization",
    "bulk_action",
    "destructive_guard",
    "undo",
    "concurrency",
    "scheduled_job",
    "background_job",
    "worker",
    "retry",
    "feature_flag",
    "rollout",
    "csrf",
    "session_security",
    "cookie_security",
    "oauth",
    "redirect_security",
    "saml",
    "webauthn",
    "mfa",
    "one_time_token",
    "api_key",
    "audit_integrity",
    "privacy_compliance",
    "graphql",
    "rag_grounding",
    "rate_limit",
    "realtime",
    "multi_client",
    "ordering",
    "reconnect",
    "api",
    "search_relevance",
    "pagination",
    "download",
    "file_content",
    "file_security",
    "file_preview",
    "notification",
    "notification_policy",
    "idempotency",
    "data_isolation",
    "time_boundary",
    "stream",
    "persistence",
    "permission",
    "runtime",
    "responsive",
    "cleanup",
]
PROVES_ONLY_DIMENSIONS_REQUIRING_EXPLICIT_EVIDENCE = {
    "csrf",
    "session_security",
    "cookie_security",
    "oauth",
    "redirect_security",
    "saml",
    "webauthn",
    "mfa",
    "one_time_token",
    "api_key",
    "audit_integrity",
    "privacy_compliance",
    "graphql",
    "rag_grounding",
    "search_relevance",
    "scheduled_job",
    "schema_migration",
    "authorization_policy",
    "financial_ledger",
    "quota_metering",
    "transaction_integrity",
    "subscription_billing",
    "agent_tool",
    "artifact_generation",
    "analytics",
    "offline_sync",
    "background_sync",
    "service_worker",
    "local_storage",
    "conflict_resolution",
    "cache_consistency",
    "webhook_security",
    "optimistic_ui",
    "localization",
    "rate_limit",
    "file_security",
    "file_preview",
    "notification_policy",
    "cleanup",
}
CLEANUP_STRATEGY_TERMS = (
    "cleanup",
    "clean up",
    "teardown",
    "cleanup api",
    "cleanup_api",
    "delete created test data",
    "created test data",
    "cleanup verification",
    "cleanup_verification",
    "alwaysrun",
    "always run",
    "always_run_teardown",
    "qa_cleanup",
    "testdata_deleted",
)
DECISION_TABLE_STRATEGY_TERMS = (
    "decision table",
    "decision_table",
    "rule matrix",
    "rule_matrix",
    "rule precedence",
    "rule_precedence",
    "boundary rows",
    "boundary cases",
    "boundary_cases",
    "negative rows",
    "negative cases",
    "negative_cases",
    "fixture input rows",
    "fixture inputs",
    "fixture_inputs",
    "expected decisions",
    "expected_decisions",
    "expected output decisions",
    "expected_outputs",
    "rule_hits",
    "approval_v7",
    "eval_approval_rules",
)
ANALYTICS_STRATEGY_TERMS = (
    "analytics",
    "analytics telemetry",
    "telemetry",
    "analytics_event",
    "analytics event",
    "event_name",
    "checkout_completed",
    "event_id",
    "schema_version",
    "event_schema",
    "consent_version",
    "consent_state",
    "analytics_consent",
    "analytics_consent=false",
    "session_id",
    "user_pseudonym_id",
    "attribution_id",
    "campaign_id",
    "attribution_credit",
    "attribution_mismatch",
    "experiment_id",
    "variant",
    "experiment_exposure",
    "experiment exposure",
    "exposure_id",
    "dedupe_key",
    "duplicate_ignored",
    "event_time",
    "event_batch",
    "queue_status",
    "pending_retry",
    "next_retry_at",
    "backoff_schedule",
    "retry_count",
    "/api/v1/analytics/events",
)
ANALYTICS_CONTEXT_STRATEGY_TERMS = (
    "analytics",
    "analytics telemetry",
    "telemetry",
    "analytics_event",
    "analytics event",
    "checkout_completed",
    "/api/v1/analytics/events",
)
SUBSCRIPTION_BILLING_STRATEGY_TERMS = (
    "subscription billing",
    "subscription_billing",
    "subscription id",
    "subscription_id",
    "subscriptions",
    "plan change",
    "change plan",
    "current_plan",
    "target_plan",
    "subscription_version",
    "billing cycle",
    "billing_cycle",
    "billing anchor",
    "billing_anchor",
    "proration",
    "proration_behavior",
    "invoice preview",
    "invoice_preview",
    "preview-change",
    "preview_change",
    "preview_id",
    "unused credit",
    "unused_credit",
    "unused_credit_cents",
    "prorated charge",
    "prorated_charge",
    "prorated_charge_cents",
    "tax jurisdiction",
    "tax_jurisdiction",
    "tax_rate",
    "tax_rate_bps",
    "tax_amount",
    "tax_cents",
    "invoice total",
    "invoice_total",
    "invoice_total_cents",
    "calculation_version",
    "invoice line items",
    "line_credit_unused",
    "line_proration_charge",
    "line_tax",
    "payment_intent",
    "requires_capture",
    "scheduled capture",
    "scheduled_capture",
    "scheduled_capture_at",
    "downgrade",
    "downgrade scheduling",
    "scheduled change",
    "scheduled_change",
    "scheduled_change_id",
    "renewal",
    "idempotency_key",
    "duplicate_ignored",
    "plan_change_forbidden",
    "authorization denial",
    "support agent",
    "no receipt email",
    "billing.preview_created",
    "billing.plan_changed",
)
SUBSCRIPTION_BILLING_CORE_STRATEGY_TERMS = (
    "subscription billing",
    "subscription_billing",
    "subscription id",
    "subscription_id",
    "subscriptions",
    "plan change",
    "change plan",
    "current_plan",
    "target_plan",
    "subscription_version",
    "billing cycle",
    "billing_cycle",
    "billing anchor",
    "billing_anchor",
    "proration",
    "proration_behavior",
    "invoice preview",
    "invoice_preview",
    "preview-change",
    "preview_change",
    "preview_id",
    "unused credit",
    "unused_credit",
    "prorated charge",
    "prorated_charge",
    "tax jurisdiction",
    "tax_jurisdiction",
    "invoice total",
    "invoice_total",
    "payment_intent",
    "scheduled capture",
    "scheduled_capture",
    "downgrade",
    "downgrade scheduling",
    "scheduled change",
    "scheduled_change",
    "billing.preview_created",
    "billing.plan_changed",
)
AGENT_TOOL_STRATEGY_TERMS = (
    "agent tool",
    "agent_tool",
    "agent tool orchestration",
    "tool call",
    "tool_call",
    "tool-call",
    "agent_session_id",
    "agent session",
    "tool_call_requested",
    "tool call requested",
    "tool_call_id",
    "tool_name",
    "tool args",
    "tool_args",
    "args_hash",
    "tool_args_redaction",
    "approval_required",
    "approval required",
    "approval_gate",
    "approval gate",
    "approval_id",
    "tool_call_approved",
    "tool_result",
    "tool_result_event",
    "tool_result_id",
    "tool_call_cancelled",
    "cancellation_event",
    "tool_execution_absence",
    "tool executor",
    "idempotency_key",
    "duplicate_ignored",
    "duplicate_absence",
    "tool_approval_forbidden",
    "authorization denial",
    "handoff_required",
    "handoff required",
    "handoff_id",
    "tool_timeout",
    "needs_human_review",
    "human_review_queue",
    "/agents/run/ws",
    "/agent-tools/",
)
ARTIFACT_GENERATION_STRATEGY_TERMS = (
    "artifact generation",
    "artifact_generation",
    "artifact job",
    "artifact_job",
    "report-jobs",
    "report jobs",
    "report job",
    "report-artifacts",
    "artifact_id",
    "artifact id",
    "artifact_ready",
    "artifact ready",
    "artifact_manifest",
    "artifact manifest",
    "manifest_id",
    "manifest id",
    "manifest_hash",
    "manifest hash",
    "content_hash",
    "content hash",
    "file_hash",
    "file hash",
    "progress event",
    "progress_event",
    "resume_token",
    "resume token",
    "checkpoint_page",
    "checkpoint page",
    "checkpoint",
    "temp_object_count",
    "temp object count",
    "partial_failed",
    "partial failed",
    "partial failure",
    "failed_sections",
    "failed sections",
    "diagnostic_artifact",
    "diagnostic artifact",
    "retention_expires_at",
    "storage_key_redacted",
    "storage key redacted",
    "download guard",
    "artifact_download_forbidden",
    "artifact download forbidden",
    "report.artifact_ready",
    "report.artifact_cancelled",
)
OFFLINE_SYNC_STRATEGY_TERMS = (
    "offline sync",
    "offline_sync",
    "offline queue",
    "offline_queue",
    "browser goes offline",
    "network offline",
    "network online",
    "reconnects",
    "reconnect",
    "indexeddb",
    "local outbox",
    "local_outbox",
    "local queue",
    "local_queue",
    "pending_sync",
    "background sync",
    "background_sync",
    "service worker",
    "service_worker",
    "client_mutation_id",
    "idempotency_key",
    "payload_hash",
    "encrypted_local_payload",
    "server_visit_id",
    "sync_version",
    "queue drain",
    "queue_drain",
    "duplicate_ignored",
    "version_conflict",
    "blocked_conflict",
    "conflict_id",
    "server_version",
    "client_version",
    "merge dialog",
    "merge_dialog",
    "resolve-conflict",
    "resolve_conflict",
    "if-match",
    "if_match",
    "merged_note_hash",
    "sync_attempt_id",
    "retry_count",
    "next_retry_at",
    "backoff_schedule",
    "sync_forbidden",
)
OFFLINE_SYNC_CORE_STRATEGY_TERMS = (
    "offline sync",
    "offline_sync",
    "offline queue",
    "offline_queue",
    "browser goes offline",
    "network offline",
    "network online",
    "indexeddb",
    "local outbox",
    "local_outbox",
    "local queue",
    "local_queue",
    "pending_sync",
    "background sync",
    "background_sync",
    "service worker",
    "service_worker",
    "client_mutation_id",
    "payload_hash",
    "encrypted_local_payload",
    "server_visit_id",
    "sync_version",
    "queue drain",
    "queue_drain",
    "version_conflict",
    "blocked_conflict",
    "conflict_id",
    "merge dialog",
    "merge_dialog",
    "resolve-conflict",
    "resolve_conflict",
    "if-match",
    "if_match",
    "sync_attempt_id",
    "sync_forbidden",
)
LOCALIZATION_STRATEGY_TERMS = (
    "localization",
    "localisation",
    "i18n",
    "locale",
    "locale switch",
    "ar-eg",
    "en-us",
    "translation catalog",
    "translation_catalog",
    "translation catalog version",
    "translation_catalog_version",
    "catalog version",
    "catalog_version",
    "missing_keys",
    "missing keys",
    "fallback_count",
    "fallback count",
    "raw key",
    "raw translation key",
    "translation_key_absence",
    "fallback_absence",
    "plural rules",
    "plural_rules",
    "singular",
    "dual",
    "many",
    "rtl",
    "ltr",
    "dir=rtl",
    "dir_attribute",
    "lang_attribute",
    "html lang",
    "currency formatting",
    "currency_format",
    "intl numberformat",
    "intl.numberformat",
    "date formatting",
    "date_time_format",
    "africa cairo",
    "africa/cairo",
    "stale catalog",
    "stale_locale_guard",
    "cached formatted values",
)
NOTIFICATION_POLICY_STRATEGY_TERMS = (
    "notification policy",
    "notification_policy",
    "notification preferences",
    "notification-preferences",
    "notification_preferences",
    "preference version",
    "preference_version",
    "prefs_v7",
    "consent source",
    "consent_source",
    "user_setting",
    "marketing_email",
    "marketing email",
    "marketing_email=false",
    "transactional_email",
    "transactional email",
    "transactional_email=true",
    "suppressed_reason",
    "suppression reason",
    "unsubscribed",
    "quiet hours",
    "quiet_hours",
    "send_after",
    "urgent_override",
    "urgent security",
    "digest_key",
    "weekly_digest",
    "event_count",
    "digest_dedupe",
    "unsubscribe token",
    "unsubscribe_token",
    "token_already_used",
)


def try_load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, "missing"
    if path.is_dir():
        return None, "path_is_directory"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, f"invalid_json: {exc.msg}"
    except OSError as exc:
        return None, f"read_error: {exc}"
    if not isinstance(value, dict):
        return None, "json_root_not_object"
    return value, None


def write_summary(path_arg: str | None, summary: dict[str, Any]) -> None:
    if path_arg:
        path = Path(path_arg).expanduser()
        atomic_write_json(path, summary)


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def iter_strings(value: Any, prefix: str = ""):
    if isinstance(value, str):
        yield prefix, value
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            yield from iter_strings(item, f"{prefix}[{idx}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from iter_strings(item, f"{prefix}.{key}" if prefix else str(key))


def iter_env_refs(value: Any, prefix: str = ""):
    if isinstance(value, list):
        for idx, item in enumerate(value):
            yield from iter_env_refs(item, f"{prefix}[{idx}]")
    elif isinstance(value, dict):
        env_name = value.get("env") or value.get("$env")
        if isinstance(env_name, str) and env_name.strip():
            yield prefix or "<root>", env_name.strip()
        for key, item in value.items():
            yield from iter_env_refs(item, f"{prefix}.{key}" if prefix else str(key))


def resolve_env_ref_for_validation(value: dict[str, Any], errors: list[str], location: str) -> Any:
    env_name = value.get("env") or value.get("$env")
    if not isinstance(env_name, str) or not env_name.strip():
        return value
    raw = os.environ.get(env_name.strip())
    if raw is None:
        return None
    resolved = f"{value.get('prefix') or ''}{raw}{value.get('suffix') or ''}"
    if value.get("json") is True:
        try:
            return json.loads(resolved)
        except json.JSONDecodeError as exc:
            errors.append(f"{location} storageState env reference {env_name.strip()} did not resolve to valid JSON: {exc.msg}.")
            return None
    return resolved


def validate_storage_state_object(value: dict[str, Any], location: str, errors: list[str], warnings: list[str], *, inline: bool = False) -> None:
    cookies = value.get("cookies")
    origins = value.get("origins")
    if cookies is not None and not isinstance(cookies, list):
        errors.append(f"{location} storageState.cookies must be an array.")
    if origins is not None and not isinstance(origins, list):
        errors.append(f"{location} storageState.origins must be an array.")
    if inline and ((isinstance(cookies, list) and cookies) or (isinstance(origins, list) and origins)):
        errors.append(f"{location} storageState embeds cookies/origins directly; use a storageState file path or env reference to a file path.")
    if cookies is None and origins is None:
        warnings.append(f"{location} storageState object has neither cookies nor origins; it may not authenticate the browser context.")


def candidate_storage_paths(value: str, plan_path: Path) -> list[Path]:
    raw_path = Path(value).expanduser()
    if raw_path.is_absolute():
        return [raw_path]
    candidates = [plan_path.parent / raw_path, Path.cwd() / raw_path]
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate.resolve(strict=False))
        if key not in seen:
            unique.append(candidate)
            seen.add(key)
    return unique


def validate_storage_state_value(
    value: Any,
    location: str,
    *,
    plan_path: Path,
    errors: list[str],
    warnings: list[str],
) -> None:
    env_name: str | None = None
    if isinstance(value, dict) and (isinstance(value.get("env"), str) or isinstance(value.get("$env"), str)):
        env_name = str(value.get("env") or value.get("$env")).strip()
        value = resolve_env_ref_for_validation(value, errors, location)
        if value is None:
            return

    if isinstance(value, dict):
        validate_storage_state_object(value, location, errors, warnings, inline=True)
        return
    if not has_text(value):
        errors.append(f"{location} storageState must be a non-empty file path, env reference, or inline storage state object without embedded cookies/origins.")
        return
    if not isinstance(value, str):
        errors.append(f"{location} storageState must be a file path string, env reference, or inline storage state object without embedded cookies/origins.")
        return

    candidates = candidate_storage_paths(value, plan_path)
    existing = next((candidate for candidate in candidates if candidate.exists()), None)
    if existing is None:
        if env_name:
            errors.append(f"{location} storageState env reference {env_name} resolved to a file path that does not exist.")
        else:
            errors.append(f"{location} storageState file does not exist: {value}.")
        return
    if existing.is_dir():
        if env_name:
            errors.append(f"{location} storageState env reference {env_name} resolved to a directory, not a file.")
        else:
            errors.append(f"{location} storageState path is a directory, not a file: {value}.")
        return
    try:
        storage_state = json.loads(existing.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"{location} storageState file is not valid JSON: {exc.msg}.")
        return
    except OSError as exc:
        errors.append(f"{location} storageState file could not be read: {exc}.")
        return
    if not isinstance(storage_state, dict):
        errors.append(f"{location} storageState file must contain a JSON object.")
        return
    validate_storage_state_object(storage_state, location, errors, warnings, inline=False)


def validate_storage_state_refs(plan: dict[str, Any], plan_path: Path, errors: list[str], warnings: list[str]) -> int:
    top_level = plan.get("storageState")
    if top_level not in (None, ""):
        validate_storage_state_value(top_level, "plan.storageState", plan_path=plan_path, errors=errors, warnings=warnings)
        return 1
    context_options = plan.get("contextOptions")
    if isinstance(context_options, dict) and context_options.get("storageState") not in (None, ""):
        validate_storage_state_value(context_options.get("storageState"), "plan.contextOptions.storageState", plan_path=plan_path, errors=errors, warnings=warnings)
        return 1
    return 0


def iter_var_refs(value: Any, prefix: str = ""):
    if isinstance(value, list):
        for idx, item in enumerate(value):
            yield from iter_var_refs(item, f"{prefix}[{idx}]")
    elif isinstance(value, dict):
        var_name = value.get("var") or value.get("$var")
        if isinstance(var_name, str) and var_name.strip():
            yield prefix or "<root>", var_name.strip()
        for key, item in value.items():
            yield from iter_var_refs(item, f"{prefix}.{key}" if prefix else str(key))


def iter_template_var_refs(value: Any, prefix: str = ""):
    if isinstance(value, list):
        for idx, item in enumerate(value):
            yield from iter_template_var_refs(item, f"{prefix}[{idx}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            location = f"{prefix}.{key}" if prefix else str(key)
            if key in TEMPLATE_FIELDS.union(RUNTIME_TEMPLATE_FIELDS) and isinstance(item, str):
                for match in TEMPLATE_VAR_RE.finditer(item):
                    yield location, match.group(1)
            yield from iter_template_var_refs(item, location)


def contains_todo(value: Any) -> bool:
    return isinstance(value, str) and "TODO" in value.upper()


def step_id(step: dict[str, Any]) -> str:
    return str(step.get("id") or step.get("stepId") or "")


def step_test_ids(step: dict[str, Any]) -> list[str]:
    return [str(item) for item in as_list(step.get("testIds") or step.get("test_ids")) if has_text(item)]


def step_requirement_ids(step: dict[str, Any]) -> list[str]:
    return [str(item) for item in as_list(step.get("requirementIds") or step.get("requirement_ids")) if has_text(item)]


def normalized_strategy_text(*values: Any) -> str:
    parts: list[str] = []
    for value in values:
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.extend(str(item) for item in value if item is not None)
    return re.sub(r"[^a-z0-9_]+", " ", " ".join(parts).lower()).strip()


def strip_generated_requirement_suffix(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    lower = value.lower()
    for marker in (" requirement:", " requirement："):
        index = lower.find(marker)
        if index >= 0:
            return value[:index]
    generated_for_prefixes = (
        "the stream emits a terminal success event for:",
        "runtime errors are absent or explicitly dispositioned for:",
    )
    for prefix in generated_for_prefixes:
        if lower.startswith(prefix):
            return value[: len(prefix) - 1]
    return value


def has_strategy_term(text: str, term: str) -> bool:
    normalized_term = normalized_strategy_text(term)
    if not normalized_term:
        return False
    return bool(re.search(rf"(?:^| ){re.escape(normalized_term)}(?: |$)", text))


def has_any_strategy_term(text: str, terms: tuple[str, ...]) -> bool:
    return any(has_strategy_term(text, term) for term in terms)


def strategy_dimensions_from_text(text: str) -> set[str]:
    dims: set[str] = set()
    if not text:
        return dims
    if has_any_strategy_term(text, ("ui_to_api", "click_response", "click to response")):
        dims.update({"interaction", "api"})
    if has_any_strategy_term(text, ("calculation", "money precision", "monetary", "decimal arithmetic", "rounding rule", "round half up", "calculation parity", "discount calculation", "tax calculation", "currency conversion", "fx rate", "rate id", "persisted total parity")):
        dims.add("calculation")
    if has_any_strategy_term(text, ("user visible", "visible", "screenshot", "page", "screen", "view", "render", "rendered", "ui", "navigation")):
        dims.add("ui")
    if has_any_strategy_term(text, ("click", "button", "tap", "press", "interaction", "actionability", "clickable", "hit test", "form", "modal", "toast")):
        dims.add("interaction")
    search_relevance_context = (
        has_any_strategy_term(text, ("search relevance", "search_relevance", "relevance_score", "ranking_model", "search_rank_v5", "result order", "result_order", "result_position", "query_rewrite", "query_rewrite_id", "canonical_query", "typo_tolerance", "synonym_expansion", "facet_counts", "facet aggregation", "total_count", "sponsored_disclosure", "stale_result_guard"))
        or (
            has_any_strategy_term(text, ("search", "query"))
            and has_any_strategy_term(text, ("relevance", "ranking", "ranked", "facet", "canonical", "typo", "synonym", "sponsored"))
        )
    )
    if search_relevance_context:
        dims.add("search_relevance")
        dims.add("api")
        if has_any_strategy_term(text, ("page=2", "pagination", "duplicate_absence", "next page", "page 2")):
            dims.add("pagination")
        if has_any_strategy_term(text, ("hidden product", "hidden products", "tenant", "another tenant", "sku-beta-secret", "beta llc", "beta@example.com")):
            dims.add("data_isolation")
        if has_any_strategy_term(text, ("stale result", "stale_result_guard", "popular products", "previous query", "retryable error", "500", "error state")):
            dims.add("runtime")
    scheduled_job_context = (
        has_any_strategy_term(text, ("scheduled job", "scheduled_job", "scheduler", "scheduler_run", "scheduler_runs", "schedule_id", "run_key", "next_run_at", "schedule expression", "schedule_expression", "cron", "due window", "due_window", "catch-up", "catch_up", "catch-up generation", "missed schedule", "missed run", "previous schedule was missed", "one invoice per account", "scheduler_lock", "advisory lock", "lock_acquired", "already_running", "duplicate_skipped"))
        or (
            has_any_strategy_term(text, ("schedule", "scheduled"))
            and has_any_strategy_term(text, ("cron", "run_key", "next_run_at", "scheduler_lock", "advisory lock", "scheduler_runs"))
        )
    )
    if scheduled_job_context:
        dims.update({"scheduled_job", "background_job", "worker", "persistence", "runtime"})
        if has_any_strategy_term(text, ("timezone", "time zone", "dst", "due window", "due_window", "next_run_at", "schedule window")):
            dims.add("time_boundary")
        if has_any_strategy_term(text, ("advisory lock", "scheduler_lock", "lock_acquired", "already_running", "concurrent scheduler", "concurrent workers", "two concurrent")):
            dims.add("concurrency")
        if has_any_strategy_term(text, ("run_key", "catch-up", "catch_up", "duplicate_skipped", "duplicate absence", "duplicate_absence", "one invoice per")):
            dims.add("idempotency")
        if has_any_strategy_term(text, ("notification_outbox", "email_outbox", "outbox", "no real email", "email")):
            dims.add("notification")
    http_cache_context = (
        has_any_strategy_term(text, ("cache consistency", "cache_consistency", "etag", "cache control", "cache-control", "if none match", "if-none-match", "304 not modified", "not modified", "stale while revalidate", "stale-while-revalidate", "surrogate key", "surrogate-key", "origin fetch", "origin_fetch", "cache status", "cache_status"))
        or (
            has_any_strategy_term(text, ("cache", "cdn", "edge cache", "revalidation", "surrogate"))
            and has_any_strategy_term(text, ("etag", "if-none-match", "cache-control", "304", "stale", "origin", "version"))
        )
    )
    optimistic_ui_context = (
        has_any_strategy_term(text, ("optimistic ui", "optimistic_ui", "optimistic update", "optimistic_update", "optimistic comment", "optimistic mutation", "optimistic state"))
        or (
            has_any_strategy_term(text, ("temp id", "temp_id", "pending state", "pending_state", "failed state", "failed_state", "retry action", "retry_action", "no success toast", "no_success_toast"))
            and has_any_strategy_term(text, ("optimistic", "client id", "comment", "mutation", "success toast"))
        )
        or (
            has_any_strategy_term(text, ("cache invalidation", "cache_invalidation", "stale cached", "stale cached success"))
            and has_any_strategy_term(text, ("optimistic", "comment", "mutation", "success data", "success toast"))
        )
        or (
            has_any_strategy_term(text, ("rollback", "roll back"))
            and has_any_strategy_term(text, ("optimistic", "temp id", "temp_id", "pending state", "pending_state", "failed state", "failed_state", "retry action", "retry_action", "success toast", "cache invalidation", "cache_invalidation"))
        )
    )
    if http_cache_context and not has_any_strategy_term(text, ("optimistic ui", "optimistic_ui", "optimistic update", "optimistic_update", "optimistic comment", "optimistic mutation", "temp_id", "pending_state", "failed_state", "retry_action")):
        optimistic_ui_context = False
    if optimistic_ui_context:
        dims.add("optimistic_ui")
    schema_migration_context = (
        has_any_strategy_term(text, ("schema migration", "schema_migration", "migration plan", "migration_plan", "migration dry run", "migration_dry_run", "expand-contract", "expand contract", "expand step", "contract step", "down migration"))
        or (
            has_any_strategy_term(text, ("migration", "migrate", "backfill", "rollback plan", "rollback_plan", "contract step", "expand step"))
            and has_any_strategy_term(text, ("schema", "schema_version", "schema diff", "foreign key", "not null", "rollback", "compatibility", "constraint"))
        )
    )
    if schema_migration_context:
        dims.add("schema_migration")
    authorization_policy_context = (
        has_any_strategy_term(text, ("authorization policy", "authorization_policy", "policy matrix", "policy_matrix", "policy decision", "policy_decision", "policy evaluate", "policy/evaluate", "matched rule", "matched_rule", "matched_rule_id", "deny precedence", "deny_precedence", "explicit deny", "explicitly denies", "role inheritance", "role_inheritance", "inherits", "resource scope", "resource_scope", "same-org", "same org", "obligation", "mask_pii", "policy_denied", "policy cache", "policy decision cache", "policy_cache_key", "policy cache key", "stale policy", "stale_policy_guard", "stale allow"))
        or (
            has_any_strategy_term(text, ("policy", "rbac", "abac"))
            and has_any_strategy_term(text, ("allow=false", "decision=deny", "deny", "matched_rule_id", "resource", "action", "tenant"))
        )
    )
    if authorization_policy_context:
        dims.add("authorization_policy")
    financial_ledger_context = (
        has_any_strategy_term(text, ("financial ledger", "financial_ledger", "ledger transaction", "ledger_transaction", "ledger entry", "ledger_entry", "double entry", "double-entry", "double_entry", "balanced debits", "balanced_debits", "debit total cents", "debit_total_cents", "credit total cents", "credit_total_cents", "ledger balance", "ledger_balance", "net ledger balance", "immutable ledger", "immutable_ledger", "reversal ledger", "reversal entry", "reversal_entry", "minor unit", "minor-unit", "minor_unit_amount", "amount cents", "amount_cents", "no float drift", "no_float_drift", "over refund", "over-refund", "over_refund_denied", "refund settled", "refund.settled", "settlement event", "settlement_event", "settlement worker", "payout reconciliation", "payout_reconciliation"))
        or (
            has_any_strategy_term(text, ("ledger", "ledger entries", "debits", "credits", "reversal"))
            and has_any_strategy_term(text, ("refund", "payment", "settlement", "amount_cents", "currency"))
        )
    )
    if financial_ledger_context:
        dims.add("financial_ledger")
    quota_metering_context = (
        has_any_strategy_term(text, ("usage quota", "quota_metering", "quota metering", "meter_key", "api_calls", "quota_window", "monthly quota", "quota limit", "quota_limit", "usage_counter", "usage counter", "counter_version", "quota_remaining", "quota remaining", "remaining", "atomic_increment", "quota_exceeded", "quota exceeded", "quota_exceeded_denial", "no_negative_remaining", "never go negative", "billing_usage_event", "billing usage event", "reset boundary", "window_reset", "usage.window_reset"))
        or (
            has_any_strategy_term(text, ("quota", "meter", "usage counter", "usage_counter"))
            and has_any_strategy_term(text, ("usage", "api_calls", "quantity", "remaining", "quota_exceeded", "counter_version"))
        )
    )
    if quota_metering_context:
        dims.add("quota_metering")
    transaction_integrity_context = (
        has_any_strategy_term(text, ("transaction integrity", "transaction_integrity", "checkout transaction", "transaction id", "transaction_id", "dbtx", "atomic commit", "atomic_commit", "payment_authorization", "payment authorization", "inventory_reservation", "inventory reservation", "outbox_event", "order.confirmed", "outbox dispatch", "outbox_dispatch", "post commit", "post_commit_publish", "publish exactly once", "publish_exactly_once", "publish_count", "saga compensation", "saga_compensation", "compensation_event", "inventory release", "inventory_release", "void authorization", "authorization_void"))
        or (
            has_any_strategy_term(text, ("transaction", "commit", "outbox", "saga"))
            and has_any_strategy_term(text, ("payment", "inventory", "order", "compensation", "publish"))
        )
    )
    if transaction_integrity_context:
        dims.add("transaction_integrity")
    subscription_billing_context = (
        (
            has_any_strategy_term(text, SUBSCRIPTION_BILLING_STRATEGY_TERMS)
            and has_any_strategy_term(text, SUBSCRIPTION_BILLING_CORE_STRATEGY_TERMS)
        )
        or (
            has_any_strategy_term(text, ("subscription", "subscriptions", "plan"))
            and has_any_strategy_term(text, ("billing", "invoice", "proration", "payment_intent", "current_plan", "target_plan"))
        )
    )
    if subscription_billing_context:
        dims.update({"subscription_billing", "api", "persistence", "runtime"})
        if has_any_strategy_term(text, ("page", "screen", "view", "visible", "opens", "click", "button", "change plan", "confirming preview", "preview sends")):
            dims.update({"ui", "interaction"})
        if has_any_strategy_term(text, ("proration", "proration_behavior", "unused credit", "unused_credit", "prorated charge", "prorated_charge", "tax jurisdiction", "tax_jurisdiction", "tax_rate", "tax amount", "tax_amount", "tax_cents", "invoice total", "calculation_version")):
            dims.add("calculation")
        if has_any_strategy_term(text, ("billing cycle", "billing_cycle", "billing anchor", "billing_anchor", "scheduled capture", "scheduled_capture", "scheduled_capture_at", "scheduled change", "scheduled_change", "downgrade", "renewal")):
            dims.add("time_boundary")
        if has_any_strategy_term(text, ("idempotency", "idempotency_key", "duplicate_ignored", "duplicate absence", "duplicate_absence", "replay", "replaying")):
            dims.add("idempotency")
        if has_any_strategy_term(text, ("403", "forbidden", "plan_change_forbidden", "authorization denial", "support agent", "denied actor")):
            dims.add("permission")
        if has_any_strategy_term(text, ("no receipt email", "must not send receipt", "receipt side effect", "receipt email")):
            dims.discard("notification")
        dims.discard("realtime")
        dims.discard("multi_client")
        dims.discard("reconnect")
        dims.discard("graphql")
        dims.discard("file_preview")
    agent_tool_context = (
        has_any_strategy_term(
            text,
            (
                "agent tool",
                "agent_tool",
                "agent tool orchestration",
                "tool call",
                "tool_call",
                "tool-call",
                "agent_session_id",
                "agent session",
                "tool_call_requested",
                "tool_call_id",
                "tool_name",
                "tool args",
                "tool_args",
                "tool_args_redaction",
                "tool_result",
                "tool_result_event",
                "tool_call_cancelled",
                "tool executor",
                "tool_approval_forbidden",
                "/agents/run/ws",
                "/agent-tools/",
            ),
        )
        or (
            has_any_strategy_term(text, ("agent", "tool"))
            and has_any_strategy_term(text, ("approval", "tool_call", "handoff", "tool_result", "args_hash", "tool executor"))
        )
    )
    if agent_tool_context:
        dims.update({"agent_tool", "api", "stream", "persistence", "runtime"})
        if has_any_strategy_term(text, ("page", "screen", "view", "visible", "opens", "ui", "approval gate", "disables", "sends prompt")):
            dims.add("ui")
        if has_any_strategy_term(text, ("click", "button", "approve", "cancel", "approval gate", "interaction", "sends prompt")):
            dims.add("interaction")
        if has_any_strategy_term(text, ("idempotency", "idempotency_key", "duplicate_ignored", "duplicate absence", "duplicate_absence", "replay", "replaying")):
            dims.add("idempotency")
        if has_any_strategy_term(text, ("403", "forbidden", "tool_approval_forbidden", "authorization denial", "viewer", "denied actor")):
            dims.add("permission")
        dims.discard("realtime")
        dims.discard("multi_client")
        dims.discard("reconnect")
        dims.discard("graphql")
        dims.discard("file_preview")
        dims.discard("notification")
    offline_sync_context = (
        has_any_strategy_term(text, OFFLINE_SYNC_CORE_STRATEGY_TERMS)
        or (
            has_any_strategy_term(text, ("offline", "outbox", "sync"))
            and has_any_strategy_term(text, ("client_mutation_id", "idempotency_key", "pending_sync", "indexeddb", "background sync", "service worker"))
        )
    )
    if offline_sync_context:
        dims.update({"offline_sync", "api", "persistence", "runtime"})
        if has_any_strategy_term(text, ("page", "screen", "view", "visible", "opens", "mobile", "ui", "pending sync", "synced state", "merge dialog")):
            dims.update({"ui", "interaction"})
        if has_any_strategy_term(text, ("indexeddb", "local outbox", "local_outbox", "local queue", "local_queue", "encrypted_local_payload", "pending_sync")):
            dims.add("local_storage")
        if has_any_strategy_term(text, ("service worker", "service_worker")):
            dims.add("service_worker")
        if has_any_strategy_term(text, ("background sync", "background_sync", "sync worker")):
            dims.add("background_sync")
        if has_any_strategy_term(text, ("version_conflict", "conflict_id", "blocked_conflict", "merge dialog", "merge_dialog", "resolve-conflict", "resolve_conflict", "if-match", "if_match")):
            dims.add("conflict_resolution")
        if has_any_strategy_term(text, ("idempotency", "idempotency_key", "duplicate_ignored", "duplicate absence", "duplicate_absence", "replay", "replaying")):
            dims.add("idempotency")
        if has_any_strategy_term(text, ("403", "forbidden", "sync_forbidden", "viewer", "outside territory", "authorization denial")):
            dims.add("permission")
        if has_any_strategy_term(text, ("retry_count", "next_retry_at", "backoff_schedule", "503", "retry scheduled")):
            dims.add("retry")
        dims.discard("artifact_generation")
        dims.discard("notification")
        dims.discard("realtime")
        dims.discard("multi_client")
        dims.discard("reconnect")
        dims.discard("graphql")
        dims.discard("file_preview")
        dims.discard("download")
        dims.discard("file_content")
        dims.discard("scheduled_job")
        dims.discard("background_job")
        dims.discard("worker")
        dims.discard("transaction_integrity")
        if not has_any_strategy_term(text, ("concurrent", "concurrency", "parallel", "simultaneous", "race condition", "winner loser", "winner/loser")):
            dims.discard("concurrency")
    analytics_context = (
        has_any_strategy_term(text, ANALYTICS_CONTEXT_STRATEGY_TERMS)
        or (
            has_any_strategy_term(text, ("event_name", "event_id", "schema_version", "consent_version"))
            and has_any_strategy_term(text, ("attribution_id", "experiment_id", "dedupe_key", "user_pseudonym_id"))
        )
    )
    if analytics_context:
        dims.update({"analytics", "api", "persistence", "runtime"})
        if has_any_strategy_term(text, ("ui", "page", "screen", "view", "visible", "opens", "browser", "checkout", "consent", "complete checkout", "button", "click")):
            dims.update({"ui", "interaction"})
        if has_any_strategy_term(text, ("pii", "raw email", "phone", "shipping_address", "card_last4", "access_token", "cookie", "leak", "redaction", "pseudonym")):
            dims.add("privacy_compliance")
        if has_any_strategy_term(text, ("dedupe_key", "duplicate_ignored", "duplicate absence", "duplicate_absence", "replay", "replaying")):
            dims.add("idempotency")
        if has_any_strategy_term(text, ("retry_count", "backoff_schedule", "next_retry_at", "503", "queue_status", "pending_retry")):
            dims.add("retry")
        if not has_any_strategy_term(text, ("feature flag", "feature_flag", "rollout", "cohort", "beta", "default_off", "default off")):
            dims.discard("feature_flag")
            dims.discard("rollout")
        if not has_any_strategy_term(text, ("websocket", "sse", "stream", "streaming")):
            dims.discard("stream")
        if not has_any_strategy_term(text, ("background job", "worker", "job_id", "dead_letter", "dead letter")):
            dims.discard("background_job")
            dims.discard("worker")
        if not has_any_strategy_term(text, ("transaction integrity", "transaction_integrity", "atomic commit", "atomic_commit", "saga", "compensation_event", "inventory_reservation", "payment_authorization")):
            dims.discard("transaction_integrity")
        if not has_any_strategy_term(text, ("audit integrity", "audit_integrity", "append only", "append-only", "hash chain", "previous_hash", "event_hash", "canonical json", "tamper")):
            dims.discard("audit_integrity")
        if not has_any_strategy_term(text, ("permission", "auth", "role", "authorized", "unauthorized", "403", "access denied", "policy_denied")):
            dims.discard("permission")
        for noisy_dim in ("artifact_generation", "notification", "realtime", "multi_client", "reconnect", "offline_sync", "background_sync", "service_worker", "local_storage", "conflict_resolution", "file_preview", "download", "file_content", "graphql", "csrf", "session_security", "cookie_security"):
            dims.discard(noisy_dim)
    artifact_generation_context = (
        has_any_strategy_term(text, ARTIFACT_GENERATION_STRATEGY_TERMS)
        or (
            has_any_strategy_term(text, ("artifact", "artifacts", "manifest"))
            and has_any_strategy_term(text, ("report", "export", "job_id", "job id", "worker", "download"))
        )
    )
    if offline_sync_context and not has_any_strategy_term(text, ARTIFACT_GENERATION_STRATEGY_TERMS):
        artifact_generation_context = False
    if analytics_context and not has_any_strategy_term(text, ("artifact job", "artifact_ready", "artifact_manifest", "report job", "download guard", "manifest_hash", "content_hash")):
        artifact_generation_context = False
    if artifact_generation_context:
        dims.update({"artifact_generation", "api", "persistence", "runtime"})
        if has_any_strategy_term(text, ("progress event", "progress_event", "artifact_ready", "artifact ready", "/events", "sse", "stream")):
            dims.add("stream")
        if has_any_strategy_term(text, ("job_id", "job id", "queued", "queue", "report job", "report-jobs")):
            dims.add("background_job")
        if has_any_strategy_term(text, ("worker", "report worker", "background worker")):
            dims.add("worker")
        if has_any_strategy_term(text, ("download", "download guard", "content-disposition", "content disposition", "download_file", "file_hash", "content_hash")):
            dims.update({"download", "file_content"})
        if has_any_strategy_term(text, ("idempotency", "idempotency_key", "duplicate_absence", "resume_token", "checkpoint_page", "resume")):
            dims.add("idempotency")
        if has_any_strategy_term(text, ("403", "forbidden", "artifact_download_forbidden", "viewer", "authorization denial", "download guard")):
            dims.add("permission")
        if has_any_strategy_term(text, ("page", "screen", "view", "visible", "opens", "submits", "ui", "green success", "partial failure")):
            dims.update({"ui", "interaction"})
        dims.discard("realtime")
        dims.discard("multi_client")
        dims.discard("reconnect")
        dims.discard("graphql")
        dims.discard("notification")
        if not has_any_strategy_term(text, ("file preview", "file_preview", "preview rendering", "preview_rendering", "signed preview token", "nosniff")):
            dims.discard("file_preview")
    cache_consistency_context = http_cache_context or (
        has_any_strategy_term(text, ("cache consistency", "cache_consistency", "etag", "cache control", "cache-control", "if none match", "if-none-match", "304 not modified", "not modified", "cache invalidation", "cache_invalidation", "cache_invalidation_event", "cache key", "cache_key", "surrogate key", "surrogate-key", "surrogate_key", "surrogate key purge", "surrogate_key_purge", "stale while revalidate", "stale-while-revalidate", "stale_revalidation", "stale response", "stale_response_guard", "stale true", "stale=true", "origin fetch", "origin_fetch", "cache status", "cache_status", "version token", "version_token", "item_version", "ui_stale_absence"))
        or (
            has_any_strategy_term(text, ("cache", "cdn", "edge cache", "revalidation", "surrogate"))
            and has_any_strategy_term(text, ("etag", "if-none-match", "cache-control", "304", "stale", "origin", "version"))
        )
    )
    if cache_consistency_context:
        dims.add("cache_consistency")
    webhook_security_context = (
        has_any_strategy_term(text, ("webhook security", "webhook_security", "hmac-sha256", "hmac signature", "hmac_signature", "raw body", "raw_body", "raw body integrity", "raw_body_integrity", "x hub signature 256", "x-hub-signature-256", "x github delivery", "x-github-delivery", "timestamp tolerance", "timestamp_tolerance", "timestamp out of tolerance", "timestamp_out_of_tolerance", "replay window", "replay_window", "delivery id", "delivery_id", "signature mismatch", "signature_mismatch", "signature version", "signature_version"))
        or (
            has_any_strategy_term(text, ("webhook", "webhooks"))
            and has_any_strategy_term(text, ("signature", "hmac", "raw_body", "raw body", "delivery_id", "delivery id", "timestamp", "replay"))
        )
    )
    if webhook_security_context:
        dims.add("webhook_security")
    if has_any_strategy_term(text, ("accessibility", "a11y", "keyboard navigation", "keyboard_navigation", "keyboard only", "keyboard_only", "tab order", "tab_order", "focus management", "focus_management", "focus trap", "focus_trap", "focus restoration", "focus_restoration", "aria semantics", "aria_semantics", "aria modal", "aria_modal", "role dialog", "role_dialog", "accessible name", "accessible_name", "screen reader", "screen_reader")):
        dims.add("accessibility")
    localization_context = has_any_strategy_term(text, LOCALIZATION_STRATEGY_TERMS)
    if localization_context:
        dims.add("localization")
        if has_any_strategy_term(text, ("rendered", "visible", "ui", "html lang", "dir=rtl", "rtl", "ltr", "layout", "overflow")):
            dims.add("ui")
        if has_any_strategy_term(text, ("locale switch", "select locale", "switching locale", "updates lang", "updates dir")):
            dims.add("interaction")
        if has_any_strategy_term(text, ("api", "/api/v1/i18n/messages", "catalog api", "response", "missing_keys", "fallback_count")):
            dims.add("api")
        if has_any_strategy_term(text, ("rtl", "ltr", "overflow", "mobile", "desktop", "responsive")):
            dims.add("responsive")
        if has_any_strategy_term(text, ("runtime", "console", "network", "stale catalog", "cached formatted values", "fallback_count", "missing_keys")):
            dims.add("runtime")
    if has_any_strategy_term(text, ("bulk action", "bulk_action", "bulk delete", "bulk-delete", "delete selected", "selected count", "selected_count", "selection state", "selection_state", "selected scope", "selected_scope")):
        dims.add("bulk_action")
    if has_any_strategy_term(text, ("destructive guard", "destructive_guard", "destructive action", "destructive_action_guard", "destructive confirmation", "confirmation modal", "confirmation_modal", "cancel escape", "cancel/escape")):
        dims.add("destructive_guard")
    if has_any_strategy_term(text, ("undo", "undo action", "undo_action", "undo restoration", "undo_restoration", "operation id", "operation_id", "restore deleted", "restores the two users")):
        dims.add("undo")
    concurrency_text = re.sub(r"\b(?:concurrent\s+index|index\s+concurrently)\b", " ", text, flags=re.IGNORECASE)
    if has_any_strategy_term(concurrency_text, ("concurrency", "concurrent", "parallel requests", "parallel", "simultaneous", "race condition", "concurrent_requests", "atomicity", "atomic", "locking", "optimistic lock", "version conflict", "version_conflict", "conflict response", "conflict_response", "winner loser", "winner/loser", "no oversell", "no_negative_inventory")):
        dims.add("concurrency")
    if has_any_strategy_term(text, ("background job", "background_job", "queued status", "queued_status", "enqueue", "enqueued", "queue", "job id", "job_id", "background worker", "background_worker")):
        dims.add("background_job")
    if has_any_strategy_term(text, ("worker", "worker log", "worker_log", "background worker", "background_worker", "queue worker", "job processor")):
        dims.add("worker")
    retry_text = re.sub(r"\bretry[-_ ]?after\b", " ", text)
    if not optimistic_ui_context and has_any_strategy_term(retry_text, ("retry", "retries", "retry count", "retry_count", "backoff", "backoff schedule", "backoff_schedule", "exponential backoff", "next retry", "next_retry_at", "dead letter", "dead_letter", "dlq")):
        dims.add("retry")
    if has_any_strategy_term(text, ("feature flag", "feature_flag", "flag evaluation", "flag_evaluation", "evaluation id", "evaluation_id", "config version", "config_version", "enabled true", "enabled false", "default off", "default_off", "feature disabled", "feature_disabled", "stale flag", "stale_flag_guard")):
        dims.add("feature_flag")
    if has_any_strategy_term(text, ("rollout", "cohort", "cohort targeting", "cohort_targeting", "cohort match", "cohort_match", "variant", "treatment", "control cohort", "control customer", "beta cohort")):
        dims.add("rollout")
    if has_any_strategy_term(text, ("csrf", "xsrf", "x csrf token", "x-csrf-token", "csrf token", "csrf_token", "csrf denial", "csrf_denial", "csrf failed", "csrf_failed", "cross origin csrf")):
        dims.add("csrf")
    if has_any_strategy_term(text, ("session security", "session_security", "session cookie", "session_cookie", "session rotation", "session_rotation", "logout invalidation", "logout_invalidation", "old session", "old cookie", "active session", "invalidated session")):
        dims.add("session_security")
    if has_any_strategy_term(text, ("cookie security", "cookie_security", "cookie flags", "cookie_flags", "set cookie", "set-cookie", "httponly", "secure cookie", "samesite", "samesite lax", "samesite strict")):
        dims.add("cookie_security")
    saml_context = has_any_strategy_term(text, ("saml", "samlrequest", "saml response", "samlresponse", "authnrequest", "relaystate", "relay state", "assertion consumer", "assertionconsumerserviceurl", "acs url", "sp entityid", "sp entity id", "saml assertion", "xml signature", "x509", "audiencerestriction", "audience restriction", "inresponseto", "in response to", "notbefore", "notonorafter", "nameid", "attribute mapping", "saml_account", "request consumption", "request_consumption"))
    oauth_protocol = has_any_strategy_term(text, ("oauth", "oidc", "openid", "pkce", "code challenge", "code_challenge", "code verifier", "code_verifier", "authorization code", "code exchange", "oauth state", "oauth_state", "oauth nonce", "oauth_nonce", "oauth account", "oauth_account"))
    if oauth_protocol or (has_any_strategy_term(text, ("sso", "identity provider", "idp")) and not saml_context):
        dims.add("oauth")
    if has_any_strategy_term(text, ("redirect security", "redirect_security", "redirect uri", "redirect_uri", "redirect allowlist", "redirect_uri_allowlist", "open redirect", "open_redirect_guard", "return_to", "external redirect", "safe fallback")):
        dims.add("redirect_security")
    if saml_context:
        dims.add("saml")
    webauthn_protocol_context = has_any_strategy_term(text, ("webauthn", "passkey", "publickeycredential", "navigator.credentials", "credential id", "credential_id", "credentialid", "clientdatajson", "client data json", "authenticatordata", "authenticator data", "attestationobject", "attestation object", "rp id", "rpid", "rpidhash", "webauthn origin", "clientdatajson origin", "userverification", "user verification", "userverified", "signcount", "sign count", "last_sign_count", "challenge consumption", "webauthn_challenge", "credential_public_key"))
    webauthn_signature_context = (
        has_any_strategy_term(text, ("signature verification",))
        and has_any_strategy_term(text, ("webauthn", "passkey", "authenticator", "clientdatajson", "authenticatordata", "credential", "rp id", "rpid", "challenge"))
    )
    if webauthn_protocol_context or webauthn_signature_context:
        dims.add("webauthn")
    if has_any_strategy_term(text, ("mfa", "2fa", "two factor", "two-factor", "multi factor", "multi-factor", "totp", "otp", "one time code", "one-time code", "authenticator app", "authenticator code", "mfa challenge", "mfa_challenge", "mfa_challenge_id", "mfa pending", "mfa_pending", "totp code", "totp_code", "totp time window", "totp_time_window", "clock skew", "clock_skew", "recovery code", "recovery_code", "recovery code consumption", "recovery_code_consumption", "mfa required", "mfa_required", "mfa_required_denial")):
        dims.add("mfa")
    one_time_token_context = has_any_strategy_term(text, ("one time token", "one-time token", "one_time_token", "password reset", "forgot password", "reset password", "reset_token", "reset token", "reset_token_hash", "magic link", "email verification", "verify email", "verification token", "invite token"))
    one_time_token_detail = has_any_strategy_term(text, ("token hash", "token_hash", "token purpose", "token_purpose", "token expiry", "token_expiry", "expires_at", "used_at", "token consumption", "token_consumption", "token replay", "token_replay_denial")) and has_any_strategy_term(text, ("password reset", "forgot password", "reset password", "reset", "magic link", "email verification", "verify email", "verification", "invite", "one time", "one-time", "email link"))
    one_time_token_artifact_context = has_any_strategy_term(text, ("notification_outbox", "email outbox", "email_outbox", "email link", "email_link", "password_hash", "password hash", "session invalidation", "session_invalidation", "account enumeration", "generic success", "unknown email", "unknown emails")) and has_any_strategy_term(text, ("password reset", "forgot password", "reset password", "reset_token", "one time", "one-time", "magic link", "email verification", "verify email", "invite token"))
    if one_time_token_context or one_time_token_detail or one_time_token_artifact_context:
        dims.add("one_time_token")
    if has_any_strategy_term(text, ("api key", "api_key", "api-key", "api keys", "personal access token", "personal_access_token", "pat", "access key", "access keys", "key id", "key_id", "key prefix", "key_prefix", "key hash", "key_hash", "secret once", "secret_once", "show once", "display once", "copy panel", "scopes", "scope denial", "insufficient_scope", "last_used_at", "last used", "revoked_at", "revoked key", "api_key.created", "api_key.revoked", "authorization bearer", "bearer secret")):
        dims.add("api_key")
    audit_integrity_context = has_any_strategy_term(text, ("audit integrity", "audit_integrity", "audit log integrity", "audit event", "audit_event", "append only", "append-only", "immutable", "tamper", "tamper denial", "tamper_denial", "audit_integrity_violation", "hash chain", "hash_chain", "previous_hash", "event_hash", "canonical json", "canonical_json", "retention policy", "retention_policy", "retention_expires_at", "legal hold", "legal_hold", "pseudonym", "actor_ref"))
    if financial_ledger_context and not has_any_strategy_term(text, ("audit integrity", "audit_integrity", "audit log integrity", "audit event", "audit_event", "append only", "append-only", "tamper", "tamper denial", "tamper_denial", "audit_integrity_violation", "hash chain", "hash_chain", "previous_hash", "event_hash", "canonical json", "canonical_json", "retention policy", "retention_policy", "retention_expires_at", "legal hold", "legal_hold", "pseudonym", "actor_ref")):
        audit_integrity_context = False
    if audit_integrity_context:
        dims.add("audit_integrity")
    privacy_compliance_context = (
        has_any_strategy_term(text, ("privacy compliance", "privacy_compliance", "dsar", "data export", "privacy export", "export_job_id", "export manifest", "export_manifest", "encrypted export", "export artifact", "export_artifact", "data_hash", "erasure", "erasure request", "erasure_request", "gdpr_erasure", "erasure_job", "data subject", "subject_user_id", "pseudonym", "pseudonymization", "actor_ref", "search_index", "search index", "search index removal", "search_index_removal", "cache purge", "purge cache", "legal_hold_blocked", "privacy.erasure_completed", "export_encryption_key", "raw deleted profile json"))
        or (
            has_any_strategy_term(text, ("privacy", "gdpr", "legal hold", "legal_hold"))
            and has_any_strategy_term(text, ("export", "erase", "erasure", "pii", "pseudonym", "search_index", "cache", "active sessions", "api keys"))
        )
    )
    if privacy_compliance_context:
        dims.add("privacy_compliance")
        if not has_any_strategy_term(text, ("optimistic ui", "optimistic_ui", "optimistic update", "optimistic_update", "optimistic comment", "temp_id", "pending_state", "failed_state", "retry_action")):
            dims.discard("optimistic_ui")
        if not has_any_strategy_term(text, ("etag", "if-none-match", "cache-control", "304 not modified", "stale-while-revalidate", "surrogate key", "surrogate-key", "origin_fetch", "cache_status")):
            dims.discard("cache_consistency")
        if not has_any_strategy_term(text, ("concurrent", "concurrency", "parallel", "simultaneous", "race condition", "winner loser", "winner/loser")):
            dims.discard("concurrency")
        if not has_any_strategy_term(text, ("download_file", "browser download", "download button", "content-disposition")):
            dims.discard("download")
            dims.discard("file_content")
        if not has_any_strategy_term(text, ("notification sent", "notification enqueue", "notification enqueued", "notification_outbox status", "outbox status", "outbox pending", "recipient-safe preview", "email preview")):
            dims.discard("notification")
        if not has_any_strategy_term(text, CLEANUP_STRATEGY_TERMS):
            dims.discard("cleanup")
    graphql_context = (
        has_any_strategy_term(text, ("graphql", "/api/graphql", "operationname", "operation name", "persistedqueryhash", "persisted query", "graphql_operation", "graphql_variables", "persisted_query_hash", "graphql errors", "graphql_errors", "partial data", "partial_data", "field authorization", "field-level authorization", "field_authorization", "field_denied", "dataloader", "n+1", "n_plus_one", "resolver_trace", "resolver count", "resolver_count", "graphql mutation", "graphql_mutation", "assignorder", "graphql subscription", "graphql_subscription", "subscription_event", "orderupdates", "lasteventid", "introspection", "__schema", "__type"))
        or (
            has_any_strategy_term(text, ("bff", "resolver", "apollo cache", "apollo"))
            and has_any_strategy_term(text, ("query", "mutation", "subscription", "variables", "operation"))
        )
    )
    if graphql_context:
        dims.add("graphql")
        dims.add("api")
        if has_any_strategy_term(text, ("field_denied", "field authorization", "field-level authorization", "introspection", "__schema", "__type", "forbidden field", "forbidden fields")):
            dims.add("authorization_policy")
            dims.add("permission")
        if has_any_strategy_term(text, ("tenantid", "tenant id", "cross tenant", "cross-tenant", "scoped data", "tenant boundary", "tenant_boundary", "beta llc", "order_beta")):
            dims.add("data_isolation")
        if has_any_strategy_term(text, ("idempotency", "idempotency_key", "duplicate_absence", "duplicate ignored", "duplicate_ignored")):
            dims.add("idempotency")
        if has_any_strategy_term(text, ("subscription", "graphql_subscription", "subscription_event", "orderupdates")):
            dims.add("realtime")
        if has_any_strategy_term(text, ("second client", "second subscribed client", "multi client", "multi_client", "subscribed client")):
            dims.add("multi_client")
        if has_any_strategy_term(text, ("sequence", "sequence_order", "ordered event", "monotonic")):
            dims.add("ordering")
        if has_any_strategy_term(text, ("reconnect", "lastEventId", "last event id", "cursor", "reconnect_replay")):
            dims.add("reconnect")
        if has_any_strategy_term(text, ("persist", "persisted", "assignment row", "audit log", "resolver_trace")):
            dims.add("persistence")
        if not has_any_strategy_term(text, ("optimistic ui", "optimistic_ui", "optimistic rollback", "temp_id", "pending_state", "failed_state", "retry_action")):
            dims.discard("optimistic_ui")
        if not has_any_strategy_term(text, ("etag", "if-none-match", "cache-control", "304 not modified", "stale-while-revalidate", "surrogate key", "surrogate-key", "origin_fetch", "cache_status")):
            dims.discard("cache_consistency")
        if not has_any_strategy_term(text, ("download_file", "downloaded file", "csv schema", "file content", "parsed file", "content-disposition")):
            dims.discard("file_content")
        if not has_any_strategy_term(text, ("business rule", "calculation", "formula", "branching rule")):
            dims.discard("logic")
    rag_grounding_context = (
        has_any_strategy_term(
            text,
            (
                "rag",
                "retrieval augmented",
                "retrieval-augmented",
                "grounded answer",
                "grounding",
                "rag_grounding",
                "retrieval trace",
                "retrieval_trace",
                "retrieved source ids",
                "retrieved_source_ids",
                "source ids",
                "source_ids",
                "source citation",
                "source_citation",
                "citation",
                "citations",
                "citation span",
                "citation_span",
                "citation_spans",
                "source excerpt match",
                "source_excerpt_match",
                "vector index",
                "vector_index",
                "embedding model",
                "embedding_model",
                "top_k",
                "top k",
                "score threshold",
                "score_threshold",
                "query hash",
                "query_hash",
                "document version",
                "document_version",
                "stale source",
                "stale_source_guard",
                "hallucination guard",
                "hallucination_guard",
                "prompt injection",
                "prompt_injection",
                "prompt injection detected",
                "prompt_injection_detected",
                "prompt_injection_guard",
                "safety trace",
                "safety_trace",
                "abstain",
                "abstention",
                "insufficient sources",
                "insufficient_sources",
            ),
        )
        or (
            has_any_strategy_term(text, ("answer_done", "answer_delta", "knowledge assistant", "assistant answer"))
            and has_any_strategy_term(text, ("source", "citation", "retrieval", "grounding", "corpus"))
        )
    )
    if rag_grounding_context:
        dims.add("rag_grounding")
        dims.add("api")
        if has_any_strategy_term(text, ("answer_done", "answer_delta", "stream", "streaming", "terminal event")):
            dims.add("stream")
        if has_any_strategy_term(text, ("tenant", "tenant_id", "cross tenant", "cross-tenant", "corpus", "foreign embeddings", "beta llc", "doc_beta_secret")):
            dims.add("data_isolation")
        if has_any_strategy_term(text, ("prompt injection", "prompt_injection", "system_prompt", "tool_credentials", "secret", "forbidden text absence", "forbidden secret")):
            dims.add("permission")
        if has_any_strategy_term(text, ("persist", "persistence", "retrieval_trace", "answer citation rows", "audit log", "rag.answer_abstained")):
            dims.add("persistence")
        if has_any_strategy_term(text, ("runtime", "failed response", "request failure", "error", "insufficient_sources", "abstention")):
            dims.add("runtime")
        if not has_any_strategy_term(text, ("optimistic ui", "optimistic_ui", "optimistic rollback", "temp_id", "pending_state", "failed_state", "retry_action")):
            dims.discard("optimistic_ui")
        if not has_any_strategy_term(text, ("etag", "if-none-match", "cache-control", "304 not modified", "stale-while-revalidate", "surrogate key", "surrogate-key", "origin_fetch", "cache_status")):
            dims.discard("cache_consistency")
        if not has_any_strategy_term(text, ("download_file", "downloaded file", "csv schema", "file content", "parsed file", "content-disposition")):
            dims.discard("download")
            dims.discard("file_content")
        if not has_any_strategy_term(text, ("notification sent", "notification enqueue", "notification enqueued", "notification_outbox status", "outbox status", "outbox pending", "recipient-safe preview", "email preview")):
            dims.discard("notification")
        if not has_any_strategy_term(text, CLEANUP_STRATEGY_TERMS):
            dims.discard("cleanup")
        if not has_any_strategy_term(text, ("business rule", "calculation", "formula", "branching rule")):
            dims.discard("logic")
    if has_any_strategy_term(text, ("rate limit", "rate_limit", "rate-limited", "rate_limited", "throttle", "throttled", "too many attempts", "too many requests", "429", "retry-after", "retry_after", "attempt count", "attempt_count", "rate limit key", "rate_limit_key", "rate limit window", "rate_limit_window", "lockout", "lockout expiry", "lockout_expires_at", "cooldown", "no session created", "account enumeration")):
        dims.add("rate_limit")
    if has_any_strategy_term(text, ("api", "http", "endpoint", "response", "request", "response json", "request json", "http json", "poll", "same object")):
        dims.add("api")
    if has_any_strategy_term(text, ("pagination", "page=2", "page 2", "next page", "previous page")):
        dims.add("pagination")
    if has_any_strategy_term(text, ("download_file", "file_hash", "downloaded file", "browser download", "download artifact", "current run file artifact", "content disposition", "content-disposition")):
        dims.add("download")
    file_content_context = has_any_strategy_term(text, ("file content", "parsed file", "csv schema", "row count", "data row", "pii redaction"))
    schema_row_count_only = schema_migration_context and has_any_strategy_term(text, ("row count", "affected row count")) and not has_any_strategy_term(text, ("file", "csv", "download", "export", "parsed file", "data row"))
    if file_content_context and not schema_row_count_only:
        dims.add("file_content")
    if has_any_strategy_term(text, ("file security", "file_security", "malware scan", "malware_scan", "scan status", "scan_status", "quarantine", "quarantined", "scan engine", "scan_engine", "scan version", "scan_version", "storage key", "storage_key", "file size validation", "file_size_validation")):
        dims.add("file_security")
    if has_any_strategy_term(text, ("file preview", "file_preview", "preview rendering", "preview_rendering", "signed url", "signed_url", "signed preview token", "preview token", "nosniff", "x-content-type-options")):
        dims.add("file_preview")
    negative_outbox_context = has_any_strategy_term(text, ("create no outbox", "create no notification_outbox", "create no export_job or notification_outbox", "no notification_outbox row", "no notification_outbox rows", "no outbox row", "no outbox rows", "no order confirmed outbox", "must not create outbox", "must not write outbox", "must not enqueue outbox", "must not create notification_outbox", "must not create notification_outbox rows", "must not write notification_outbox", "must not enqueue notification_outbox", "must not enqueue downstream_generation_job or notification_outbox", "must not publish order.confirmed", "must not send receipt email", "no receipt email", "no receipt side effect", "receipt side effect"))
    positive_notification_context = has_any_strategy_term(text, ("notification sent", "notification enqueue", "notification enqueued", "notification_outbox status", "outbox status", "outbox pending", "outbox preview", "receipt", "email preview", "no real email"))
    if (positive_notification_context and not negative_outbox_context and not subscription_billing_context and not agent_tool_context and not artifact_generation_context and not offline_sync_context and not analytics_context) or (has_any_strategy_term(text, ("notification", "outbox")) and not authorization_policy_context and not financial_ledger_context and not quota_metering_context and not transaction_integrity_context and not subscription_billing_context and not agent_tool_context and not artifact_generation_context and not offline_sync_context and not analytics_context and not negative_outbox_context):
        dims.add("notification")
    notification_policy_context = has_any_strategy_term(text, NOTIFICATION_POLICY_STRATEGY_TERMS)
    if notification_policy_context:
        dims.add("notification_policy")
        dims.add("notification")
        if has_any_strategy_term(text, ("settings", "page", "ui", "visible", "toggle", "turns", "turn off", "turns marketing_email off")):
            dims.add("ui")
            dims.add("interaction")
        if has_any_strategy_term(text, ("api", "patch /api", "post /api", "get /api", "response", "request body")):
            dims.add("api")
        if has_any_strategy_term(text, ("outbox", "email_outbox", "audit log", "persist", "persistence", "unsubscribed_at", "token_hash")):
            dims.add("persistence")
        if has_any_strategy_term(text, ("quiet hours", "send_after", "timezone", "time zone")):
            dims.add("time_boundary")
        if has_any_strategy_term(text, ("idempotency_key", "duplicate", "replay", "digest_dedupe")):
            dims.add("idempotency")
        if has_any_strategy_term(text, ("unsubscribe token", "token_hash", "token_already_used", "token replay")):
            dims.add("one_time_token")
            dims.add("permission")
        if has_any_strategy_term(text, ("runtime", "console", "request failure", "failed response", "no real email")):
            dims.add("runtime")
    if has_any_strategy_term(text, ("idempotency", "idempotent", "idempotency key", "duplicate absence", "duplicate ignored")):
        dims.add("idempotency")
    if has_any_strategy_term(text, ("data isolation", "tenant boundary", "tenant isolation", "cross tenant denial", "cross tenant", "cross workspace", "workspace boundary", "another workspace", "foreign tenant absence", "same tenant row set parity")):
        dims.add("data_isolation")
    if not audit_integrity_context and has_any_strategy_term(text, ("time boundary", "date range boundary", "date range", "timezone", "time zone", "inclusive start", "exclusive end", "dst boundary", "daylight saving", "boundary fixture rows")):
        dims.add("time_boundary")
    if not audit_integrity_context and has_any_strategy_term(text, ("stream", "streaming", "websocket", "sse", "answer_done", "answer_chunk", "terminal event")):
        dims.add("stream")
    if not audit_integrity_context and has_any_strategy_term(text, ("realtime", "real time", "real-time", "live event", "live update", "collaboration", "broadcast", "broadcast event", "broadcast_event", "block updated")):
        dims.add("realtime")
    if has_any_strategy_term(text, ("multi client", "multi-client", "multi_client", "two clients", "both clients", "sender recipient", "recipient client")):
        dims.add("multi_client")
    if not audit_integrity_context and has_any_strategy_term(text, ("ordering", "sequence order", "sequence_order", "sequence", "ordered arrival", "in order")):
        dims.add("ordering")
    if has_any_strategy_term(text, ("reconnect", "reconnect replay", "reconnect_replay", "cursor", "replay exactly", "catch up", "catch-up", "resume live", "resumed live")):
        dims.add("reconnect")
    if has_any_strategy_term(text, ("persist", "persisted", "persistence", "database", "db", "postgres", "session", "turn", "log", "stdout")):
        dims.add("persistence")
    auth_token_context = has_any_strategy_term(
        text,
        (
            "access token",
            "access_token",
            "id token",
            "id_token",
            "refresh token",
            "refresh_token",
            "session token",
            "session_token",
            "auth token",
            "auth_token",
            "bearer token",
            "csrf token",
            "csrf_token",
            "x csrf token",
            "x-csrf-token",
            "reset token",
            "reset_token",
            "verification token",
            "invite token",
            "one time token",
            "one-time token",
            "one_time_token",
            "personal access token",
            "token hash",
            "token_hash",
            "token purpose",
            "token_purpose",
            "token expiry",
            "token_expiry",
            "token consumption",
            "token_consumption",
            "token replay",
            "token_replay_denial",
        ),
    )
    if has_any_strategy_term(text, ("permission", "auth", "login", "role", "credential", "authorized", "unauthorized", "authenticated", "authentication", "authorization")) or auth_token_context:
        dims.add("permission")
    if has_any_strategy_term(text, ("runtime", "console", "network", "error", "failed response", "request failure", "500", "exception")):
        dims.add("runtime")
    if has_any_strategy_term(text, ("responsive", "mobile", "desktop", "viewport", "breakpoint")):
        dims.add("responsive")
    if has_any_strategy_term(text, CLEANUP_STRATEGY_TERMS):
        dims.add("cleanup")
    if has_any_strategy_term(text, DECISION_TABLE_STRATEGY_TERMS):
        dims.add("logic")
        if has_any_strategy_term(text, ("stdout json", "stdout_json", "terminal status", "terminal_status", "runtime disposition")):
            dims.add("runtime")
    if has_any_strategy_term(text, ("logic", "rule", "validation", "branch", "state transition", "retry")):
        dims.add("logic")
    if localization_context:
        if not has_any_strategy_term(text, ("ledger", "ledger entry", "double entry", "refund", "payment", "payout", "settlement", "balanced debits", "reversal")):
            dims.discard("financial_ledger")
        if not has_any_strategy_term(text, ("money precision", "decimal arithmetic", "rounding rule", "round half up", "tax calculation", "discount calculation", "currency conversion", "fx rate", "no float drift", "floating point")):
            dims.discard("calculation")
        if not has_any_strategy_term(text, ("time boundary", "date range boundary", "date range", "time range", "inclusive start", "exclusive end", "dst boundary", "daylight saving", "boundary fixture rows")):
            dims.discard("time_boundary")
        if not has_any_strategy_term(text, ("business rule", "decision table", "rule matrix", "branching rule", "state transition table")):
            dims.discard("logic")
        if not has_any_strategy_term(text, ("persist", "persisted", "persistence", "database", "db", "row", "audit log")):
            dims.discard("persistence")
    if webhook_security_context and not has_any_strategy_term(text, ("websocket", "sse", "broadcast", "live event", "multi client", "multi-client", "sequence order", "sequence_order", "ordered arrival")):
        dims.discard("realtime")
        dims.discard("multi_client")
        dims.discard("ordering")
        dims.discard("stream")
    if webhook_security_context and not has_any_strategy_term(text, ("notification sent", "notification enqueue", "notification enqueued", "notification_outbox status", "outbox status", "outbox pending", "receipt", "email preview")):
        dims.discard("notification")
    if privacy_compliance_context:
        if not has_any_strategy_term(text, ("optimistic ui", "optimistic_ui", "optimistic update", "optimistic_update", "optimistic comment", "temp_id", "pending_state", "failed_state", "retry_action")):
            dims.discard("optimistic_ui")
        if not has_any_strategy_term(text, ("etag", "if-none-match", "cache-control", "304 not modified", "stale-while-revalidate", "surrogate key", "surrogate-key", "origin_fetch", "cache_status")):
            dims.discard("cache_consistency")
        if not has_any_strategy_term(text, ("concurrent", "concurrency", "parallel", "simultaneous", "race condition", "winner loser", "winner/loser")):
            dims.discard("concurrency")
        if not has_any_strategy_term(text, ("download_file", "browser download", "download button", "content-disposition")):
            dims.discard("download")
            dims.discard("file_content")
        if not has_any_strategy_term(text, ("notification sent", "notification enqueue", "notification enqueued", "notification_outbox status", "outbox status", "outbox pending", "recipient-safe preview", "email preview")):
            dims.discard("notification")
        if not has_any_strategy_term(text, CLEANUP_STRATEGY_TERMS):
            dims.discard("cleanup")
    if graphql_context and not has_any_strategy_term(text, ("optimistic ui", "optimistic_ui", "optimistic rollback", "temp_id", "pending_state", "failed_state", "retry_action")):
        dims.discard("optimistic_ui")
    if graphql_context and not has_any_strategy_term(text, ("etag", "if-none-match", "cache-control", "304 not modified", "stale-while-revalidate", "surrogate key", "surrogate-key", "origin_fetch", "cache_status")):
        dims.discard("cache_consistency")
    if graphql_context and not has_any_strategy_term(text, ("download_file", "downloaded file", "csv schema", "file content", "parsed file", "content-disposition")):
        dims.discard("file_content")
    if graphql_context and not has_any_strategy_term(text, ("business rule", "calculation", "formula", "branching rule")):
        dims.discard("logic")
    if rag_grounding_context and not has_any_strategy_term(text, ("optimistic ui", "optimistic_ui", "optimistic rollback", "temp_id", "pending_state", "failed_state", "retry_action")):
        dims.discard("optimistic_ui")
    if rag_grounding_context and not has_any_strategy_term(text, ("etag", "if-none-match", "cache-control", "304 not modified", "stale-while-revalidate", "surrogate key", "surrogate-key", "origin_fetch", "cache_status")):
        dims.discard("cache_consistency")
    if rag_grounding_context and not has_any_strategy_term(text, ("download_file", "downloaded file", "csv schema", "file content", "parsed file", "content-disposition")):
        dims.discard("download")
        dims.discard("file_content")
    if rag_grounding_context and not has_any_strategy_term(text, ("notification sent", "notification enqueue", "notification enqueued", "notification_outbox status", "outbox status", "outbox pending", "recipient-safe preview", "email preview")):
        dims.discard("notification")
    if rag_grounding_context and not has_any_strategy_term(text, CLEANUP_STRATEGY_TERMS):
        dims.discard("cleanup")
    if rag_grounding_context and not has_any_strategy_term(text, ("business rule", "calculation", "formula", "branching rule")):
        dims.discard("logic")
    if search_relevance_context:
        if not has_any_strategy_term(text, ("concurrent", "concurrency", "parallel", "simultaneous", "race condition", "atomic", "lock", "locking", "optimistic lock")):
            dims.discard("concurrency")
        if not has_any_strategy_term(text, ("sequence_order", "sequence order", "ordered event", "event sequence", "monotonic event")):
            dims.discard("ordering")
        if not has_any_strategy_term(text, ("idempotency", "idempotency_key", "duplicate_ignored", "idempotent replay")):
            dims.discard("idempotency")
        if not has_any_strategy_term(text, ("websocket", "sse", "stream", "streaming", "live event", "broadcast", "multi client", "multi-client", "reconnect")):
            dims.discard("stream")
            dims.discard("realtime")
            dims.discard("multi_client")
            dims.discard("reconnect")
        if not has_any_strategy_term(text, ("persist", "persisted", "persistence", "database", "db", "postgres", "audit log", "audit_log")):
            dims.discard("persistence")
        if not has_any_strategy_term(text, ("permission", "auth", "role", "authorized", "unauthorized", "403", "policy_denied", "access denied")):
            dims.discard("permission")
        if not has_any_strategy_term(text, ("download_file", "downloaded file", "csv schema", "file content", "parsed file", "content-disposition")):
            dims.discard("download")
            dims.discard("file_content")
        if not has_any_strategy_term(text, ("business rule", "calculation", "formula", "branching rule")):
            dims.discard("logic")
    if scheduled_job_context:
        if not has_any_strategy_term(text, ("websocket", "sse", "stream", "streaming", "live event", "broadcast", "multi client", "multi-client", "reconnect cursor")):
            dims.discard("stream")
            dims.discard("realtime")
            dims.discard("multi_client")
            dims.discard("reconnect")
        if not has_any_strategy_term(text, ("sequence_order", "sequence order", "ordered event", "event sequence", "monotonic event")):
            dims.discard("ordering")
        if not has_any_strategy_term(text, ("api path", "endpoint", "http", "response body", "request body")):
            dims.discard("api")
        if not has_any_strategy_term(text, ("pagination", "page=2", "page 2", "next page", "previous page")):
            dims.discard("pagination")
        if not has_any_strategy_term(text, ("download_file", "downloaded file", "csv schema", "file content", "parsed file", "content-disposition")):
            dims.discard("download")
            dims.discard("file_content")
        if not has_any_strategy_term(text, ("permission", "auth", "role", "authorized", "unauthorized", "403", "policy_denied", "access denied")):
            dims.discard("permission")
    if has_any_strategy_term(text, DECISION_TABLE_STRATEGY_TERMS):
        strong_authz = has_any_strategy_term(text, ("authorization policy", "authorization_policy", "policy evaluate", "policy/evaluate", "rbac", "abac", "direct api denial", "policy_denied", "resource_scope", "obligation"))
        if not strong_authz:
            dims.discard("authorization_policy")
            dims.discard("permission")
        if not has_any_strategy_term(text, ("get /api", "post /api", "put /api", "patch /api", "delete /api", "api endpoint", "api path", "http request", "request body", "response body")):
            dims.discard("api")
        if not has_any_strategy_term(text, ("ui entry", "page", "screen", "view", "rendered control", "button selector")):
            dims.discard("ui")
        if not has_any_strategy_term(text, ("database", "db", "postgres", "persisted row", "persistence", "audit log", "log row")):
            dims.discard("persistence")
    if notification_policy_context:
        if not has_any_strategy_term(text, ("concurrent", "concurrency", "parallel", "simultaneous", "race condition", "concurrent_requests", "double click", "winner loser", "winner/loser")):
            dims.discard("concurrency")
        if not has_any_strategy_term(text, ("pagination", "page=2", "page 2", "next page", "previous page")):
            dims.discard("pagination")
        if not has_any_strategy_term(text, ("transaction integrity", "transaction_integrity", "atomic commit", "atomic_commit", "saga", "compensation_event", "outbox dispatch", "post_commit_publish", "publish exactly once")):
            dims.discard("transaction_integrity")
    if subscription_billing_context:
        if not has_any_strategy_term(text, ("concurrent", "concurrency", "parallel", "simultaneous", "race condition", "winner loser", "winner/loser")):
            dims.discard("concurrency")
        if not has_any_strategy_term(text, ("pagination", "page=2", "page 2", "next page", "previous page")):
            dims.discard("pagination")
        if not has_any_strategy_term(text, ("transaction integrity", "transaction_integrity", "atomic commit", "atomic_commit", "saga", "compensation_event", "outbox dispatch", "post_commit_publish", "publish exactly once")):
            dims.discard("transaction_integrity")
        if not has_any_strategy_term(text, ("financial ledger", "financial_ledger", "ledger entry", "double entry", "refund ledger", "settlement")):
            dims.discard("financial_ledger")
    if agent_tool_context:
        if not has_any_strategy_term(text, ("concurrent", "concurrency", "parallel", "simultaneous", "race condition", "winner loser", "winner/loser")):
            dims.discard("concurrency")
        if not has_any_strategy_term(text, ("pagination", "page=2", "page 2", "next page", "previous page")):
            dims.discard("pagination")
        if not has_any_strategy_term(text, ("sequence_order", "sequence order", "ordered event", "event sequence", "monotonic event")):
            dims.discard("ordering")
        dims.discard("realtime")
        dims.discard("multi_client")
        dims.discard("reconnect")
        dims.discard("graphql")
        dims.discard("file_preview")
        dims.discard("notification")
    if artifact_generation_context:
        if not has_any_strategy_term(text, ("concurrent", "concurrency", "parallel", "simultaneous", "race condition", "winner loser", "winner/loser")):
            dims.discard("concurrency")
        if not has_any_strategy_term(text, ("pagination", "page=2", "page 2", "next page", "previous page")):
            dims.discard("pagination")
        if not has_any_strategy_term(text, ("sequence_order", "sequence order", "ordered event", "event sequence", "monotonic event")):
            dims.discard("ordering")
        if not has_any_strategy_term(text, ("file preview", "file_preview", "preview rendering", "preview_rendering", "signed preview token", "nosniff")):
            dims.discard("file_preview")
        dims.discard("realtime")
        dims.discard("multi_client")
        dims.discard("reconnect")
        dims.discard("graphql")
        dims.discard("notification")
        dims.discard("schema_migration")
        dims.discard("agent_tool")
        if not has_any_strategy_term(text, ("audit integrity", "audit_integrity", "append only", "append-only", "tamper", "hash chain", "previous_hash", "event_hash", "canonical json")):
            dims.discard("audit_integrity")
        if not has_any_strategy_term(text, ("privacy compliance", "privacy_compliance", "dsar", "erasure", "pseudonymization", "legal_hold_blocked")):
            dims.discard("privacy_compliance")
        if not has_any_strategy_term(text, ("file security", "file_security", "malware", "scan_status", "scan status", "quarantine", "quarantined")):
            dims.discard("file_security")
        if not has_any_strategy_term(text, ("cleanup api", "cleanup_api", "delete created test data", "testdata_deleted", "qa_cleanup", "always_run_teardown", "teardown")):
            dims.discard("cleanup")
    if analytics_context:
        dims.update({"analytics", "api", "persistence", "runtime"})
        if has_any_strategy_term(text, ("ui", "page", "screen", "view", "visible", "opens", "browser", "checkout", "consent", "button", "click")):
            dims.update({"ui", "interaction"})
        if has_any_strategy_term(text, ("pii", "raw email", "phone", "shipping_address", "card_last4", "access_token", "cookie", "leak", "redaction", "pseudonym")):
            dims.add("privacy_compliance")
        if has_any_strategy_term(text, ("dedupe_key", "duplicate_ignored", "duplicate absence", "duplicate_absence", "replay", "replaying")):
            dims.add("idempotency")
        if has_any_strategy_term(text, ("retry_count", "backoff_schedule", "next_retry_at", "503", "queue_status", "pending_retry")):
            dims.add("retry")
        if not has_any_strategy_term(text, ("feature flag", "feature_flag", "rollout", "cohort", "beta", "default_off", "default off")):
            dims.discard("feature_flag")
            dims.discard("rollout")
        if not has_any_strategy_term(text, ("websocket", "sse", "stream", "streaming")):
            dims.discard("stream")
        if not has_any_strategy_term(text, ("background job", "worker", "job_id", "dead_letter", "dead letter")):
            dims.discard("background_job")
            dims.discard("worker")
        if not has_any_strategy_term(text, ("transaction integrity", "transaction_integrity", "atomic commit", "atomic_commit", "saga", "compensation_event", "inventory_reservation", "payment_authorization")):
            dims.discard("transaction_integrity")
        if not has_any_strategy_term(text, ("audit integrity", "audit_integrity", "append only", "append-only", "hash chain", "previous_hash", "event_hash", "canonical json", "tamper")):
            dims.discard("audit_integrity")
        if not has_any_strategy_term(text, ("permission", "auth", "role", "authorized", "unauthorized", "403", "access denied", "policy_denied")):
            dims.discard("permission")
        for noisy_dim in ("artifact_generation", "notification", "realtime", "multi_client", "reconnect", "offline_sync", "background_sync", "service_worker", "local_storage", "conflict_resolution", "file_preview", "download", "file_content", "graphql", "csrf", "session_security", "cookie_security"):
            dims.discard(noisy_dim)
    if offline_sync_context:
        dims.update({"offline_sync", "api", "persistence", "runtime"})
        if has_any_strategy_term(text, ("indexeddb", "local outbox", "local_outbox", "local queue", "local_queue", "encrypted_local_payload", "pending_sync")):
            dims.add("local_storage")
        if has_any_strategy_term(text, ("service worker", "service_worker")):
            dims.add("service_worker")
        if has_any_strategy_term(text, ("background sync", "background_sync", "sync worker")):
            dims.add("background_sync")
        if has_any_strategy_term(text, ("version_conflict", "conflict_id", "blocked_conflict", "merge dialog", "merge_dialog", "resolve-conflict", "resolve_conflict", "if-match", "if_match")):
            dims.add("conflict_resolution")
        if has_any_strategy_term(text, ("idempotency", "idempotency_key", "duplicate_ignored", "duplicate absence", "duplicate_absence", "replay", "replaying")):
            dims.add("idempotency")
        if has_any_strategy_term(text, ("403", "forbidden", "sync_forbidden", "viewer", "outside territory", "authorization denial")):
            dims.add("permission")
        if has_any_strategy_term(text, ("retry_count", "next_retry_at", "backoff_schedule", "503", "retry scheduled")):
            dims.add("retry")
        for noisy_dim in ("artifact_generation", "notification", "realtime", "multi_client", "reconnect", "graphql", "file_preview", "download", "file_content", "scheduled_job", "background_job", "worker", "transaction_integrity"):
            dims.discard(noisy_dim)
        if not has_any_strategy_term(text, ("concurrent", "concurrency", "parallel", "simultaneous", "race condition", "winner loser", "winner/loser")):
            dims.discard("concurrency")
    return dims


def has_strong_api_strategy_signal(text: str) -> bool:
    if has_any_strategy_term(text, ("api", "endpoint", "same object", "poll", "api path", "http api")):
        return True
    return bool(re.search(r"(^|[\s\"'`(])/(?:api|v\d+)/", text, re.IGNORECASE))


def strategy_dimensions_for_test(test: dict[str, Any]) -> set[str]:
    declared_type = str(test.get("type") or "").strip().lower()
    if declared_type == "code_pr":
        return {"logic"}
    text = normalized_strategy_text(
        test.get("type"),
        strip_generated_requirement_suffix(test.get("expected")),
        test.get("steps"),
        test.get("required_evidence"),
    )
    dims = strategy_dimensions_from_text(text)
    if declared_type in STRATEGY_DIMENSION_ORDER:
        dims.add(declared_type)
    if declared_type == "runtime" and "api" in dims and not has_strong_api_strategy_signal(text):
        dims.discard("api")
    if not dims:
        dims.add("logic")
    return dims


def strategy_dimensions_for_step(step: dict[str, Any]) -> set[str]:
    action = str(step.get("action") or "").strip()
    evidence_text = normalized_strategy_text(step.get("evidenceType") or step.get("evidence_type"))
    proves_text = normalized_strategy_text(step.get("proves"))
    explicit_dims = explicit_strategy_dimensions(step)
    dims = strategy_dimensions_from_text(evidence_text)
    proves_dims = strategy_dimensions_from_text(proves_text)
    dims.update(dim for dim in proves_dims if dim not in PROVES_ONLY_DIMENSIONS_REQUIRING_EXPLICIT_EVIDENCE)
    dims.update(explicit_dims)
    if action in {"goto", "expectText", "expectAnyText", "expectVisible", "expectHidden", "expectLocatorCount", "expectUrlContains", "screenshot", "dismissIfPresent"}:
        dims.add("ui")
    if action in {"clickText", "clickRole", "click", "clickAndWaitForResponse", "expectClickable", "fillLabel", "fillPlaceholder", "fill", "press"}:
        dims.add("interaction")
    if action in {"api", "pollApi", "waitForResponse", "clickAndWaitForResponse"}:
        dims.add("api")
    if action in {"websocket", "sse"}:
        dims.add("stream")
    if action in {"expectNoConsoleErrors", "expectNoRequest", "expectNoRequestFailures", "expectNoFailedResponses"}:
        dims.add("runtime")
    if action == "cleanupApi":
        dims.update({"api", "cleanup"})
    if action == "command" and "code_pr" in evidence_text and not explicit_dims:
        dims.add("logic")
    return dims


def explicit_strategy_dimensions(step: dict[str, Any]) -> set[str]:
    raw_values = [
        step.get("strategyDimensions"),
        step.get("strategy_dimensions"),
        step.get("provesDimensions"),
        step.get("proves_dimensions"),
        step.get("evidenceDimensions"),
        step.get("evidence_dimensions"),
    ]
    dims: set[str] = set()
    for value in raw_values:
        if isinstance(value, str):
            candidates = re.split(r"[\s,]+", value)
        elif isinstance(value, list):
            candidates = [str(item) for item in value]
        else:
            candidates = []
        for candidate in candidates:
            normalized = candidate.strip().lower().replace("-", "_")
            if normalized in STRATEGY_DIMENSION_ORDER:
                dims.add(normalized)
    return dims


def build_strategy_coverage(tests: list[dict[str, Any]], test_step_dims: dict[str, set[str]]) -> dict[str, Any]:
    def empty_dimension() -> dict[str, Any]:
        return {
            "planned_count": 0,
            "executable_count": 0,
            "observed_executable_count": 0,
            "incidental_executable_count": 0,
            "blocked_count": 0,
            "untested_count": 0,
            "inconclusive_count": 0,
            "test_ids": [],
            "executable_test_ids": [],
            "observed_test_ids": [],
            "incidental_test_ids": [],
        }

    dimensions: dict[str, dict[str, Any]] = {}
    for name in STRATEGY_DIMENSION_ORDER:
        dimensions[name] = empty_dimension()
    for test in tests:
        test_id = str(test.get("id") or "")
        if not test_id:
            continue
        planned_dims = strategy_dimensions_for_test(test)
        observed_dims = test_step_dims.get(test_id, set())
        dims = planned_dims.union(observed_dims)
        status = str(test.get("status") or "")
        for dim in sorted(dims, key=lambda item: STRATEGY_DIMENSION_ORDER.index(item) if item in STRATEGY_DIMENSION_ORDER else 999):
            item = dimensions.setdefault(dim, empty_dimension())
            planned = dim in planned_dims
            observed = dim in observed_dims
            if planned:
                item["planned_count"] += 1
                if status == "Blocked":
                    item["blocked_count"] += 1
                elif status == "Untested":
                    item["untested_count"] += 1
                elif status == "Inconclusive":
                    item["inconclusive_count"] += 1
                item["test_ids"].append(test_id)
            if observed:
                item["observed_executable_count"] += 1
                item["observed_test_ids"].append(test_id)
            if planned and observed:
                item["executable_count"] += 1
                item["executable_test_ids"].append(test_id)
            elif observed:
                item["incidental_executable_count"] += 1
                item["incidental_test_ids"].append(test_id)
    used_dimensions = {
        name: item
        for name, item in dimensions.items()
        if int(item.get("planned_count") or 0) > 0 or int(item.get("observed_executable_count") or 0) > 0
    }
    gaps = []
    for name, item in used_dimensions.items():
        if int(item.get("planned_count") or 0) > 0 and int(item.get("executable_count") or 0) == 0:
            gaps.append({
                "dimension": name,
                "reason": "no_executable_probe",
                "planned_count": item.get("planned_count", 0),
                "observed_executable_count": item.get("observed_executable_count", 0),
                "blocked_count": item.get("blocked_count", 0),
                "untested_count": item.get("untested_count", 0),
                "test_ids": item.get("test_ids", [])[:12],
                "observed_test_ids": item.get("observed_test_ids", [])[:12],
            })
    return {
        "schema_version": 1,
        "dimension_order": STRATEGY_DIMENSION_ORDER,
        "dimensions": used_dimensions,
        "covered_dimensions": [name for name, item in used_dimensions.items() if int(item.get("executable_count") or 0) > 0],
        "observed_dimensions": [name for name, item in used_dimensions.items() if int(item.get("observed_executable_count") or 0) > 0],
        "gap_count": len(gaps),
        "gaps": gaps,
    }


def is_runtime_string(value: Any) -> bool:
    if has_text(value):
        return True
    if isinstance(value, dict):
        return any(has_text(value.get(key)) for key in ("var", "$var", "template", "$template", "env", "$env"))
    return False


def is_reference_object(value: Any) -> bool:
    return isinstance(value, dict) and any(has_text(value.get(key)) for key in ("var", "$var", "template", "$template", "env", "$env"))


def is_env_reference_object(value: Any) -> bool:
    return isinstance(value, dict) and any(has_text(value.get(key)) for key in ("env", "$env"))


def is_auth_like_name(value: str) -> bool:
    return bool(AUTH_SECRET_NAME_RE.search(value) or SESSION_COOKIE_NAME_RE.search(value))


def is_auth_like_runtime_var_name(value: str) -> bool:
    return bool(AUTH_RUNTIME_VAR_NAME_RE.search(value))


def is_secret_safe_material_reference(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if is_env_reference_object(value):
        return True
    if any(has_text(value.get(key)) for key in ("var", "$var")):
        return True
    template_value = value.get("template") if "template" in value else value.get("$template")
    return has_text(template_value) and bool(TEMPLATE_VAR_RE.search(str(template_value)))


def is_secret_safe_header_reference(value: Any, *, allow_runtime: bool) -> bool:
    if not isinstance(value, dict):
        return False
    if is_env_reference_object(value):
        return True
    if allow_runtime and any(has_text(value.get(key)) for key in ("var", "$var")):
        return True
    template_value = value.get("template") if "template" in value else value.get("$template")
    return allow_runtime and has_text(template_value) and bool(TEMPLATE_VAR_RE.search(str(template_value)))


def validate_header_material(value: Any, location: str, errors: list[str], *, allow_runtime: bool) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        errors.append(f"{location} must be an object mapping header names to values.")
        return
    for header_name, header_value in value.items():
        name_text = str(header_name)
        if not has_text(name_text):
            errors.append(f"{location} contains an empty header name.")
            continue
        if not is_runtime_string(header_value):
            errors.append(f"{location}.{name_text} must be text or a runtime/env/template reference.")
            continue
        if AUTH_HEADER_NAME_RE.search(name_text) and not is_secret_safe_header_reference(header_value, allow_runtime=allow_runtime):
            hint = "env reference" if not allow_runtime else "env or runtime reference"
            errors.append(f"{location}.{name_text} writes auth-like header material directly; use an {hint}.")


def validate_runtime_var_material(value: Any, location: str, errors: list[str]) -> None:
    if value is None or not isinstance(value, dict):
        return
    for name, item in value.items():
        if not isinstance(name, str) or not VAR_NAME_RE.match(name):
            continue
        if is_auth_like_runtime_var_name(name) and not is_env_reference_object(item):
            errors.append(f"{location}.{name} writes auth-like runtime material directly; use an env reference.")


def validate_auth_like_field_material(value: Any, location: str, errors: list[str]) -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            validate_auth_like_field_material(item, f"{location}[{index}]", errors)
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        key_text = str(key)
        item_location = f"{location}.{key_text}" if location else key_text
        if is_auth_like_runtime_var_name(key_text):
            if is_secret_safe_material_reference(item):
                continue
            if not isinstance(item, (dict, list)) and item is not None:
                errors.append(f"{item_location} writes auth-like material directly; use an env or runtime reference.")
                continue
        validate_auth_like_field_material(item, item_location, errors)


def validate_auth_setup_material(step: dict[str, Any], location: str, errors: list[str], warnings: list[str]) -> None:
    action = step.get("action")
    if action == "setLocalStorage":
        values = step.get("values")
        if values is not None and not isinstance(values, dict):
            errors.append(f"{location} setLocalStorage.values must be an object.")
            return
        for key, value in (values or {}).items():
            key_text = str(key)
            if AUTH_SECRET_NAME_RE.search(key_text) and not is_reference_object(value):
                errors.append(f"{location} setLocalStorage.{key_text} writes auth-like material directly; use an env reference or storageState.")
            elif SESSION_COOKIE_NAME_RE.search(key_text) and isinstance(value, str):
                warnings.append(f"{location} setLocalStorage.{key_text} looks session-like; prefer an env reference or storageState.")
    elif action == "addCookies":
        cookies = step.get("cookies") if isinstance(step.get("cookies"), list) else [step.get("cookie")] if step.get("cookie") is not None else []
        for index, cookie in enumerate(cookies):
            if not isinstance(cookie, dict):
                errors.append(f"{location} addCookies cookie[{index}] must be an object.")
                continue
            name = str(cookie.get("name") or "")
            value = cookie.get("value")
            if (AUTH_SECRET_NAME_RE.search(name) or SESSION_COOKIE_NAME_RE.search(name)) and value is not None and not is_reference_object(value):
                errors.append(f"{location} addCookies cookie {name or f'[{index}]'} writes auth-like material directly; use an env reference or storageState.")


def validate_json_expectation(value: Any, location: str, name: str, errors: list[str]) -> None:
    if value is not None and (not isinstance(value, dict) or not value):
        errors.append(f"{location} {name} must be a non-empty JSON expectation object.")


def validate_json_any_expectation(value: Any, location: str, name: str, errors: list[str]) -> None:
    if value is None:
        return
    if not isinstance(value, list) or not value:
        errors.append(f"{location} {name} must be a non-empty array of JSON expectation objects.")
        return
    for index, item in enumerate(value):
        if not isinstance(item, dict) or not item:
            errors.append(f"{location} {name}[{index}] must be a non-empty JSON expectation object.")


def validate_response_header_map(value: Any, location: str, name: str, errors: list[str], *, text_only: bool = False) -> None:
    if value is None:
        return
    if not isinstance(value, dict) or not value:
        errors.append(f"{location} {name} must be a non-empty object mapping response header names to expectations.")
        return
    for header_name, expected in value.items():
        if not has_text(str(header_name)):
            errors.append(f"{location} {name} contains an empty response header name.")
        if text_only and not is_runtime_string(expected):
            errors.append(f"{location} {name}.{header_name} must be text or a runtime/env/template reference.")
        elif not text_only and not (is_runtime_string(expected) or isinstance(expected, (int, float, bool)) or (isinstance(expected, dict) and has_text(expected.get("op")))):
            errors.append(f"{location} {name}.{header_name} must be an expected value, operator object, or runtime/env/template reference.")


def validate_extract_response_header(value: Any, location: str, errors: list[str], produced_vars: set[str]) -> None:
    if value is None:
        return
    if not isinstance(value, dict) or not value:
        errors.append(f"{location} extractResponseHeader must be a non-empty object mapping variable names to header names.")
        return
    for var_name, spec in value.items():
        if not isinstance(var_name, str) or not VAR_NAME_RE.match(var_name):
            errors.append(f"{location} extractResponseHeader contains invalid runtime variable name: {var_name!r}.")
            continue
        if isinstance(spec, dict):
            header_name = spec.get("header") or spec.get("name")
            if not has_text(header_name):
                errors.append(f"{location} extractResponseHeader.{var_name} is missing header or name.")
        elif not has_text(spec):
            errors.append(f"{location} extractResponseHeader.{var_name} must be a response header name or object with header/name.")
        produced_vars.add(var_name)


def validate_extract_json_spec(value: Any, location: str, name: str, errors: list[str], produced_vars: set[str] | None = None) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        errors.append(f"{location} {name} must be an object mapping variable names to JSON paths.")
        return
    for var_name, spec in value.items():
        if not has_text(str(var_name)):
            errors.append(f"{location} has an empty {name} variable name.")
            continue
        if isinstance(spec, dict):
            paths = spec.get("paths")
            if paths is not None:
                if not isinstance(paths, list) or not any(has_text(item) for item in paths):
                    errors.append(f"{location} {name}.{var_name}.paths must contain at least one JSON path string.")
            elif not has_text(spec.get("path")):
                errors.append(f"{location} {name}.{var_name} is missing path.")
        elif not has_text(spec):
            errors.append(f"{location} {name}.{var_name} must be a JSON path string or object with path.")
        if produced_vars is not None:
            produced_vars.add(str(var_name))


def all_steps(plan: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for scenario in as_list(plan.get("scenarios")):
        scenario_id = scenario.get("id", "")
        for step in as_list(scenario.get("steps")):
            merged = dict(step)
            merged["_scenario_id"] = scenario_id
            steps.append(merged)
    return steps


def command_text(command: Any) -> str:
    if isinstance(command, list):
        return " ".join(str(part) for part in command)
    return str(command or "")


def command_parts(command: Any) -> list[str]:
    if isinstance(command, list):
        return [str(part) for part in command]
    if isinstance(command, str):
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()
    return []


def strip_leading_env_assignments(parts: list[str]) -> list[str]:
    index = 0
    while index < len(parts) and ENV_ASSIGNMENT_RE.match(parts[index]):
        index += 1
    if index < len(parts) - 1 and Path(parts[index]).name.lower() == "env":
        nested_index = env_wrapper_nested_command_index(parts, index)
        if nested_index is not None:
            return parts[nested_index:]
    return parts[index:]


def skip_package_runner_options(parts: list[str], index: int) -> int:
    while index < len(parts):
        part = str(parts[index])
        if part == "--":
            return index + 1
        if not part.startswith("-"):
            break
        option = part.split("=", 1)[0]
        index += 1
        if "=" not in part and option in PACKAGE_RUNNER_OPTIONS_WITH_VALUE and index < len(parts):
            index += 1
    return index


def package_runner_cross_env_index(parts: list[str], start_index: int = 0) -> int | None:
    if start_index >= len(parts):
        return None
    starter = Path(parts[start_index]).name.lower()
    if starter == "cross-env":
        return start_index
    if starter == "corepack" and start_index + 1 < len(parts):
        return package_runner_cross_env_index(parts, start_index + 1)
    if starter == "npx":
        index = skip_package_runner_options(parts, start_index + 1)
        if index < len(parts) and Path(parts[index]).name.lower() == "cross-env":
            return index
        return None
    if starter not in {"npm", "pnpm", "yarn"}:
        return None
    index = skip_package_runner_options(parts, start_index + 1)
    if index >= len(parts) or parts[index] not in PACKAGE_CROSS_ENV_EXEC_SUBCOMMANDS:
        return None
    index = skip_package_runner_options(parts, index + 1)
    if index < len(parts) and Path(parts[index]).name.lower() == "cross-env":
        return index
    return None


def env_wrapper_nested_command_index(parts: list[str], env_index: int = 0) -> int | None:
    if env_index >= len(parts) or Path(parts[env_index]).name.lower() != "env":
        return None
    index = env_index + 1
    while index < len(parts):
        part = str(parts[index])
        if part == "--":
            index += 1
            break
        if ENV_ASSIGNMENT_RE.match(part):
            index += 1
            continue
        if part in {"-i", "--ignore-environment"}:
            index += 1
            continue
        if part == "-u":
            if index + 1 >= len(parts) or not ENV_NAME_RE.match(str(parts[index + 1])):
                return None
            index += 2
            continue
        if part.startswith("--unset="):
            if not ENV_NAME_RE.match(part.split("=", 1)[1]):
                return None
            index += 1
            continue
        break
    if index >= len(parts):
        return None
    return index


def strip_cross_env_assignments(parts: list[str]) -> list[str]:
    cross_env_start = package_runner_cross_env_index(parts)
    if cross_env_start is None:
        return parts
    index = cross_env_start + 1
    while index < len(parts) and ENV_ASSIGNMENT_RE.match(parts[index]):
        index += 1
    if index < len(parts) and parts[index] == "--":
        index += 1
    return parts[index:]


def is_mypy_command(parts: list[str]) -> bool:
    parts = strip_leading_env_assignments(parts)
    parts = strip_cross_env_assignments(parts)
    if not parts:
        return False
    executable = Path(parts[0]).name.lower()
    if executable == "mypy":
        return True
    python_like = executable in {"python", "python.exe"} or executable.startswith(("python2", "python3"))
    if len(parts) >= 3 and python_like and parts[1] == "-m" and parts[2] == "mypy":
        return True
    if executable in {"uv", "poetry", "pipenv", "pdm", "rye", "hatch"} and len(parts) >= 3 and parts[1] == "run":
        return is_mypy_command(parts[2:])
    return False


def resolve_plan_path(path_value: Any, plan_dir: Path, cwd_path: Path | None = None) -> Path | None:
    if not has_text(path_value):
        return None
    candidate = Path(str(path_value)).expanduser()
    if candidate.is_absolute():
        return candidate.resolve(strict=False)
    base = cwd_path if cwd_path is not None else plan_dir
    return (base / candidate).resolve(strict=False)


def iter_required_path_specs(step: dict[str, Any]):
    for field, expected_kind in (
        ("requiredFiles", "file"),
        ("required_files", "file"),
        ("requiredDirectories", "directory"),
        ("required_directories", "directory"),
        ("requiredDirs", "directory"),
        ("required_dirs", "directory"),
        ("requiredPaths", "path"),
        ("required_paths", "path"),
    ):
        value = step.get(field)
        if value is None:
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            if isinstance(item, dict):
                path_value = item.get("path")
                kind = str(item.get("type") or item.get("kind") or expected_kind)
            else:
                path_value = item
                kind = expected_kind
            yield field, path_value, kind


def validate_required_path(path: Path | None, kind: str, location: str, source: str, errors: list[str]) -> None:
    if path is None:
        errors.append(f"{location} {source} must be a non-empty path.")
        return
    normalized_kind = kind.lower().replace("-", "_")
    if normalized_kind in {"file", "required_file"}:
        if not path.exists():
            errors.append(f"{location} required file does not exist: {path}")
        elif not path.is_file():
            errors.append(f"{location} required file path is not a file: {path}")
    elif normalized_kind in {"directory", "dir", "required_directory"}:
        if not path.exists():
            errors.append(f"{location} required directory does not exist: {path}")
        elif not path.is_dir():
            errors.append(f"{location} required directory path is not a directory: {path}")
    else:
        if not path.exists():
            errors.append(f"{location} required path does not exist: {path}")


def validate_command_prerequisites(step: dict[str, Any], location: str, command_base: Path, errors: list[str]) -> None:
    cwd_path: Path | None = None
    cwd_value = step.get("cwd")
    if cwd_value not in (None, ""):
        cwd_path = resolve_plan_path(cwd_value, command_base)
        if cwd_path is None:
            errors.append(f"{location} cwd must be a non-empty path.")
        elif not cwd_path.exists():
            errors.append(f"{location} cwd path does not exist: {cwd_path}")
        elif not cwd_path.is_dir():
            errors.append(f"{location} cwd path is not a directory: {cwd_path}")
    for field, path_value, kind in iter_required_path_specs(step):
        validate_required_path(resolve_plan_path(path_value, command_base, cwd_path), kind, location, field, errors)

    parts = command_parts(step.get("command") or step.get("cmd"))
    if not is_mypy_command(parts):
        return
    for index, part in enumerate(parts):
        config_value: str | None = None
        if part == "--config-file" and index + 1 < len(parts):
            config_value = parts[index + 1]
        elif part.startswith("--config-file="):
            config_value = part.split("=", 1)[1]
        if config_value:
            config_path = resolve_plan_path(config_value, command_base, cwd_path)
            if config_path is None or not config_path.exists():
                errors.append(f"{location} mypy config file does not exist: {config_path or config_value}")
            elif not config_path.is_file():
                errors.append(f"{location} mypy config path is not a file: {config_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a QA probe plan against a requirement matrix before execution.")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--summary", help="Optional path to write plan-audit-summary.json")
    parser.add_argument("--allow-unsafe-command", action="store_true", help="Warn instead of fail for command steps that look destructive.")
    parser.add_argument("--project-root", help="Project checkout root used as the default base for command cwd and required path checks.")
    args = parser.parse_args()

    plan_path = Path(args.plan).expanduser().resolve()
    matrix_path = Path(args.matrix).expanduser().resolve()
    command_base = Path(args.project_root).expanduser().resolve() if args.project_root else plan_path.parent
    errors: list[str] = []
    warnings: list[str] = []
    input_artifact_errors: list[dict[str, str]] = []

    plan, plan_load_error = try_load_json(plan_path)
    matrix, matrix_load_error = try_load_json(matrix_path)
    for name, path, load_error in (("plan", plan_path, plan_load_error), ("matrix", matrix_path, matrix_load_error)):
        if load_error:
            input_artifact_errors.append({"name": name, "path": str(path), "error": load_error})
            errors.append(f"{name} artifact is unreadable: {path} ({load_error}).")
    if input_artifact_errors:
        summary = {
            "schema_version": 1,
            "plan": str(plan_path),
            "matrix": str(matrix_path),
            "artifact_hashes": {"plan_sha256": file_sha256(plan_path), "matrix_sha256": file_sha256(matrix_path)},
            "requirement_count": 0,
            "test_count": 0,
            "scenario_count": 0,
            "step_count": 0,
            "mapped_executable_test_count": 0,
            "mapped_executable_requirement_count": 0,
            "coverage_sufficient": False,
            "coverage_gap_count": None,
            "coverage_gap_dimensions": [],
            "passed": False,
            "errors": errors,
            "warnings": warnings,
            "input_artifact_errors": input_artifact_errors,
        }
        write_summary(args.summary, summary)
        print(json.dumps(summary, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1
    assert plan is not None
    assert matrix is not None

    errors.extend(validate_artifact_schema("plan", plan))
    errors.extend(validate_artifact_schema("matrix", matrix))

    for document, field, artifact in (
        (plan, "schemaVersion", "plan"),
        (matrix, "schemaVersion", "matrix"),
    ):
        version_error = schema_version_error(document.get(field), field=field, artifact=artifact)
        if version_error:
            errors.append(version_error)

    for source_name, document in (("plan", plan), ("matrix", matrix)):
        for location, text in iter_strings(document):
            if contains_todo(text):
                errors.append(f"{source_name}.{location} still contains TODO text.")
            if any(pattern.search(text) for pattern in SECRET_PATTERNS):
                errors.append(f"Secret-like value found in {source_name}.{location}; use env/storage state or redact before execution.")
        for location, env_name in iter_env_refs(document):
            if env_name not in os.environ:
                errors.append(f"{source_name}.{location} references missing environment variable {env_name}.")
    storage_state_check_count = validate_storage_state_refs(plan, plan_path, errors, warnings)
    validate_header_material(plan.get("defaultHeaders"), "plan.defaultHeaders", errors, allow_runtime=False)
    validate_header_material(plan.get("extraHTTPHeaders"), "plan.extraHTTPHeaders", errors, allow_runtime=False)
    validate_runtime_var_material(plan.get("runtimeVars"), "plan.runtimeVars", errors)
    validate_runtime_var_material(plan.get("vars"), "plan.vars", errors)
    context_options = plan.get("contextOptions")
    if isinstance(context_options, dict):
        validate_header_material(context_options.get("extraHTTPHeaders"), "plan.contextOptions.extraHTTPHeaders", errors, allow_runtime=False)

    requirements = as_list(matrix.get("requirements"))
    tests = as_list(matrix.get("tests"))
    if not requirements:
        errors.append("matrix.requirements is empty.")
    if not tests:
        errors.append("matrix.tests is empty.")
    if not as_list(plan.get("scenarios")):
        errors.append("plan.scenarios is empty.")

    req_by_id: dict[str, dict[str, Any]] = {}
    for req in requirements:
        req_id = req.get("id")
        if not has_text(req_id):
            errors.append("A matrix requirement is missing id.")
            continue
        if req_id in req_by_id:
            errors.append(f"Duplicate matrix requirement id: {req_id}")
        req_by_id[str(req_id)] = req
        test_ids = [str(item) for item in as_list(req.get("test_ids")) if has_text(item)]
        if not test_ids:
            errors.append(f"Requirement {req_id} has no test_ids mapping.")
        if not has_text(req.get("text")):
            errors.append(f"Requirement {req_id} is missing text.")

    test_by_id: dict[str, dict[str, Any]] = {}
    for test in tests:
        test_id = test.get("id")
        if not has_text(test_id):
            errors.append("A matrix test is missing id.")
            continue
        if test_id in test_by_id:
            errors.append(f"Duplicate matrix test id: {test_id}")
        test_by_id[str(test_id)] = test
        req_ids = [str(item) for item in as_list(test.get("requirement_ids")) if has_text(item)]
        if not req_ids:
            errors.append(f"Test {test_id} has no requirement_ids mapping.")
        for req_id in req_ids:
            if req_id not in req_by_id:
                errors.append(f"Test {test_id} references missing requirement {req_id}.")
        if not has_text(test.get("expected")):
            errors.append(f"Test {test_id} is missing expected behavior.")

    for req in requirements:
        req_id = str(req.get("id", ""))
        for test_id in [str(item) for item in as_list(req.get("test_ids")) if has_text(item)]:
            if test_id not in test_by_id:
                errors.append(f"Requirement {req_id} references missing test {test_id}.")

    steps = all_steps(plan)
    step_ids = set()
    executable_test_ids: set[str] = set()
    executable_requirement_ids: set[str] = set()
    test_step_dims: dict[str, set[str]] = {}
    produced_vars: set[str] = set(DEFAULT_RUNTIME_VARS)
    for field in ("runtimeVars", "vars"):
        configured_vars = plan.get(field)
        if configured_vars is not None:
            if not isinstance(configured_vars, dict):
                errors.append(f"plan.{field} must be an object mapping runtime variable names to values.")
            else:
                for name in configured_vars:
                    if not isinstance(name, str) or not VAR_NAME_RE.match(name):
                        errors.append(f"plan.{field} contains invalid runtime variable name: {name!r}.")
                    else:
                        produced_vars.add(name)
    for step in steps:
        sid = step_id(step)
        action = step.get("action")
        location = f"scenario {step.get('_scenario_id') or '<missing>'} step {sid or '<missing>'}"
        for var_location, var_name in iter_var_refs(step):
            if var_name not in produced_vars:
                warnings.append(f"{location} references runtime variable {var_name} at {var_location} before an earlier extractJson producer.")
        for var_location, var_name in iter_template_var_refs(step):
            if var_name not in produced_vars:
                warnings.append(f"{location} references runtime template variable {var_name} at {var_location} before an earlier extractJson producer.")
        if not has_text(action):
            errors.append(f"{location} is missing action.")
            continue
        action = str(action)
        if action not in DEFAULT_TOOL_ACTIONS:
            errors.append(
                f"{location} uses unsupported action {action!r}; "
                "the default Tool Registry rejects it before runner execution."
            )
            continue
        if sid:
            if sid in step_ids:
                errors.append(f"Duplicate step id: {sid}")
            step_ids.add(sid)
        elif action in EVIDENCE_ACTIONS:
            errors.append(f"{location} needs a stable id.")

        if action in EVIDENCE_ACTIONS:
            if not has_text(step.get("proves")):
                errors.append(f"{location} needs `proves` text.")
            if not has_text(step.get("evidenceType") or step.get("evidence_type")):
                warnings.append(f"{location} has no evidenceType; ledger will infer a generic type.")
            test_ids = step_test_ids(step)
            req_ids = step_requirement_ids(step)
            step_dims = strategy_dimensions_for_step(step)
            if not test_ids:
                errors.append(f"{location} needs testIds.")
            if not req_ids:
                errors.append(f"{location} needs requirementIds.")
            for test_id in test_ids:
                if test_id not in test_by_id:
                    errors.append(f"{location} references missing matrix test {test_id}.")
                executable_test_ids.add(test_id)
                test_step_dims.setdefault(test_id, set()).update(step_dims)
            for req_id in req_ids:
                if req_id not in req_by_id:
                    errors.append(f"{location} references missing matrix requirement {req_id}.")
                executable_requirement_ids.add(req_id)

        if action == "command":
            command_value = step.get("command") or step.get("cmd")
            cmd_text = command_text(command_value)
            parts = command_parts(command_value)
            shell_enabled = step.get("shell") is True
            if isinstance(command_value, str) or shell_enabled:
                if isinstance(command_value, str):
                    message = f"{location} uses a shell string command; array form is required by default."
                else:
                    message = f"{location} enables shell execution; array commands must keep shell disabled by default."
                if args.allow_unsafe_command:
                    warnings.append(message)
                else:
                    errors.append(message)
            secret_boundary = command_secret_boundary_violation(parts)
            if secret_boundary:
                errors.append(
                    f"{location} command crosses the secret boundary ({secret_boundary}); "
                    "--allow-unsafe-command cannot override secret reads, exports, or mutations."
                )
            if DESTRUCTIVE_COMMAND_RE.search(cmd_text):
                message = f"{location} command looks destructive: {cmd_text}"
                if args.allow_unsafe_command:
                    warnings.append(message)
                else:
                    errors.append(message)
            validate_command_prerequisites(step, location, command_base, errors)

        extract_json = step.get("extractJson") or step.get("extract_json")
        expect_json_any = step.get("expectJsonAny") or step.get("expect_json_any")
        expect_stdout_json = step.get("expectStdoutJson") or step.get("expect_stdout_json")
        expect_stdout_json_any = step.get("expectStdoutJsonAny") or step.get("expect_stdout_json_any")
        extract_stdout_json = step.get("extractStdoutJson") or step.get("extract_stdout_json")
        expect_status_any = step.get("expectStatusAny") or step.get("expect_status_any")
        request_text_contains = step.get("expectRequestTextContains") or step.get("expect_request_text_contains")
        request_text_not_contains = step.get("expectRequestTextNotContains") or step.get("expect_request_text_not_contains")
        request_json = step.get("expectRequestJson") or step.get("expect_request_json")
        response_header = step.get("expectResponseHeader") or step.get("expect_response_header")
        response_header_contains = step.get("expectResponseHeaderContains") or step.get("expect_response_header_contains")
        response_header_matches = step.get("expectResponseHeaderMatches") or step.get("expect_response_header_matches")
        extract_response_header = step.get("extractResponseHeader") or step.get("extract_response_header")
        if any(item is not None for item in (expect_stdout_json, expect_stdout_json_any, extract_stdout_json)) and action != "command":
            errors.append(f"{location} uses stdout JSON fields but action {action} is not command.")
        if any(item is not None for item in (request_text_contains, request_text_not_contains, request_json, step.get("captureRequestBody"), step.get("capture_request_body"))) and action not in HTTP_REQUEST_ACTIONS:
            errors.append(f"{location} uses request-body capture/assertion fields but action {action} does not expose an HTTP request body.")
        if any(item is not None for item in (response_header, response_header_contains, response_header_matches, extract_response_header, step.get("captureResponseHeaders"), step.get("capture_response_headers"))) and action not in HTTP_REQUEST_ACTIONS:
            errors.append(f"{location} uses response-header capture/assertion fields but action {action} does not expose an HTTP response.")
        validate_header_material(step.get("headers"), f"{location}.headers", errors, allow_runtime=True)
        validate_auth_like_field_material(step.get("json"), f"{location}.json", errors)
        if isinstance(step.get("body"), (dict, list)):
            validate_auth_like_field_material(step.get("body"), f"{location}.body", errors)
        validate_auth_like_field_material(step.get("env"), f"{location}.env", errors)
        validate_auth_setup_material(step, location, errors, warnings)
        if request_text_contains is not None and not is_runtime_string(request_text_contains):
            errors.append(f"{location} expectRequestTextContains must be text or a runtime/env/template reference.")
        if request_text_not_contains is not None and not is_runtime_string(request_text_not_contains):
            errors.append(f"{location} expectRequestTextNotContains must be text or a runtime/env/template reference.")
        validate_response_header_map(response_header, location, "expectResponseHeader", errors)
        validate_response_header_map(response_header_contains, location, "expectResponseHeaderContains", errors, text_only=True)
        validate_response_header_map(response_header_matches, location, "expectResponseHeaderMatches", errors, text_only=True)
        validate_extract_response_header(extract_response_header, location, errors, produced_vars)
        validate_json_expectation(request_json, location, "expectRequestJson", errors)
        validate_json_expectation(expect_stdout_json, location, "expectStdoutJson", errors)
        validate_json_any_expectation(expect_stdout_json_any, location, "expectStdoutJsonAny", errors)
        validate_extract_json_spec(extract_stdout_json, location, "extractStdoutJson", errors, produced_vars)
        if expect_status_any is not None:
            if not isinstance(expect_status_any, list) or not expect_status_any:
                errors.append(f"{location} expectStatusAny must be a non-empty array of HTTP status numbers.")
            else:
                for index, item in enumerate(expect_status_any):
                    if not isinstance(item, int) or isinstance(item, bool) or item < 100 or item > 599:
                        errors.append(f"{location} expectStatusAny[{index}] must be an HTTP status number.")
        validate_json_any_expectation(expect_json_any, location, "expectJsonAny", errors)
        validate_extract_json_spec(extract_json, location, "extractJson", errors, produced_vars)

        if action == "cleanupApi":
            if not any(has_text(step.get(field)) for field in ("path", "pathTemplate", "url", "urlTemplate")):
                errors.append(f"{location} cleanupApi needs path, pathTemplate, url, or urlTemplate.")
            if step.get("expectStatus") is None and expect_status_any is None:
                errors.append(f"{location} cleanupApi needs expectStatus or expectStatusAny so teardown evidence is auditable.")
            method = str(step.get("method") or "GET").upper()
            if method in {"GET", "HEAD"}:
                warnings.append(f"{location} cleanupApi uses {method}; prefer a project-approved reversible cleanup endpoint.")
            if step.get("alwaysRun") is not True:
                warnings.append(f"{location} cleanupApi should set alwaysRun=true for readable teardown intent.")
            evidence_type = step.get("evidenceType") or step.get("evidence_type")
            if evidence_type != "cleanup":
                warnings.append(f"{location} cleanupApi should use evidenceType `cleanup`.")

    for test_id, test in test_by_id.items():
        status = test.get("status")
        if test_id not in executable_test_ids and status not in ALLOWED_NON_EXECUTED_STATUSES:
            errors.append(f"Matrix test {test_id} has no executable probe step and is not marked Blocked/Untested/Inconclusive.")
    for req_id, req in req_by_id.items():
        status = req.get("status")
        if req_id not in executable_requirement_ids and status not in ALLOWED_NON_EXECUTED_STATUSES:
            errors.append(f"Matrix requirement {req_id} has no executable probe step and is not marked Blocked/Untested/Inconclusive.")

    strategy_coverage = build_strategy_coverage(tests, test_step_dims)
    coverage_gaps = as_list(strategy_coverage.get("gaps"))
    coverage_gap_dimensions = [
        str(item.get("dimension"))
        for item in coverage_gaps
        if isinstance(item, dict) and has_text(item.get("dimension"))
    ]
    coverage_gap_count = int(strategy_coverage.get("gap_count") or 0)
    summary = {
        "schema_version": 1,
        "plan": str(plan_path),
        "matrix": str(matrix_path),
        "artifact_hashes": {"plan_sha256": file_sha256(plan_path), "matrix_sha256": file_sha256(matrix_path)},
        "requirement_count": len(requirements),
        "test_count": len(tests),
        "scenario_count": len(as_list(plan.get("scenarios"))),
        "step_count": len(steps),
        "mapped_executable_test_count": len(executable_test_ids),
        "mapped_executable_requirement_count": len(executable_requirement_ids),
        "storage_state_check_count": storage_state_check_count,
        "coverage_sufficient": not errors and coverage_gap_count == 0,
        "coverage_gap_count": coverage_gap_count,
        "coverage_gap_dimensions": coverage_gap_dimensions,
        "passed": not errors,
        "errors": errors,
        "warnings": warnings,
        "strategy_coverage": strategy_coverage,
    }

    write_summary(args.summary, summary)

    if errors:
        print(json.dumps(summary, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
