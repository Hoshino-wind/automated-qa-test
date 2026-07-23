"""需求分类、业务/Oracle 模型与语义产物构建。"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .intents import (
    analytics_evidence_layers,
    artifact_generation_evidence_layers,
    explicit_http_statuses,
    filter_contextual_evidence_layers,
    graphql_evidence_layers,
    has_accessibility_intent,
    has_account_enumeration_guard_intent,
    has_agent_tool_approval_intent,
    has_agent_tool_authorization_denial_intent,
    has_agent_tool_cancellation_intent,
    has_agent_tool_handoff_intent,
    has_agent_tool_intent,
    has_agent_tool_redaction_intent,
    has_alert_outbox_intent,
    has_always_run_cleanup_intent,
    has_analytics_intent,
    has_api_key_denial_intent,
    has_api_key_hash_intent,
    has_api_key_intent,
    has_api_key_last_used_intent,
    has_api_key_prefix_intent,
    has_api_key_revocation_intent,
    has_api_key_scope_intent,
    has_api_key_secret_leak_guard_intent,
    has_api_key_secret_once_intent,
    has_aria_semantics_intent,
    has_artifact_cancellation_intent,
    has_artifact_download_guard_intent,
    has_artifact_generation_intent,
    has_artifact_partial_failure_intent,
    has_artifact_progress_intent,
    has_artifact_resume_intent,
    has_atomicity_intent,
    has_audit_append_only_intent,
    has_audit_canonical_json_intent,
    has_audit_hash_chain_intent,
    has_audit_integrity_intent,
    has_audit_integrity_leak_guard_intent,
    has_audit_legal_hold_intent,
    has_audit_log_intent,
    has_audit_pseudonym_redaction_intent,
    has_audit_retention_intent,
    has_audit_tamper_denial_intent,
    has_authorization_policy_intent,
    has_authorization_void_intent,
    has_background_job_intent,
    has_background_sync_intent,
    has_backward_compatibility_intent,
    has_billing_usage_event_intent,
    has_browser_scroll_state_intent,
    has_bulk_action_intent,
    has_business_revocation_intent,
    has_cache_consistency_intent,
    has_cache_control_intent,
    has_cache_invalidation_event_intent,
    has_cache_invalidation_intent,
    has_cache_status_intent,
    has_catch_up_intent,
    has_chinese,
    has_cleanup_intent,
    has_cleanup_verification_intent,
    has_concurrency_intent,
    has_conflict_response_intent,
    has_cookie_security_intent,
    has_cross_tenant_denial_intent,
    has_csrf_intent,
    has_currency_conversion_intent,
    has_dead_letter_intent,
    has_decision_table_logic_intent,
    has_deny_precedence_intent,
    has_destructive_confirmation_intent,
    has_direct_api_denial_intent,
    has_disabled_state_intent,
    has_discount_calculation_intent,
    has_double_entry_intent,
    has_download_intent,
    has_dst_boundary_intent,
    has_due_window_intent,
    has_empty_state_intent,
    has_error_state_intent,
    has_escape_close_intent,
    has_etag_intent,
    has_exclusive_end_intent,
    has_feature_flag_intent,
    has_file_preview_intent,
    has_file_security_intent,
    has_file_validation_intent,
    has_financial_ledger_intent,
    has_flag_default_off_intent,
    has_float_drift_guard_intent,
    has_focus_management_intent,
    has_focus_trap_intent,
    has_forbidden_text_absence_intent,
    has_frontend_local_state_only_intent,
    has_graphql_batching_intent,
    has_graphql_cache_version_intent,
    has_graphql_field_authorization_intent,
    has_graphql_intent,
    has_graphql_introspection_guard_intent,
    has_graphql_mutation_intent,
    has_graphql_operation_variables_intent,
    has_graphql_partial_error_intent,
    has_graphql_persisted_query_intent,
    has_graphql_subscription_intent,
    has_hmac_signature_intent,
    has_idempotency_intent,
    has_if_none_match_intent,
    has_immutable_ledger_intent,
    has_inclusive_start_intent,
    has_inventory_release_intent,
    has_inventory_reservation_intent,
    has_keyboard_navigation_intent,
    has_list_interaction_intent,
    has_localization_intent,
    has_locking_intent,
    has_lockout_intent,
    has_logout_invalidation_intent,
    has_mfa_intent,
    has_mfa_pending_intent,
    has_mfa_recovery_code_intent,
    has_mfa_replay_guard_intent,
    has_migration_backfill_intent,
    has_migration_concurrent_index_intent,
    has_migration_foreign_key_intent,
    has_migration_not_null_intent,
    has_migration_plan_intent,
    has_migration_rollback_intent,
    has_minor_unit_amount_intent,
    has_money_precision_intent,
    has_multi_client_intent,
    has_negative_request_intent,
    has_no_negative_inventory_intent,
    has_no_persistence_side_effect_intent,
    has_no_real_email_intent,
    has_no_write_or_duplicate_absence_intent,
    has_nosniff_intent,
    has_not_modified_denial_intent,
    has_notification_intent,
    has_notification_policy_intent,
    has_notification_quiet_hours_intent,
    has_oauth_code_exchange_intent,
    has_oauth_intent,
    has_oauth_nonce_intent,
    has_oauth_replay_guard_intent,
    has_oauth_state_intent,
    has_offline_conflict_resolution_intent,
    has_offline_local_storage_intent,
    has_offline_sync_intent,
    has_one_time_token_consumption_intent,
    has_one_time_token_email_link_intent,
    has_one_time_token_expiry_intent,
    has_one_time_token_intent,
    has_one_time_token_password_update_intent,
    has_one_time_token_replay_guard_intent,
    has_one_time_token_session_invalidation_intent,
    has_open_redirect_guard_intent,
    has_operation_id_intent,
    has_optimistic_pending_intent,
    has_optimistic_rollback_intent,
    has_optimistic_ui_intent,
    has_ordering_intent,
    has_origin_fetch_intent,
    has_outbox_dispatch_intent,
    has_over_refund_denial_intent,
    has_pagination_intent,
    has_payment_authorization_intent,
    has_policy_cache_guard_intent,
    has_policy_decision_intent,
    has_policy_obligation_intent,
    has_privacy_cache_purge_intent,
    has_privacy_compliance_intent,
    has_privacy_erasure_intent,
    has_privacy_export_intent,
    has_privacy_legal_hold_intent,
    has_privacy_pseudonymization_intent,
    has_privacy_search_index_removal_intent,
    has_privacy_session_invalidation_intent,
    has_progress_intent,
    has_publish_exactly_once_intent,
    has_quarantine_intent,
    has_quota_exceeded_denial_intent,
    has_quota_metering_intent,
    has_quota_remaining_intent,
    has_quota_reset_boundary_intent,
    has_quota_window_intent,
    has_rag_abstention_intent,
    has_rag_citation_intent,
    has_rag_document_version_intent,
    has_rag_grounding_intent,
    has_rag_hallucination_guard_intent,
    has_rag_prompt_injection_guard_intent,
    has_rag_retrieval_trace_intent,
    has_rag_secret_leak_guard_intent,
    has_rag_vector_index_intent,
    has_rate_limit_intent,
    has_raw_body_integrity_intent,
    has_realtime_intent,
    has_reconnect_replay_intent,
    has_redirect_security_intent,
    has_replay_window_intent,
    has_resource_creation_intent,
    has_resource_scope_intent,
    has_response_header_intent,
    has_responsive_intent,
    has_retry_after_intent,
    has_retry_backoff_intent,
    has_reversal_ledger_intent,
    has_role_inheritance_intent,
    has_rollout_intent,
    has_rounding_rule_intent,
    has_run_key_intent,
    has_saga_compensation_intent,
    has_same_runtime_object_intent,
    has_saml_attribute_mapping_intent,
    has_saml_audience_recipient_intent,
    has_saml_in_response_to_intent,
    has_saml_intent,
    has_saml_replay_guard_intent,
    has_saml_request_intent,
    has_saml_signature_intent,
    has_saml_time_window_intent,
    has_scan_status_intent,
    has_schedule_expression_intent,
    has_scheduled_job_intent,
    has_scheduler_lock_intent,
    has_schema_migration_intent,
    has_schema_version_intent,
    has_search_facet_intent,
    has_search_query_rewrite_intent,
    has_search_ranking_intent,
    has_search_relevance_intent,
    has_search_sponsored_intent,
    has_search_stale_result_guard_intent,
    has_secret_leak_guard_intent,
    has_selected_scope_intent,
    has_service_worker_intent,
    has_session_rotation_intent,
    has_session_security_intent,
    has_settlement_reconciliation_intent,
    has_signature_validation_intent,
    has_signed_url_intent,
    has_soft_delete_intent,
    has_stale_flag_guard_intent,
    has_stale_response_guard_intent,
    has_stale_revalidation_intent,
    has_static_reference_only_intent,
    has_subscription_authorization_denial_intent,
    has_subscription_billing_intent,
    has_subscription_invoice_preview_intent,
    has_subscription_proration_intent,
    has_subscription_scheduled_capture_intent,
    has_subscription_scheduled_change_intent,
    has_subscription_tax_intent,
    has_success_toast_intent,
    has_surrogate_key_purge_intent,
    has_tax_calculation_intent,
    has_tenant_isolation_intent,
    has_time_boundary_intent,
    has_timestamp_tolerance_intent,
    has_timezone_intent,
    has_totp_intent,
    has_trace_correlation_intent,
    has_transaction_integrity_intent,
    has_transaction_outbox_intent,
    has_undo_intent,
    has_unsubscribe_token_intent,
    has_upload_intent,
    has_usage_counter_intent,
    has_validation_error_ux_intent,
    has_version_token_intent,
    has_webauthn_assertion_intent,
    has_webauthn_attestation_intent,
    has_webauthn_challenge_intent,
    has_webauthn_intent,
    has_webauthn_origin_rp_intent,
    has_webauthn_replay_guard_intent,
    has_webauthn_sign_count_intent,
    has_webhook_security_intent,
    has_word,
    has_worker_intent,
    method_endpoint_paths,
    offline_sync_evidence_layers,
    path_is_api_for_text,
    path_is_code_file_for_text,
    path_is_stream,
    point_is_code_pr_file_context,
    requirement_specific_evidence_layers,
    terminal_status_value,
)
from .support import (
    PATH_RE,
    build_command_step_fields,
    extract_blocked_validation_commands,
    extract_code_file_paths,
    extract_paths,
    extract_shell_commands,
    extract_validation_commands,
    path_is_code_file,
    redact,
    split_requirement_points,
)


@dataclass(slots=True)
class ClassificationContext:
    """分类阶段共享上下文：路径与标签显式建模，领域信号集中存放。"""

    lower_without_paths: str
    tags: set[str]
    api_like_paths: list[str]
    ui_like_paths: list[str]
    flags: dict[str, bool]


def _collect_classification_context(
    text: str,
    paths: list[str],
) -> ClassificationContext:
    lower = text.lower()
    lower_without_paths = PATH_RE.sub(" ", lower)
    tags: set[str] = set()
    route_paths = [path for path in paths if not path_is_code_file_for_text(text, path)]
    stream_paths = [path for path in route_paths if path_is_stream(path)]
    api_like_paths = [path for path in route_paths if path_is_api_for_text(text, path) and not path_is_stream(path)]
    ui_like_paths = [path for path in route_paths if not path_is_api_for_text(text, path) and not path_is_stream(path)]
    stream_mentioned = bool(stream_paths) or has_word(lower, r"\bwebsocket\b", r"\bsse\b", r"\bstream\b", r"\bws\b", r"\banswer_done\b", r"\banswer_chunk\b") or has_chinese(lower, "流式")
    realtime_mentioned = has_realtime_intent(text)
    multi_client_mentioned = has_multi_client_intent(text)
    ordering_mentioned = has_ordering_intent(text)
    reconnect_mentioned = has_reconnect_replay_intent(text)
    command_mentioned = bool(extract_shell_commands(text)) or has_word(lower_without_paths, r"\bcli\b", r"\bstdout\b", r"\bstderr\b", r"\bexit\s+code\b", r"\bdry[- ]run\b")
    responsive_mentioned = has_responsive_intent(text)
    negative_request_mentioned = has_negative_request_intent(text)
    list_interaction_mentioned = has_list_interaction_intent(text)
    empty_state_mentioned = has_empty_state_intent(text)
    error_state_mentioned = has_error_state_intent(text)
    upload_mentioned = has_upload_intent(text)
    file_validation_mentioned = has_file_validation_intent(text)
    file_security_mentioned = has_file_security_intent(text)
    file_preview_mentioned = has_file_preview_intent(text)
    progress_mentioned = has_progress_intent(text)
    download_mentioned = has_download_intent(text)
    response_header_mentioned = has_response_header_intent(text)
    signature_mentioned = has_signature_validation_intent(text)
    webhook_security_mentioned = has_webhook_security_intent(text)
    csrf_mentioned = has_csrf_intent(text)
    session_security_mentioned = has_session_security_intent(text)
    cookie_security_mentioned = has_cookie_security_intent(text)
    oauth_mentioned = has_oauth_intent(text)
    redirect_security_mentioned = has_redirect_security_intent(text)
    saml_mentioned = has_saml_intent(text)
    webauthn_mentioned = has_webauthn_intent(text)
    mfa_mentioned = has_mfa_intent(text)
    one_time_token_mentioned = has_one_time_token_intent(text)
    api_key_mentioned = has_api_key_intent(text)
    rate_limit_mentioned = has_rate_limit_intent(text)
    bulk_action_mentioned = has_bulk_action_intent(text)
    selected_scope_mentioned = has_selected_scope_intent(text)
    destructive_guard_mentioned = has_destructive_confirmation_intent(text)
    soft_delete_mentioned = has_soft_delete_intent(text)
    undo_mentioned = has_undo_intent(text)
    operation_id_mentioned = has_operation_id_intent(text)
    idempotency_mentioned = has_idempotency_intent(text)
    notification_mentioned = has_notification_intent(text)
    notification_policy_mentioned = has_notification_policy_intent(text)
    background_job_mentioned = has_background_job_intent(text)
    artifact_generation_mentioned = has_artifact_generation_intent(text)
    analytics_mentioned = has_analytics_intent(text)
    if has_artifact_progress_intent(text):
        stream_mentioned = True
    scheduled_job_mentioned = has_scheduled_job_intent(text)
    worker_mentioned = has_worker_intent(text)
    retry_backoff_mentioned = has_retry_backoff_intent(text)
    dead_letter_mentioned = has_dead_letter_intent(text)
    alert_outbox_mentioned = has_alert_outbox_intent(text)
    feature_flag_mentioned = has_feature_flag_intent(text)
    rollout_mentioned = has_rollout_intent(text)
    flag_default_off_mentioned = has_flag_default_off_intent(text)
    direct_api_denial_mentioned = has_direct_api_denial_intent(text)
    stale_flag_guard_mentioned = has_stale_flag_guard_intent(text)
    authorization_policy_mentioned = has_authorization_policy_intent(text)
    financial_ledger_mentioned = has_financial_ledger_intent(text)
    quota_metering_mentioned = has_quota_metering_intent(text)
    transaction_integrity_mentioned = has_transaction_integrity_intent(text)
    subscription_billing_mentioned = has_subscription_billing_intent(text)
    agent_tool_mentioned = has_agent_tool_intent(text)
    cache_consistency_mentioned = has_cache_consistency_intent(text)
    schema_migration_mentioned = has_schema_migration_intent(text)
    optimistic_ui_mentioned = has_optimistic_ui_intent(text)
    audit_log_mentioned = has_audit_log_intent(text)
    audit_integrity_mentioned = has_audit_integrity_intent(text)
    privacy_compliance_mentioned = has_privacy_compliance_intent(text)
    graphql_mentioned = has_graphql_intent(text)
    rag_grounding_mentioned = has_rag_grounding_intent(text)
    search_relevance_mentioned = has_search_relevance_intent(text)
    cleanup_mentioned = has_cleanup_intent(text)
    decision_table_logic_mentioned = has_decision_table_logic_intent(text)
    localization_mentioned = has_localization_intent(text)
    offline_sync_mentioned = has_offline_sync_intent(text)
    offline_local_storage_mentioned = has_offline_local_storage_intent(text)
    background_sync_mentioned = has_background_sync_intent(text)
    service_worker_mentioned = has_service_worker_intent(text)
    offline_conflict_resolution_mentioned = has_offline_conflict_resolution_intent(text)
    if privacy_compliance_mentioned and not has_word(lower_without_paths, r"\bdownload[_ -]?file\b", r"\bcontent-disposition\b", r"\bdownload\s+(?:button|file|csv|artifact)\b", r"\bbrowser\s+download\b"):
        download_mentioned = False
    no_write_mentioned = has_no_write_or_duplicate_absence_intent(text)
    tenant_isolation_mentioned = has_tenant_isolation_intent(text)
    cross_tenant_denial_mentioned = has_cross_tenant_denial_intent(text)
    no_persistence_side_effect_mentioned = has_no_persistence_side_effect_intent(text)
    time_boundary_mentioned = has_time_boundary_intent(text)
    money_precision_mentioned = has_money_precision_intent(text)
    accessibility_mentioned = has_accessibility_intent(text)
    concurrency_mentioned = (
        has_concurrency_intent(text)
        or has_conflict_response_intent(text)
        or has_locking_intent(text)
        or has_atomicity_intent(text)
        or has_no_negative_inventory_intent(text)
    )
    return ClassificationContext(
        lower_without_paths=lower_without_paths,
        tags=tags,
        api_like_paths=api_like_paths,
        ui_like_paths=ui_like_paths,
        flags={
        "accessibility_mentioned": accessibility_mentioned,
        "agent_tool_mentioned": agent_tool_mentioned,
        "alert_outbox_mentioned": alert_outbox_mentioned,
        "analytics_mentioned": analytics_mentioned,
        "api_key_mentioned": api_key_mentioned,
        "artifact_generation_mentioned": artifact_generation_mentioned,
        "audit_integrity_mentioned": audit_integrity_mentioned,
        "audit_log_mentioned": audit_log_mentioned,
        "authorization_policy_mentioned": authorization_policy_mentioned,
        "background_job_mentioned": background_job_mentioned,
        "background_sync_mentioned": background_sync_mentioned,
        "bulk_action_mentioned": bulk_action_mentioned,
        "cache_consistency_mentioned": cache_consistency_mentioned,
        "cleanup_mentioned": cleanup_mentioned,
        "command_mentioned": command_mentioned,
        "concurrency_mentioned": concurrency_mentioned,
        "cookie_security_mentioned": cookie_security_mentioned,
        "cross_tenant_denial_mentioned": cross_tenant_denial_mentioned,
        "csrf_mentioned": csrf_mentioned,
        "dead_letter_mentioned": dead_letter_mentioned,
        "decision_table_logic_mentioned": decision_table_logic_mentioned,
        "destructive_guard_mentioned": destructive_guard_mentioned,
        "direct_api_denial_mentioned": direct_api_denial_mentioned,
        "download_mentioned": download_mentioned,
        "empty_state_mentioned": empty_state_mentioned,
        "error_state_mentioned": error_state_mentioned,
        "feature_flag_mentioned": feature_flag_mentioned,
        "file_preview_mentioned": file_preview_mentioned,
        "file_security_mentioned": file_security_mentioned,
        "file_validation_mentioned": file_validation_mentioned,
        "financial_ledger_mentioned": financial_ledger_mentioned,
        "flag_default_off_mentioned": flag_default_off_mentioned,
        "graphql_mentioned": graphql_mentioned,
        "idempotency_mentioned": idempotency_mentioned,
        "list_interaction_mentioned": list_interaction_mentioned,
        "localization_mentioned": localization_mentioned,
        "mfa_mentioned": mfa_mentioned,
        "money_precision_mentioned": money_precision_mentioned,
        "multi_client_mentioned": multi_client_mentioned,
        "negative_request_mentioned": negative_request_mentioned,
        "no_persistence_side_effect_mentioned": no_persistence_side_effect_mentioned,
        "no_write_mentioned": no_write_mentioned,
        "notification_mentioned": notification_mentioned,
        "notification_policy_mentioned": notification_policy_mentioned,
        "oauth_mentioned": oauth_mentioned,
        "offline_conflict_resolution_mentioned": offline_conflict_resolution_mentioned,
        "offline_local_storage_mentioned": offline_local_storage_mentioned,
        "offline_sync_mentioned": offline_sync_mentioned,
        "one_time_token_mentioned": one_time_token_mentioned,
        "operation_id_mentioned": operation_id_mentioned,
        "optimistic_ui_mentioned": optimistic_ui_mentioned,
        "ordering_mentioned": ordering_mentioned,
        "privacy_compliance_mentioned": privacy_compliance_mentioned,
        "progress_mentioned": progress_mentioned,
        "quota_metering_mentioned": quota_metering_mentioned,
        "rag_grounding_mentioned": rag_grounding_mentioned,
        "rate_limit_mentioned": rate_limit_mentioned,
        "realtime_mentioned": realtime_mentioned,
        "reconnect_mentioned": reconnect_mentioned,
        "redirect_security_mentioned": redirect_security_mentioned,
        "response_header_mentioned": response_header_mentioned,
        "responsive_mentioned": responsive_mentioned,
        "retry_backoff_mentioned": retry_backoff_mentioned,
        "rollout_mentioned": rollout_mentioned,
        "saml_mentioned": saml_mentioned,
        "scheduled_job_mentioned": scheduled_job_mentioned,
        "schema_migration_mentioned": schema_migration_mentioned,
        "search_relevance_mentioned": search_relevance_mentioned,
        "selected_scope_mentioned": selected_scope_mentioned,
        "service_worker_mentioned": service_worker_mentioned,
        "session_security_mentioned": session_security_mentioned,
        "signature_mentioned": signature_mentioned,
        "soft_delete_mentioned": soft_delete_mentioned,
        "stale_flag_guard_mentioned": stale_flag_guard_mentioned,
        "stream_mentioned": stream_mentioned,
        "subscription_billing_mentioned": subscription_billing_mentioned,
        "tenant_isolation_mentioned": tenant_isolation_mentioned,
        "time_boundary_mentioned": time_boundary_mentioned,
        "transaction_integrity_mentioned": transaction_integrity_mentioned,
        "undo_mentioned": undo_mentioned,
        "upload_mentioned": upload_mentioned,
        "webauthn_mentioned": webauthn_mentioned,
        "webhook_security_mentioned": webhook_security_mentioned,
        "worker_mentioned": worker_mentioned,
        },
    )


def _disambiguate_classification_context(
    text: str,
    context: ClassificationContext,
) -> None:
    flags = context.flags
    if flags["privacy_compliance_mentioned"] and not has_word(context.lower_without_paths, r"\bconcurr(?:ent|ency)\b", r"\bparallel\b", r"\bsimultaneous(?:ly)?\b", r"\brace\s+condition\b", r"\btwo\s+concurrent\b"):
        flags["concurrency_mentioned"] = False
    if flags["audit_integrity_mentioned"]:
        flags["ordering_mentioned"] = False
        flags["time_boundary_mentioned"] = False
    if flags["webhook_security_mentioned"] and not (flags["stream_mentioned"] or flags["realtime_mentioned"] or flags["multi_client_mentioned"] or flags["reconnect_mentioned"]):
        flags["ordering_mentioned"] = False
    if flags["search_relevance_mentioned"]:
        if not has_word(context.lower_without_paths, r"\bsequence[_ -]?order\b", r"\bordered\s+event\b", r"\bevent\s+sequence\b", r"\bmonotonic\s+event\b"):
            flags["ordering_mentioned"] = False
        if not has_word(context.lower_without_paths, r"\bconcurr(?:ent|ency)\b", r"\bparallel\b", r"\bsimultaneous(?:ly)?\b", r"\brace\s+condition\b", r"\batomic\b", r"\block(?:ing)?\b"):
            flags["concurrency_mentioned"] = False
    if flags["scheduled_job_mentioned"]:
        if not has_word(context.lower_without_paths, r"\bsequence[_ -]?order\b", r"\bordered\s+event\b", r"\bevent\s+sequence\b", r"\bmonotonic\s+event\b", r"\brealtime\b", r"\bwebsocket\b"):
            flags["ordering_mentioned"] = False
        if not has_word(context.lower_without_paths, r"\breconnect\b", r"\breconnect[_ -]?replay\b", r"\bcursor\b", r"\bresume\s+live\b"):
            flags["reconnect_mentioned"] = False
    if flags["notification_policy_mentioned"] and not has_word(context.lower_without_paths, r"\bconcurr(?:ent|ency)\b", r"\bparallel\b", r"\bsimultaneous(?:ly)?\b", r"\brace\s+condition\b", r"\batomic\b", r"\block(?:ing)?\b", r"\bdouble[- ]click\b"):
        flags["concurrency_mentioned"] = False
    if flags["subscription_billing_mentioned"]:
        flags["realtime_mentioned"] = False
        flags["multi_client_mentioned"] = False
        flags["reconnect_mentioned"] = False
        if has_subscription_scheduled_change_intent(text) or has_subscription_scheduled_capture_intent(text):
            flags["time_boundary_mentioned"] = True
        if has_subscription_proration_intent(text) or has_subscription_tax_intent(text):
            flags["money_precision_mentioned"] = True
    if flags["agent_tool_mentioned"]:
        flags["realtime_mentioned"] = False
        flags["multi_client_mentioned"] = False
        flags["reconnect_mentioned"] = False
    if flags["artifact_generation_mentioned"]:
        flags["realtime_mentioned"] = False
        flags["multi_client_mentioned"] = False
        flags["reconnect_mentioned"] = False
    if flags["offline_sync_mentioned"]:
        flags["realtime_mentioned"] = False
        flags["multi_client_mentioned"] = False
        flags["reconnect_mentioned"] = False
        flags["artifact_generation_mentioned"] = False
        flags["notification_mentioned"] = False
        if not has_word(context.lower_without_paths, r"\bconcurr(?:ent|ency)\b", r"\bparallel\b", r"\bsimultaneous(?:ly)?\b", r"\brace\s+condition\b"):
            flags["concurrency_mentioned"] = False
    if flags["localization_mentioned"]:
        if not has_word(context.lower_without_paths, r"\bbulk[- ](?:delete|archive|update|action)\b", r"\bdelete\s+selected\b", r"\bselected_count\b"):
            flags["bulk_action_mentioned"] = False
            flags["selected_scope_mentioned"] = False


def _apply_core_classification_tags(
    text: str,
    context: ClassificationContext,
) -> None:
    flags = context.flags
    if context.api_like_paths or flags["response_header_mentioned"] or flags["signature_mentioned"] or flags["webhook_security_mentioned"] or flags["graphql_mentioned"] or flags["rag_grounding_mentioned"] or flags["search_relevance_mentioned"] or flags["csrf_mentioned"] or flags["session_security_mentioned"] or flags["cookie_security_mentioned"] or flags["oauth_mentioned"] or flags["redirect_security_mentioned"] or flags["saml_mentioned"] or flags["webauthn_mentioned"] or flags["mfa_mentioned"] or flags["one_time_token_mentioned"] or flags["api_key_mentioned"] or flags["audit_integrity_mentioned"] or flags["schema_migration_mentioned"] or flags["authorization_policy_mentioned"] or flags["financial_ledger_mentioned"] or flags["quota_metering_mentioned"] or flags["transaction_integrity_mentioned"] or flags["subscription_billing_mentioned"] or flags["agent_tool_mentioned"] or flags["artifact_generation_mentioned"] or flags["offline_sync_mentioned"] or flags["analytics_mentioned"] or flags["cache_consistency_mentioned"] or flags["optimistic_ui_mentioned"] or flags["rate_limit_mentioned"] or flags["file_security_mentioned"] or flags["file_preview_mentioned"] or flags["bulk_action_mentioned"] or flags["destructive_guard_mentioned"] or flags["undo_mentioned"] or flags["operation_id_mentioned"] or flags["cleanup_mentioned"] or flags["time_boundary_mentioned"] or flags["money_precision_mentioned"] or flags["feature_flag_mentioned"] or flags["direct_api_denial_mentioned"] or (not flags["stream_mentioned"] and has_word(context.lower_without_paths, r"\bapi\b", r"\bendpoint\b", r"\bhttp\b", r"\bwebhook\b")) or has_chinese(context.lower_without_paths, "接口"):
        context.tags.add("api")
    if flags["stream_mentioned"]:
        context.tags.add("stream")
    if flags["realtime_mentioned"]:
        context.tags.add("realtime")
    if flags["multi_client_mentioned"]:
        context.tags.add("multi_client")
    if flags["ordering_mentioned"]:
        context.tags.add("ordering")
    if flags["reconnect_mentioned"]:
        context.tags.add("reconnect")
    if flags["command_mentioned"]:
        context.tags.add("command")
    if flags["responsive_mentioned"]:
        context.tags.add("responsive")
    if flags["localization_mentioned"]:
        context.tags.update({"localization", "runtime"})
    if flags["notification_policy_mentioned"]:
        context.tags.update({"notification_policy", "notification", "runtime"})
        if has_word(context.lower_without_paths, r"\bopens?\b", r"\bsettings\b", r"\bturns?\b", r"\btoggles?\b", r"\boff\b", r"\bon\b", r"\bpreference\b"):
            context.tags.update({"ui", "interaction"})
    if flags["subscription_billing_mentioned"]:
        context.tags.update({"subscription_billing", "runtime"})
        if has_word(context.lower_without_paths, r"\bopens?\b", r"\bclick(?:s|ing)?\b", r"\bchange\s+plan\b", r"\bpreview\b", r"\bconfirm(?:s|ing)?\b"):
            context.tags.update({"ui", "interaction"})
        if has_subscription_proration_intent(text) or has_subscription_tax_intent(text):
            context.tags.add("calculation")
        if has_subscription_scheduled_change_intent(text) or has_subscription_scheduled_capture_intent(text):
            context.tags.add("time_boundary")
        if has_subscription_authorization_denial_intent(text):
            context.tags.add("permission")
    if flags["agent_tool_mentioned"]:
        context.tags.update({"agent_tool", "stream", "api", "persistence", "runtime"})
        if has_word(context.lower_without_paths, r"\bopens?\b", r"\bpage\b", r"\bui\b", r"\bshows?\b", r"\bdisables?\b", r"\bapproval\s+gate\b", r"\bsends?\s+prompt\b"):
            context.tags.update({"ui", "interaction"})
        if has_agent_tool_approval_intent(text) or has_agent_tool_cancellation_intent(text):
            context.tags.add("interaction")
        if has_idempotency_intent(text):
            context.tags.add("idempotency")
        if has_agent_tool_authorization_denial_intent(text):
            context.tags.add("permission")
    if flags["artifact_generation_mentioned"]:
        context.tags.update({"artifact_generation", "api", "persistence", "runtime"})
        if has_artifact_progress_intent(text):
            context.tags.add("stream")
        if has_background_job_intent(text) or has_word(context.lower_without_paths, r"\bjob[_ -]?id\b", r"\bqueued\b", r"\bqueue\b"):
            context.tags.add("background_job")
        if has_worker_intent(text) or has_word(context.lower_without_paths, r"\bworker\b"):
            context.tags.add("worker")
        if has_download_intent(text) or has_artifact_download_guard_intent(text):
            context.tags.update({"download", "file_content"})
        if has_idempotency_intent(text) or has_artifact_resume_intent(text):
            context.tags.add("idempotency")
        if has_artifact_download_guard_intent(text):
            context.tags.add("permission")
        if has_word(context.lower_without_paths, r"\bopens?\b", r"\bsubmits?\b", r"\bshows?\b", r"\bui\b", r"\bcomplete\b", r"\bsuccess\s+state\b", r"\bpartial\s+failure\b"):
            context.tags.update({"ui", "interaction"})
        if not has_word(context.lower_without_paths, r"\bfile\s+preview\b", r"\bpreview\s+rendering\b", r"\bsigned\s+preview\s+token\b", r"\bnosniff\b"):
            context.tags.discard("file_preview")
        context.tags.discard("realtime")
        context.tags.discard("multi_client")
        context.tags.discard("reconnect")
        context.tags.discard("graphql")
        context.tags.discard("notification")
    if flags["offline_sync_mentioned"]:
        context.tags.update({"offline_sync", "api", "persistence", "runtime"})
        if context.ui_like_paths or has_word(context.lower_without_paths, r"\bopens?\b", r"\bmobile\b", r"\bui\b", r"\bshows?\b", r"\bdialog\b", r"\bmerge\b", r"\bpending\s+sync\b", r"\bsynced\s+state\b"):
            context.tags.update({"ui", "interaction"})
        if flags["offline_local_storage_mentioned"]:
            context.tags.add("local_storage")
        if flags["background_sync_mentioned"]:
            context.tags.add("background_sync")
        if flags["service_worker_mentioned"]:
            context.tags.add("service_worker")
        if flags["offline_conflict_resolution_mentioned"]:
            context.tags.add("conflict_resolution")
        if flags["idempotency_mentioned"]:
            context.tags.add("idempotency")
        if flags["retry_backoff_mentioned"]:
            context.tags.add("retry")
        if has_word(context.lower_without_paths, r"\b403\b", r"\bforbidden\b", r"\bsync[_ -]?forbidden\b", r"\bviewer\b", r"\boutside\s+territory\b"):
            context.tags.add("permission")
        for noisy_tag in ("artifact_generation", "notification", "realtime", "multi_client", "reconnect", "graphql", "file_preview", "download", "file_content", "scheduled_job", "background_job", "worker", "transaction_integrity", "concurrency"):
            context.tags.discard(noisy_tag)
    if flags["analytics_mentioned"]:
        context.tags.update({"analytics", "api", "persistence", "runtime"})
        if context.ui_like_paths or has_word(context.lower_without_paths, r"\bopens?\b", r"\bcheckout\b", r"\bcomplete(?:s|d)?\b", r"\baccepts?\b", r"\bconsent\b", r"\bui\b", r"\bbutton\b", r"\bpage\b", r"\bbrowser\b"):
            context.tags.update({"ui", "interaction"})
        if has_word(context.lower_without_paths, r"\bpii\b", r"\braw\s+email\b", r"\bphone\b", r"\bshipping[_ -]?address\b", r"\bcard[_ -]?last4\b", r"\baccess[_ -]?token\b", r"\bcookie\b", r"\bleak\b", r"\bredact(?:ed|ion)?\b", r"\bpseudonym"):
            context.tags.add("privacy_compliance")
        if flags["idempotency_mentioned"] or has_word(context.lower_without_paths, r"\bdedupe[_ -]?key\b", r"\bduplicate[_ -]?ignored\b", r"\breplay(?:ing|ed)?\b"):
            context.tags.add("idempotency")
        if flags["retry_backoff_mentioned"] or has_word(context.lower_without_paths, r"\bretry[_ -]?count\b", r"\bbackoff[_ -]?schedule\b", r"\bnext[_ -]?retry[_ -]?at\b", r"\b503\b", r"\bqueue[_ -]?status\b"):
            context.tags.add("retry")
        if not has_word(context.lower_without_paths, r"\bfeature\s+flag\b", r"\bflag[_ -]?evaluation\b", r"\brollout\b", r"\bcohort\b", r"\bbeta\b", r"\bdefault[_ -]?off\b"):
            context.tags.discard("feature_flag")
            context.tags.discard("rollout")
        if not has_word(context.lower_without_paths, r"\bwebsocket\b", r"\bsse\b", r"\bstream(?:ing)?\b"):
            context.tags.discard("stream")
        if not has_word(context.lower_without_paths, r"\bbackground\s+job\b", r"\bworker\b", r"\bjob[_ -]?id\b", r"\bdead[_ -]?letter\b"):
            context.tags.discard("background_job")
            context.tags.discard("worker")
        if not has_word(context.lower_without_paths, r"\btransaction\s+integrity\b", r"\batomic[_ -]?commit\b", r"\bsaga\b", r"\bcompensation[_ -]?event\b", r"\binventory[_ -]?reservation\b", r"\bpayment[_ -]?authorization\b"):
            context.tags.discard("transaction_integrity")
        if not has_word(context.lower_without_paths, r"\baudit\s+integrity\b", r"\bappend[- ]?only\b", r"\bhash\s+chain\b", r"\bprevious[_ -]?hash\b", r"\bevent[_ -]?hash\b", r"\bcanonical\s+json\b", r"\btamper\b"):
            context.tags.discard("audit_integrity")
        if not has_word(context.lower_without_paths, r"\bpermission\b", r"\bauth(?:orized|orization|enticated|entication)?\b", r"\brole\b", r"\b403\b", r"\baccess\s+denied\b", r"\bpolicy[_ -]?denied\b"):
            context.tags.discard("permission")
        for noisy_tag in ("artifact_generation", "notification", "realtime", "multi_client", "reconnect", "offline_sync", "local_storage", "background_sync", "service_worker", "conflict_resolution", "file_preview", "download", "file_content", "graphql", "csrf", "session_security", "cookie_security"):
            context.tags.discard(noisy_tag)
    if has_word(context.lower_without_paths, r"\bdb\b", r"\bdatabase\b", r"\bpostgres\b", r"\bsql\b", r"\bpersist(?:ed|ence)?\b", r"\bsessions?\b", r"\bturns?\b", r"\bsession[_ -]?id\b", r"\bturns?\b", r"\bturn[_ -]?id\b", r"\bjob[_ -]?id\b", r"\bwrites?\b", r"\brecords?\b", r"\brow\b", r"\brows\b", r"\bpayments?\b", r"\boutbox\b", r"\baudit\b", r"\baudit[_ -]?events?\b", r"\bevent[_ -]?hash\b", r"\bprevious[_ -]?hash\b", r"\bretention_expires_at\b", r"\blegal_hold\b", r"\bdeleted_at\b", r"\bdeleted_by\b", r"\bscan_status\b", r"\bstorage[_ -]?key\b", r"\bfailed_attempt_count\b", r"\blockout_expires_at\b", r"\boauth_account\b", r"\bsaml_account\b", r"\bsaml_req_", r"\brelaystate\b", r"\bmfa_challenge_id\b", r"\bmfa_verified_at\b", r"\brecovery_code_hash\b", r"\bmfa_failed_count\b", r"\bwebauthn_chal_", r"\bcredential_public_key\b", r"\blast_sign_count\b", r"\bbackup_eligible\b", r"\bbackup_state\b", r"\bpassword_reset_request\b", r"\bpwreset_req_", r"\breset_token_hash\b", r"\btoken_hash\b", r"\bkey_hash\b", r"\bkey_prefix\b", r"\blast_used_at\b", r"\brevoked_at\b", r"\bapi_key\.created\b", r"\bapi_key\.revoked\b", r"\bpassword_hash\b", r"\bused_at\b", r"\bexpires_at\b", r"\bnotification_outbox\b") or has_chinese(context.lower_without_paths, "数据库", "持久", "写入", "记录") or flags["tenant_isolation_mentioned"] or flags["no_persistence_side_effect_mentioned"] or flags["selected_scope_mentioned"] or flags["soft_delete_mentioned"] or flags["undo_mentioned"] or flags["cleanup_mentioned"] or flags["file_security_mentioned"] or flags["webhook_security_mentioned"] or flags["rag_grounding_mentioned"] or flags["csrf_mentioned"] or flags["session_security_mentioned"] or flags["oauth_mentioned"] or flags["saml_mentioned"] or flags["webauthn_mentioned"] or flags["mfa_mentioned"] or flags["one_time_token_mentioned"] or flags["api_key_mentioned"] or flags["audit_integrity_mentioned"] or flags["schema_migration_mentioned"] or flags["authorization_policy_mentioned"] or flags["financial_ledger_mentioned"] or flags["quota_metering_mentioned"] or flags["transaction_integrity_mentioned"] or flags["subscription_billing_mentioned"] or flags["agent_tool_mentioned"] or flags["artifact_generation_mentioned"] or flags["offline_sync_mentioned"] or flags["cache_consistency_mentioned"] or flags["optimistic_ui_mentioned"] or flags["rate_limit_mentioned"] or flags["background_job_mentioned"] or flags["scheduled_job_mentioned"] or flags["worker_mentioned"] or flags["dead_letter_mentioned"] or flags["alert_outbox_mentioned"] or flags["feature_flag_mentioned"] or flags["flag_default_off_mentioned"] or flags["stale_flag_guard_mentioned"]:
        context.tags.add("persistence")


def _apply_domain_classification_tags(
    text: str,
    context: ClassificationContext,
) -> None:
    flags = context.flags
    permission_chinese = (
        has_chinese(context.lower_without_paths, "登录", "权限", "鉴权", "只允许", "未授权")
        or (has_chinese(context.lower_without_paths, "不能", "不得", "禁止") and has_chinese(context.lower_without_paths, "用户", "游客", "角色", "坐席", "主管", "管理员", "商家", "客服"))
    )
    permission_role_mentioned = has_word(
        context.lower_without_paths,
        r"\brbac\b",
        r"\brole[- ]based\b",
        r"\buser\s+roles?\b",
        r"\baccount\s+roles?\b",
        r"\badmin\s+role\b",
        r"\bviewer\s+role\b",
        r"\bguest\s+role\b",
        r"\broles?\s+(?:can|cannot|must|must\s+not|should|should\s+not|may|may\s+not)\b",
    )
    if (
        has_word(
            context.lower_without_paths,
            r"\blogin\b",
            r"\bauth(?:enticated|orized|orization)?\b",
            r"\btoken\b",
            r"\bpermission\b",
            r"\bunauthorized\b",
            r"\bforbidden\b",
            r"\bdenied\b",
            r"\bguest\b",
            r"\banonymous\b",
        )
        or permission_role_mentioned
        or flags["signature_mentioned"]
        or flags["webhook_security_mentioned"]
        or flags["graphql_mentioned"] and (has_graphql_field_authorization_intent(text) or has_graphql_introspection_guard_intent(text))
        or flags["rag_grounding_mentioned"] and (has_rag_prompt_injection_guard_intent(text) or has_rag_secret_leak_guard_intent(text))
        or flags["csrf_mentioned"]
        or flags["session_security_mentioned"]
        or flags["cookie_security_mentioned"]
        or flags["oauth_mentioned"]
        or flags["redirect_security_mentioned"]
        or flags["saml_mentioned"]
        or flags["webauthn_mentioned"]
        or flags["mfa_mentioned"]
        or flags["one_time_token_mentioned"]
        or flags["api_key_mentioned"]
        or flags["audit_integrity_mentioned"]
        or flags["authorization_policy_mentioned"]
        or has_subscription_authorization_denial_intent(text)
        or has_agent_tool_authorization_denial_intent(text)
        or flags["rate_limit_mentioned"]
        or flags["tenant_isolation_mentioned"]
        or flags["cross_tenant_denial_mentioned"]
        or (has_word(context.lower_without_paths, r"\bviewer\b", r"\badmin\b") and has_word(context.lower_without_paths, r"\brole\b", r"\b403\b", r"\bpermission\b", r"\bforbidden\b"))
        or flags["rollout_mentioned"]
        or flags["direct_api_denial_mentioned"]
        or flags["flag_default_off_mentioned"]
        or permission_chinese
    ):
        context.tags.add("permission")
    if flags["authorization_policy_mentioned"]:
        context.tags.add("authorization_policy")
    if flags["financial_ledger_mentioned"]:
        context.tags.add("financial_ledger")
    if flags["quota_metering_mentioned"]:
        context.tags.add("quota_metering")
    if flags["transaction_integrity_mentioned"]:
        context.tags.add("transaction_integrity")
    if flags["cache_consistency_mentioned"]:
        context.tags.add("cache_consistency")
    if flags["webhook_security_mentioned"]:
        context.tags.add("webhook_security")
    if flags["privacy_compliance_mentioned"]:
        context.tags.update({"privacy_compliance", "api", "persistence", "permission", "runtime"})
        if has_privacy_session_invalidation_intent(text):
            context.tags.add("session_security")
        if has_privacy_export_intent(text) or has_privacy_erasure_intent(text):
            context.tags.add("background_job")
        if "worker" in context.lower_without_paths or "privacy worker" in context.lower_without_paths:
            context.tags.add("worker")
    if flags["graphql_mentioned"]:
        context.tags.update({"graphql", "api", "runtime"})
        if context.ui_like_paths or has_word(context.lower_without_paths, r"\bopens?\b", r"\bvisible\b", r"\bshown\b", r"\bdisplay\b", r"\bdashboard\b"):
            context.tags.update({"ui", "interaction"})
        if has_graphql_field_authorization_intent(text) or has_graphql_introspection_guard_intent(text):
            context.tags.update({"authorization_policy", "permission"})
        if flags["tenant_isolation_mentioned"] or flags["cross_tenant_denial_mentioned"] or has_word(context.lower_without_paths, r"\btenantid\b", r"\bcross[- ]tenant\b", r"\bscoped\s+data\b"):
            context.tags.add("data_isolation")
        if has_graphql_mutation_intent(text) and has_idempotency_intent(text):
            context.tags.add("idempotency")
        if has_graphql_subscription_intent(text):
            context.tags.update({"realtime", "multi_client", "ordering", "reconnect"})
    if flags["rag_grounding_mentioned"]:
        context.tags.update({"rag_grounding", "api", "persistence", "runtime"})
        if context.ui_like_paths or has_word(context.lower_without_paths, r"\bopens?\b", r"\basks?\b", r"\banswer\b", r"\bassistant\b"):
            context.tags.update({"ui", "interaction"})
        if flags["stream_mentioned"] or has_word(context.lower_without_paths, r"\banswer_done\b", r"\banswer_delta\b", r"\bstream\b"):
            context.tags.add("stream")
        if flags["tenant_isolation_mentioned"] or flags["cross_tenant_denial_mentioned"] or has_word(context.lower_without_paths, r"\btenant[_ -]?id\b", r"\bcorpus[_ -]?id\b", r"\bcross[- ]tenant\b", r"\bforeign\s+embeddings?\b"):
            context.tags.add("data_isolation")
        if has_rag_prompt_injection_guard_intent(text) or has_rag_secret_leak_guard_intent(text):
            context.tags.add("permission")
    if flags["search_relevance_mentioned"]:
        context.tags.update({"search_relevance", "api", "runtime"})
        if context.ui_like_paths or has_word(context.lower_without_paths, r"\bopens?\b", r"\bvisible\b", r"\bresults?\b", r"\bfacet\b", r"\bsearch(?:es|ing|ed)?\b"):
            context.tags.update({"ui", "interaction"})
        if has_pagination_intent(text):
            context.tags.add("pagination")
        if flags["tenant_isolation_mentioned"] or flags["cross_tenant_denial_mentioned"] or has_word(context.lower_without_paths, r"\btenant\b", r"\bhidden\s+products?\b", r"\banother\s+tenant\b", r"\bsku-beta-secret\b"):
            context.tags.add("data_isolation")
        if not has_word(context.lower_without_paths, r"\bwebsocket\b", r"\bsse\b", r"\bstream(?:ing)?\b", r"\blive\s+event\b", r"\bbroadcast\b", r"\bmulti[- ]client\b", r"\breconnect\b"):
            context.tags.discard("stream")
            context.tags.discard("realtime")
            context.tags.discard("multi_client")
            context.tags.discard("reconnect")
        if not has_word(context.lower_without_paths, r"\bsequence[_ -]?order\b", r"\bordered\s+event\b", r"\bevent\s+sequence\b", r"\bmonotonic\s+event\b"):
            context.tags.discard("ordering")
        if not has_word(context.lower_without_paths, r"\bconcurr(?:ent|ency)\b", r"\bparallel\b", r"\bsimultaneous(?:ly)?\b", r"\brace\s+condition\b", r"\batomic\b", r"\block(?:ing)?\b"):
            context.tags.discard("concurrency")
        if not has_word(context.lower_without_paths, r"\bpersist(?:ed|ence)?\b", r"\bdatabase\b", r"\bdb\b", r"\bpostgres\b", r"\baudit\s+log\b", r"\baudit_log\b"):
            context.tags.discard("persistence")
        if not has_word(context.lower_without_paths, r"\bpermission\b", r"\bauth\b", r"\brole\b", r"\bunauthorized\b", r"\b403\b", r"\bpolicy_denied\b", r"\baccess\s+denied\b"):
            context.tags.discard("permission")
    if has_stale_revalidation_intent(text) or has_cache_invalidation_event_intent(text):
        context.tags.add("background_job")
    if has_outbox_dispatch_intent(text) or has_saga_compensation_intent(text):
        context.tags.add("background_job")
        context.tags.add("worker")
    if flags["transaction_integrity_mentioned"] and has_word(context.lower_without_paths, r"\bdispatcher\s+retry\b", r"\bretry\b", r"\bretries\b"):
        context.tags.add("retry")
    if flags["oauth_mentioned"]:
        context.tags.add("oauth")
    if flags["redirect_security_mentioned"]:
        context.tags.add("redirect_security")
    if flags["saml_mentioned"]:
        context.tags.add("saml")
        context.tags.add("redirect_security")
    if flags["webauthn_mentioned"]:
        context.tags.add("webauthn")
    if flags["mfa_mentioned"]:
        context.tags.add("mfa")
    if flags["one_time_token_mentioned"]:
        context.tags.add("one_time_token")
    if flags["one_time_token_mentioned"] and has_one_time_token_email_link_intent(text):
        context.tags.add("notification")
    if flags["api_key_mentioned"]:
        context.tags.add("api_key")
    if flags["audit_integrity_mentioned"]:
        context.tags.add("audit_integrity")
    if flags["schema_migration_mentioned"]:
        context.tags.add("schema_migration")
    if flags["optimistic_ui_mentioned"]:
        context.tags.add("optimistic_ui")
    if flags["tenant_isolation_mentioned"] or flags["cross_tenant_denial_mentioned"]:
        context.tags.add("data_isolation")
    if flags["time_boundary_mentioned"] and not flags["audit_integrity_mentioned"]:
        context.tags.add("time_boundary")
    if flags["money_precision_mentioned"]:
        context.tags.add("calculation")
    if flags["accessibility_mentioned"]:
        context.tags.add("accessibility")
    if flags["concurrency_mentioned"]:
        context.tags.add("concurrency")
    if flags["notification_mentioned"]:
        context.tags.add("notification")
    if flags["idempotency_mentioned"]:
        context.tags.add("idempotency")
    if flags["csrf_mentioned"]:
        context.tags.add("csrf")
    if flags["session_security_mentioned"]:
        context.tags.add("session_security")
    if flags["cookie_security_mentioned"]:
        context.tags.add("cookie_security")
    if flags["rate_limit_mentioned"]:
        context.tags.add("rate_limit")
    if flags["file_security_mentioned"]:
        context.tags.add("file_security")
    if flags["file_preview_mentioned"]:
        context.tags.add("file_preview")
    if flags["bulk_action_mentioned"]:
        context.tags.add("bulk_action")
    if flags["destructive_guard_mentioned"]:
        context.tags.add("destructive_guard")
    if flags["undo_mentioned"]:
        context.tags.add("undo")
    if flags["cleanup_mentioned"]:
        context.tags.update({"cleanup", "persistence", "runtime"})
    if flags["decision_table_logic_mentioned"]:
        context.tags.update({"logic", "command", "runtime"})
    if flags["background_job_mentioned"]:
        context.tags.add("background_job")
    if flags["scheduled_job_mentioned"]:
        context.tags.update({"scheduled_job", "background_job", "worker", "command", "persistence", "runtime"})
        if not context.api_like_paths and not has_word(context.lower_without_paths, r"\bapi\s+path\b", r"\bendpoint\b", r"\bhttp\b"):
            context.tags.discard("api")
        if has_schedule_expression_intent(text) or has_due_window_intent(text) or has_timezone_intent(text) or has_dst_boundary_intent(text):
            context.tags.add("time_boundary")
        if has_scheduler_lock_intent(text):
            context.tags.add("concurrency")
        if has_run_key_intent(text) or has_catch_up_intent(text) or has_word(context.lower_without_paths, r"\bduplicate[_ -]?skipped\b", r"\bone\s+invoice\s+per\b"):
            context.tags.add("idempotency")
        if has_notification_intent(text) or has_no_real_email_intent(text):
            context.tags.add("notification")
    if flags["worker_mentioned"]:
        context.tags.add("worker")
    if flags["retry_backoff_mentioned"]:
        context.tags.add("retry")
    if flags["feature_flag_mentioned"]:
        context.tags.add("feature_flag")
    if flags["rollout_mentioned"]:
        context.tags.add("rollout")
    if context.ui_like_paths or flags["list_interaction_mentioned"] or flags["empty_state_mentioned"] or flags["error_state_mentioned"] or flags["upload_mentioned"] or flags["file_validation_mentioned"] or flags["file_preview_mentioned"] or flags["progress_mentioned"] or flags["download_mentioned"] or flags["bulk_action_mentioned"] or flags["destructive_guard_mentioned"] or flags["undo_mentioned"] or flags["time_boundary_mentioned"] or flags["money_precision_mentioned"] or flags["accessibility_mentioned"] or flags["saml_mentioned"] or flags["webauthn_mentioned"] or flags["mfa_mentioned"] or flags["api_key_mentioned"] or flags["graphql_mentioned"] or flags["rag_grounding_mentioned"] or flags["optimistic_ui_mentioned"] or flags["schema_migration_mentioned"] or flags["authorization_policy_mentioned"] or flags["financial_ledger_mentioned"] or flags["quota_metering_mentioned"] or flags["transaction_integrity_mentioned"] or flags["cache_consistency_mentioned"] or has_word(context.lower_without_paths, r"\bclick(?:s|able|ed|ing)?\b", r"\bbutton\b", r"\bsav(?:e|es|ed|ing)\b", r"\bvisible\b", r"\bmodal\b", r"\boverlay\b", r"\btoast\b", r"\bpage\b", r"\bscreen\b", r"\bview\b", r"\bshows?\b", r"\bdisplay\b", r"\brender\b", r"\bform\b", r"\binput\b", r"\bdisabled\b", r"\bloading\b", r"\bui\b", r"\bhides?\b", r"\bhidden\b") or has_chinese(context.lower_without_paths, "页面", "按钮", "点击", "显示", "弹窗", "交互"):
        context.tags.add("ui")


def _apply_specialized_classification_tags(
    text: str,
    context: ClassificationContext,
) -> None:
    flags = context.flags
    if has_word(context.lower_without_paths, r"\bconsole\b", r"\bnetwork\b", r"\berror\b", r"\bruntime\b", r"\b500\b", r"\b401\b", r"\b403\b", r"\b404\b", r"\b429\b", r"\btraceback\b") or has_chinese(context.lower_without_paths, "报错", "错误") or flags["negative_request_mentioned"] or flags["signature_mentioned"] or flags["webhook_security_mentioned"] or flags["graphql_mentioned"] or flags["rag_grounding_mentioned"] or flags["csrf_mentioned"] or flags["session_security_mentioned"] or flags["cookie_security_mentioned"] or flags["oauth_mentioned"] or flags["redirect_security_mentioned"] or flags["saml_mentioned"] or flags["webauthn_mentioned"] or flags["mfa_mentioned"] or flags["one_time_token_mentioned"] or flags["api_key_mentioned"] or flags["audit_integrity_mentioned"] or flags["schema_migration_mentioned"] or flags["authorization_policy_mentioned"] or flags["financial_ledger_mentioned"] or flags["quota_metering_mentioned"] or flags["transaction_integrity_mentioned"] or flags["agent_tool_mentioned"] or flags["cache_consistency_mentioned"] or flags["optimistic_ui_mentioned"] or flags["rate_limit_mentioned"] or flags["file_security_mentioned"] or flags["destructive_guard_mentioned"] or flags["no_persistence_side_effect_mentioned"] or flags["notification_mentioned"] or flags["audit_log_mentioned"] or flags["no_write_mentioned"] or flags["cross_tenant_denial_mentioned"] or flags["concurrency_mentioned"] or flags["realtime_mentioned"] or flags["multi_client_mentioned"] or flags["ordering_mentioned"] or flags["reconnect_mentioned"] or flags["background_job_mentioned"] or flags["scheduled_job_mentioned"] or flags["worker_mentioned"] or flags["retry_backoff_mentioned"] or flags["dead_letter_mentioned"] or flags["alert_outbox_mentioned"] or flags["feature_flag_mentioned"] or flags["rollout_mentioned"] or flags["flag_default_off_mentioned"] or flags["direct_api_denial_mentioned"] or flags["stale_flag_guard_mentioned"] or has_dst_boundary_intent(text) or has_float_drift_guard_intent(text):
        context.tags.add("runtime")
    if flags["decision_table_logic_mentioned"]:
        context.tags.update({"logic", "command", "runtime"})
        if not context.api_like_paths and not has_word(context.lower_without_paths, r"\b(?:get|post|put|patch|delete)\s+/api\b", r"\bapi\s+(?:path|endpoint|request|response)\b", r"\bendpoint\b", r"\bhttp\b"):
            context.tags.discard("api")
        if not context.ui_like_paths:
            context.tags.discard("ui")
        if not has_word(context.lower_without_paths, r"\bauthorization\s+policy\b", r"\bpolicy/evaluate\b", r"\brbac\b", r"\babac\b", r"\bdirect\s+api\s+denial\b"):
            context.tags.discard("authorization_policy")
            context.tags.discard("permission")
        if not has_word(context.lower_without_paths, r"\bdb\b", r"\bdatabase\b", r"\bpostgres\b", r"\bpersist(?:ed|ence)?\b", r"\baudit\b", r"\blog\s+(?:row|event|record|trail)\b"):
            context.tags.discard("persistence")
    if flags["artifact_generation_mentioned"]:
        if not has_word(context.lower_without_paths, r"\bfile\s+preview\b", r"\bpreview\s+rendering\b", r"\bsigned\s+preview\s+token\b", r"\bnosniff\b"):
            context.tags.discard("file_preview")
        context.tags.discard("realtime")
        context.tags.discard("multi_client")
        context.tags.discard("reconnect")
        context.tags.discard("graphql")
        context.tags.discard("notification")
    if flags["offline_sync_mentioned"]:
        context.tags.update({"offline_sync", "api", "persistence", "runtime"})
        if flags["offline_local_storage_mentioned"]:
            context.tags.add("local_storage")
        if flags["background_sync_mentioned"]:
            context.tags.add("background_sync")
        if flags["service_worker_mentioned"]:
            context.tags.add("service_worker")
        if flags["offline_conflict_resolution_mentioned"]:
            context.tags.add("conflict_resolution")
        if flags["retry_backoff_mentioned"]:
            context.tags.add("retry")
        if flags["idempotency_mentioned"]:
            context.tags.add("idempotency")
        if has_word(context.lower_without_paths, r"\b403\b", r"\bforbidden\b", r"\bsync[_ -]?forbidden\b", r"\bviewer\b", r"\boutside\s+territory\b"):
            context.tags.add("permission")
        for noisy_tag in ("artifact_generation", "notification", "realtime", "multi_client", "reconnect", "graphql", "file_preview", "download", "file_content", "scheduled_job", "background_job", "worker", "transaction_integrity"):
            context.tags.discard(noisy_tag)
        if not has_word(context.lower_without_paths, r"\bconcurr(?:ent|ency)\b", r"\bparallel\b", r"\bsimultaneous(?:ly)?\b", r"\brace\s+condition\b"):
            context.tags.discard("concurrency")
    if flags["analytics_mentioned"]:
        context.tags.update({"analytics", "api", "persistence", "runtime"})
        if context.ui_like_paths or has_word(context.lower_without_paths, r"\bopens?\b", r"\bcheckout\b", r"\bcomplete(?:s|d)?\b", r"\baccepts?\b", r"\bconsent\b", r"\bui\b", r"\bbutton\b", r"\bpage\b", r"\bbrowser\b"):
            context.tags.update({"ui", "interaction"})
        if has_word(context.lower_without_paths, r"\bpii\b", r"\braw\s+email\b", r"\bphone\b", r"\bshipping[_ -]?address\b", r"\bcard[_ -]?last4\b", r"\baccess[_ -]?token\b", r"\bcookie\b", r"\bleak\b", r"\bredact(?:ed|ion)?\b", r"\bpseudonym"):
            context.tags.add("privacy_compliance")
        if flags["idempotency_mentioned"] or has_word(context.lower_without_paths, r"\bdedupe[_ -]?key\b", r"\bduplicate[_ -]?ignored\b", r"\breplay(?:ing|ed)?\b"):
            context.tags.add("idempotency")
        if flags["retry_backoff_mentioned"] or has_word(context.lower_without_paths, r"\bretry[_ -]?count\b", r"\bbackoff[_ -]?schedule\b", r"\bnext[_ -]?retry[_ -]?at\b", r"\b503\b", r"\bqueue[_ -]?status\b"):
            context.tags.add("retry")
        if not has_word(context.lower_without_paths, r"\bfeature\s+flag\b", r"\bflag[_ -]?evaluation\b", r"\brollout\b", r"\bcohort\b", r"\bbeta\b", r"\bdefault[_ -]?off\b"):
            context.tags.discard("feature_flag")
            context.tags.discard("rollout")
        if not has_word(context.lower_without_paths, r"\bwebsocket\b", r"\bsse\b", r"\bstream(?:ing)?\b"):
            context.tags.discard("stream")
        if not has_word(context.lower_without_paths, r"\bbackground\s+job\b", r"\bworker\b", r"\bjob[_ -]?id\b", r"\bdead[_ -]?letter\b"):
            context.tags.discard("background_job")
            context.tags.discard("worker")
        if not has_word(context.lower_without_paths, r"\btransaction\s+integrity\b", r"\batomic[_ -]?commit\b", r"\bsaga\b", r"\bcompensation[_ -]?event\b", r"\binventory[_ -]?reservation\b", r"\bpayment[_ -]?authorization\b"):
            context.tags.discard("transaction_integrity")
        if not has_word(context.lower_without_paths, r"\baudit\s+integrity\b", r"\bappend[- ]?only\b", r"\bhash\s+chain\b", r"\bprevious[_ -]?hash\b", r"\bevent[_ -]?hash\b", r"\bcanonical\s+json\b", r"\btamper\b"):
            context.tags.discard("audit_integrity")
        if not has_word(context.lower_without_paths, r"\bpermission\b", r"\bauth(?:orized|orization|enticated|entication)?\b", r"\brole\b", r"\b403\b", r"\baccess\s+denied\b", r"\bpolicy[_ -]?denied\b"):
            context.tags.discard("permission")
        for noisy_tag in ("artifact_generation", "notification", "realtime", "multi_client", "reconnect", "offline_sync", "local_storage", "background_sync", "service_worker", "conflict_resolution", "file_preview", "download", "file_content", "graphql", "csrf", "session_security", "cookie_security"):
            context.tags.discard(noisy_tag)
    if has_validation_error_ux_intent(text):
        context.tags.update({"ui", "interaction", "api", "runtime"})
        explicit_backend_state = (
            has_word(
                context.lower_without_paths,
                r"\bdatabase\b",
                r"\bpostgres\b",
                r"\bsql\b",
                r"\bpersist(?:ed|ence|ing)?\b",
                r"\b(?:row|record|audit\s+event)\s+(?:is\s+)?(?:written|created|updated)\b",
            )
            or has_chinese(context.lower_without_paths, "数据库", "持久化", "数据行", "审计记录")
        )
        if not explicit_backend_state:
            context.tags.discard("persistence")
    if has_business_revocation_intent(text):
        context.tags.update({"logic", "api", "persistence", "runtime"})
        if has_concurrency_intent(text):
            context.tags.add("concurrency")
    if has_browser_scroll_state_intent(text):
        context.tags.update({"ui", "interaction", "runtime"})
    if has_frontend_local_state_only_intent(text):
        context.tags.update({"ui", "interaction"})
        for backend_tag in ("api", "persistence", "permission", "session_security", "cookie_security", "cache_consistency"):
            context.tags.discard(backend_tag)
    if has_static_reference_only_intent(text):
        context.tags.intersection_update({"ui", "interaction", "responsive", "accessibility", "localization", "logic", "runtime"})
        context.tags.add("ui")


_CLASSIFICATION_TAG_FAMILIES: tuple[
    Callable[[str, ClassificationContext], None], ...
] = (
    _apply_core_classification_tags,
    _apply_domain_classification_tags,
    _apply_specialized_classification_tags,
)


def classify(text: str, paths: list[str]) -> set[str]:
    """采集并消歧需求信号，再按稳定规则族投影标签。"""
    context = _collect_classification_context(text, paths)
    _disambiguate_classification_context(text, context)
    for apply_tags in _CLASSIFICATION_TAG_FAMILIES:
        apply_tags(text, context)
    if not context.tags:
        context.tags.add("logic")
    return context.tags

def status_for_tests(tests: list[dict[str, Any]]) -> str:
    return "Untested" if any(test.get("status") == "Untested" for test in tests) else "Blocked"

def singularize_token(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_-]+", " ", value).strip().lower()
    if text.endswith("ies") and len(text) > 4:
        return text[:-3] + "y"
    if text.endswith("ses") and len(text) > 4:
        return text[:-2]
    if text.endswith("s") and len(text) > 3:
        return text[:-1]
    return text

def stable_id(prefix: str, index: int) -> str:
    return f"{prefix}{index}"

def add_indexed_item(indexed: dict[str, dict[str, Any]], key: str, source_req_id: str, evidence: str, **fields: Any) -> None:
    if not key:
        return
    item = indexed.setdefault(key, {"name": key, "source_requirement_ids": [], "evidence": []})
    if source_req_id not in item["source_requirement_ids"]:
        item["source_requirement_ids"].append(source_req_id)
    if evidence and evidence not in item["evidence"]:
        item["evidence"].append(evidence)
    item.update({name: value for name, value in fields.items() if value not in (None, "", [])})

def extract_actors_from_text(text: str) -> list[str]:
    actors: list[str] = []
    single_role_pattern = (
        r"\b(admin|admins|analyst|analysts|viewer|viewers|editor|editors|user|users|customer|customers|"
        r"partner|partners|operator|operators|manager|managers|auditor|auditors|reviewer|reviewers|"
        r"approver|approvers|merchant|merchants|guest|guests|member|members|owner|owners|engineer|engineers|"
        r"developer|developers)\s+"
        r"(?:can|should|must|cannot|opens?|clicks?|runs?|calls?|sees?|sends?|selects?|enters?|types?|"
        r"filters?|downloads?|uploads?|creates?|updates?|deletes?)\b"
    )
    for match in re.finditer(single_role_pattern, text, re.IGNORECASE):
        actor = re.sub(r"\s+", " ", match.group(1)).strip().lower()
        if actor and actor not in actors:
            actors.append(actor)
    patterns = [
        r"\b(?:an?\s+)?(authenticated\s+[A-Za-z][A-Za-z0-9 _-]{1,50}?)(?:\s+can|\s+should|\s+must|\s+opens?|\s+clicks?|\s+sends?)\b",
        r"\b(?:an?\s+)?([A-Za-z][A-Za-z0-9 _-]{1,40}?\s+(?:operator|admin|manager|analyst|reviewer|approver|user|guest|merchant|customer|member|engineer|provider|integration|client|service|system))(?:\s+can|\s+should|\s+must|\s+cannot|\s+must not|\s+opens?|\s+clicks?|\s+runs?|\s+sends?|\s+calls?)\b",
        r"\b([A-Za-z][A-Za-z0-9 _-]{1,40}?\s+(?:operator|admin|manager|analyst|reviewer|approver|user|guest|merchant|customer|member|engineer|provider|integration|client|service|system))\s*(?:运行|执行|打开|点击|发送|调用)\b",
        r"\b(guest users?|anonymous users?|authenticated users?)\b",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            actor = re.sub(r"\s+", " ", match.group(1)).strip().lower()
            actor = re.sub(r"^(?:an?|the)\s+", "", actor)
            if actor and actor not in actors:
                actors.append(actor)
    for match in re.finditer(r"\b((?:org|organization|tenant|workspace)\s+admin)\s+([A-Z][A-Za-z0-9_-]+)\b", text, re.IGNORECASE):
        for raw_actor in (match.group(1), match.group(2)):
            actor = re.sub(r"\s+", " ", raw_actor).strip().lower()
            if actor and actor not in actors:
                actors.append(actor)
    for match in re.finditer(r"\b(?:editor|viewer|user|admin|member|owner)\s+([A-Z][A-Za-z0-9_-]+)\b", text):
        actor = match.group(1).strip().lower()
        if actor and actor not in actors:
            actors.append(actor)
    chinese_role_markers = ("用户", "游客", "管理员", "运营", "商家", "客服", "坐席", "主管", "审核员", "角色", "成员", "访客")
    chinese_actor_patterns = [
        r"(?:已登录)?([^，。；,.!?！？、/\s]{2,16})(?=\s*在\s*/)",
        r"(?:已登录)?([^，。；,.!?！？、/\s]{2,16})(?=\s*(?:可|可以|点击|发送|打开|必须|不能|不得|禁止))",
    ]
    for pattern in chinese_actor_patterns:
        for match in re.finditer(pattern, text):
            actor = re.sub(r"^(?:已登录|登录后)", "", match.group(1)).strip()
            if actor and any(marker in actor for marker in chinese_role_markers) and actor not in actors:
                actors.append(actor)
    lower_text = text.lower()
    if has_offline_sync_intent(text):
        for term in ("field rep", "service worker", "background sync worker", "worker", "viewer", "another device"):
            if term in lower_text and term not in actors:
                actors.append(term)
    if has_analytics_intent(text):
        for term in ("analytics pipeline", "experiment service", "attribution service"):
            if term not in actors:
                actors.append(term)
    for match in re.finditer(r"\b([A-Za-z0-9_-]+-worker)\b", text, re.IGNORECASE):
        actor = match.group(1).lower()
        if actor and actor not in actors:
            actors.append(actor)
    if re.search(r"\bworker\b", lower_text) and "worker" not in actors:
        actors.append("worker")
    for term in ("payment provider", "outbox dispatcher", "saga compensation worker", "compensation worker"):
        if term in lower_text and term not in actors:
            actors.append(term)
    if has_webhook_security_intent(text):
        for term in ("GitHub", "github", "webhook verifier", "verifier"):
            if (term.lower() in lower_text or term in {"GitHub", "webhook verifier"}) and term not in actors:
                actors.append(term)
    for term in ("privacy officer", "data subject", "privacy worker"):
        if term in lower_text and term not in actors:
            actors.append(term)
    if has_authorization_policy_intent(text):
        for term in ("contractor", "support_agent", "org_admin", "report_admin"):
            if re.search(rf"\b{re.escape(term)}\b", lower_text) and term not in actors:
                actors.append(term)
    if has_graphql_intent(text):
        for term in ("support lead", "GraphQL BFF", "BFF", "resolver", "GraphQL resolver", "second subscribed client", "public client"):
            if term.lower() in lower_text and term not in actors:
                actors.append(term)
    if has_rag_grounding_intent(text):
        for term in ("support analyst", "knowledge assistant", "assistant", "retrieval pipeline", "retrieval worker"):
            if term in lower_text and term not in actors:
                actors.append(term)
    if has_search_relevance_intent(text):
        for term in ("search service", "ranking service", "ranker"):
            if (term in lower_text or (term in {"ranking service", "ranker"} and has_search_ranking_intent(text))) and term not in actors:
                actors.append(term)
    if has_notification_policy_intent(text):
        for term in ("notification worker", "worker", "campaign sender", "campaign"):
            if (term in lower_text or term in {"notification worker", "campaign sender"}) and term not in actors:
                actors.append(term)
    if has_subscription_billing_intent(text):
        for term in ("billing admin", "support agent", "billing service", "payment scheduler", "scheduler"):
            if (term in lower_text or term in {"billing service", "payment scheduler"}) and term not in actors:
                actors.append(term)
    if has_agent_tool_intent(text):
        for term in ("ops user", "approver", "viewer", "agent runtime", "tool executor"):
            if (term in lower_text or term in {"agent runtime", "tool executor"}) and term not in actors:
                actors.append(term)
        if has_agent_tool_handoff_intent(text):
            for term in ("human reviewer", "handoff queue"):
                if term not in actors:
                    actors.append(term)
    if has_artifact_generation_intent(text):
        for term in ("analyst", "report worker", "worker", "ops", "viewer"):
            if (term in lower_text or term in {"report worker", "worker"}) and term not in actors:
                actors.append(term)
    if has_scheduled_job_intent(text):
        for term in ("billing scheduler", "scheduler", "scheduler worker", "scheduler workers"):
            if (term in lower_text or term in {"scheduler", "scheduler worker"}) and term not in actors:
                actors.append(term)
    if has_decision_table_logic_intent(text):
        for term in ("approval engine", "rules engine", "requester", "manager"):
            if (term in lower_text or term in {"approval engine", "rules engine"}) and term not in actors:
                actors.append(term)
    if has_saga_compensation_intent(text) and "saga compensation worker" not in actors:
        actors.append("saga compensation worker")
    for term in ("cdn edge cache", "edge cache", "cdn", "origin service", "origin"):
        if term in lower_text and term not in actors:
            actors.append(term)
    for term in ("客服主管", "普通坐席", "商家运营", "管理员", "运营", "商家", "游客", "用户", "审核员", "坐席"):
        if term in text and term not in actors:
            actors.append(term)
    for term in ("shopper", "customer", "admin", "viewer", "project member", "member", "old client", "new client"):
        if re.search(rf"\b{term}\b", lower_text) and term not in actors:
            actors.append(term)
    for term in ("old session", "old cookie"):
        if term in lower_text and term not in actors:
            actors.append(term)
    if has_oauth_intent(text):
        for term in ("identity provider", "idp"):
            if (term in lower_text or term == "identity provider") and term not in actors:
                actors.append(term)
    if has_saml_intent(text):
        for term in ("SAML IdP", "idp"):
            if (term.lower() in lower_text or term == "SAML IdP") and term not in actors:
                actors.append(term)
    if has_webauthn_intent(text):
        for term in ("authenticator", "passkey"):
            if (term in lower_text or term == "authenticator") and term not in actors:
                actors.append(term)
    for match in re.finditer(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", text):
        actor = match.group(1).lower()
        if actor and (has_mfa_intent(text) or has_one_time_token_intent(text)) and actor not in actors:
            actors.append(actor)
    if not actors and re.search(r"\buser\b", text, re.IGNORECASE):
        actors.append("user")
    return actors

def extract_entities_from_text(text: str, paths: list[str]) -> list[str]:
    ignored = {
        "api", "v1", "v2", "id", "ws", "sse", "stream", "events",
        "approve", "create", "update", "delete", "submit", "save",
        "send", "search", "login", "logout", "refresh",
        "a", "an", "and", "or", "the", "from", "to", "with", "for",
        "pending", "approved", "completed", "ready", "succeeded",
        "status", "state",
    }
    entities: list[str] = []
    for path in paths:
        for segment in re.split(r"[/{}?&#=.,-]+", path):
            token = singularize_token(segment)
            if token and token not in ignored and not token.isdigit() and token not in entities:
                entities.append(token)
    noun_patterns = [
        r"\b([A-Za-z][A-Za-z0-9_-]+)\s+(?:detail|details|status|record|records|data|state|workflow|audit log|database)\b",
        r"\b(?:persist|stores?|records?)\s+(?:the\s+)?([A-Za-z][A-Za-z0-9_-]+)",
    ]
    for pattern in noun_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            token = singularize_token(match.group(1))
            if token and token not in ignored and token not in entities:
                entities.append(token)
    lower_text = text.lower()
    persistence_identifier_context = has_word(
        lower_text,
        r"\bpersist(?:s|ed|ence)?\b",
        r"\bstores?\b",
        r"\bwrites?\b",
        r"\brecords?\b",
        r"\bdatabase\b",
        r"\bdb\b",
        r"\brow\b",
        r"\brows\b",
        r"\baudit\b",
        r"\blog\b",
    )
    for match in re.finditer(r"\b([A-Za-z][A-Za-z0-9]+(?:_[A-Za-z0-9]+)+)\b", text):
        token = match.group(1)
        if (
            token.endswith("_id")
            or token.endswith("_count")
            or token.endswith("_imports")
            or token.endswith("_import")
            or persistence_identifier_context
            or has_word(text.lower(), r"\bresponse\b", r"\bjson\b", r"\breturn(?:s|ed)?\b", r"\bmust\s+not\s+include\b")
        ) and token not in ignored and token not in entities:
            entities.append(token)
    if has_scheduled_job_intent(text):
        scheduled_terms = [
            "scheduler_run",
            "scheduler_runs",
            "schedule_id",
            "monthly_invoices",
            "run_key",
            "billrun_2026_06_30",
            "job_id",
            "sched_inv_123",
            "next_run_at",
            "due_count",
            "generated_invoice_ids",
            "invoice",
            "invoice_month",
            "account",
            "notification_outbox",
            "email_outbox",
            "audit log",
            "qa_marker",
            "QA_SCHEDULE_123",
            "scheduler_lock",
            "advisory lock",
        ]
        lower_text = text.lower()
        for term in scheduled_terms:
            if (term.lower() in lower_text or (term == "scheduler_run" and "scheduler_runs" in lower_text)) and term not in entities:
                entities.append(term)
    if has_decision_table_logic_intent(text):
        decision_terms = [
            "approval_decision_table.json",
            "decision table",
            "approval_request",
            "policy_version",
            "approval_v7",
            "rule_hits",
            "expected_decisions",
            "approver_group",
        ]
        lower_text = text.lower()
        for term in decision_terms:
            if (term.lower() in lower_text or term in {"decision table", "approval_request"}) and term not in entities:
                entities.append(term)
    if has_accessibility_intent(text):
        accessibility_terms = [
            ("modal", ("modal", "弹窗")),
            ("dialog", ("dialog", "role=dialog")),
            ("Name input", ("name input", "labeled name input")),
            ("Save button", ("save button", "save/cancel", "save")),
            ("Cancel button", ("cancel button", "save/cancel", "cancel")),
            ("Edit profile", ("edit profile",)),
        ]
        lower = text.lower()
        for label, needles in accessibility_terms:
            if any(needle.lower() in lower for needle in needles) and label not in entities:
                entities.append(label)
    if has_localization_intent(text):
        localization_terms = [
            "locale",
            "ar-EG",
            "en-US",
            "translation catalog",
            "translation_catalog_version",
            "i18n_2026_06",
            "fallback_count",
            "missing_keys",
            "plural_rules",
            "item_count",
            "amount_cents",
            "123456",
            "currency",
            "EGP",
            "delivery date",
            "Africa/Cairo",
        ]
        lower = text.lower()
        for term in localization_terms:
            if (term.lower() in lower or term in {"locale", "translation catalog"}) and term not in entities:
                entities.append(term)
    if has_privacy_compliance_intent(text):
        privacy_terms = [
            "privacy request",
            "subject_user_id",
            "user_priv_123",
            "export_job_id",
            "dsar_export_123",
            "erasure_job",
            "actor_ref",
            "pseudonym_user_priv_123",
            "search_index",
            "cache",
            "active sessions",
            "API keys",
            "legal_hold",
            "user_hold_456",
            "privacy.erasure_completed",
            "data_hash",
            "hash_dsar_123",
            "notification_outbox",
        ]
        for term in privacy_terms:
            if (term.lower() in text.lower() or (term == "privacy request" and re.search(r"/privacy/requests?\b|\bprivacy\s+requests?\b", text, re.IGNORECASE))) and term not in entities:
                entities.append(term)
    if re.search(r"/privacy/requests?\b|\bprivacy\s+requests?\b", text, re.IGNORECASE) and "privacy request" not in entities:
        entities.append("privacy request")
    if has_graphql_intent(text):
        graphql_terms = [
            "OrderDashboardQuery",
            "persistedQueryHash",
            "gql_hash_dash_123",
            "tenantId",
            "acme",
            "beta",
            "order_qa_123",
            "order_beta_001",
            "Beta LLC",
            "delayedCount",
            "customer.ssn",
            "internalNotes",
            "resolver_trace",
            "resolver_count",
            "DataLoader",
            "assignOrder",
            "assigneeId",
            "agent_qa_1",
            "idempotency_key",
            "assign_qa_123",
            "order_version",
            "v3",
            "Apollo cache",
            "assignment row",
            "audit log",
            "order.assigned",
            "sequence",
            "42",
            "cursor",
            "cur_42",
            "lastEventId",
            "cur_41",
            "__schema",
            "__type",
        ]
        for term in graphql_terms:
            if term.lower() in text.lower() and term not in entities:
                entities.append(term)
    if has_rag_grounding_intent(text):
        rag_terms = [
            "answer_id",
            "rag_ans_123",
            "qa_marker",
            "QA_RAG_123",
            "tenant_id",
            "acme",
            "beta",
            "corpus_id",
            "support_kb",
            "beta_kb",
            "vector_index",
            "support_kb_v12",
            "embedding_model",
            "text-embedding-3-large",
            "top_k",
            "score_threshold",
            "retrieval_trace",
            "rag_trace_123",
            "query_hash",
            "qhash_rag_123",
            "source_ids",
            "doc_policy_2026",
            "doc_sla_2026",
            "citation_spans",
            "quote_start",
            "quote_end",
            "document_version",
            "v4",
            "v3",
            "doc_malicious_001",
            "safety_trace",
            "prompt_injection_detected",
            "system_prompt",
            "tool_credentials",
            "doc_beta_secret",
            "Beta LLC",
            "beta@example.com",
            "answer citation rows",
            "audit log",
            "rag.answer_abstained",
        ]
        for term in rag_terms:
            if term.lower() in text.lower() and term not in entities:
                entities.append(term)
    for term in ("订单", "工单", "会话", "消息", "智能体", "审计日志", "数据库", "audit log", "audit event", "event_id", "evt_qa_123", "actor_id", "action", "order.approved", "resource_id", "req_audit_123", "previous_hash", "hash_prev_123", "event_hash", "hash_evt_123", "hash_algorithm", "sha256", "sequence", "audit_integrity_violation", "req_tamper_123", "actor_ref", "pseudonym_user_qa_1", "retention_expires_at", "legal_hold", "raw IP", "escalation audit log", "tenant", "org", "organization", "workspace", "access grant", "Beta LLC", "subscription", "created_at", "timezone", "America/Los_Angeles", "DST", "invoice", "line item", "currency", "rate_id", "invoice_totals", "calculation_version", "webhook", "payment", "payout", "job_id", "payout_qa_123", "bank transfer", "schema_version", "migration_audit", "20260618_add_org_membership", "users.organization_id", "organizations", "org_default", "idx_users_organization_id", "fk_users_organization_id", "notification_outbox", "alert_outbox", "outbox", "receipt email", "receipt_email_preview", "event_id", "correlation_id", "request_id", "req_migration_123", "req_comment_fail", "csrf_token", "csrf_qa_123", "session_id", "sess_new_123", "sess_old_001", "Set-Cookie", "refresh token", "refresh_token", "failed_attempt_count", "lockout_expires_at", "Retry-After", "client_ip", "qa@example.test", "mfa@example.test", "mfa_challenge_id", "chal_qa_123", "mfa_pending", "TOTP", "totp_code", "clock_skew_seconds", "sess_mfa_123", "recovery code", "REC-QA-1", "recovery_code_hash", "mfa_failed_count", "req_mfa_123", "transfer_id", "transfer_qa_123", "totp_secret", "password_reset_request", "pwreset_req_123", "reset_token", "reset_token_qa_123", "reset_token_hash", "purpose", "password_reset", "expires_at", "used_at", "message_id", "msg_reset_123", "reset email", "password_hash", "new_password", "qa-reset@example.test", "req_pwreset_123", "API key", "api key", "personal access token", "PAT", "key_id", "key_qa_123", "key_prefix", "qa_live_123", "api_key_secret_once", "key_hash", "scopes", "read:orders", "write:orders", "created_by", "last_used_at", "revoked_at", "qa-ci-key", "req_key_123", "order_qa_123", "bearer", "Authorization", "insufficient_scope", "SAML", "saml", "AuthnRequest", "saml_req_123", "SAMLRequest", "RelayState", "relay_qa_123", "AssertionConsumerServiceURL", "ACS", "SP entityID", "sp_entity_qa", "SAMLResponse", "response_qa_123", "x509 certificate", "cert_qa_123", "issuer", "AudienceRestriction", "Destination", "Recipient", "InResponseTo", "NotBefore", "NotOnOrAfter", "NameID", "saml_user@example.test", "group attribute", "Admins", "saml_account", "sess_saml_123", "req_saml_123", "private_key", "WebAuthn", "webauthn", "passkey", "webauthn_chal_123", "rpId", "rpIdHash", "app.example.test", "credentialId", "cred_qa_123", "clientDataJSON", "authenticatorData", "signature", "sig_qa_123", "signCount", "last_sign_count", "sess_passkey_123", "attestationObject", "credential_public_key", "backup_eligible", "backup_state", "req_webauthn_123", "credential_private_key", "raw authenticator secret", "profile_settings", "display_name", "QA Secure Name", "operation_id", "temp_id", "temp_qa_123", "comment_id", "comment_qa_123", "idempotency_key", "comment_retry_123", "task_qa_123", "QA_OPTIMISTIC_123", "bulkdel_qa_123", "user_qa_1", "user_qa_2", "user_qa_keep", "selected_count", "deleted_at", "deleted_by", "toast", "document", "doc_secure_123", "attachment", "att_clean_123", "contract.pdf", "eicar.txt", "scan_status", "scan_engine", "scan_version", "storage_key", "signed preview token", "signed URL", "oauth", "oauth_account", "provider", "acme", "redirect_uri", "state", "state_qa_123", "nonce", "nonce_qa_123", "code_challenge", "challenge_qa_123", "code_verifier", "authorization code", "code_qa_123", "sess_oauth_123", "subject", "sub_qa_123", "req_oauth_123", "access_token", "id_token", "sequence", "cursor", "PII", "email", "phone", "ssn"):
        if term in text and term not in entities:
            entities.append(term)
    return entities

def extract_state_transitions(text: str, req_id: str) -> list[dict[str, Any]]:
    transitions: list[dict[str, Any]] = []
    for match in re.finditer(r"\bfrom\s+([A-Za-z0-9_-]+)\s+to\s+([A-Za-z0-9_-]+)\b", text, re.IGNORECASE):
        transitions.append({
            "requirement_id": req_id,
            "from": match.group(1).lower(),
            "to": match.group(2).lower(),
            "source": text,
        })
    for match in re.finditer(r"\b([A-Za-z][A-Za-z0-9_-]+)\s+from\s+([0-9]+)\s+to\s+([0-9]+)\b", text, re.IGNORECASE):
        transitions.append({
            "requirement_id": req_id,
            "from": match.group(1).lower(),
            "to": match.group(3).lower(),
            "source": text,
        })
    chinese_match = re.search(r"从\s*([^，。；\s]+)\s*(?:变为|到|至)\s*([^，。；\s]+)", text)
    if chinese_match:
        transitions.append({
            "requirement_id": req_id,
            "from": chinese_match.group(1),
            "to": chinese_match.group(2),
            "source": text,
        })
    if has_soft_delete_intent(text) and "deleted" in text.lower() and not any(item.get("from") == "active" and item.get("to") == "deleted" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "active",
            "to": "deleted",
            "source": text,
        })
    if has_quarantine_intent(text) and not any(item.get("from") == "pending" and item.get("to") == "quarantined" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "pending",
            "to": "quarantined",
            "source": text,
        })
    if has_rate_limit_intent(text) and "failed_attempt_count" in text and not any(item.get("from") == "failed_attempt_count" and item.get("to") == "0" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "failed_attempt_count",
            "to": "0",
            "source": text,
        })
    if has_lockout_intent(text) and not any(item.get("from") == "locked" and item.get("to") == "unlocked" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "locked",
            "to": "unlocked",
            "source": text,
        })
    oauth_state_match = re.search(r"\b(state_[A-Za-z0-9_-]+)\b.{0,80}\bconsumed\b", text, re.IGNORECASE | re.DOTALL)
    if has_oauth_state_intent(text) and oauth_state_match and not any(item.get("from") == oauth_state_match.group(1).lower() and item.get("to") == "consumed" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": oauth_state_match.group(1).lower(),
            "to": "consumed",
            "source": text,
        })
    if has_mfa_recovery_code_intent(text) and not any(item.get("from") == "unused" and item.get("to") == "used" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "unused",
            "to": "used",
            "source": text,
        })
    if has_localization_intent(text):
        lower = text.lower()
        if "ar-eg" in lower and "en-us" in lower and not any(item.get("from") == "ar-eg" and item.get("to") == "en-us" for item in transitions):
            transitions.append({
                "requirement_id": req_id,
                "from": "ar-EG",
                "to": "en-US",
                "source": text,
            })
        if (("rtl" in lower and "ltr" in lower) or ("ltr" in lower and ("en-us" in lower or "switching locale" in lower or "switch locale" in lower))) and not any(item.get("from") == "rtl" and item.get("to") == "ltr" for item in transitions):
            transitions.append({
                "requirement_id": req_id,
                "from": "rtl",
                "to": "ltr",
                "source": text,
            })
    if has_notification_policy_intent(text):
        lower = text.lower()
        if "marketing_email=false" in lower and not any(item.get("from") == "marketing_email" and item.get("to") == "false" for item in transitions):
            transitions.append({
                "requirement_id": req_id,
                "from": "marketing_email",
                "to": "false",
                "source": text,
            })
        unsub_match = re.search(r"\b(unsub[_ -]?token[_A-Za-z0-9-]*)\b", text, re.IGNORECASE)
        if has_unsubscribe_token_intent(text) and unsub_match and not any(item.get("from") == unsub_match.group(1) and item.get("to") == "consumed" for item in transitions):
            transitions.append({
                "requirement_id": req_id,
                "from": unsub_match.group(1),
                "to": "consumed",
                "source": text,
            })
        if has_notification_quiet_hours_intent(text) and not any(item.get("from") == "queued" and item.get("to") == "deferred" for item in transitions):
            transitions.append({
                "requirement_id": req_id,
                "from": "queued",
                "to": "deferred",
                "source": text,
            })
    if has_subscription_billing_intent(text):
        lower = text.lower()
        version_match = re.search(r"\bsubscription[_ -]?version\s*=\s*(sub[_A-Za-z0-9-]+)\b", text, re.IGNORECASE)
        if version_match and not any(item.get("from") == "subscription_version" and item.get("to") == version_match.group(1) for item in transitions):
            transitions.append({
                "requirement_id": req_id,
                "from": "subscription_version",
                "to": version_match.group(1),
                "source": text,
            })
        if re.search(r"\b(?:plan|current[_ -]?plan)\s*=\s*pro\b", lower) and not any(item.get("from") == "current_plan" and item.get("to") == "pro" for item in transitions):
            transitions.append({
                "requirement_id": req_id,
                "from": "current_plan",
                "to": "pro",
                "source": text,
            })
        if has_subscription_scheduled_change_intent(text) and not any(item.get("from") == "target_plan" and item.get("to") == "scheduled" for item in transitions):
            transitions.append({
                "requirement_id": req_id,
                "from": "target_plan",
                "to": "scheduled",
                "source": text,
            })
    if has_agent_tool_approval_intent(text) and not any(item.get("from") == "pending_approval" and item.get("to") == "approved" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "pending_approval",
            "to": "approved",
            "source": text,
        })
    if has_agent_tool_cancellation_intent(text) and not any(item.get("from") == "pending_tool_call" and item.get("to") == "cancelled" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "pending_tool_call",
            "to": "cancelled",
            "source": text,
        })
    if has_agent_tool_handoff_intent(text) and not any(item.get("from") == "running" and item.get("to") == "needs_human_review" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "running",
            "to": "needs_human_review",
            "source": text,
        })
    if has_webauthn_challenge_intent(text) and has_word(text.lower(), r"\bconsume(?:d|s)?\b", r"\bconsumed\b") and not any(item.get("from") == "pending" and item.get("to") == "consumed" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "pending",
            "to": "consumed",
            "source": text,
        })
    sign_count_match = re.search(r"\blast_sign_count\s*=\s*(\d+)\b", text, re.IGNORECASE)
    if has_webauthn_sign_count_intent(text) and sign_count_match and not any(item.get("from") == "last_sign_count" and item.get("to") == sign_count_match.group(1) for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "last_sign_count",
            "to": sign_count_match.group(1),
            "source": text,
        })
    if has_saml_intent(text) and has_word(text.lower(), r"\bconsume(?:d|s)?\b", r"\bconsumed\b", r"\breplay\b") and not any(item.get("from") == "pending" and item.get("to") == "consumed" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "pending",
            "to": "consumed",
            "source": text,
        })
    if has_one_time_token_consumption_intent(text) and not any(item.get("from") == "unused" and item.get("to") == "used" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "unused",
            "to": "used",
            "source": text,
        })
    if has_one_time_token_session_invalidation_intent(text) and not any(item.get("from") == "active sessions" and item.get("to") == "invalidated" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "active sessions",
            "to": "invalidated",
            "source": text,
        })
    if has_api_key_revocation_intent(text) and not any(item.get("from") == "active" and item.get("to") == "revoked" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "active",
            "to": "revoked",
            "source": text,
        })
    if has_privacy_compliance_intent(text) and has_api_key_revocation_intent(text) and not any(item.get("from") == "API keys" and item.get("to") == "revoked" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "API keys",
            "to": "revoked",
            "source": text,
        })
    if has_audit_pseudonym_redaction_intent(text) and not any(item.get("from") == "profile PII" and item.get("to") == "redacted" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "profile PII",
            "to": "redacted",
            "source": text,
        })
    if has_privacy_pseudonymization_intent(text) and not any(item.get("from") == "profile PII" and item.get("to") == "pseudonymized" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "profile PII",
            "to": "pseudonymized",
            "source": text,
        })
    if has_privacy_session_invalidation_intent(text) and not any(item.get("from") == "active sessions" and item.get("to") == "deleted" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "active sessions",
            "to": "deleted",
            "source": text,
        })
    if has_audit_retention_intent(text) and not any(item.get("from") == "audit event" and item.get("to") == "retained" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "audit event",
            "to": "retained",
            "source": text,
        })
    if has_optimistic_rollback_intent(text) and not any(item.get("from") == "pending" and item.get("to") == "failed" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "pending",
            "to": "failed",
            "source": text,
        })
    if has_optimistic_pending_intent(text) and has_word(text.lower(), r"\bcomment[_ -]?id\b", r"\bserver\s+id\b") and not any(item.get("from") == "temp_id" and item.get("to") == "comment_id" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "temp_id",
            "to": "comment_id",
            "source": text,
        })
    schema_version_match = re.search(r"\bschema[_ -]?version\s*(\d+)\s*(?:->|to)\s*(\d+)\b", text, re.IGNORECASE)
    if has_schema_version_intent(text) and schema_version_match:
        for version in (schema_version_match.group(2), schema_version_match.group(1) if has_migration_rollback_intent(text) else ""):
            if version and not any(item.get("from") == "schema_version" and item.get("to") == version for item in transitions):
                transitions.append({
                    "requirement_id": req_id,
                    "from": "schema_version",
                    "to": version,
                    "source": text,
                })
    if has_migration_not_null_intent(text) and not any(item.get("from") == "nullable" and item.get("to") == "not null" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "nullable",
            "to": "not null",
            "source": text,
        })
    if has_authorization_policy_intent(text) and has_word(text.lower(), r"\ballow=false\b", r"\bdecision\s*=\s*deny\b", r"\bstale\s+allow\b") and not any(item.get("from") == "allow" and item.get("to") == "deny" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "allow",
            "to": "deny",
            "source": text,
        })
    policy_version_match = re.search(r"\bpolicy[_ -]?version\s*=\s*([A-Za-z0-9_-]+)\b", text, re.IGNORECASE)
    if has_authorization_policy_intent(text) and policy_version_match and not any(item.get("from") == "policy_version" and item.get("to") == policy_version_match.group(1) for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "policy_version",
            "to": policy_version_match.group(1),
            "source": text,
        })
    graphql_version_match = re.search(r"\border[_ -]?version\s*=\s*([A-Za-z0-9_-]+)\b", text, re.IGNORECASE)
    if has_graphql_cache_version_intent(text) and graphql_version_match and not any(item.get("from") == "order_version" and item.get("to") == graphql_version_match.group(1) for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "order_version",
            "to": graphql_version_match.group(1),
            "source": text,
        })
    if has_quota_metering_intent(text):
        for field, value in re.findall(r"\b(used|remaining)\s*=\s*([0-9]+)\b", text, re.IGNORECASE):
            field_name = field.lower()
            if not any(item.get("from") == field_name and item.get("to") == value for item in transitions):
                transitions.append({
                    "requirement_id": req_id,
                    "from": field_name,
                    "to": value,
                    "source": text,
                })
    if has_cache_consistency_intent(text):
        for field, value in re.findall(r"\b(item[_ -]?version|price[_ -]?cents)\s*=\s*([A-Za-z0-9_-]+)\b", text, re.IGNORECASE):
            field_name = field.lower().replace("-", "_").replace(" ", "_")
            if not any(item.get("from") == field_name and item.get("to") == value for item in transitions):
                transitions.append({
                    "requirement_id": req_id,
                    "from": field_name,
                    "to": value,
                    "source": text,
                })
    if has_scheduled_job_intent(text):
        if has_catch_up_intent(text) and not any(item.get("from") == "missed" and item.get("to") == "completed" for item in transitions):
            transitions.append({
                "requirement_id": req_id,
                "from": "missed",
                "to": "completed",
                "source": text,
            })
        if has_scheduler_lock_intent(text) and not any(item.get("from") == "lock_acquired" and item.get("to") == "already_running" for item in transitions):
            transitions.append({
                "requirement_id": req_id,
                "from": "lock_acquired",
                "to": "already_running",
                "source": text,
            })
    if has_cleanup_intent(text) and has_word(text.lower(), r"\bdeleted\b", r"\bdeleted\s*=\s*true\b", r"\breturns?\s+404\b", r"\btestdata_deleted\b"):
        if not any(item.get("from") == "active" and item.get("to") == "deleted" for item in transitions):
            transitions.append({
                "requirement_id": req_id,
                "from": "active",
                "to": "deleted",
                "source": text,
            })
    if has_rag_grounding_intent(text) and has_word(text.lower(), r"\banswer_done\b", r"\banswered\b") and not any(item.get("from") == "retrieving" and item.get("to") == "answered" for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "retrieving",
            "to": "answered",
            "source": text,
        })
    document_version_match = re.search(r"\bdocument[_ -]?version\s*=\s*([A-Za-z0-9_-]+)\b", text, re.IGNORECASE)
    if has_rag_document_version_intent(text) and document_version_match and not any(item.get("from") == "document_version" and item.get("to") == document_version_match.group(1) for item in transitions):
        transitions.append({
            "requirement_id": req_id,
            "from": "document_version",
            "to": document_version_match.group(1),
            "source": text,
        })
    if has_decision_table_logic_intent(text):
        lower = text.lower()
        for target in ("auto_approved", "manual_review", "rejected"):
            if target in lower and not any(item.get("from") == "pending" and item.get("to") == target for item in transitions):
                transitions.append({
                    "requirement_id": req_id,
                    "from": "pending",
                    "to": target,
                    "source": text,
                })
    if has_artifact_generation_intent(text):
        artifact_transitions = []
        if has_artifact_progress_intent(text) or "artifact_ready" in text.lower():
            artifact_transitions.append(("queued", "artifact_ready"))
        if has_artifact_cancellation_intent(text):
            artifact_transitions.append(("running", "cancelled"))
        if has_artifact_partial_failure_intent(text):
            artifact_transitions.append(("running", "partial_failed"))
        checkpoint_match = re.search(r"\bcheckpoint[_ -]?page\s*=\s*(\d+)\b", text, re.IGNORECASE)
        if checkpoint_match:
            artifact_transitions.append(("checkpoint_page", checkpoint_match.group(1)))
        for source_state, target_state in artifact_transitions:
            if not any(item.get("from") == source_state and item.get("to") == target_state for item in transitions):
                transitions.append({
                    "requirement_id": req_id,
                    "from": source_state,
                    "to": target_state,
                    "source": text,
                })
    if has_offline_sync_intent(text):
        for source_state, target_state in (
            ("offline", "online"),
            ("pending_sync", "synced"),
            ("pending_sync", "blocked_conflict"),
            ("blocked_conflict", "resolved"),
            ("retry_count", "1"),
        ):
            if not any(item.get("from") == source_state and item.get("to") == target_state for item in transitions):
                transitions.append({
                    "requirement_id": req_id,
                    "from": source_state,
                    "to": target_state,
                    "source": text,
                })
    if has_analytics_intent(text):
        for source_state, target_state in (
            ("checkout", "paid"),
            ("queue_status", "pending_retry"),
            ("attribution_credit", "committed"),
            ("experiment_exposure", "persisted"),
        ):
            if source_state in text.lower() or target_state in text.lower() or source_state == "checkout":
                if not any(item.get("from") == source_state and item.get("to") == target_state for item in transitions):
                    transitions.append({
                        "requirement_id": req_id,
                        "from": source_state,
                        "to": target_state,
                        "source": text,
                    })
    return transitions

def extract_workflow_label(text: str, paths: list[str], tests: list[dict[str, Any]]) -> str:
    lower = text.lower()
    action_words = workflow_terms_from_text(text)
    action = next((word for word in action_words if re.search(rf"\b{word}\b", lower)), "")
    if not action and has_cross_tenant_denial_intent(text):
        action = "cross-tenant denial"
    if not action and has_tenant_isolation_intent(text):
        action = "tenant isolation"
    if not action and has_optimistic_ui_intent(text):
        action = "optimistic update"
    if not action and has_schema_migration_intent(text):
        action = "schema migration"
    if not action and has_authorization_policy_intent(text):
        action = "authorization policy"
    if not action and has_decision_table_logic_intent(text):
        action = "decision table"
    if not action and has_offline_sync_intent(text):
        action = "offline sync"
    if not action and has_analytics_intent(text):
        action = "analytics telemetry"
    if not action and has_financial_ledger_intent(text):
        action = "financial ledger"
    if not action and has_quota_metering_intent(text):
        action = "quota metering"
    if not action and has_webhook_security_intent(text):
        action = "webhook security"
    if not action and has_cache_consistency_intent(text):
        action = "cache consistency"
    if not action and has_time_boundary_intent(text) and not has_audit_integrity_intent(text):
        action = "time boundary"
    if not action and has_money_precision_intent(text):
        action = "money precision"
    if not action and has_accessibility_intent(text):
        action = "accessibility"
    if not action and has_reconnect_replay_intent(text):
        action = "reconnect replay"
    if not action and has_ordering_intent(text):
        action = "sequence ordering"
    if not action and has_realtime_intent(text):
        action = "realtime collaboration"
    if not action and has_concurrency_intent(text):
        action = "concurrency"
    if not action and has_background_job_intent(text):
        action = "background job"
    if not action and has_worker_intent(text):
        action = "worker"
    if not action and has_retry_backoff_intent(text):
        action = "retry"
    if not action and has_feature_flag_intent(text):
        action = "feature flag"
    if not action and has_rollout_intent(text):
        action = "rollout"
    if not action and has_csrf_intent(text):
        action = "csrf"
    if not action and has_session_security_intent(text):
        action = "session security"
    if not action and has_cookie_security_intent(text):
        action = "cookie security"
    if not action and has_oauth_intent(text):
        action = "oauth callback"
    if not action and has_redirect_security_intent(text):
        action = "redirect security"
    if not action and has_saml_intent(text):
        action = "saml sso"
    if not action and has_api_key_intent(text):
        action = "api key lifecycle"
    if not action and has_audit_integrity_intent(text):
        action = "audit log integrity"
    if not action and has_one_time_token_intent(text):
        action = "one-time token"
    if not action and has_webauthn_intent(text):
        action = "webauthn passkey"
    if not action and has_mfa_intent(text):
        action = "mfa verification"
    if not action and has_rate_limit_intent(text):
        action = "rate limit"
    if not action and has_agent_tool_intent(text):
        action = "agent tool orchestration"
    if not action and has_resource_creation_intent(text):
        action = "create"
    if not action and has_cleanup_intent(text):
        action = "cleanup"
    if not action and has_file_security_intent(text):
        action = "file security"
    if not action and has_file_preview_intent(text):
        action = "file preview"
    if not action and has_bulk_action_intent(text):
        action = "bulk delete"
    if not action and has_destructive_confirmation_intent(text):
        action = "destructive confirmation"
    if not action and has_soft_delete_intent(text):
        action = "soft delete"
    if not action and has_undo_intent(text):
        action = "undo"
    if ("backfill" in lower or "backfill_import" in lower) and re.search(r"\bdry[- ]run\b", lower):
        action = "backfill dry-run"
    if not action:
        for term in ("审批", "批准", "创建", "更新", "删除", "提交", "保存", "发送", "搜索", "刷新", "持久化", "完成", "上传", "过滤", "升级", "流式"):
            if term in text:
                action = term
                break
    entities = extract_entities_from_text(text, paths)
    if action and entities:
        return f"{action} {entities[0]}"
    if action:
        return action
    executable_types = [test.get("type", "") for test in tests]
    return ", ".join(item for item in executable_types if item) or "requirement workflow"

WORKFLOW_ACTION_WORDS = [
    "bulk delete", "bulk-delete", "delete selected", "approve", "create", "update", "delete", "submit", "save", "send",
    "search", "login", "refresh", "persist", "complete", "upload",
    "filter", "escalate", "cancel", "escape", "answer_done", "completed", "stream",
    "backfill", "backfill_import", "dry-run", "import", "checkout",
    "validation", "validate", "test", "tests", "testing", "测试", "continue", "sort", "pagination",
    "empty state", "retryable error", "progress", "download",
    "csv", "content-disposition", "content-type", "application/json",
    "filename", "api endpoint", "pricing api", "price_cents", "webhook", "signature",
    "stripe-signature", "idempotent", "idempotency", "idempotency-key",
    "replay", "duplicate_ignored", "notification", "receipt",
    "tenant isolation", "data isolation", "cross-tenant", "access denied",
    "access_denied", "tenant.access_denied", "same account ids",
    "date range", "time boundary", "timezone", "inclusive", "start boundary",
    "exclusive", "end boundary", "dst",
    "preview", "decimal arithmetic", "money precision", "round half-up",
    "rounding", "discount", "tax", "currency conversion",
    "keyboard", "tab", "focus", "focus trap", "aria", "accessible name",
    "escape", "success toast", "accessibility", "a11y",
    "optimistic comment", "optimistic update", "optimistic",
    "pending", "rollback", "roll back", "failed", "retry action",
    "cache invalidation", "temp_id", "no success toast",
    "schema migration", "migration", "schema", "expand-contract",
    "expand step", "contract step", "backfill", "batch",
    "concurrent index", "index concurrently", "foreign key",
    "not null", "zero-null", "rollback plan", "down migration",
    "backward compatibility", "old client", "new client",
    "authorization policy", "policy matrix", "policy evaluate",
    "policy/evaluate", "decision", "deny precedence",
    "explicitly denies", "role inheritance", "inherits",
    "obligation", "mask_pii", "direct API denial",
    "policy_denied", "resource scope", "same-org",
    "policy decision cache", "cache_key", "stale allow",
    "financial ledger", "ledger", "ledger transaction", "ledger entry",
    "double-entry", "balanced debits", "debit_total_cents",
    "credit_total_cents", "immutable ledger", "must not mutate",
    "reversal ledger", "linked to tx_charge_123", "minor-unit cents",
    "amount_cents", "no float drift", "over_refund_denied",
    "refund.settled", "settlement worker", "reconciliation",
    "payout_reconciliation",
    "usage quota", "quota metering", "meter_key", "api_calls",
    "quota_window", "monthly quota", "usage counter", "counter_version",
    "remaining", "never go negative", "quota_exceeded",
    "billing_usage_event", "quota reset worker", "reset boundary",
    "window_reset",
    "subscription billing", "plan change", "current_plan",
    "target_plan", "subscription_version", "billing anchor",
    "proration", "proration_behavior", "invoice preview", "preview_id",
    "unused credit", "unused_credit_cents", "prorated charge",
    "prorated_charge_cents", "tax jurisdiction", "tax_rate_bps",
    "invoice line items", "scheduled capture", "requires_capture",
    "downgrade scheduling", "scheduled_change",
    "plan_change_forbidden", "no receipt email",
    "agent tool orchestration", "agent tool", "tool call",
    "agent_session_id", "tool_call_requested", "tool_call_id",
    "tool_name", "approval_required", "approval_id",
    "tool_call_approved", "tool_result", "tool_result_id",
    "tool_call_cancelled", "tool args redaction", "tool_args",
    "args_hash", "tool_approval_forbidden", "tool_timeout",
    "handoff_required", "handoff_id", "human_review_queue",
    "artifact generation", "artifact job", "report-jobs",
    "progress event", "artifact_ready", "artifact_manifest",
    "manifest_id", "manifest_hash", "content_hash", "file_hash",
    "resume_token", "checkpoint_page", "temp_object_count=0",
    "partial_failed", "failed_sections", "diagnostic_artifact",
    "storage_key_redacted", "download guard",
    "artifact_download_forbidden",
    "analytics telemetry", "analytics", "analytics_event",
    "event_name", "checkout_completed", "event_id", "schema_version",
    "consent_version", "user_pseudonym_id", "attribution_id",
    "campaign_id", "experiment_id", "experiment exposure",
    "experiment_exposure", "exposure_id", "dedupe_key",
    "duplicate_ignored", "event_time", "pii redaction",
    "raw email", "analytics_consent=false", "queue_status",
    "pending_retry", "attribution_mismatch",
    "offline sync", "offline queue", "network offline", "indexeddb",
    "local outbox", "pending_sync", "service worker",
    "background sync", "client_mutation_id", "sync_version",
    "queue drain", "version_conflict", "conflict_id",
    "blocked_conflict", "merge dialog", "resolve-conflict",
    "if-match", "server_version", "retry scheduled",
    "sync_forbidden", "encrypted_local_payload",
    "webhook security", "webhook_security", "hmac-sha256", "hmac",
    "raw body", "raw_body", "x-hub-signature-256",
    "timestamp tolerance", "timestamp_out_of_tolerance",
    "replay window", "delivery_id", "signature_mismatch",
    "signature_version", "no side effects",
    "cache consistency", "cache_consistency", "etag", "cache-control",
    "if-none-match", "304 not modified", "not modified",
    "cache_invalidation_event", "cache invalidation", "surrogate-key",
    "surrogate_key", "stale-while-revalidate", "origin_fetch",
    "origin fetch", "cache_status", "stale response", "stale=true",
    "version token", "item_version",
    "concurrent", "parallel", "optimistic lock", "version_conflict",
    "conflict", "409", "no oversell", "below 0",
    "enqueue", "queued", "queue", "background job", "worker",
    "retry", "retries", "retry_count", "exponential backoff", "backoff",
    "next_retry_at", "dead_letter", "dead letter", "alert", "alert_outbox",
    "scheduled job", "scheduler", "cron", "schedule", "schedule_id",
    "next_run_at", "run_key", "catch-up", "missed", "advisory lock",
    "scheduler_lock", "lock_acquired", "already_running",
    "duplicate_skipped", "dry-run", "no real email",
    "feature flag", "feature_flag", "new_pricing_editor", "rollout",
    "cohort", "cohort_match", "variant", "treatment", "default off",
    "default-off", "feature_flag_default_off", "feature_disabled",
    "stale cached flag", "stale cached",
    "realtime", "real-time", "collaboration", "broadcast",
    "block.updated", "reconnect", "cursor", "replay exactly",
    "sequence", "ordering", "same workspace", "another workspace",
    "csrf", "x-csrf-token", "csrf_failed", "session rotation",
    "rotates session_id", "logout", "invalidated", "cookie flags",
    "httponly", "secure", "samesite=lax", "no leak", "must not leak",
    "oauth", "pkce", "redirect_uri", "allowlisted",
    "authorization code", "code exchange", "open redirect", "return_to",
    "state", "nonce", "consumed",
    "saml", "sso", "authnrequest", "samlrequest", "relaystate",
    "acs", "assertionconsumerserviceurl", "xml signature", "x509",
    "audiencerestriction", "destination", "recipient", "inresponseto",
    "notbefore", "notonorafter", "nameid", "group attribute",
    "webauthn", "passkey", "challenge", "rpid", "rpidhash",
    "origin", "clientdatajson", "credentialid", "authenticatordata",
    "signature", "public key", "signcount", "last_sign_count",
    "attestationobject", "credential_private_key",
    "mfa", "mfa_required", "totp", "time window", "clock_skew_seconds",
    "clock skew", "recovery code", "used_at", "reused challenge",
    "mfa_pending",
    "password reset", "forgot password", "reset password",
    "one-time token", "one time token", "magic link",
    "email verification", "verify email", "reset_token_hash",
    "token hash", "token purpose", "expires_at", "used_at",
    "notification_outbox", "reset email", "email link",
    "password_hash", "invalidate all existing sessions",
    "wrong-purpose", "wrong-tenant",
    "api key", "api keys", "personal access token", "pat",
    "secret once", "copy panel", "hash only", "key_hash",
    "key_prefix", "scopes", "insufficient_scope",
    "last_used_at", "revoked_at", "generic unauthorized",
    "audit log", "audit event", "append-only", "immutable",
    "previous_hash", "event_hash", "canonical json",
    "tamper", "audit_integrity_violation",
    "retention_expires_at", "legal_hold", "pseudonym",
    "actor_ref", "privacy-deleted", "raw ip",
    "rate limit", "rate_limited", "429", "retry-after", "lockout",
    "cooldown", "failed_attempt_count", "generic error",
    "account enumeration", "reset",
    "selected count", "selected_count", "selection", "destructive confirmation",
    "confirmation modal", "soft delete", "soft-deleted", "undo",
    "unselected", "no extra ids", "operation_id",
    "cleanup", "clean up", "teardown", "same runtime object",
    "same-object", "always run", "alwaysrun", "cleanup verification",
    "testdata_deleted", "qa_cleanup",
    "decision table", "rule matrix", "rule precedence",
    "boundary rows", "negative rows", "expected_decisions",
    "fixture input rows", "expected output decisions",
    "malware scan", "scan_status", "scan status", "quarantined",
    "quarantine", "preview", "signed preview token", "signed url",
    "signed URL", "nosniff", "file size validation", "25mb",
    "search relevance", "relevance", "ranking_model", "search_rank_v5",
    "query_rewrite", "query_rewrite_id", "canonical_query",
    "typo tolerance", "wirless", "synonym", "cordless",
    "facet counts", "facet aggregation", "total_count",
    "result order", "position", "sponsored disclosure",
    "sponsored_disclosure", "stale result", "popular products",
]

def append_experience_workflow_terms(text: str, lower: str, terms: list[str]) -> None:
    """Append product-flow, scheduling, time, money, accessibility, and cache terms."""
    if has_offline_sync_intent(text):
        for term in (
            "offline sync",
            "offline queue",
            "network offline",
            "reconnect",
            "IndexedDB",
            "local outbox",
            "pending_sync",
            "service worker",
            "background sync",
            "client_mutation_id",
            "idempotency_key",
            "duplicate_ignored",
            "sync_version",
            "queue drain",
            "version_conflict",
            "409",
            "conflict_id",
            "blocked_conflict",
            "merge dialog",
            "resolve-conflict",
            "If-Match",
            "server_version",
            "retry scheduled",
            "retry_count",
            "backoff_schedule",
            "sync_forbidden",
            "encrypted_local_payload",
        ):
            if term not in terms:
                terms.append(term)
    if has_pagination_intent(text) and "pagination" not in terms:
        terms.append("pagination")
    if has_empty_state_intent(text) and "empty state" not in terms:
        terms.append("empty state")
    if has_error_state_intent(text) and "retryable error" not in terms:
        terms.append("retryable error")
    if has_search_relevance_intent(text):
        for term in ("search relevance", "relevance"):
            if term not in terms:
                terms.append(term)
    if has_search_ranking_intent(text):
        for term in ("ranking_model", "search_rank_v5", "result order", "position"):
            if term not in terms and (term in lower or term in {"result order", "position"}):
                terms.append(term)
    if has_search_query_rewrite_intent(text):
        for term in ("query_rewrite", "query_rewrite_id", "canonical_query", "typo tolerance", "wirless", "synonym", "cordless"):
            if term not in terms and (term in lower or term in {"typo tolerance", "synonym"}):
                terms.append(term)
    if has_search_facet_intent(text):
        for term in ("facet counts", "facet aggregation", "total_count"):
            if term not in terms and (term in lower or term == "facet aggregation"):
                terms.append(term)
    if has_search_sponsored_intent(text):
        for term in ("sponsored disclosure", "sponsored_disclosure"):
            if term not in terms and (term in lower or term == "sponsored disclosure"):
                terms.append(term)
    if has_search_stale_result_guard_intent(text):
        for term in ("stale result", "popular products"):
            if term not in terms and (term in lower or term == "stale result"):
                terms.append(term)
    if has_scheduled_job_intent(text):
        for term in ("scheduled job", "scheduler"):
            if term not in terms:
                terms.append(term)
    if has_decision_table_logic_intent(text):
        for term in ("decision table", "rule precedence", "boundary rows", "negative rows", "expected_decisions", "fixture input rows"):
            if term not in terms:
                terms.append(term)
        if "amount=1000" in lower and "amount=1000" not in terms:
            terms.append("amount=1000")
    if has_localization_intent(text):
        for term in (
            "localization",
            "i18n",
            "locale switch",
            "ar-EG",
            "dir=rtl",
            "rtl",
            "translation catalog",
            "catalog version",
            "missing_keys",
            "fallback_count",
            "plural rules",
            "singular",
            "dual",
            "many",
            "currency formatting",
            "Intl.NumberFormat",
            "date formatting",
            "Africa/Cairo",
            "stale catalog",
            "cached formatted values",
        ):
            if term not in terms:
                terms.append(term)
    if has_notification_policy_intent(text):
        for term in (
            "notification preferences",
            "preference_version",
            "consent_source",
            "user_setting",
            "marketing_email=false",
            "transactional_email=true",
            "suppressed_reason",
            "unsubscribed",
            "quiet hours",
            "send_after",
            "urgent_override",
            "digest_key",
            "weekly_digest_2026_w27",
            "event_count=3",
            "idempotency_key",
            "duplicate",
            "unsubscribe token",
            "token_hash",
            "token_already_used",
            "no leak",
            "raw unsubscribe token",
        ):
            if term not in terms:
                terms.append(term)
    if has_resource_creation_intent(text) and "create" not in terms:
        terms.append("create")
    if has_same_runtime_object_intent(text):
        for term in ("same runtime object", "same-object"):
            if term not in terms:
                terms.append(term)
    if has_cleanup_intent(text):
        for term in ("cleanup", "teardown"):
            if term not in terms:
                terms.append(term)
    if has_always_run_cleanup_intent(text):
        for term in ("always run", "alwaysRun"):
            if term not in terms:
                terms.append(term)
    if has_cleanup_verification_intent(text) and "cleanup verification" not in terms:
        terms.append("cleanup verification")
    if has_word(lower, r"\btestdata_deleted\b", r"\bproject\.testdata_deleted\b") and "testdata_deleted" not in terms:
        terms.append("testdata_deleted")
    if has_schedule_expression_intent(text):
        for term in ("cron", "schedule", "next_run_at"):
            if term not in terms and (term in lower or term in {"cron", "schedule"}):
                terms.append(term)
    if has_run_key_intent(text):
        for term in ("run_key", "billrun_2026_06_30"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_catch_up_intent(text):
        for term in ("catch-up", "missed"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_scheduler_lock_intent(text):
        for term in ("advisory lock", "scheduler_lock", "already_running", "duplicate_skipped"):
            if term not in terms and (term in lower or term == "advisory lock"):
                terms.append(term)
    if has_no_real_email_intent(text) and "no real email" not in terms:
        terms.append("no real email")
    if has_progress_intent(text) and "progress" not in terms:
        terms.append("progress")
    if has_download_intent(text) and "export" in lower and "export" not in terms:
        terms.append("export")
    if has_tenant_isolation_intent(text):
        for term in ("tenant isolation", "data isolation"):
            if term not in terms:
                terms.append(term)
    if has_time_boundary_intent(text) and not has_audit_integrity_intent(text):
        for term in ("date range", "time boundary"):
            if term not in terms:
                terms.append(term)
    if has_timezone_intent(text) and "timezone" not in terms:
        terms.append("timezone")
    if has_inclusive_start_intent(text):
        for term in ("inclusive", "start boundary"):
            if term not in terms:
                terms.append(term)
    if has_exclusive_end_intent(text):
        for term in ("exclusive", "end boundary"):
            if term not in terms:
                terms.append(term)
    if has_dst_boundary_intent(text) and "dst" not in terms:
        terms.append("dst")
    if has_money_precision_intent(text):
        for term in ("money precision", "decimal arithmetic"):
            if term not in terms:
                terms.append(term)
    if has_rounding_rule_intent(text):
        for term in ("rounding", "round half-up"):
            if term not in terms and term in lower:
                terms.append(term)
        if "rounding" not in terms:
            terms.append("rounding")
    if has_discount_calculation_intent(text) and "discount" not in terms:
        terms.append("discount")
    if has_tax_calculation_intent(text) and "tax" not in terms:
        terms.append("tax")
    if has_currency_conversion_intent(text) and "currency conversion" not in terms:
        terms.append("currency conversion")
    if has_idempotency_intent(text):
        for term in ("idempotent", "idempotency", "idempotency_key", "replay"):
            if term not in terms:
                terms.append(term)
    if has_realtime_intent(text):
        for term in ("realtime", "collaboration", "broadcast"):
            if term not in terms and (term in lower or term == "realtime"):
                terms.append(term)
        if "block.updated" in lower and "block.updated" not in terms:
            terms.append("block.updated")
    if has_multi_client_intent(text):
        for term in ("same workspace", "multi-client"):
            if term not in terms and (term in lower or term == "multi-client"):
                terms.append(term)
    if has_ordering_intent(text):
        for term in ("sequence", "ordering"):
            if term not in terms:
                terms.append(term)
    if has_reconnect_replay_intent(text):
        for term in ("reconnect", "cursor", "replay"):
            if term not in terms:
                terms.append(term)
    if has_cross_tenant_denial_intent(text) and "another workspace" in lower and "another workspace" not in terms:
        terms.append("another workspace")
    if has_keyboard_navigation_intent(text):
        for term in ("keyboard", "tab"):
            if term not in terms:
                terms.append(term)
    if has_focus_trap_intent(text):
        if "focus trap" not in terms:
            terms.append("focus trap")
    elif has_focus_management_intent(text) and "focus" not in terms:
        terms.append("focus")
    if has_aria_semantics_intent(text):
        for term in ("aria", "accessible name"):
            if term not in terms:
                terms.append(term)
    if has_escape_close_intent(text) and "escape" not in terms:
        terms.append("escape")
    if has_success_toast_intent(text) and "success toast" not in terms:
        terms.append("success toast")
    if has_optimistic_ui_intent(text):
        for term in ("optimistic comment", "optimistic update", "optimistic"):
            if term not in terms and term in lower:
                terms.append(term)
        if not any(term in terms for term in ("optimistic comment", "optimistic update", "optimistic")):
            terms.append("optimistic update")
    if has_optimistic_pending_intent(text):
        for term in ("pending", "temp_id"):
            if term not in terms and term in lower:
                terms.append(term)
        if "pending" not in terms:
            terms.append("pending")
    if has_optimistic_rollback_intent(text):
        for term in ("rollback", "roll back", "failed", "retry action"):
            if term not in terms and term in lower:
                terms.append(term)
        if "rollback" not in terms and "roll back" not in terms:
            terms.append("rollback")
        if "retry action" not in terms and "retry" in lower:
            terms.append("retry action")
    if has_cache_invalidation_intent(text):
        for term in ("cache invalidation", "stale cached"):
            if term not in terms and term in lower:
                terms.append(term)
        if "cache invalidation" not in terms and "stale cached" not in terms:
            terms.append("cache invalidation")

def append_platform_workflow_terms(text: str, lower: str, terms: list[str]) -> None:
    """Append migration, policy, finance, quota, billing, agent, and artifact terms."""
    if has_schema_migration_intent(text):
        for term in ("schema migration", "migration", "schema"):
            if term not in terms and (term in lower or term in {"schema migration", "migration"}):
                terms.append(term)
    if has_migration_plan_intent(text):
        for term in ("expand-contract", "expand step", "contract step"):
            if term not in terms and (term in lower or term == "expand-contract"):
                terms.append(term)
    if has_migration_backfill_intent(text):
        for term in ("backfill", "batch"):
            if term not in terms and (term in lower or term == "backfill"):
                terms.append(term)
    if has_migration_concurrent_index_intent(text):
        for term in ("concurrent index", "index concurrently"):
            if term not in terms and (term in lower or term == "concurrent index"):
                terms.append(term)
    if has_migration_foreign_key_intent(text):
        for term in ("foreign key", "fk_users_organization_id"):
            if term not in terms and (term in lower or term == "foreign key"):
                terms.append(term)
    if has_migration_not_null_intent(text):
        for term in ("not null", "zero-null"):
            if term not in terms and (term in lower or term == "not null"):
                terms.append(term)
    if has_migration_rollback_intent(text):
        for term in ("rollback", "down migration"):
            if term not in terms and (term in lower or term == "rollback"):
                terms.append(term)
    if has_backward_compatibility_intent(text):
        for term in ("backward compatibility", "old client", "new client"):
            if term not in terms and (term in lower or term == "backward compatibility"):
                terms.append(term)
    if has_authorization_policy_intent(text):
        for term in ("authorization policy", "policy matrix"):
            if term not in terms and (term in lower or term == "authorization policy"):
                terms.append(term)
    if has_policy_decision_intent(text):
        for term in ("policy evaluate", "decision"):
            if term not in terms and (term in lower or term == "policy evaluate"):
                terms.append(term)
    if has_deny_precedence_intent(text):
        for term in ("deny precedence", "explicitly denies"):
            if term not in terms and (term in lower or term == "deny precedence"):
                terms.append(term)
    if has_role_inheritance_intent(text):
        for term in ("role inheritance", "inherits"):
            if term not in terms and (term in lower or term == "role inheritance"):
                terms.append(term)
    if has_policy_obligation_intent(text):
        for term in ("obligation", "mask_pii"):
            if term not in terms and (term in lower or term == "obligation"):
                terms.append(term)
    if has_authorization_policy_intent(text) and has_direct_api_denial_intent(text):
        for term in ("direct API denial", "policy_denied"):
            if term not in terms and (term.lower() in lower or term == "direct API denial"):
                terms.append(term)
    if has_resource_scope_intent(text):
        for term in ("resource scope", "same-org"):
            if term not in terms and (term in lower or term == "resource scope"):
                terms.append(term)
    if has_policy_cache_guard_intent(text):
        for term in ("policy decision cache", "cache_key", "stale allow"):
            if term not in terms and (term in lower or term == "policy decision cache"):
                terms.append(term)
    if has_financial_ledger_intent(text):
        for term in ("financial ledger", "ledger transaction", "ledger entry"):
            if term not in terms and (term in lower or term == "financial ledger"):
                terms.append(term)
    if has_double_entry_intent(text):
        for term in ("double-entry", "balanced debits", "debit_total_cents", "credit_total_cents"):
            if term not in terms and (term in lower or term in {"double-entry", "balanced debits"}):
                terms.append(term)
    if has_immutable_ledger_intent(text):
        for term in ("immutable ledger", "must not mutate"):
            if term not in terms and (term in lower or term == "immutable ledger"):
                terms.append(term)
    if has_reversal_ledger_intent(text):
        for term in ("reversal ledger", "linked to tx_charge_123"):
            if term not in terms and (term in lower or term == "reversal ledger"):
                terms.append(term)
    if has_minor_unit_amount_intent(text):
        for term in ("minor-unit cents", "amount_cents", "no float drift"):
            if term not in terms and (term in lower or term == "minor-unit cents"):
                terms.append(term)
    if has_over_refund_denial_intent(text):
        for term in ("over_refund_denied", "409"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_settlement_reconciliation_intent(text):
        for term in ("settlement worker", "refund.settled", "reconciliation", "payout_reconciliation"):
            if term not in terms and (term in lower or term in {"settlement worker", "reconciliation"}):
                terms.append(term)
    if has_quota_metering_intent(text):
        for term in ("usage quota", "quota metering", "meter_key", "api_calls"):
            if term not in terms and (term in lower or term in {"usage quota", "quota metering"}):
                terms.append(term)
    if has_quota_window_intent(text):
        for term in ("quota_window", "monthly quota"):
            if term not in terms and (term in lower or term == "quota_window"):
                terms.append(term)
    if has_usage_counter_intent(text):
        for term in ("usage counter", "counter_version"):
            if term not in terms and (term in lower or term == "usage counter"):
                terms.append(term)
    if has_quota_remaining_intent(text):
        for term in ("remaining", "never go negative"):
            if term not in terms and (term in lower or term == "remaining"):
                terms.append(term)
    if has_quota_exceeded_denial_intent(text):
        for term in ("quota_exceeded", "409"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_billing_usage_event_intent(text):
        for term in ("billing_usage_event",):
            if term not in terms and term in lower:
                terms.append(term)
    if has_quota_reset_boundary_intent(text):
        for term in ("quota reset worker", "reset boundary", "window_reset"):
            if term not in terms and (term in lower or term == "reset boundary"):
                terms.append(term)
    if has_subscription_billing_intent(text):
        for term in ("subscription billing", "plan change", "current_plan", "target_plan", "subscription_version"):
            if term not in terms and (term in lower or term in {"subscription billing", "plan change"}):
                terms.append(term)
    if has_subscription_proration_intent(text):
        for term in ("proration", "proration_behavior", "unused credit", "unused_credit_cents", "prorated charge", "prorated_charge_cents"):
            if term not in terms and (term in lower or term in {"unused credit", "prorated charge"}):
                terms.append(term)
    if has_subscription_invoice_preview_intent(text):
        for term in ("invoice preview", "preview_id"):
            if term not in terms and (term in lower or term == "invoice preview"):
                terms.append(term)
    if has_subscription_tax_intent(text):
        for term in ("tax jurisdiction", "tax_rate_bps"):
            if term not in terms and (term in lower or term == "tax jurisdiction"):
                terms.append(term)
    if has_word(lower, r"\bline[_ -]?items?\b", r"\bline_credit_unused\b", r"\bline_proration_charge\b", r"\bline_tax\b"):
        for term in ("invoice line items",):
            if term not in terms:
                terms.append(term)
    if has_subscription_scheduled_capture_intent(text):
        for term in ("scheduled capture", "requires_capture"):
            if term not in terms and (term in lower or term == "scheduled capture"):
                terms.append(term)
    if has_subscription_scheduled_change_intent(text):
        for term in ("downgrade scheduling", "scheduled_change", "billing anchor", "renewal"):
            if term not in terms and (term in lower or term in {"downgrade scheduling", "billing anchor", "renewal"}):
                terms.append(term)
    if has_subscription_authorization_denial_intent(text):
        for term in ("authorization denial", "plan_change_forbidden"):
            if term not in terms and (term in lower or term == "authorization denial"):
                terms.append(term)
    if has_subscription_billing_intent(text) and has_word(lower, r"\bno\s+receipt\s+email\b", r"\bmust\s+not\b.{0,140}\bsend\s+(?:a\s+)?receipt\s+email\b", r"\bmust\s+not\s+send\s+(?:a\s+)?receipt\s+email\b", r"\bmust\s+not\s+create\s+.{0,80}\breceipt\s+email\b", r"\bwithout\s+sending\s+(?:a\s+)?receipt\b"):
        if "no receipt email" not in terms:
            terms.append("no receipt email")
    if has_agent_tool_intent(text):
        for term in ("agent tool orchestration", "tool call", "tool_call_requested", "tool_call_id", "tool_name"):
            if term not in terms:
                terms.append(term)
    if has_agent_tool_approval_intent(text):
        for term in ("approval_required", "approval_id", "tool_call_approved", "tool_result", "tool_result_id"):
            if term not in terms:
                terms.append(term)
    if has_agent_tool_cancellation_intent(text):
        for term in ("tool_call_cancelled",):
            if term not in terms:
                terms.append(term)
    if has_agent_tool_redaction_intent(text):
        for term in ("tool args redaction", "args_hash"):
            if term not in terms:
                terms.append(term)
    if has_agent_tool_authorization_denial_intent(text):
        for term in ("authorization denial", "tool_approval_forbidden"):
            if term not in terms:
                terms.append(term)
    if has_agent_tool_handoff_intent(text):
        for term in ("handoff_required", "handoff_id", "tool_timeout"):
            if term not in terms:
                terms.append(term)
    if has_artifact_generation_intent(text):
        for term in (
            "artifact generation",
            "artifact job",
            "job_id",
            "progress event",
            "artifact_ready",
            "artifact_manifest",
            "manifest_id",
            "manifest_hash",
            "content_hash",
            "file_hash",
            "resume_token",
            "checkpoint_page",
            "cancel/cancelled",
            "temp_object_count=0",
            "partial_failed",
            "failed_sections",
            "diagnostic_artifact",
            "retention_expires_at",
            "storage_key_redacted",
            "download guard",
            "artifact_download_forbidden",
        ):
            if term not in terms and (term in lower or term in {"artifact generation", "artifact job", "progress event", "cancel/cancelled", "download guard"}):
                terms.append(term)

def append_distributed_workflow_terms(text: str, lower: str, terms: list[str]) -> None:
    """Append webhook, privacy, GraphQL, RAG, cache, transaction, worker, and rollout terms."""
    if has_webhook_security_intent(text):
        for term in ("webhook security", "webhook_security"):
            if term not in terms and (term in lower or term == "webhook security"):
                terms.append(term)
    if has_privacy_compliance_intent(text):
        for term in ("privacy compliance", "privacy_compliance"):
            if term not in terms and (term in lower or term == "privacy compliance"):
                terms.append(term)
    if has_privacy_export_intent(text):
        for term in ("DSAR", "data export"):
            if term not in terms and (term.lower() in lower or term == "data export"):
                terms.append(term)
    if has_privacy_erasure_intent(text):
        for term in ("erasure", "gdpr_erasure"):
            if term not in terms and term.lower() in lower:
                terms.append(term)
    if has_privacy_pseudonymization_intent(text):
        for term in ("pseudonymize", "actor_ref"):
            if term not in terms and (term in lower or term == "pseudonymize"):
                terms.append(term)
    if has_privacy_search_index_removal_intent(text):
        for term in ("search index", "search_index"):
            if term not in terms and (term in lower or term == "search index"):
                terms.append(term)
    if has_privacy_cache_purge_intent(text):
        for term in ("cache purge", "cache"):
            if term not in terms and (term in lower or term == "cache purge"):
                terms.append(term)
    if has_privacy_legal_hold_intent(text):
        for term in ("legal hold", "legal_hold_blocked"):
            if term not in terms and (term in lower or term == "legal hold"):
                terms.append(term)
    if has_graphql_intent(text):
        for term in ("GraphQL", "graphql"):
            if term not in terms and (term.lower() in lower or term == "GraphQL"):
                terms.append(term)
        if "BFF" not in terms and "bff" in lower:
            terms.append("BFF")
    if has_graphql_persisted_query_intent(text):
        for term in ("persisted query", "persistedQueryHash"):
            if term not in terms and (term.lower() in lower or term == "persisted query"):
                terms.append(term)
    if has_graphql_operation_variables_intent(text):
        for term in ("operationName", "OrderDashboardQuery", "variables", "tenantId"):
            if term not in terms and term.lower() in lower:
                terms.append(term)
    if has_graphql_field_authorization_intent(text):
        for term in ("field-level authorization", "FIELD_DENIED"):
            if term not in terms and (term.lower() in lower or term == "field-level authorization"):
                terms.append(term)
    if has_graphql_partial_error_intent(text):
        for term in ("partial data", "GraphQL errors", "HTTP 200 with errors"):
            if term not in terms and (term.lower() in lower or term == "partial data"):
                terms.append(term)
    if has_graphql_batching_intent(text):
        for term in ("DataLoader", "N+1"):
            if term not in terms and term.lower() in lower:
                terms.append(term)
    if has_graphql_mutation_intent(text):
        for term in ("mutation", "assignOrder"):
            if term not in terms and term.lower() in lower:
                terms.append(term)
    if has_graphql_cache_version_intent(text):
        for term in ("Apollo cache", "returned version"):
            if term not in terms and (term.lower() in lower or term == "returned version"):
                terms.append(term)
    if has_graphql_subscription_intent(text):
        for term in ("subscription", "orderUpdates"):
            if term not in terms and term.lower() in lower:
                terms.append(term)
    if has_reconnect_replay_intent(text) or (has_graphql_intent(text) and "lasteventid" in lower):
        for term in ("reconnect", "lastEventId"):
            if term not in terms and (term.lower() in lower or term == "reconnect"):
                terms.append(term)
    if has_graphql_introspection_guard_intent(text):
        for term in ("introspection", "__schema"):
            if term not in terms and term.lower() in lower:
                terms.append(term)
    if has_rag_grounding_intent(text):
        for term in ("RAG", "retrieval augmented", "grounded answer", "grounding"):
            if term not in terms and (term.lower() in lower or term == "RAG"):
                terms.append(term)
    if has_rag_retrieval_trace_intent(text):
        for term in ("retrieval pipeline", "retrieval_trace"):
            if term not in terms and (term in lower or term == "retrieval pipeline"):
                terms.append(term)
    if has_rag_vector_index_intent(text):
        for term in ("vector_index", "embedding_model", "top_k", "score_threshold"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_rag_citation_intent(text):
        for term in ("source_ids", "citations", "citation_spans", "quote_start"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_rag_document_version_intent(text):
        for term in ("document_version", "stale"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_rag_hallucination_guard_intent(text):
        for term in ("hallucination", "unsupported"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_rag_prompt_injection_guard_intent(text):
        for term in ("prompt injection", "prompt_injection_detected"):
            if term not in terms and (term in lower or term == "prompt injection"):
                terms.append(term)
    if has_rag_abstention_intent(text):
        for term in ("abstain", "insufficient_sources"):
            if term not in terms and (term in lower or term == "abstain"):
                terms.append(term)
    if has_hmac_signature_intent(text):
        for term in ("HMAC-SHA256", "hmac"):
            if term not in terms and term.lower() in lower:
                terms.append(term)
    if has_raw_body_integrity_intent(text):
        for term in ("raw body", "raw_body"):
            if term not in terms and (term in lower or term == "raw body"):
                terms.append(term)
    if has_timestamp_tolerance_intent(text):
        for term in ("timestamp tolerance", "timestamp_out_of_tolerance"):
            if term not in terms and (term in lower or term == "timestamp tolerance"):
                terms.append(term)
    if has_replay_window_intent(text):
        for term in ("replay window", "delivery_id"):
            if term not in terms and (term in lower or term == "replay window"):
                terms.append(term)
    if has_webhook_security_intent(text) and "signature_mismatch" in lower and "signature_mismatch" not in terms:
        terms.append("signature_mismatch")
    if has_no_persistence_side_effect_intent(text) and "no side effects" in lower and "no side effects" not in terms:
        terms.append("no side effects")
    if has_cache_consistency_intent(text):
        for term in ("cache consistency", "cache_consistency"):
            if term not in terms and (term in lower or term == "cache consistency"):
                terms.append(term)
    if has_etag_intent(text):
        for term in ("etag",):
            if term not in terms and term in lower:
                terms.append(term)
    if has_cache_control_intent(text):
        for term in ("cache-control", "stale-while-revalidate"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_if_none_match_intent(text):
        for term in ("if-none-match",):
            if term not in terms and term in lower:
                terms.append(term)
    if has_not_modified_denial_intent(text):
        for term in ("304 not modified", "not modified"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_cache_invalidation_event_intent(text):
        for term in ("cache invalidation", "cache_invalidation_event"):
            if term not in terms and (term in lower or term == "cache invalidation"):
                terms.append(term)
    if has_surrogate_key_purge_intent(text):
        for term in ("surrogate-key purge", "surrogate_key"):
            if term not in terms and (term in lower or term == "surrogate-key purge"):
                terms.append(term)
    if has_stale_revalidation_intent(text):
        for term in ("stale-while-revalidate",):
            if term not in terms and term in lower:
                terms.append(term)
    if has_origin_fetch_intent(text):
        for term in ("origin_fetch", "origin fetch"):
            if term not in terms and (term in lower or term == "origin fetch"):
                terms.append(term)
    if has_cache_status_intent(text):
        for term in ("cache_status", "MISS", "HIT"):
            if term not in terms and term.lower() in lower:
                terms.append(term)
    if has_stale_response_guard_intent(text):
        for term in ("stale response", "stale=true"):
            if term not in terms and (term in lower or term == "stale response"):
                terms.append(term)
    if has_version_token_intent(text):
        for term in ("version token", "item_version"):
            if term not in terms and (term in lower or term == "version token"):
                terms.append(term)
    if has_transaction_integrity_intent(text):
        for term in ("checkout transaction", "transaction integrity", "transaction_id", "atomic commit"):
            if term not in terms and (term in lower or term in {"checkout transaction", "transaction integrity"}):
                terms.append(term)
    if has_payment_authorization_intent(text):
        for term in ("payment_authorization", "payment authorization"):
            if term not in terms and (term in lower or term == "payment_authorization"):
                terms.append(term)
    if has_inventory_reservation_intent(text):
        for term in ("inventory_reservation", "inventory reservation"):
            if term not in terms and (term in lower or term == "inventory_reservation"):
                terms.append(term)
    if has_transaction_outbox_intent(text):
        for term in ("outbox_event", "order.confirmed"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_saga_compensation_intent(text):
        for term in ("saga compensation", "compensation_event"):
            if term not in terms and (term in lower or term == "saga compensation"):
                terms.append(term)
    if has_inventory_release_intent(text):
        for term in ("release inventory", "inventory.release"):
            if term not in terms and (term in lower or term == "release inventory"):
                terms.append(term)
    if has_authorization_void_intent(text):
        for term in ("void authorization",):
            if term not in terms and term in lower:
                terms.append(term)
    if has_publish_exactly_once_intent(text):
        for term in ("publish exactly once", "publish_count"):
            if term not in terms and (term in lower or term == "publish exactly once"):
                terms.append(term)
    if has_trace_correlation_intent(text):
        for term in ("trace_id", "correlation_id"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_concurrency_intent(text):
        for term in ("concurrent", "parallel"):
            if term not in terms:
                terms.append(term)
    if has_locking_intent(text):
        for term in ("optimistic lock", "version_conflict"):
            if term not in terms and term in lower:
                terms.append(term)
        if "optimistic lock" not in terms and "version_conflict" not in terms:
            terms.append("optimistic lock")
    if has_conflict_response_intent(text):
        for term in ("conflict", "409"):
            if term not in terms:
                terms.append(term)
    if has_no_negative_inventory_intent(text):
        for term in ("no oversell", "below 0"):
            if term not in terms:
                terms.append(term)
    if has_background_job_intent(text):
        for term in ("enqueue", "queued", "background job"):
            if term not in terms and term in lower:
                terms.append(term)
        if "background job" not in terms and "enqueue" not in terms and "queued" not in terms:
            terms.append("background job")
    if has_worker_intent(text) and "worker" not in terms:
        terms.append("worker")
    if has_retry_backoff_intent(text):
        for term in ("retry", "exponential backoff", "backoff"):
            if term not in terms and term in lower:
                terms.append(term)
        if "retry" not in terms and "retries" in lower:
            terms.append("retry")
    if has_dead_letter_intent(text):
        for term in ("dead_letter", "dead letter"):
            if term not in terms and term in lower:
                terms.append(term)
        if "dead_letter" not in terms and "dead letter" not in terms:
            terms.append("dead_letter")
    if has_alert_outbox_intent(text):
        for term in ("alert", "alert_outbox"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_feature_flag_intent(text):
        for term in ("feature flag", "feature_flag"):
            if term not in terms and term in lower:
                terms.append(term)
        if "feature flag" not in terms and "feature_flag" not in terms:
            terms.append("feature flag")
    if has_rollout_intent(text):
        for term in ("rollout", "cohort", "cohort_match", "variant", "treatment"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_flag_default_off_intent(text):
        for term in ("default off", "default-off", "feature_flag_default_off"):
            if term not in terms and term in lower:
                terms.append(term)
        if not any(term in terms for term in ("default off", "default-off", "feature_flag_default_off")):
            terms.append("default off")
    if has_direct_api_denial_intent(text) and "feature_disabled" not in terms and "feature_disabled" in lower:
        terms.append("feature_disabled")
    if has_stale_flag_guard_intent(text):
        for term in ("stale cached flag", "stale cached"):
            if term not in terms and term in lower:
                terms.append(term)
        if "stale cached flag" not in terms and "stale cached" not in terms:
            terms.append("stale cached flag")

def append_security_workflow_terms(text: str, lower: str, terms: list[str]) -> None:
    """Append browser security, identity, key, audit, upload, and destructive-action terms."""
    if has_csrf_intent(text):
        for term in ("csrf", "x-csrf-token"):
            if term not in terms:
                terms.append(term)
        if "csrf_failed" in lower and "csrf_failed" not in terms:
            terms.append("csrf_failed")
    if has_session_rotation_intent(text):
        for term in ("session rotation", "rotates session_id"):
            if term not in terms:
                terms.append(term)
    if has_logout_invalidation_intent(text):
        for term in ("logout", "invalidated"):
            if term not in terms and (term in lower or term == "invalidated"):
                terms.append(term)
    if has_cookie_security_intent(text):
        for term in ("cookie flags", "httponly", "secure", "samesite=lax"):
            if term not in terms and (term in lower or term == "cookie flags"):
                terms.append(term)
    if has_oauth_intent(text):
        for term in ("oauth", "pkce"):
            if term not in terms and (term in lower or term == "oauth"):
                terms.append(term)
    if has_redirect_security_intent(text):
        for term in ("redirect_uri", "allowlisted"):
            if term not in terms and (term in lower or term == "redirect_uri"):
                terms.append(term)
    if has_oauth_code_exchange_intent(text):
        for term in ("authorization code", "code exchange"):
            if term not in terms:
                terms.append(term)
    if has_oauth_state_intent(text) or has_oauth_nonce_intent(text):
        for term in ("state", "nonce"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_oauth_replay_guard_intent(text):
        for term in ("replay", "consumed"):
            if term not in terms and (term in lower or term == "replay"):
                terms.append(term)
    if has_open_redirect_guard_intent(text):
        for term in ("open redirect", "return_to"):
            if term not in terms and (term in lower or term == "open redirect"):
                terms.append(term)
    if has_saml_intent(text):
        for term in ("saml", "sso"):
            if term not in terms and (term in lower or term == "saml"):
                terms.append(term)
    if has_saml_request_intent(text):
        for term in ("authnrequest", "samlrequest", "relaystate", "acs", "assertionconsumerserviceurl"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_saml_signature_intent(text):
        for term in ("xml signature", "x509"):
            if term not in terms and (term in lower or term == "xml signature"):
                terms.append(term)
    if has_saml_audience_recipient_intent(text):
        for term in ("audiencerestriction", "destination", "recipient"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_saml_in_response_to_intent(text) and "inresponseto" not in terms and "inresponseto" in lower:
        terms.append("inresponseto")
    if has_saml_time_window_intent(text):
        for term in ("notbefore", "notonorafter"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_saml_attribute_mapping_intent(text):
        for term in ("nameid", "group attribute"):
            if term not in terms and (term in lower or term == "group attribute"):
                terms.append(term)
    if has_saml_replay_guard_intent(text) and "replay" not in terms:
        terms.append("replay")
    if has_webauthn_intent(text):
        for term in ("webauthn", "passkey"):
            if term not in terms and (term in lower or term == "webauthn"):
                terms.append(term)
    if has_webauthn_challenge_intent(text):
        for term in ("challenge", "pending"):
            if term not in terms and (term in lower or term == "challenge"):
                terms.append(term)
    if has_webauthn_origin_rp_intent(text):
        for term in ("rpid", "rpidhash", "origin", "clientdatajson"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_webauthn_assertion_intent(text):
        for term in ("credentialid", "signature", "public key"):
            if term not in terms and (term in lower or term == "public key"):
                terms.append(term)
    if has_webauthn_sign_count_intent(text):
        for term in ("signcount", "last_sign_count"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_webauthn_replay_guard_intent(text) and "replay" not in terms:
        terms.append("replay")
    if has_webauthn_attestation_intent(text):
        for term in ("attestationobject", "credential_public_key"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_mfa_intent(text):
        for term in ("mfa", "mfa_required"):
            if term not in terms and (term in lower or term == "mfa"):
                terms.append(term)
    if has_totp_intent(text):
        for term in ("totp", "time window"):
            if term not in terms and (term in lower or term == "totp"):
                terms.append(term)
    if has_mfa_intent(text) and has_word(lower, r"\bclock_skew_seconds\b", r"\bclock\s+skew\b"):
        for term in ("clock_skew_seconds", "clock skew"):
            if term not in terms and (term in lower or term == "clock skew"):
                terms.append(term)
    if has_mfa_recovery_code_intent(text):
        for term in ("recovery code", "used_at"):
            if term not in terms and (term in lower or term == "recovery code"):
                terms.append(term)
    if has_mfa_replay_guard_intent(text):
        for term in ("replay", "reused challenge"):
            if term not in terms and (term in lower or term == "replay"):
                terms.append(term)
    if has_mfa_pending_intent(text):
        for term in ("mfa_pending", "pending"):
            if term not in terms and (term in lower or term == "mfa_pending"):
                terms.append(term)
    if has_one_time_token_intent(text):
        for term in ("password reset", "forgot password", "one-time token", "reset_token_hash"):
            if term not in terms and (term in lower or term in {"password reset", "one-time token"}):
                terms.append(term)
    if has_account_enumeration_guard_intent(text) and has_one_time_token_intent(text):
        for term in ("generic success", "unknown emails", "account enumeration"):
            if term not in terms and (term in lower or term in {"generic success", "unknown emails"}):
                terms.append(term)
    if has_one_time_token_expiry_intent(text) and "expires_at" not in terms and "expires_at" in lower:
        terms.append("expires_at")
    if has_one_time_token_email_link_intent(text):
        for term in ("notification_outbox", "reset email", "email link"):
            if term not in terms and (term in lower or term in {"reset email", "email link"}):
                terms.append(term)
    if has_one_time_token_password_update_intent(text) and "password_hash" not in terms and "password_hash" in lower:
        terms.append("password_hash")
    if has_one_time_token_session_invalidation_intent(text):
        for term in ("invalidate all existing sessions", "active sessions"):
            if term not in terms and (term in lower or term == "invalidate all existing sessions"):
                terms.append(term)
    if has_one_time_token_replay_guard_intent(text):
        for term in ("replay", "wrong-purpose", "wrong-tenant"):
            if term not in terms and (term in lower or term == "replay"):
                terms.append(term)
    if has_api_key_intent(text):
        for term in ("api key", "personal access token"):
            if term not in terms and (term in lower or term == "api key"):
                terms.append(term)
    if has_api_key_secret_once_intent(text):
        for term in ("secret once", "copy panel"):
            if term not in terms and (term in lower or term == "secret once"):
                terms.append(term)
    if has_api_key_hash_intent(text):
        for term in ("hash only", "key_hash"):
            if term not in terms and (term in lower or term == "hash only"):
                terms.append(term)
    if has_api_key_prefix_intent(text) and "key_prefix" not in terms and "key_prefix" in lower:
        terms.append("key_prefix")
    if has_api_key_scope_intent(text):
        for term in ("scopes", "insufficient_scope"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_api_key_last_used_intent(text) and "last_used_at" not in terms and "last_used_at" in lower:
        terms.append("last_used_at")
    if has_api_key_revocation_intent(text):
        for term in ("revoked_at", "revokes"):
            if term not in terms and (term in lower or term == "revokes"):
                terms.append(term)
    if has_api_key_denial_intent(text) and "generic unauthorized" not in terms and "generic unauthorized" in lower:
        terms.append("generic unauthorized")
    if has_api_key_secret_leak_guard_intent(text):
        for term in ("no leak", "Authorization"):
            if term not in terms and (term.lower() in lower or term == "no leak"):
                terms.append(term)
    if has_audit_integrity_intent(text):
        for term in ("audit log", "audit event"):
            if term not in terms and (term in lower or term == "audit log"):
                terms.append(term)
    if has_audit_append_only_intent(text):
        for term in ("append-only", "immutable"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_audit_hash_chain_intent(text):
        for term in ("previous_hash", "event_hash"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_audit_canonical_json_intent(text) and "canonical JSON" not in terms and "canonical json" in lower:
        terms.append("canonical JSON")
    if has_audit_tamper_denial_intent(text):
        for term in ("tamper", "audit_integrity_violation"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_audit_retention_intent(text) or has_audit_legal_hold_intent(text):
        for term in ("retention_expires_at", "legal_hold"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_audit_pseudonym_redaction_intent(text):
        for term in ("pseudonym", "actor_ref", "privacy-deleted"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_audit_integrity_leak_guard_intent(text):
        for term in ("no leak", "raw IP"):
            if term not in terms and (term.lower() in lower or term == "no leak"):
                terms.append(term)
    if has_rate_limit_intent(text):
        for term in ("rate limit", "rate_limited", "429", "failed_attempt_count"):
            if term not in terms and (term in lower or term in {"rate limit", "failed_attempt_count"}):
                terms.append(term)
    if has_retry_after_intent(text) and "Retry-After" not in terms:
        terms.append("Retry-After")
    if has_lockout_intent(text):
        for term in ("lockout", "cooldown"):
            if term not in terms and (term in lower or term == "lockout"):
                terms.append(term)
    if has_account_enumeration_guard_intent(text):
        for term in ("generic error", "account enumeration"):
            if term not in terms:
                terms.append(term)
    if has_rate_limit_intent(text) and "reset" in lower and "reset" not in terms:
        terms.append("reset")
    if has_secret_leak_guard_intent(text):
        for term in ("no leak", "must not leak"):
            if term not in terms:
                terms.append(term)
    if has_upload_intent(text) and "upload" not in terms:
        terms.append("upload")
    if has_file_security_intent(text):
        for term in ("malware scan", "scan_status"):
            if term not in terms:
                terms.append(term)
    if has_scan_status_intent(text):
        for term in ("pending", "clean"):
            if term not in terms and term in lower:
                terms.append(term)
    if has_quarantine_intent(text):
        for term in ("quarantined", "quarantine"):
            if term not in terms and (term in lower or term == "quarantine"):
                terms.append(term)
    if has_file_preview_intent(text):
        if "preview" not in terms:
            terms.append("preview")
    if has_signed_url_intent(text):
        for term in ("signed preview token", "signed URL"):
            if term not in terms:
                terms.append(term)
    if has_nosniff_intent(text) and "nosniff" not in terms:
        terms.append("nosniff")
    if has_file_validation_intent(text) and has_word(lower, r"\bfile\s+size\b", r"\b25mb\b", r"\blarger\s+than\b"):
        for term in ("file size validation", "25MB"):
            if term not in terms:
                terms.append(term)
    if has_bulk_action_intent(text):
        for term in ("bulk delete", "bulk-delete", "selected count", "selected_count"):
            if term not in terms and (term in lower or term in {"bulk delete", "selected count"}):
                terms.append(term)
    if has_destructive_confirmation_intent(text):
        for term in ("destructive confirmation", "confirmation modal"):
            if term not in terms:
                terms.append(term)
    if has_soft_delete_intent(text):
        for term in ("soft delete", "soft-deleted"):
            if term not in terms:
                terms.append(term)
    if has_selected_scope_intent(text):
        for term in ("unselected", "no extra ids"):
            if term not in terms and (term in lower or term == "unselected"):
                terms.append(term)
    if has_undo_intent(text) and "undo" not in terms:
        terms.append("undo")
    if has_response_header_intent(text):
        if "content-disposition" in lower and "content-disposition" not in terms:
            terms.append("content-disposition")
        if "filename" in lower and "filename" not in terms:
            terms.append("filename")

def workflow_terms_from_text(text: str) -> list[str]:
    lower = text.lower()
    terms: list[str] = []
    for word in WORKFLOW_ACTION_WORDS:
        if re.search(rf"\b{re.escape(word)}\b", lower) and word not in terms:
            terms.append(word)
    if has_forbidden_text_absence_intent(text) and "forbidden text absence" not in terms:
        terms.append("forbidden text absence")
    if has_negative_request_intent(text) and "forbidden request absence" not in terms:
        terms.append("forbidden request absence")
    for status_phrase in re.findall(r"\bHTTP\s+([1-5][0-9]{2})\s+with\s+errors?\b", text, flags=re.IGNORECASE):
        term = f"HTTP {status_phrase} with errors"
        if term not in terms:
            terms.append(term)
    for status_code in explicit_http_statuses(text, default=None):
        status_text = str(status_code)
        if status_text not in terms:
            terms.append(status_text)
    append_experience_workflow_terms(text, lower, terms)
    append_platform_workflow_terms(text, lower, terms)
    append_distributed_workflow_terms(text, lower, terms)
    append_security_workflow_terms(text, lower, terms)
    for term in ("审批", "批准", "创建", "更新", "删除", "提交", "保存", "发送", "搜索", "刷新", "持久化", "完成", "上传", "过滤", "升级", "流式", "校验", "验证", "继续"):
        if term in text and term not in terms:
            terms.append(term)
    return terms

def evidence_layers_for_test_type(test_type: str) -> list[str]:
    mapping = {
        "ui": ["ui"],
        "logic": ["ui", "logic"],
        "interaction": ["ui_interaction"],
        "optimistic_ui": ["optimistic_update", "temp_id", "pending_state", "rollback", "failed_state", "retry_action", "cache_invalidation", "stale_data_guard"],
        "schema_migration": ["schema_migration", "migration_plan", "migration_dry_run", "schema_version", "schema_diff", "backfill_count", "batch_checkpoint", "index_concurrently", "foreign_key_constraint", "not_null_constraint", "zero_null_verification", "rollback_plan", "backward_compatibility", "api_response"],
        "authorization_policy": ["authorization_policy", "policy_matrix", "policy_decision", "matched_rule", "deny_precedence", "role_inheritance", "resource_scope", "obligation", "direct_api_denial", "no_persistence_side_effect", "policy_cache_key", "stale_policy_guard", "audit_log", "api_response"],
        "financial_ledger": ["financial_ledger", "ledger_entry", "double_entry", "ledger_balance", "immutable_ledger", "reversal_entry", "minor_unit_amount", "no_float_drift", "over_refund_denial", "idempotency_key", "duplicate_absence", "settlement_event", "payout_reconciliation", "audit_log", "api_response"],
        "quota_metering": ["quota_metering", "usage_counter", "quota_window", "quota_remaining", "atomic_increment", "counter_version", "quota_exceeded_denial", "no_negative_remaining", "idempotency_key", "duplicate_absence", "billing_usage_event", "reset_boundary", "audit_log", "api_response"],
        "transaction_integrity": ["transaction_integrity", "transaction_id", "atomic_commit", "order_state", "payment_authorization", "inventory_reservation", "outbox_event", "outbox_dispatch", "post_commit_publish", "publish_exactly_once", "idempotency_key", "duplicate_absence", "saga_compensation", "compensation_event", "inventory_release", "authorization_void", "correlation_id", "trace_id", "audit_log", "api_response"],
        "subscription_billing": ["subscription_billing", "subscription_id", "current_plan", "target_plan", "subscription_version", "billing_cycle", "billing_anchor", "proration_behavior", "invoice_preview", "proration_line_item", "unused_credit", "prorated_charge", "tax_jurisdiction", "tax_rate", "tax_amount", "invoice_total", "calculation_version", "payment_intent", "scheduled_capture", "scheduled_change", "idempotency_key", "duplicate_absence", "authorization_denial", "forbidden text absence", "no_persistence_side_effect", "audit_log", "api_response"],
        "agent_tool": ["agent_tool", "agent_session_id", "tool_call_event", "tool_call_id", "tool_name", "tool_args_redaction", "args_hash", "approval_gate", "approval_id", "tool_result_event", "tool_result_id", "cancellation_event", "tool_execution_absence", "idempotency_key", "duplicate_absence", "authorization_denial", "handoff_required", "handoff_id", "audit_log", "persistence", "forbidden text absence", "stream", "websocket", "api_response", "request body", "runtime"],
        "artifact_generation": artifact_generation_evidence_layers(),
        "analytics": analytics_evidence_layers(),
        "offline_sync": offline_sync_evidence_layers(),
        "background_sync": ["background_sync", "service_worker", "network_offline", "network_online", "sync_batch", "retry_count", "backoff_schedule", "next_retry_at", "local_queue", "runtime"],
        "service_worker": ["service_worker", "background_sync", "network_offline", "network_online", "forbidden request absence", "runtime"],
        "local_storage": ["local_queue", "indexeddb", "encrypted_local_payload", "client_mutation_id", "payload_hash", "pending_state", "persistence"],
        "conflict_resolution": ["conflict_response", "conflict_id", "server_version", "client_version", "blocked_conflict", "merge_dialog", "merge_resolution", "if_match", "sync_version", "audit_log", "api_response"],
        "cache_consistency": ["cache_consistency", "etag", "cache_control", "if_none_match", "not_modified_denial", "cache_invalidation", "cache_key", "surrogate_key_purge", "stale_revalidation", "stale_response_guard", "origin_fetch", "cache_status", "version_token", "ui_stale_absence", "response_headers", "trace_id", "audit_log", "api_response"],
        "webhook_security": ["webhook_security", "signature_validation", "hmac_signature", "raw_body_integrity", "timestamp_tolerance", "replay_window", "signature_version", "request_headers", "request body", "idempotency_key", "duplicate_absence", "no_persistence_side_effect", "forbidden text absence", "audit_log", "api_response"],
        "privacy_compliance": ["privacy_compliance", "privacy_export", "export_artifact", "export_manifest", "encrypted_export", "data_hash", "erasure_request", "pseudonymization", "pii_redaction", "session_invalidation", "api_key_revocation", "search_index_removal", "cache_invalidation", "legal_hold", "retention_policy", "idempotency_key", "duplicate_absence", "data_isolation", "tenant_boundary", "forbidden text absence", "audit_log", "api_response"],
        "graphql": ["graphql_operation", "graphql_variables", "persisted_query_hash", "graphql_errors", "partial_data", "field_authorization", "dataloader_batch", "resolver_trace", "n_plus_one_guard", "graphql_mutation", "graphql_subscription", "subscription_event", "sequence_order", "reconnect_replay", "duplicate_absence", "tenant_boundary", "forbidden text absence", "audit_log", "api_response"],
        "rag_grounding": ["rag_grounding", "retrieval_trace", "retrieved_source_ids", "vector_index", "embedding_model", "top_k", "score_threshold", "query_hash", "source_citation", "citation_span", "source_excerpt_match", "document_version", "stale_source_guard", "hallucination_guard", "prompt_injection_guard", "safety_trace", "abstention", "insufficient_sources", "tenant_boundary", "forbidden text absence", "audit_log", "api_response"],
        "search_relevance": ["search_relevance", "search_id", "query_params", "result_order", "result_position", "relevance_score", "ranking_model", "query_rewrite", "canonical_query", "typo_tolerance", "synonym_expansion", "facet_counts", "total_count", "sponsored_disclosure", "stale_result_guard", "tenant_boundary", "forbidden text absence", "api_response"],
        "pagination": ["pagination", "result_order", "duplicate_absence", "total_count", "api_response"],
        "ui_to_api": ["ui_interaction", "api_response"],
        "api": ["api_response"],
        "api_followup": ["api_response"],
        "api_poll": ["api_response", "terminal_status"],
        "websocket": ["stream", "websocket"],
        "sse": ["stream"],
        "persistence": ["persistence"],
        "permission": ["permission"],
        "runtime": ["runtime"],
        "cleanup": ["cleanup", "cleanup_api", "extracted runtime id", "same runtime id", "always_run_teardown", "cleanup_verification", "deletion_absence", "cascade_cleanup", "outbox_absence", "audit_log", "persistence", "runtime"],
        "command": ["command"],
        "responsive": ["responsive"],
        "upload": ["file_fixture", "upload_request"],
        "download": ["download_file", "file_hash"],
        "file_content": ["download_file", "file_hash"],
        "file_security": ["malware_scan", "scan_status", "quarantine"],
        "file_preview": ["preview_rendering", "signed_url", "response_headers"],
        "notification": ["notification", "outbox"],
        "notification_policy": ["notification_policy", "notification_preferences", "preference_version", "consent_state", "consent_source", "suppression_reason", "unsubscribe_token", "quiet_hours", "send_after", "timezone", "urgent_override", "digest_key", "digest_dedupe", "event_count", "email_outbox", "no_real_email", "idempotency_key", "duplicate_absence", "forbidden text absence", "audit_log", "persistence", "runtime"],
        "idempotency": ["idempotency_key", "duplicate_absence"],
        "data_isolation": ["tenant_boundary", "data_isolation", "cross_tenant_denial"],
        "realtime": ["realtime", "broadcast_event", "stream"],
        "multi_client": ["multi_client", "broadcast_event", "stream"],
        "ordering": ["sequence_order", "duplicate_absence"],
        "reconnect": ["reconnect_replay", "sequence_order", "duplicate_absence"],
        "csrf": ["csrf_token", "csrf_header", "csrf_denial", "request_headers", "api_response"],
        "session_security": ["session_cookie", "session_rotation", "logout_invalidation", "api_response"],
        "cookie_security": ["session_cookie", "cookie_flags", "response_headers"],
        "oauth": ["oauth_state", "oauth_nonce", "pkce_challenge", "pkce_verifier", "authorization_code", "code_exchange", "api_response"],
        "redirect_security": ["redirect_location", "redirect_uri_allowlist", "open_redirect_guard", "api_response"],
        "saml": ["saml_authn_request", "saml_request", "relay_state", "saml_response", "saml_assertion", "xml_signature", "x509_certificate", "audience_restriction", "recipient", "in_response_to", "assertion_time_window", "name_id", "attribute_mapping", "request_consumption"],
        "webauthn": ["webauthn_challenge", "rp_id", "origin", "credential_id", "client_data_json", "authenticator_data", "signature_verification", "user_verification", "sign_count", "challenge_consumption"],
        "mfa": ["mfa_challenge", "mfa_pending", "totp_code", "totp_time_window", "mfa_verification", "recovery_code", "mfa_required_denial"],
        "one_time_token": ["one_time_token", "token_hash", "token_purpose", "token_expiry", "token_consumption", "token_replay_denial", "email_outbox", "email_link", "api_response"],
        "api_key": ["api_key_secret_once", "api_key_hash", "api_key_prefix", "api_key_scopes", "api_key_expiry", "api_key_last_used", "api_key_revocation", "api_key_auth_success", "api_key_scope_denial", "api_key_replay_denial", "api_response"],
        "audit_integrity": ["audit_event", "audit_sequence", "append_only", "hash_chain", "previous_hash", "event_hash", "canonical_json", "tamper_denial", "retention_policy", "legal_hold", "pii_redaction", "api_response"],
        "rate_limit": ["attempt_count", "rate_limit_key", "rate_limited_response", "retry_after_header", "lockout_state"],
        "bulk_action": ["selection_state", "selected_count", "selected_scope", "ui_interaction"],
        "destructive_guard": ["confirmation_modal", "destructive_action_guard", "forbidden request absence"],
        "undo": ["undo_action", "undo_restoration", "operation_id"],
        "time_boundary": ["date_range_boundary", "timezone"],
        "calculation": ["money_precision", "calculation_parity"],
        "accessibility": ["keyboard_navigation", "focus_management", "aria_semantics", "accessible_name"],
        "localization": ["localization", "locale_switch", "translation_catalog", "catalog_version", "translation_key_absence", "fallback_absence", "plural_rules", "rtl_layout", "lang_attribute", "dir_attribute", "currency_format", "date_time_format", "timezone", "stale_locale_guard", "ui", "ui_interaction", "api_response", "query_params", "responsive", "runtime"],
        "concurrency": ["concurrent_requests", "atomicity", "conflict_response", "locking"],
        "scheduled_job": ["scheduled_job", "schedule_expression", "scheduler_run", "run_key", "job_id", "next_run_at", "timezone", "due_window", "catch_up", "scheduler_lock", "duplicate_absence", "dry_run", "no_persistence_side_effect", "invoice_rows", "outbox", "audit_log", "persistence"],
        "background_job": ["queued_status", "job_id", "background_worker"],
        "worker": ["worker_log", "background_worker", "terminal_status"],
        "retry": ["retry_count", "backoff_schedule", "dead_letter"],
        "feature_flag": ["feature_flag", "flag_evaluation", "evaluation_id", "config_version"],
        "rollout": ["cohort_targeting", "variant", "feature_flag"],
        "input": ["input_artifact"],
    }
    return mapping.get(str(test_type), [str(test_type or "evidence")])

def evidence_layers_for_requirement(test_type: str, text: str) -> list[str]:
    if test_type == "graphql":
        layers = graphql_evidence_layers(text)
    else:
        layers = evidence_layers_for_test_type(test_type)
        for layer in requirement_specific_evidence_layers(text):
            if layer not in layers:
                layers.append(layer)
    lower = text.lower()
    if test_type == "command" and ("stdout json" in lower or "stdout_json" in lower):
        layers.append("stdout_json")
    if test_type == "notification" and has_no_real_email_intent(text):
        layers.append("no_real_email")
    if has_disabled_state_intent(text) and "disabled_state" not in layers:
        layers.append("disabled_state")
    if terminal_status_value(text) and "terminal_status" not in layers:
        layers.append("terminal_status")
    return filter_contextual_evidence_layers(text, layers)

def weak_signals_for_layers(layers: list[str]) -> list[str]:
    weak: list[str] = []
    if "ui" in layers or "ui_interaction" in layers:
        weak.append("Visible text or screenshots without actionability/API/state evidence.")
    if "analytics" in layers or "analytics_event" in layers:
        weak.append("Analytics accepted without captured event payload, schema version, consent state, event id, and persisted analytics row evidence.")
    if "consent_state" in layers or "consent_version" in layers:
        weak.append("Tracking success accepted without proving no event is emitted when analytics consent is false or missing.")
    if "attribution_id" in layers or "experiment_exposure" in layers:
        weak.append("Conversion attribution accepted without same-session attribution, persisted experiment exposure, and mismatch denial evidence.")
    if "event_time" in layers or "event_batch" in layers:
        weak.append("Telemetry timing accepted without captured event_time, batch contents, and duplicate absence evidence.")
    if "optimistic_update" in layers or "rollback" in layers:
        weak.append("Optimistic UI state accepted without proving failure rollback, cache invalidation, no success toast, and no persisted side effect.")
    if "temp_id" in layers or "pending_state" in layers:
        weak.append("Temporary client id accepted as success without replacement by a server id on retry success.")
    if "cache_invalidation" in layers:
        weak.append("Refresh or retry accepted without proving stale cached success data was invalidated.")
    if "no_success_toast" in layers:
        weak.append("Failed optimistic mutation accepted without proving the success toast is absent.")
    if "schema_migration" in layers or "migration_plan" in layers or "migration_dry_run" in layers:
        weak.append("Migration command exit 0 accepted without proving expand-contract order, dry-run JSON, schema version, rollback, and compatibility evidence.")
    if "backfill_count" in layers or "batch_checkpoint" in layers:
        weak.append("Backfill accepted without exact affected-row count and batch checkpoint evidence for the same migration id.")
    if "index_concurrently" in layers or "foreign_key_constraint" in layers or "not_null_constraint" in layers:
        weak.append("Schema change accepted without captured concurrent-index, validated foreign-key, zero-null, and NOT NULL constraint evidence.")
    if "rollback_plan" in layers or "backward_compatibility" in layers:
        weak.append("Migration accepted without reversible rollback proof and old/new client API compatibility evidence.")
    if "authorization_policy" in layers or "policy_decision" in layers:
        weak.append("Authorization accepted from a hidden button or one 403 without captured policy decision, matched rule, resource scope, no-side-effect, and audit evidence.")
    if "deny_precedence" in layers or "role_inheritance" in layers:
        weak.append("Role check accepted without proving explicit deny overrides inherited or wildcard permissions.")
    if "policy_cache_key" in layers or "stale_policy_guard" in layers:
        weak.append("Policy cache accepted without actor/resource/action/tenant cache-key proof and stale-allow invalidation after policy change.")
    if "financial_ledger" in layers or "double_entry" in layers or "ledger_balance" in layers:
        weak.append("Refund/payment success accepted without proving balanced debit/credit ledger entries, same-currency zero net balance, and original-entry immutability.")
    if "immutable_ledger" in layers or "reversal_entry" in layers:
        weak.append("Refund accepted without proving original ledger entries were not mutated and reversal entries link to the original transaction.")
    if "minor_unit_amount" in layers or "no_float_drift" in layers:
        weak.append("Money movement accepted without proving minor-unit cents arithmetic and absence of floating-point drift.")
    if "over_refund_denial" in layers:
        weak.append("Over-refund denial accepted without 409 response, no extra ledger entries, and no outbox or persistence side effect.")
    if "settlement_event" in layers or "payout_reconciliation" in layers:
        weak.append("Refund settlement accepted without provider-event, settlement-worker, payout reconciliation, and audit correlation evidence.")
    if "quota_metering" in layers or "usage_counter" in layers or "quota_remaining" in layers:
        weak.append("Usage quota accepted without proving the same tenant, meter key, quota window, counter row, used/remaining values, and response body.")
    if "atomic_increment" in layers or "counter_version" in layers or "no_negative_remaining" in layers:
        weak.append("Quota concurrency accepted without captured winner/loser requests, counter-version transition, and persisted non-negative remaining balance.")
    if "quota_exceeded_denial" in layers:
        weak.append("Quota-exceeded denial accepted without 409/denial body plus no downstream job, outbox, billing, or counter side effect.")
    if "billing_usage_event" in layers:
        weak.append("Billing usage accepted without proving exactly one billing event for the accepted usage event and none for denied or duplicate requests.")
    if "reset_boundary" in layers:
        weak.append("Quota reset accepted without exact window-boundary fixture, previous-period carryover, reset audit event, and no early reset proof.")
    if "transaction_integrity" in layers or "atomic_commit" in layers or "transaction_id" in layers:
        weak.append("Checkout success accepted without proving the same transaction id and atomic commit across order, payment, inventory, and outbox rows.")
    if "outbox_event" in layers or "outbox_dispatch" in layers or "post_commit_publish" in layers or "publish_exactly_once" in layers:
        weak.append("Outbox success accepted without proving post-commit publish timing, exactly-once publish_count, and no pre-commit or duplicate dispatch.")
    if "saga_compensation" in layers or "compensation_event" in layers or "inventory_release" in layers or "authorization_void" in layers:
        weak.append("Saga compensation accepted without proving inventory release, authorization void, failed order state, no confirmed outbox event, and no receipt side effect.")
    if "subscription_billing" in layers or "subscription_version" in layers or "invoice_preview" in layers:
        weak.append("Subscription plan-change accepted without proving preview no-mutation behavior, confirmed subscription_version transition, invoice/payment rows, and audit boundaries.")
    if "proration_behavior" in layers or "unused_credit" in layers or "prorated_charge" in layers or "tax_jurisdiction" in layers:
        weak.append("Subscription proration accepted without proving unused credit, prorated charge, tax jurisdiction/rate/amount, invoice total, and calculation version for the same preview id.")
    if "scheduled_capture" in layers or "scheduled_change" in layers:
        weak.append("Subscription schedule accepted without proving scheduled capture/change timing, current-plan preservation until renewal, and no immediate payment/refund side effects.")
    if "authorization_denial" in layers:
        weak.append("Plan-change denial accepted without proving denied actor, 403 body, no subscription/invoice/payment mutation, and no billing.plan_changed audit row.")
    if "agent_tool" in layers or "tool_call_event" in layers:
        weak.append("Agent-tool run accepted from generic stream/API success without proving tool_call_requested, tool identity, approval gate, tool result/cancel/handoff events, and same agent_session_id binding.")
    if "tool_args_redaction" in layers or "args_hash" in layers:
        weak.append("Agent tool arguments accepted without proving args_hash binding and raw ssn/payment_token absence in stream, API, logs, and reports.")
    if "approval_gate" in layers or "approval_id" in layers:
        weak.append("Tool approval accepted without proving approval_required appeared before execution and final answer stayed disabled until approval.")
    if "tool_execution_absence" in layers or "cancellation_event" in layers:
        weak.append("Tool cancellation/denial accepted without proving executor non-invocation, no tool_result, and no outbound payment/refund or audit side effects.")
    if "handoff_required" in layers or "handoff_id" in layers:
        weak.append("Agent handoff accepted without proving tool_timeout reason, needs_human_review persistence, human review queue row, and absence of successful answer_done.")
    if "artifact_generation" in layers or "artifact_manifest" in layers:
        weak.append("Artifact export accepted from queued/API success without artifact_ready, manifest id/hash, content hash, retention, audit, and persistence evidence.")
    if "progress_event" in layers or "artifact_ready" in layers:
        weak.append("Async artifact job accepted without ordered progress events and a terminal artifact_ready event for the same job id.")
    if "resume_token" in layers or "checkpoint" in layers:
        weak.append("Artifact resume accepted without checkpoint binding, same artifact id, and duplicate page/file absence.")
    if "temp_object_absence" in layers or "partial_failure" in layers:
        weak.append("Artifact cancel or partial failure accepted without temp-object cleanup, failed section diagnostics, and non-green UI state proof.")
    if "authorization_denial" in layers and ("download_file" in layers or "content_disposition" in layers):
        weak.append("Artifact download guard accepted without denied-viewer 403, signed_url/storage_key/content_hash leak absence, and no download audit side effect.")
    if "trace_id" in layers or "correlation_id" in layers:
        weak.append("Trace/correlation evidence accepted without proving the same ids across order, payment, inventory, outbox, audit, and worker evidence.")
    if "cache_consistency" in layers or "etag" in layers or "if_none_match" in layers:
        weak.append("Cache behavior accepted from one 200 response without proving ETag/If-None-Match revalidation, 304 denial after mutation, and version-token freshness.")
    if "cache_invalidation" in layers or "cache_key" in layers or "surrogate_key_purge" in layers:
        weak.append("Cache invalidation accepted without proving the specific cache key, surrogate-key purge, origin refresh, and audit/invalidation event.")
    if "stale_revalidation" in layers or "stale_response_guard" in layers:
        weak.append("Stale-while-revalidate accepted without bounded stale age, Warning header, MISS-to-HIT transition, and no resurrection of old body data.")
    if "ui_stale_absence" in layers:
        weak.append("UI refresh accepted without binding the visible row to the returned version token and proving stale cached/fallback data is absent.")
    if "api_response" in layers:
        weak.append("HTTP status alone without response body, same-object id, or checked JSON evidence.")
    if "stream" in layers:
        weak.append("Prompt/request marker only, zero stream messages, or missing terminal event evidence.")
    if "realtime" in layers or "broadcast_event" in layers:
        weak.append("Single-client stream success without proving the named live event was broadcast to the other subscribed client.")
    if "multi_client" in layers:
        weak.append("One browser/session success without two independently identified client connections and recipient-side evidence.")
    if "sequence_order" in layers:
        weak.append("Received event accepted without captured sequence ordering and duplicate-absence evidence.")
    if "reconnect_replay" in layers:
        weak.append("Reconnect accepted without cursor-bound replay evidence proving exactly-once catch-up and resumed live events.")
    if "persistence" in layers or "terminal_status" in layers:
        weak.append("Seed data, fallback text, or handwritten terminal-state notes without returned/persisted status evidence.")
    if "permission" in layers:
        weak.append("Single-role success without denied-role evidence when authorization is part of the requirement.")
    if "runtime" in layers:
        weak.append("Ignoring console/network failures without count-aware runtime disposition evidence.")
    if "responsive" in layers:
        weak.append("Single desktop screenshot without mobile viewport, overflow, or visibility evidence.")
    if "localization" in layers or "translation_catalog" in layers:
        weak.append("Localized UI text accepted without catalog version, missing-key, fallback-count, and raw-key absence evidence.")
    if "plural_rules" in layers or "locale_switch" in layers:
        weak.append("Single-locale screenshot accepted without locale switch, plural-form rows, and stale-catalog/cache guard evidence.")
    if "rtl_layout" in layers or "lang_attribute" in layers or "dir_attribute" in layers:
        weak.append("RTL/localized layout accepted without html lang/dir assertions, mirrored layout checks, and overflow evidence.")
    if "currency_format" in layers or "date_time_format" in layers:
        weak.append("Localized amount/date text accepted without Intl/locale/timezone parity and unchanged API value evidence.")
    if "disabled_state" in layers:
        weak.append("Assuming a button is usable from text alone without explicit enabled/disabled state evidence.")
    if "file_fixture" in layers:
        weak.append("Upload UI evidence without a named safe test file fixture and file content boundary.")
    if "upload_request" in layers or "multipart_request" in layers:
        weak.append("Upload success wording without captured multipart request evidence and redacted file/marker assertions.")
    if "request_marker" in layers:
        weak.append("Marker present only in the intended upload input, not in returned API, UI, log, or persistence evidence.")
    if "progress_indicator" in layers:
        weak.append("Final success text without progress or async transition evidence for the same upload/import id.")
    if "file_validation" in layers:
        weak.append("Invalid file validation copy without proving the forbidden upload request was absent.")
    if "file_size_validation" in layers:
        weak.append("Large-file validation accepted without proving the oversized fixture was rejected before any upload request.")
    if "malware_scan" in layers or "scan_status" in layers:
        weak.append("Attachment upload accepted without proving scan pending/clean/quarantined status transitions for the same attachment id.")
    if "quarantine" in layers:
        weak.append("Malware upload accepted without quarantine state, scan engine/version, no-preview/download proof, and audit evidence.")
    if "preview_rendering" in layers:
        weak.append("Preview success accepted without proving only a clean scanned file rendered under the same workspace.")
    if "signed_url" in layers:
        weak.append("Preview/download accepted without signed URL/token binding and forbidden signed URL leak checks.")
    if "nosniff" in layers:
        weak.append("File preview accepted without captured X-Content-Type-Options nosniff response header.")
    if "storage_key_redaction" in layers:
        weak.append("Storage key redaction accepted without proving the key is absent from response bodies, URLs, logs, and report artifacts.")
    if "download_file" in layers or "file_hash" in layers:
        weak.append("Export/download success without a current-run downloaded file artifact and content hash.")
    if "response_headers" in layers:
        weak.append("Download response accepted without captured content-type/content-disposition headers.")
    if "csv_schema" in layers or "row_count" in layers:
        weak.append("Downloaded CSV not parsed for required headers, data rows, and summary parity.")
    if "pii_redaction" in layers:
        weak.append("Export accepted without forbidden PII column/value absence checks.")
    if "request_headers" in layers:
        weak.append("Webhook/API request accepted without captured required request headers.")
    if "csrf_token" in layers or "csrf_header" in layers:
        weak.append("CSRF-protected mutation accepted without proving the token was captured, sent in the expected header, and bound to the active session.")
    if "csrf_denial" in layers:
        weak.append("CSRF denial accepted without missing/stale/cross-origin token attempts, 403 response body, no-write proof, and audit evidence.")
    if "session_cookie" in layers:
        weak.append("Authenticated request success without proving the relevant session cookie identity and lifecycle.")
    if "cookie_flags" in layers:
        weak.append("Set-Cookie accepted without captured HttpOnly, Secure, and SameSite flag evidence.")
    if "session_rotation" in layers:
        weak.append("Login/refresh accepted without proving old session invalidation and new session continuity.")
    if "logout_invalidation" in layers:
        weak.append("Logout accepted without proving the logged-out session and previously valid CSRF token are rejected.")
    if "oauth_state" in layers or "oauth_nonce" in layers:
        weak.append("OAuth callback success accepted without proving state and nonce were issued, matched, consumed, and rejected on replay or mismatch.")
    if "pkce_challenge" in layers or "pkce_verifier" in layers:
        weak.append("OAuth authorization accepted without proving PKCE challenge method, code_verifier binding, and wrong-verifier denial.")
    if "authorization_code" in layers or "code_exchange" in layers:
        weak.append("OAuth callback accepted without server-side code-exchange evidence and replay denial for the same authorization code/state.")
    if "redirect_uri_allowlist" in layers or "open_redirect_guard" in layers:
        weak.append("Redirect success accepted without proving redirect_uri/return_to allowlist enforcement and external open-redirect denial.")
    if "session_creation" in layers or "oauth_account" in layers:
        weak.append("OAuth login accepted without proving the created session and provider subject were persisted for the same callback.")
    if "saml_authn_request" in layers or "saml_request" in layers:
        weak.append("SAML login accepted without proving AuthnRequest id, RelayState, ACS URL, SP entityID, pending request persistence, and redirect binding.")
    if "xml_signature" in layers or "x509_certificate" in layers:
        weak.append("SAML ACS success accepted without proving XML signature validation against the expected x509 certificate and unsigned/unknown-certificate denial.")
    if "audience_restriction" in layers or "destination" in layers or "recipient" in layers:
        weak.append("SAML assertion accepted without proving AudienceRestriction, Destination, and Recipient match the service provider and ACS endpoint.")
    if "in_response_to" in layers or "request_consumption" in layers:
        weak.append("SAML response accepted without proving InResponseTo matches a pending request, is consumed once, and replay is denied.")
    if "assertion_time_window" in layers:
        weak.append("SAML assertion accepted without proving NotBefore/NotOnOrAfter validity and expired assertion denial.")
    if "name_id" in layers or "attribute_mapping" in layers:
        weak.append("SAML login accepted without proving NameID, group/attribute mapping, and persisted saml_account/role evidence for the same assertion.")
    if "webauthn_challenge" in layers or "challenge_consumption" in layers:
        weak.append("Passkey success accepted without proving the WebAuthn challenge was issued for the same session, not expired, consumed once, and rejected on replay.")
    if "rp_id" in layers or "origin" in layers:
        weak.append("WebAuthn assertion accepted without proving clientDataJSON origin and authenticatorData rpIdHash match the expected relying party.")
    if "credential_id" in layers or "signature_verification" in layers:
        weak.append("Passkey login accepted without proving credential id lookup and stored public-key signature verification.")
    if "user_verification" in layers:
        weak.append("WebAuthn assertion accepted without proving userVerification/userVerified policy was enforced.")
    if "sign_count" in layers:
        weak.append("Passkey assertion accepted without proving signCount increased and cloned authenticator counters were denied without session side effects.")
    if "attestation_object" in layers or "credential_public_key" in layers:
        weak.append("Passkey registration accepted without proving attestation/clientDataJSON origin binding and storage of public key material only.")
    if "mfa_challenge" in layers or "mfa_pending" in layers:
        weak.append("Password success accepted without proving a pending MFA challenge was created and no full session/token existed before verification.")
    if "totp_code" in layers or "totp_time_window" in layers or "clock_skew" in layers:
        weak.append("MFA success accepted without proving TOTP code, current time window, allowed clock skew, and expired/wrong-code denial.")
    if "mfa_verification" in layers or ("session_creation" in layers and "mfa_challenge" in layers):
        weak.append("MFA verification accepted without proving the challenge rotated to verified and session creation happened only after MFA.")
    if "recovery_code" in layers or "recovery_code_consumption" in layers:
        weak.append("Recovery-code MFA accepted without proving hashed storage, used_at consumption, and replay denial.")
    if "mfa_required_denial" in layers:
        weak.append("Protected API denial accepted without proving mfa_pending requests return mfa_required and persist no protected side effect.")
    if "one_time_token" in layers or "token_hash" in layers:
        weak.append("Password reset, magic-link, or email-verification success without token hash, purpose, expiry, one-time consumption, replay denial, and no-enumeration evidence.")
    if "email_outbox" in layers or "email_link" in layers:
        weak.append("Email sent wording without current-run outbox row, safe recipient boundary, and redacted one-time link evidence.")
    if "session_invalidation" in layers:
        weak.append("Password reset accepted without proving existing sessions were invalidated and no new login session was created automatically.")
    if "api_key_secret_once" in layers or "api_key_hash" in layers:
        weak.append("API key creation accepted without proving the raw secret appears only once and persisted/listed records expose only hash-safe prefix metadata.")
    if "api_key_scopes" in layers or "api_key_scope_denial" in layers:
        weak.append("API key authorization accepted without proving scoped allow/deny behavior and no mutation for insufficient-scope requests.")
    if "api_key_last_used" in layers or "api_key_revocation" in layers:
        weak.append("API key lifecycle accepted without proving last_used_at updates, revoked_at state, revoked/expired/tampered denial, and audit evidence.")
    if "audit_event" in layers or "hash_chain" in layers:
        weak.append("Audit log visibility accepted without proving append-only writes, monotonic sequence, previous_hash/event_hash recomputation, and current-run event readability.")
    if "tamper_denial" in layers:
        weak.append("Audit integrity accepted without proving PATCH/DELETE tamper attempts are denied and leave sequence/hash/event fields unchanged.")
    if "retention_policy" in layers or "legal_hold" in layers:
        weak.append("Privacy deletion accepted without proving legal-hold retention, pseudonymized actor reference, and forbidden PII/raw-IP absence in audit APIs, logs, and reports.")
    if "attempt_count" in layers or "rate_limit_key" in layers:
        weak.append("Rate-limit claim without proving the exact attempt counter and account/client key used for throttling.")
    if "rate_limited_response" in layers or "retry_after_header" in layers:
        weak.append("429/Retry-After accepted without captured response body and response-header evidence for the limiting attempt.")
    if "lockout_state" in layers or "lockout_expiry" in layers:
        weak.append("Lockout accepted without persisted lockout expiry, cooldown UI, and post-window reset evidence.")
    if "no_session_created" in layers:
        weak.append("Denied login accepted without proving no session, Set-Cookie, or refresh token was created.")
    if "account_enumeration_guard" in layers:
        weak.append("Generic login error accepted without comparing existing and unknown accounts for account-enumeration leakage.")
    if "selection_state" in layers or "selected_count" in layers:
        weak.append("Bulk action accepted without proving the exact selected rows/count before the destructive control became enabled.")
    if "selected_scope" in layers or "unselected_unchanged" in layers:
        weak.append("Bulk mutation accepted without proving only the selected ids changed and unselected rows remained unchanged.")
    if "confirmation_modal" in layers or "destructive_action_guard" in layers:
        weak.append("Destructive action accepted without proving confirmation text, cancel/Escape no-request behavior, and request absence before confirmation.")
    if "soft_delete" in layers or "deleted_at" in layers or "deleted_by" in layers:
        weak.append("Delete success accepted without proving soft-delete fields and absence of hard deletion.")
    if "undo_action" in layers or "undo_restoration" in layers:
        weak.append("Undo UI accepted without operation-id binding, restore-state evidence, and undo audit/log evidence.")
    if "operation_id" in layers:
        weak.append("Operation success accepted without carrying the same operation_id across API, UI, audit, undo, and persistence checks.")
    if "signature_validation" in layers:
        weak.append("Webhook success path without invalid-signature rejection and no-write evidence.")
    if "webhook_security" in layers or "hmac_signature" in layers or "raw_body_integrity" in layers:
        weak.append("Webhook signature accepted without proving HMAC over exact raw body bytes, malformed/reordered body rejection, and no side effects.")
    if "timestamp_tolerance" in layers:
        weak.append("Webhook timestamp accepted without proving out-of-tolerance denial and rejected-event audit evidence.")
    if "replay_window" in layers:
        weak.append("Webhook replay accepted without proving delivery id replay-window behavior, duplicate_ignored response, and duplicate side-effect absence.")
    if "signature_version" in layers:
        weak.append("Webhook signature accepted without preserving and auditing the verified signature version.")
    if "privacy_compliance" in layers or "privacy_export" in layers or "erasure_request" in layers:
        weak.append("Privacy export/erasure accepted without proving DSAR artifact manifest, encrypted export, erasure side effects, legal-hold behavior, and PII leak absence.")
    if "graphql_operation" in layers or "graphql_errors" in layers or "graphql_mutation" in layers:
        weak.append("GraphQL HTTP 200 or visible dashboard data accepted without proving operationName, variables, data/errors shape, field-level authorization, resolver batching, mutation side effects, and forbidden-field leak absence.")
    if "graphql_subscription" in layers or "subscription_event" in layers:
        weak.append("GraphQL subscription accepted without proving another subscribed client received the same ordered event, reconnect replay worked, and duplicate events were absent.")
    if "dataloader_batch" in layers or "n_plus_one_guard" in layers:
        weak.append("GraphQL resolver success accepted without resolver_trace or DataLoader batching evidence proving no N+1 query behavior.")
    if "rag_grounding" in layers or "retrieval_trace" in layers or "source_citation" in layers:
        weak.append("RAG answer accepted from UI text or stream completion without proving retrieval trace, source ids, citation spans, source excerpt matches, and grounding for every factual sentence.")
    if "prompt_injection_guard" in layers:
        weak.append("RAG safety accepted without proving malicious retrieved prompt text was treated as untrusted content and secrets/system prompt stayed absent.")
    if "abstention" in layers or "insufficient_sources" in layers:
        weak.append("No-source RAG answer accepted without proving abstention, absence of citation rows, and audit evidence for insufficient sources.")
    if "search_index_removal" in layers or "cache_invalidation" in layers:
        weak.append("Privacy erasure accepted without proving search-index removal and cache purge for the same subject user.")
    if "pseudonymization" in layers:
        weak.append("Privacy erasure accepted without proving pseudonymized actor references while preserving required audit/ledger retention.")
    if "offline_sync" in layers or "local_queue" in layers:
        weak.append("Offline draft UI accepted without proving offline request absence, encrypted IndexedDB/local outbox state, reconnect sync, server acknowledgement, and queue drain for the same client_mutation_id.")
    if "service_worker" in layers or "background_sync" in layers:
        weak.append("Background sync accepted without service-worker/background-sync evidence, retry scheduling, and no duplicate side effects.")
    if "conflict_id" in layers or "merge_dialog" in layers or "merge_resolution" in layers:
        weak.append("409 conflict accepted without proving blocked local queue state, server/local value comparison, If-Match merge request, resolved status, and conflict audit log.")
    if "next_retry_at" in layers or "backoff_schedule" in layers:
        weak.append("Retry scheduled wording accepted without retry_count, next_retry_at, backoff schedule, and unchanged pending outbox evidence.")
    if "idempotency_key" in layers or "duplicate_absence" in layers:
        weak.append("Replay accepted without proving same idempotency key produced no duplicate row or side effect.")
    if "audit_log" in layers:
        weak.append("Audit claim without current-run audit/log event evidence for the same id or marker.")
    if "outbox" in layers or "notification" in layers:
        weak.append("Notification claim without outbox/worker evidence and recipient-safe preview.")
    if "notification_policy" in layers or "notification_preferences" in layers or "quiet_hours" in layers:
        weak.append("Notification policy accepted from generic outbox success without preference version, consent source, suppression reason, quiet-hours/send_after, digest dedupe, unsubscribe-token, and no-real-email proof.")
    if "no_real_email" in layers:
        weak.append("Email dry-run accepted without proving no real external email was sent.")
    if "tenant_boundary" in layers or "data_isolation" in layers:
        weak.append("Single-tenant success without cross-tenant denial and same-tenant row-set parity evidence.")
    if "cross_tenant_denial" in layers:
        weak.append("Cross-tenant access claim without 403/404 response evidence and forbidden foreign-tenant text absence.")
    if "no_persistence_side_effect" in layers:
        weak.append("Denied access accepted without proving no access grant or other persistence side effect was created.")
    if "date_range_boundary" in layers or "timezone" in layers:
        weak.append("Date filter accepted without timezone-aware request binding, inclusive start, and exclusive end row evidence.")
    if "dst_boundary" in layers:
        weak.append("DST boundary accepted without proving nonexistent or ambiguous local times are rejected or visibly normalized.")
    if "money_precision" in layers or "calculation_parity" in layers:
        weak.append("Monetary UI/API success without decimal arithmetic, rounding-rule, request-body, and persisted total parity evidence.")
    if "currency_conversion" in layers:
        weak.append("Currency conversion accepted without captured FX rate, rate_id, and converted-total parity evidence.")
    if "queued_status" in layers or "background_worker" in layers:
        weak.append("Queued API response accepted as completion without worker execution, same job id, and terminal-state evidence.")
    if "worker_log" in layers:
        weak.append("Worker claim without current-run worker log, job id correlation, and persisted terminal status.")
    if "retry_count" in layers or "backoff_schedule" in layers:
        weak.append("Retry claim without captured retry count, backoff schedule, and duplicate-side-effect absence.")
    if "dead_letter" in layers:
        weak.append("Dead-letter claim without max-retry evidence, dead-letter state, and correlated alert/outbox record.")
    if "alert_outbox" in layers:
        weak.append("Alert/outbox claim without current-run outbox row, correlation id, and safe recipient boundary.")
    if "feature_flag" in layers or "flag_evaluation" in layers:
        weak.append("Beta UI success without captured feature-flag evaluation, evaluation id, and config version.")
    if "cohort_targeting" in layers or "variant" in layers:
        weak.append("Single enabled user accepted without control-cohort denial and variant/cohort evidence.")
    if "default_off" in layers:
        weak.append("Flag-service failure accepted without proving default-off UI/API behavior and correlated runtime log.")
    if "direct_api_denial" in layers:
        weak.append("Hidden UI accepted without direct API denial evidence for non-enabled users.")
    if "stale_flag_guard" in layers:
        weak.append("Feature flag refresh accepted without proving stale cached flag data was not reused.")
    if "keyboard_navigation" in layers:
        weak.append("Mouse/click success without keyboard-only tab and keypress evidence.")
    if "focus_management" in layers or "focus_trap" in layers:
        weak.append("Visible modal without proving focus entry, trap boundaries, close behavior, and focus restoration.")
    if "aria_semantics" in layers or "accessible_name" in layers:
        weak.append("Rendered controls without role, aria-modal, labels, and accessible-name assertions.")
    if "concurrent_requests" in layers:
        weak.append("Sequential single-request success without simultaneous or parallel request evidence.")
    if "atomicity" in layers or "locking" in layers:
        weak.append("Happy-path mutation success without proving atomic update/lock behavior under contention.")
    if "conflict_response" in layers:
        weak.append("Conflict wording without captured loser response status/body and winner/loser correlation.")
    if "no_negative_inventory" in layers:
        weak.append("Inventory success without proving no oversell, no second decrement, and persisted non-negative quantity.")
    if "query_params" in layers:
        weak.append("Successful API status without captured request URL/query parameters and UI/API row parity.")
    if "sorting" in layers:
        weak.append("Sorted-looking UI without proving the response and rendered rows use the requested order.")
    if "pagination" in layers:
        weak.append("Page navigation text without captured page-specific request parameters and row-set evidence.")
    if "empty_state" in layers:
        weak.append("Empty-state copy without proving prior rows disappeared and no stale data remains visible.")
    if "error_state" in layers:
        weak.append("Generic error copy without a captured failed response or retryable-state assertion.")
    if "stale_data_guard" in layers:
        weak.append("Cached or fallback UI that masks an empty/error backend result.")
    if "command" in layers:
        weak.append("Command exit code alone without captured stdout/stderr artifacts and current project/environment boundary.")
    if "stdout_json" in layers:
        weak.append("Plain stdout text without parsed JSON path assertions for the required fields.")
    if "decision_table" in layers or "rule_matrix" in layers:
        weak.append("Generic command success, UI screenshot, or API 200 without fixture input rows, rule hits, and expected decisions for every branch.")
    if "rule_precedence" in layers:
        weak.append("Happy-path approval without proving override and deny precedence rows.")
    if "boundary_cases" in layers or "negative_cases" in layers:
        weak.append("Single nominal row without boundary and negative decision-table rows.")
    return weak or ["Generic success wording without current-run evidence bound to this requirement."]

def build_business_model(requirement: str, requirements: list[dict[str, Any]], tests: list[dict[str, Any]], gaps: list[str]) -> dict[str, Any]:
    tests_by_req: dict[str, list[dict[str, Any]]] = {}
    for test in tests:
        for req_id in test.get("requirement_ids", []):
            tests_by_req.setdefault(req_id, []).append(test)

    actor_index: dict[str, dict[str, Any]] = {}
    entity_index: dict[str, dict[str, Any]] = {}
    workflows: list[dict[str, Any]] = []
    transitions: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    entry_points: list[str] = []
    api_paths: list[str] = []

    for req in requirements:
        req_id = str(req.get("id") or "")
        text = str(req.get("text") or "")
        endpoint_paths = method_endpoint_paths(text)
        explicit_paths = [path for path in extract_paths(text) if not path_is_code_file_for_text(text, path)]
        inherited_api_paths = [
            str(path)
            for path in req.get("inherited_api_paths", [])
            if str(path or "")
        ]
        inherited_entry_paths = [
            str(path)
            for path in req.get("inherited_entry_points", [])
            if str(path or "") and not path_is_code_file_for_text(text, str(path))
        ]
        paths = list(dict.fromkeys([*explicit_paths, *inherited_api_paths, *inherited_entry_paths]))
        for actor in extract_actors_from_text(text):
            add_indexed_item(actor_index, actor, req_id, text)
        for entity in extract_entities_from_text(text, paths):
            add_indexed_item(entity_index, entity, req_id, text)
        for path in paths:
            if path in inherited_api_paths or path_is_api_for_text(text, path) or path_is_stream(path) or path in endpoint_paths:
                if path not in api_paths:
                    api_paths.append(path)
            elif path not in entry_points:
                entry_points.append(path)
        transitions.extend(extract_state_transitions(text, req_id))
        if re.search(r"\b(can|must|should|shall|cannot|must not|should not)\b", text, re.IGNORECASE) or has_chinese(text, "必须", "应该", "不能", "需要"):
            rules.append({"id": stable_id("BR", len(rules) + 1), "requirement_id": req_id, "text": text})
        req_tests = tests_by_req.get(req_id, [])
        workflows.append({
            "id": stable_id("W", len(workflows) + 1),
            "label": extract_workflow_label(text, paths, req_tests),
            "signals": workflow_terms_from_text(text),
            "source_requirement_ids": [req_id],
            "entry_points": [path for path in [*explicit_paths, *inherited_entry_paths] if path in entry_points],
            "api_paths": [path for path in paths if path in api_paths],
            "evidence_layers": sorted({layer for test in req_tests for layer in evidence_layers_for_requirement(str(test.get("type") or ""), text)}),
            "blocked": any(test.get("status") == "Blocked" for test in req_tests),
        })

    actors = [
        {"id": stable_id("A", index), **item}
        for index, item in enumerate(actor_index.values(), 1)
    ] or [{"id": "A1", "name": "unspecified actor", "source_requirement_ids": [], "evidence": [], "needs_confirmation": True}]
    entities = [
        {"id": stable_id("E", index), **item}
        for index, item in enumerate(entity_index.values(), 1)
    ]

    return {
        "schema_version": 1,
        "generated_from": {"requirement": "requirement.md", "matrix": "test-matrix.json", "plan": "test-plan.json"},
        "source_preview": redact(requirement[:1200]) if requirement.strip() else "",
        "actors": actors,
        "entities": entities,
        "entry_points": entry_points,
        "api_paths": api_paths,
        "workflows": workflows,
        "business_rules": rules,
        "state_transitions": transitions,
        "risk_assumptions": [
            {"id": stable_id("RA", index), "text": gap, "source": "scaffold coverage gap"}
            for index, gap in enumerate(gaps, 1)
        ],
        "agent_team_contract": {
            "business_agent": {
                "produces": ["requirement.md", "business-model.json", "oracle-model.json"],
                "must_confirm": ["actors", "business rules", "environment boundary", "data boundary"],
            },
            "qa_agent": {
                "consumes": ["requirement.md", "business-model.json", "oracle-model.json", "test-matrix.json", "test-plan.json"],
                "produces": ["evidence-ledger.json", "defects.json", "qa-verdict.json", "report.md", "closeout-candidates.json"],
            },
            "handoff_rule": "Do not treat business-model.json or oracle-model.json as proof; they are planning/oracle contracts that must be verified by current-run evidence.",
        },
    }

def build_oracle_model(requirements: list[dict[str, Any]], tests: list[dict[str, Any]]) -> dict[str, Any]:
    tests_by_req: dict[str, list[dict[str, Any]]] = {}
    for test in tests:
        for req_id in test.get("requirement_ids", []):
            tests_by_req.setdefault(req_id, []).append(test)
    oracle_requirements: list[dict[str, Any]] = []
    for req in requirements:
        req_id = str(req.get("id") or "")
        req_tests = tests_by_req.get(req_id, [])
        req_text = str(req.get("text") or "")
        layers = sorted({layer for test in req_tests for layer in evidence_layers_for_requirement(str(test.get("type") or ""), req_text)})
        oracle_requirements.append({
            "requirement_id": req_id,
            "requirement_text": req_text,
            "oracle_tests": [test.get("id") for test in req_tests],
            "required_evidence_layers": layers,
            "pass_rule": "All mapped tests must be Passed and each cited evidence item must be current-run, lineage-bound, and sufficient for its layer.",
            "weak_signals_to_avoid": weak_signals_for_layers(layers),
            "blocked_until": [
                test.get("notes") or "Required evidence input is missing."
                for test in req_tests
                if test.get("status") == "Blocked"
            ],
        })
    layer_counts: dict[str, int] = {}
    for item in oracle_requirements:
        for layer in item.get("required_evidence_layers", []):
            layer_counts[layer] = layer_counts.get(layer, 0) + 1
    return {
        "schema_version": 1,
        "generated_from": {"matrix": "test-matrix.json", "business_model": "business-model.json"},
        "requirements": oracle_requirements,
        "summary": {
            "requirement_count": len(oracle_requirements),
            "evidence_layer_counts": dict(sorted(layer_counts.items())),
            "blocked_oracle_count": sum(1 for item in oracle_requirements if item.get("blocked_until")),
        },
    }

def percent(numerator: int | float, denominator: int | float) -> float:
    if not denominator:
        return 100.0
    return round((float(numerator) / float(denominator)) * 100.0, 1)

def list_ids(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item or "").strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []

def has_non_empty_items(value: Any) -> bool:
    if not isinstance(value, list):
        return False
    return any(str(item or "").strip() for item in value)

def step_test_ids(step: dict[str, Any]) -> list[str]:
    return list_ids(step.get("testIds") or step.get("test_ids") or step.get("testId") or step.get("test_id"))

def requirement_test_ids(requirement: dict[str, Any]) -> list[str]:
    return list_ids(requirement.get("test_ids") or requirement.get("testIds") or requirement.get("tests"))

def test_requirement_ids(test: dict[str, Any]) -> list[str]:
    return list_ids(test.get("requirement_ids") or test.get("requirementIds") or test.get("requirements"))

def test_has_definition_quality(test: dict[str, Any]) -> bool:
    return bool(
        str(test.get("id") or "").strip()
        and test_requirement_ids(test)
        and str(test.get("type") or "").strip()
        and str(test.get("expected") or "").strip()
        and str(test.get("status") or "").strip()
        and has_non_empty_items(test.get("steps"))
        and has_non_empty_items(test.get("required_evidence"))
    )

def oracle_requirement_complete(item: dict[str, Any]) -> bool:
    return bool(
        str(item.get("requirement_id") or "").strip()
        and item.get("oracle_tests")
        and item.get("required_evidence_layers")
        and str(item.get("pass_rule") or "").strip()
    )

def business_model_quality_checks(business_model: dict[str, Any]) -> dict[str, bool]:
    actors = [item for item in business_model.get("actors", []) if isinstance(item, dict)]
    meaningful_actors = [
        item
        for item in actors
        if str(item.get("name") or "").strip().lower() != "unspecified actor" and not item.get("needs_confirmation")
    ]
    entry_api_paths = [*business_model.get("entry_points", []), *business_model.get("api_paths", [])]
    return {
        "actors_present": bool(meaningful_actors),
        "workflows_present": bool(business_model.get("workflows")),
        "domain_surface_present": bool(
            business_model.get("entities")
            or business_model.get("entry_points")
            or business_model.get("api_paths")
            or business_model.get("state_transitions")
            or business_model.get("business_rules")
        ),
        "qa_contract_present": bool(business_model.get("agent_team_contract", {}).get("qa_agent", {}).get("consumes")),
        "no_code_paths_as_routes": not any(path_is_code_file(str(path)) for path in entry_api_paths),
    }

def average(values: list[float]) -> float:
    if not values:
        return 100.0
    return round(sum(values) / len(values), 1)

def build_qa_metrics(requirements: list[dict[str, Any]], tests: list[dict[str, Any]], steps: list[dict[str, Any]], gaps: list[str], business_model: dict[str, Any], oracle_model: dict[str, Any]) -> dict[str, Any]:
    layer_counts = oracle_model.get("summary", {}).get("evidence_layer_counts", {})
    blocked_tests = [test for test in tests if test.get("status") == "Blocked"]
    planned_step_test_ids = {test_id for step in steps if isinstance(step, dict) for test_id in step_test_ids(step)}
    mapped_requirements = [req for req in requirements if requirement_test_ids(req)]
    executable_requirements = [
        req
        for req in requirements
        if any(test_id in planned_step_test_ids for test_id in requirement_test_ids(req))
    ]
    executable_tests = [test for test in tests if str(test.get("id") or "") in planned_step_test_ids]
    complete_tests = [test for test in tests if test_has_definition_quality(test)]
    oracle_items = [item for item in oracle_model.get("requirements", []) if isinstance(item, dict)]
    complete_oracle_items = [item for item in oracle_items if oracle_requirement_complete(item)]
    business_checks = business_model_quality_checks(business_model)
    requirement_mapping_percent = percent(len(mapped_requirements), len(requirements))
    executable_requirement_coverage_percent = percent(len(executable_requirements), len(requirements))
    executable_test_coverage_percent = percent(len(executable_tests), len(tests))
    executable_coverage_percent = average([
        executable_requirement_coverage_percent,
        executable_test_coverage_percent,
    ])
    test_definition_quality_percent = percent(len(complete_tests), len(tests))
    oracle_coverage_percent = percent(len(complete_oracle_items), len(requirements))
    business_modeling_proxy_percent = percent(sum(1 for passed in business_checks.values() if passed), len(business_checks))
    coverage_proxy_percent = average([
        requirement_mapping_percent,
        executable_requirement_coverage_percent,
        executable_test_coverage_percent,
    ])
    test_accuracy_proxy_percent = average([
        test_definition_quality_percent,
        oracle_coverage_percent,
    ])
    overall_quality_proxy_percent = average([
        coverage_proxy_percent,
        test_accuracy_proxy_percent,
        business_modeling_proxy_percent,
    ])
    target_percent = 95.0
    return {
        "schema_version": 1,
        "generated_from": {
            "business_model": "business-model.json",
            "oracle_model": "oracle-model.json",
            "matrix": "test-matrix.json",
            "plan": "test-plan.json",
        },
        "summary": {
            "requirement_count": len(requirements),
            "test_count": len(tests),
            "planned_step_count": len(steps),
            "actor_count": len(business_model.get("actors", [])),
            "entity_count": len(business_model.get("entities", [])),
            "workflow_count": len(business_model.get("workflows", [])),
            "oracle_requirement_count": len(oracle_model.get("requirements", [])),
            "blocked_test_count": len(blocked_tests),
            "coverage_gap_count": len(gaps),
            "evidence_layer_counts": layer_counts,
        },
        "quality_scores": {
            "source_mapped_coverage_percent": requirement_mapping_percent,
            "requirement_mapping_percent": requirement_mapping_percent,
            "executable_coverage_percent": executable_coverage_percent,
            "executable_requirement_coverage_percent": executable_requirement_coverage_percent,
            "executable_test_coverage_percent": executable_test_coverage_percent,
            "pass_claim_coverage_percent": None,
            "coverage_proxy_percent": coverage_proxy_percent,
            "test_definition_quality_percent": test_definition_quality_percent,
            "oracle_coverage_percent": oracle_coverage_percent,
            "test_accuracy_proxy_percent": test_accuracy_proxy_percent,
            "business_modeling_proxy_percent": business_modeling_proxy_percent,
            "overall_quality_proxy_percent": overall_quality_proxy_percent,
        },
        "quality_targets": {
            "target_percent": target_percent,
            "source_mapped_coverage_met": requirement_mapping_percent >= target_percent,
            "executable_coverage_met": executable_coverage_percent >= target_percent,
            "pass_claim_coverage_met": None,
            "coverage_proxy_met": coverage_proxy_percent >= target_percent,
            "test_accuracy_proxy_met": test_accuracy_proxy_percent >= target_percent,
            "business_modeling_proxy_met": business_modeling_proxy_percent >= target_percent,
            "overall_quality_proxy_met": overall_quality_proxy_percent >= target_percent,
            "note": "Source-mapped and executable coverage are planning metrics. Pass-claim coverage is not evaluated by qa-metrics.json and requires audited ledger plus qa-verdict.json with can_claim_pass=true.",
        },
        "coverage_breakdown": {
            "source_mapped": {
                "percent": requirement_mapping_percent,
                "mapped_requirement_count": len(mapped_requirements),
                "total_requirement_count": len(requirements),
                "source": "test-matrix.json requirement/test_id mapping",
                "semantics": "planning coverage only; does not prove execution or pass.",
            },
            "executable": {
                "percent": executable_coverage_percent,
                "requirement_percent": executable_requirement_coverage_percent,
                "test_percent": executable_test_coverage_percent,
                "executable_requirement_count": len(executable_requirements),
                "total_requirement_count": len(requirements),
                "executable_test_count": len(executable_tests),
                "total_test_count": len(tests),
                "planned_step_count": len(steps),
                "source": "test-plan.json executable step lineage",
                "semantics": "planned executable probe coverage only; does not prove probe success or pass.",
            },
            "pass_claim": {
                "status": "not_evaluated",
                "percent": None,
                "passed_requirement_count": None,
                "total_requirement_count": len(requirements),
                "source": "qa-verdict.json plus audited evidence-ledger.json",
                "semantics": "final pass-claim coverage is available only after evidence audit and verdict generation.",
            },
        },
        "quality_inputs": {
            "mapped_requirement_count": len(mapped_requirements),
            "executable_requirement_count": len(executable_requirements),
            "executable_test_count": len(executable_tests),
            "complete_test_definition_count": len(complete_tests),
            "complete_oracle_requirement_count": len(complete_oracle_items),
            "business_model_checks": business_checks,
        },
        "effectiveness_metrics": {
            "automation_readiness": "ready" if steps and not blocked_tests else "needs_input",
            "manual_intervention_points": len(gaps) + len(blocked_tests),
            "business_semantics_present": bool(business_model.get("workflows")),
            "oracle_coverage_complete": len(oracle_model.get("requirements", [])) == len(requirements),
        },
    }

def build_closeout_candidates(business_model: dict[str, Any], oracle_model: dict[str, Any], gaps: list[str]) -> dict[str, Any]:
    stable_candidates = [
        {
            "source": "business-model.json",
            "type": "business_rule",
            "text": item.get("text", ""),
            "source_requirement_id": item.get("requirement_id"),
            "confirmation_required": True,
        }
        for item in business_model.get("business_rules", [])
    ]
    improvement_candidates = [
        {
            "source": "scaffold-summary.json",
            "type": "coverage_gap",
            "text": gap,
            "confirmation_required": True,
        }
        for gap in gaps
    ]
    improvement_candidates.extend(
        {
            "source": "oracle-model.json",
            "type": "blocked_oracle",
            "text": f"{item.get('requirement_id')}: {', '.join(item.get('blocked_until', []))}",
            "confirmation_required": True,
        }
        for item in oracle_model.get("requirements", [])
        if item.get("blocked_until")
    )
    return {
        "schema_version": 1,
        "human_confirmation_required": True,
        "stable_knowledge_candidates": stable_candidates,
        "qa_process_improvement_candidates": improvement_candidates,
        "archive_only": [
            "requirement.md",
            "test-charter.md",
            "test-matrix.json",
            "test-plan.json",
            "business-model.json",
            "oracle-model.json",
            "qa-metrics.json",
        ],
        "rule": "Never write these candidates to memory, prompts, DB, or skill files without explicit human confirmation.",
    }

def make_test(req_id: str, test_index: int, layer: str, point: dict[str, Any], status: str, expected: str, steps: list[str], evidence: list[str]) -> dict[str, Any]:
    return {
        "id": f"T{test_index}",
        "requirement_ids": [req_id],
        "type": layer,
        "steps": steps,
        "expected": expected,
        "required_evidence": evidence,
        "status": status,
        **({"notes": "Generated as a blocked probe because required entrypoint, runtime data, credential, or safe test data is missing."} if status == "Blocked" else {}),
    }

def scaffold_code_pr(requirement: str, base_url: str, artifact_dir: Path) -> dict[str, Any]:
    code_paths = extract_code_file_paths(requirement)
    validation_commands = extract_validation_commands(requirement)
    blocked_validation_commands = extract_blocked_validation_commands(requirement)
    source_points = [
        point
        for point in split_requirement_points(requirement)
        if point_is_code_pr_file_context(point["text"])
    ]
    source_summary = "; ".join(point["text"] for point in source_points[:8])
    requirements: list[dict[str, Any]] = [
        {
            "id": "R1",
            "source": "PR code paths",
            "text": (
                f"Code changes are reviewed against the files named in the PR body: {source_summary}"
                if source_summary
                else "Code changes are reviewed against the files named in the PR body."
            ),
            "test_ids": ["T1"],
            "status": "Untested",
        }
    ]
    tests: list[dict[str, Any]] = [
        {
            "id": "T1",
            "requirement_ids": ["R1"],
            "type": "code_pr",
            "steps": ["Run static PR hygiene checks from the project checkout, not browser route probes."],
            "expected": "The PR diff has no whitespace/check-format issues and code paths are treated as source files, not routes.",
            "required_evidence": ["command stdout/stderr", "changed file list", "static check exit code"],
            "status": "Untested",
        }
    ]
    steps: list[dict[str, Any]] = [
        {
            "action": "command",
            "id": "T1-git-diff-check",
            "testIds": ["T1"],
            "requirementIds": ["R1"],
            "command": ["git", "diff", "--check"],
            "expectExitCode": 0,
            "captureStdout": True,
            "captureStderr": True,
            "evidenceType": "code_pr",
            "proves": "The current PR/worktree diff has no whitespace or conflict-marker issues.",
        }
    ]
    for index, command in enumerate(validation_commands, 2):
        test_id = f"T{index}"
        req_id = f"R{index}"
        requirements.append({
            "id": req_id,
            "source": "PR validation command",
            "text": f"PR tests/validation command from PR body should pass: `{command}`.",
            "test_ids": [test_id],
            "status": "Untested",
        })
        tests.append({
            "id": test_id,
            "requirement_ids": [req_id],
            "type": "code_pr",
            "steps": [f"Run `{command}` from the project checkout."],
            "expected": f"`{command}` exits successfully and emits no test failure.",
            "required_evidence": ["command stdout/stderr", "exit code"],
            "status": "Untested",
        })
        command_env, command_parts = build_command_step_fields(command)
        step = {
            "action": "command",
            "id": f"{test_id}-validation-command",
            "testIds": [test_id],
            "requirementIds": [req_id],
            "command": command_parts,
            "expectExitCode": 0,
            "captureStdout": True,
            "captureStderr": True,
            "evidenceType": "code_pr",
            "proves": f"The PR validation command `{command}` exits successfully.",
        }
        if command_env:
            step["env"] = command_env
        steps.append(step)

    next_index = len(requirements) + 1
    for command in blocked_validation_commands:
        test_id = f"T{next_index}"
        req_id = f"R{next_index}"
        requirements.append({
            "id": req_id,
            "source": "PR validation command",
            "text": f"PR validation command from PR body is mutating or unsafe and is blocked: `{command}`.",
            "test_ids": [test_id],
            "status": "Blocked",
        })
        tests.append({
            "id": test_id,
            "requirement_ids": [req_id],
            "type": "code_pr",
            "steps": [
                f"Do not run `{command}` automatically; replace it with a non-mutating check command or get explicit safe-environment authorization."
            ],
            "expected": f"`{command}` is not executed automatically because it can mutate the checkout or project state.",
            "required_evidence": ["blocked command safety rationale", "safe replacement command or explicit authorization"],
            "status": "Blocked",
            "notes": "Generated as a blocked code_pr validation probe because the command appears mutating or unsafe.",
        })
        next_index += 1

    gaps = [
        "Code PR scaffold mode does not infer browser/API routes from source file paths; add explicit UI/API acceptance criteria when runtime behavior must be tested."
    ]
    gaps.extend(
        f"PR validation command `{command}` is blocked because it appears mutating or unsafe; provide a non-mutating check or explicit safe-environment authorization."
        for command in blocked_validation_commands
    )
    business_model = build_business_model(requirement, requirements, tests, gaps)
    oracle_model = build_oracle_model(requirements, tests)
    qa_metrics = build_qa_metrics(requirements, tests, steps, gaps, business_model, oracle_model)
    closeout_candidates = build_closeout_candidates(business_model, oracle_model, gaps)
    plan = {
        "schemaVersion": 2,
        "baseUrl": base_url,
        "artifactDir": str(artifact_dir),
        "metadata": {
            "scaffoldMode": "code_pr",
            "codeFilePaths": code_paths,
        },
        "scenarios": [
            {
                "id": "code-pr-static-validation",
                "title": "Code PR static and command validation",
                "steps": steps,
            }
        ],
    }
    matrix = {"schemaVersion": 2, "requirements": requirements, "tests": tests}
    summary = {
        "schema_version": 1,
        "status": "scaffolded",
        "scaffold_mode": "code_pr",
        "base_url": base_url,
        "requirement_count": len(requirements),
        "test_count": len(tests),
        "planned_step_count": len(steps),
        "code_file_path_count": len(code_paths),
        "validation_command_count": len(validation_commands),
        "validation_commands": validation_commands,
        "blocked_validation_command_count": len(blocked_validation_commands),
        "blocked_validation_commands": blocked_validation_commands,
        "coverage_gaps": gaps,
        "input_artifact_errors": [],
        "business_model": {
            "actor_count": len(business_model.get("actors", [])),
            "entity_count": len(business_model.get("entities", [])),
            "workflow_count": len(business_model.get("workflows", [])),
            "business_rule_count": len(business_model.get("business_rules", [])),
        },
        "oracle_model": oracle_model.get("summary", {}),
        "qa_metrics": "qa-metrics.json",
        "closeout_candidates": "closeout-candidates.json",
    }
    return {
        "charter": render_charter(requirement, requirements, tests, gaps, business_model, oracle_model),
        "matrix": matrix,
        "plan": plan,
        "summary": summary,
        "business_model": business_model,
        "oracle_model": oracle_model,
        "qa_metrics": qa_metrics,
        "closeout_candidates": closeout_candidates,
    }

def append_code_pr_command_tests(
    requirement: str,
    requirements: list[dict[str, Any]],
    tests: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    *,
    next_req_index: int,
    test_index: int,
    source_points: list[dict[str, Any]] | None = None,
) -> tuple[int, int, list[str], list[str]]:
    code_paths = extract_code_file_paths(requirement)
    validation_commands = extract_validation_commands(requirement)
    blocked_validation_commands = extract_blocked_validation_commands(requirement)
    source_summary = "; ".join(
        point["text"]
        for point in (source_points or [])
        if point_is_code_pr_file_context(point["text"])
    )
    req_id = f"R{next_req_index}"
    test_id = f"T{test_index}"
    requirements.append({
        "id": req_id,
        "source": "PR code paths",
        "text": (
            f"Code changes are reviewed against the files named in the PR body: {source_summary}"
            if source_summary
            else "Code changes are reviewed against the files named in the PR body."
        ),
        "test_ids": [test_id],
        "status": "Untested",
    })
    tests.append({
        "id": test_id,
        "requirement_ids": [req_id],
        "type": "code_pr",
        "steps": ["Run static PR hygiene checks from the project checkout, not browser route probes."],
        "expected": "The PR diff has no whitespace/check-format issues and code paths are treated as source files, not routes.",
        "required_evidence": ["command stdout/stderr", "changed file list", "static check exit code"],
        "status": "Untested",
    })
    steps.append({
        "action": "command",
        "id": f"{test_id}-git-diff-check",
        "testIds": [test_id],
        "requirementIds": [req_id],
        "command": ["git", "diff", "--check"],
        "expectExitCode": 0,
        "captureStdout": True,
        "captureStderr": True,
        "evidenceType": "code_pr",
        "proves": "The current PR/worktree diff has no whitespace or conflict-marker issues.",
    })
    next_req_index += 1
    test_index += 1

    for command in validation_commands:
        req_id = f"R{next_req_index}"
        test_id = f"T{test_index}"
        requirements.append({
            "id": req_id,
            "source": "PR validation command",
            "text": f"PR tests/validation command from PR body should pass: `{command}`.",
            "test_ids": [test_id],
            "status": "Untested",
        })
        tests.append({
            "id": test_id,
            "requirement_ids": [req_id],
            "type": "code_pr",
            "steps": [f"Run `{command}` from the project checkout."],
            "expected": f"`{command}` exits successfully and emits no test failure.",
            "required_evidence": ["command stdout/stderr", "exit code"],
            "status": "Untested",
        })
        command_env, command_parts = build_command_step_fields(command)
        step = {
            "action": "command",
            "id": f"{test_id}-validation-command",
            "testIds": [test_id],
            "requirementIds": [req_id],
            "command": command_parts,
            "expectExitCode": 0,
            "captureStdout": True,
            "captureStderr": True,
            "evidenceType": "code_pr",
            "proves": f"The PR validation command `{command}` exits successfully.",
        }
        if command_env:
            step["env"] = command_env
        steps.append(step)
        next_req_index += 1
        test_index += 1

    for command in blocked_validation_commands:
        req_id = f"R{next_req_index}"
        test_id = f"T{test_index}"
        requirements.append({
            "id": req_id,
            "source": "PR validation command",
            "text": f"PR validation command from PR body is mutating or unsafe and is blocked: `{command}`.",
            "test_ids": [test_id],
            "status": "Blocked",
        })
        tests.append({
            "id": test_id,
            "requirement_ids": [req_id],
            "type": "code_pr",
            "steps": [
                f"Do not run `{command}` automatically; replace it with a non-mutating check command or get explicit safe-environment authorization."
            ],
            "expected": f"`{command}` is not executed automatically because it can mutate the checkout or project state.",
            "required_evidence": ["blocked command safety rationale", "safe replacement command or explicit authorization"],
            "status": "Blocked",
            "notes": "Generated as a blocked code_pr validation probe because the command appears mutating or unsafe.",
        })
        next_req_index += 1
        test_index += 1
    return next_req_index, test_index, code_paths, validation_commands

def render_charter(requirement: str, requirements: list[dict[str, Any]], tests: list[dict[str, Any]], gaps: list[str], business_model: dict[str, Any] | None = None, oracle_model: dict[str, Any] | None = None) -> str:
    test_by_req: dict[str, list[str]] = {}
    for test in tests:
        for req_id in test.get("requirement_ids", []):
            test_by_req.setdefault(req_id, []).append(test["id"])
    business_model = business_model or {}
    oracle_model = oracle_model or {}

    lines = [
        "# Test Charter",
        "",
        "## Source",
        "",
        "- Requirement source: requirement.md",
        "- Target environment: To be confirmed before execution.",
        "- Data boundary: State local/test/staging/prod and mock/seed/real data before pass/fail.",
        "- Test account/role: To be provided when auth is required.",
        "",
        "## Requirement Extraction",
        "",
        "| ID | Requirement Point | Source Evidence | Test Mapping | Status |",
        "| --- | --- | --- | --- | --- |",
    ]
    for req in requirements:
        lines.append(f"| {req['id']} | {req['text']} | {req['source']} | {', '.join(test_by_req.get(req['id'], []))} | {req['status']} |")

    lines.extend([
        "",
        "## Behavior Model",
        "",
        "| Area | Notes |",
        "| --- | --- |",
        f"| User goal | {requirements[0]['text'] if requirements else 'Requirement source missing.'} |",
        "| Actors and permissions | Extracted into permission tests when mentioned; otherwise confirm manually. |",
        "| Entry points | Generated only when explicit paths or `--entry-path` were available. |",
        "| API/data dependencies | Generated for explicit safe read-only API endpoints; click-to-response probes are generated when a click target and API path appear in the same requirement; when an authorized click response returns an id and the requirement names a read-only `{id}` endpoint, a follow-up API probe verifies the same object. Mutating endpoints are blocked pending safe data. |",
        "| Stream/WebSocket/SSE dependencies | Generated only with explicit endpoint and `--allow-live-stream`; otherwise blocked pending auth/payload. |",
        "| Persistence/display rules | Generated only when a project-approved helper command was supplied. |",
        "| Strong pass signals | Current-run UI/API/stream/persistence evidence mapped in the ledger. |",
        "| Weak/misleading signals | Screenshots without interaction, prompt markers only in user input, fallback text without stream completion. |",
        "",
        "## Business Intent Model",
        "",
        "- Artifact: `business-model.json`",
        f"- Actors: {', '.join(item.get('name', '') for item in business_model.get('actors', [])) or 'To be confirmed.'}",
        f"- Entities: {', '.join(item.get('name', '') for item in business_model.get('entities', [])) or 'None extracted.'}",
        f"- Workflows: {', '.join(item.get('label', '') for item in business_model.get('workflows', [])) or 'None extracted.'}",
        "- Contract: business-model.json is planning context, not proof; final pass still requires current-run evidence.",
        "",
        "## Oracle Model",
        "",
        "- Artifact: `oracle-model.json`",
        f"- Oracle requirements: {len(oracle_model.get('requirements', []))}",
        f"- Evidence layer counts: `{json.dumps(oracle_model.get('summary', {}).get('evidence_layer_counts', {}), ensure_ascii=False)}`",
        "- Pass rule: every mapped test must pass with current-run, lineage-bound evidence for its required layer.",
        "",
        "## Test Matrix",
        "",
        "| ID | Requirement | Test Type | Steps/Probe | Expected Result | Required Evidence | Actual Evidence | Status |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ])
    for test in tests:
        lines.append(
            f"| {test['id']} | {', '.join(test['requirement_ids'])} | {test['type']} | "
            f"{'; '.join(test.get('steps', []))} | {test['expected']} | {', '.join(test.get('required_evidence', []))} |  | {test['status']} |"
        )

    lines.extend([
        "",
        "## Coverage Gaps",
        "",
    ])
    if gaps:
        lines.extend(f"- {gap}" for gap in gaps)
    else:
        lines.append("- None identified by the scaffold. Re-check after inspecting the actual app and repo.")
    lines.append("")
    lines.append("## Raw Requirement Preview")
    lines.append("")
    lines.append(redact(requirement[:3000]) if requirement.strip() else "No requirement source was provided.")
    lines.append("")
    return "\n".join(lines)
