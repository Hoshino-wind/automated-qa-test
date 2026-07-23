"""分层探针规则与需求点上下文。"""

import re
import shlex
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .intents import (
    analytics_evidence_layers,
    api_path,
    api_target,
    append_forbidden_visible_text_assertion_steps,
    append_visible_text_assertion_steps,
    artifact_generation_evidence_layers,
    async_poll_config,
    expect_json_any_for_placeholders,
    explicit_forbidden_visible_text_targets,
    explicit_visible_text_targets,
    extract_json_spec,
    graphql_evidence_layers,
    graphql_probe_focus,
    graphql_probe_instruction,
    graphql_runtime_probe_instruction,
    has_agent_tool_intent,
    has_analytics_intent,
    has_api_key_intent,
    has_api_response_context_intent,
    has_artifact_generation_intent,
    has_artifact_progress_intent,
    has_async_status_intent,
    has_audit_integrity_intent,
    has_authorization_policy_intent,
    has_background_job_intent,
    has_bulk_action_intent,
    has_cache_consistency_intent,
    has_chinese,
    has_cleanup_intent,
    has_click_intent,
    has_cookie_security_intent,
    has_cross_tenant_denial_intent,
    has_csrf_intent,
    has_csv_content_intent,
    has_dead_letter_intent,
    has_decision_table_logic_intent,
    has_destructive_confirmation_intent,
    has_direct_api_denial_intent,
    has_disabled_state_intent,
    has_download_intent,
    has_dst_boundary_intent,
    has_error_state_intent,
    has_escape_close_intent,
    has_feature_flag_intent,
    has_file_preview_intent,
    has_file_security_intent,
    has_financial_ledger_intent,
    has_flag_default_off_intent,
    has_float_drift_guard_intent,
    has_graphql_intent,
    has_idempotency_intent,
    has_list_interaction_intent,
    has_localization_intent,
    has_lockout_intent,
    has_mfa_intent,
    has_money_precision_intent,
    has_multi_client_intent,
    has_negative_request_intent,
    has_notification_intent,
    has_notification_policy_intent,
    has_oauth_intent,
    has_offline_sync_intent,
    has_one_time_token_intent,
    has_optimistic_ui_intent,
    has_ordering_intent,
    has_pii_redaction_intent,
    has_privacy_compliance_intent,
    has_quota_metering_intent,
    has_rag_grounding_intent,
    has_rate_limit_intent,
    has_realtime_intent,
    has_reconnect_replay_intent,
    has_redirect_security_intent,
    has_retry_backoff_intent,
    has_rollout_intent,
    has_saml_intent,
    has_scan_status_intent,
    has_scheduled_job_intent,
    has_schema_migration_intent,
    has_search_relevance_intent,
    has_session_security_intent,
    has_stale_flag_guard_intent,
    has_subscription_billing_intent,
    has_tenant_isolation_intent,
    has_time_boundary_intent,
    has_transaction_integrity_intent,
    has_ui_stale_absence_intent,
    has_undo_intent,
    has_upload_intent,
    has_webauthn_intent,
    has_webhook_security_intent,
    has_word,
    has_worker_intent,
    http_status_expectation_fields_for_target,
    identifier_can_bind_placeholder,
    infer_button_name,
    offline_sync_evidence_layers,
    path_is_stream,
    path_placeholders,
    requirement_specific_evidence_layers,
    returned_identifier_names,
    terminal_status_value,
    ui_path,
)
from .modeling import (
    classify,
    make_test,
    status_for_tests,
)
from .support import (
    extract_method_path,
    extract_method_paths,
    extract_paths,
    extract_shell_commands,
)


def _apply_foundation_execution_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    shell_commands: list[str],
    page_path: str | None,
    paths: list[str],
    method_path: tuple[str, str] | None,
) -> int:
    """追加命令与决策表执行规则。"""
    if "command" in tags:
        command_label = shell_commands[0] if shell_commands else "<project command>"
        evidence = ["command stdout/stderr", "exit code", "project/environment boundary"]
        if "stdout json" in text.lower() or "stdout_json" in text.lower():
            evidence.append("stdout_json")
        evidence = list(dict.fromkeys([*evidence, *requirement_specific_evidence_layers(text)]))
        test = make_test(
            req_id,
            test_index,
            "command",
            point,
            "Blocked",
            f"Command `{command_label}` satisfies requirement: {text}",
            [
                "Confirm the project root, runtime/data boundary, command safety, required fixtures, and expected stdout/stderr assertions before execution."
            ],
            evidence,
        )
        req_tests.append(test)
        tests.append(test)
        gaps.append(f"{req_id}: command probe for `{command_label}` needs confirmed project root, environment/data boundary, and safe execution authorization.")
        test_index += 1

    if has_decision_table_logic_intent(text):
        logic_evidence = list(dict.fromkeys([
            "logic",
            "command",
            "stdout_json",
            "decision_table",
            "rule_matrix",
            "rule_precedence",
            "boundary_cases",
            "negative_cases",
            "fixture_inputs",
            "expected_outputs",
            "terminal_status",
            "runtime",
            *requirement_specific_evidence_layers(text),
        ]))
        logic_test = make_test(
            req_id,
            test_index,
            "logic",
            point,
            "Blocked",
            f"Decision-table business rules satisfy every branch for requirement: {text}",
            [
                "Run the project-approved rule-evaluation command against the named fixture, parse stdout JSON, and compare every fixture input row to its expected decision, approver group, rule hit, boundary case, negative case, and precedence outcome."
            ],
            logic_evidence,
        )
        req_tests.append(logic_test)
        tests.append(logic_test)
        gaps.append(f"{req_id}: decision-table logic probe needs the named fixture rows, parsed stdout JSON, expected_decisions for every branch, rule-hit matrix, boundary and negative rows, precedence override proof, and runtime disposition.")
        test_index += 1
    return test_index

def _apply_foundation_experience_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    shell_commands: list[str],
    page_path: str | None,
    paths: list[str],
    method_path: tuple[str, str] | None,
) -> int:
    """追加响应式、无障碍与本地化规则。"""
    if "responsive" in tags:
        responsive_status = "Blocked"
        responsive_steps = (
            [f"Add viewport-specific checks for `{page_path}` at the named mobile and desktop sizes before execution."]
            if page_path
            else ["Identify the user-facing entry path and viewport sizes before responsive behavior can be proven."]
        )
        responsive_test = make_test(
            req_id,
            test_index,
            "responsive",
            point,
            responsive_status,
            f"Responsive behavior satisfies requirement: {text}",
            responsive_steps,
            ["mobile viewport screenshot", "desktop viewport screenshot", "no horizontal overflow", "critical control visibility"],
        )
        req_tests.append(responsive_test)
        tests.append(responsive_test)
        if page_path:
            gaps.append(f"{req_id}: responsive probe for `{page_path}` needs explicit mobile/desktop viewport execution.")
        else:
            gaps.append(f"{req_id}: responsive probe needs a UI entry path.")
        test_index += 1

    if "accessibility" in tags:
        accessibility_evidence = list(dict.fromkeys([
            "keyboard_navigation",
            "focus_management",
            "aria_semantics",
            "accessible_name",
            *requirement_specific_evidence_layers(text),
            "tab_order",
            "focus_restoration",
        ]))
        if has_escape_close_intent(text):
            accessibility_evidence.append("escape close")
        if has_negative_request_intent(text):
            accessibility_evidence.append("forbidden request absence")
        accessibility_test = make_test(
            req_id,
            test_index,
            "accessibility",
            point,
            "Blocked",
            f"Keyboard and assistive-technology behavior satisfies requirement: {text}",
            [
                (
                    f"From `{page_path}`, use keyboard-only navigation to reach the target control, open the modal/dialog, assert role/ARIA/accessible names, verify focus entry/trap/restoration, and capture Escape/no-request behavior where required."
                    if page_path
                    else "Identify the user-facing entry path and stable accessibility selectors before keyboard/focus/ARIA behavior can be proven."
                )
            ],
            accessibility_evidence,
        )
        req_tests.append(accessibility_test)
        tests.append(accessibility_test)
        gaps.append(f"{req_id}: accessibility probe needs keyboard-only execution, stable role/name selectors, focus trap/restoration assertions, and ARIA/accessible-name evidence.")
        test_index += 1

    if "localization" in tags:
        localization_evidence = list(dict.fromkeys([
            "localization",
            "locale_switch",
            "translation_catalog",
            "catalog_version",
            "translation_key_absence",
            "fallback_absence",
            "plural_rules",
            "rtl_layout",
            "lang_attribute",
            "dir_attribute",
            "currency_format",
            "date_time_format",
            "timezone",
            "stale_locale_guard",
            "ui",
            "ui_interaction",
            "api_response",
            "query_params",
            "responsive",
            "runtime",
            *requirement_specific_evidence_layers(text),
        ]))
        localization_steps = [
            (
                f"From `{page_path}`, drive the named locale path and locale switch; capture catalog API response, html lang/dir, rendered copy, plural rows, RTL layout/no-overflow evidence, localized currency/date parity, stale-catalog absence, and count-aware runtime disposition."
                if page_path
                else "Identify the localized UI entry path and stable locale fixtures before localization behavior can be proven."
            )
        ]
        localization_test = make_test(
            req_id,
            test_index,
            "localization",
            point,
            "Blocked",
            f"Localization/i18n behavior satisfies requirement without fallback or stale-catalog evidence gaps: {text}",
            localization_steps,
            localization_evidence,
        )
        req_tests.append(localization_test)
        tests.append(localization_test)
        gaps.append(f"{req_id}: localization probe needs locale-switch execution, translation catalog version, missing_keys/fallback_count and raw-key absence, plural-rule fixtures, html lang/dir and RTL no-overflow proof, Intl currency/date timezone parity, stale-catalog guard, and runtime disposition.")
        test_index += 1
    return test_index

def _apply_foundation_interaction_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    shell_commands: list[str],
    page_path: str | None,
    paths: list[str],
    method_path: tuple[str, str] | None,
) -> int:
    """追加批量、破坏性操作与撤销规则。"""
    if "bulk_action" in tags:
        bulk_evidence = list(dict.fromkeys([
            "selection_state",
            "selected_count",
            "selected_scope",
            "ui_interaction",
            "request body",
            *requirement_specific_evidence_layers(text),
        ]))
        bulk_test = make_test(
            req_id,
            test_index,
            "bulk_action",
            point,
            "Blocked",
            f"Bulk action scope and selected-row state satisfy requirement: {text}",
            [
                "Use stable row selectors and safe fixture ids to prove the exact selected ids/count, enabled/disabled destructive control state, request body ids, and no mutation outside the selected scope."
            ],
            bulk_evidence,
        )
        req_tests.append(bulk_test)
        tests.append(bulk_test)
        gaps.append(f"{req_id}: bulk-action probe needs safe fixture ids, row selectors, selected-count assertion, request-body id binding, and unselected-row no-change proof.")
        test_index += 1

    if "destructive_guard" in tags:
        destructive_evidence = list(dict.fromkeys([
            "confirmation_modal",
            "destructive_action_guard",
            "forbidden request absence",
            "ui_interaction",
            "runtime",
            *requirement_specific_evidence_layers(text),
        ]))
        destructive_test = make_test(
            req_id,
            test_index,
            "destructive_guard",
            point,
            "Blocked",
            f"Destructive confirmation and cancel/no-request behavior satisfy requirement: {text}",
            [
                "Open the destructive confirmation with safe fixtures, assert the required confirmation text, prove Cancel/Escape closes without sending the mutation, then bind the confirmed mutation request to the same selected ids."
            ],
            destructive_evidence,
        )
        req_tests.append(destructive_test)
        tests.append(destructive_test)
        gaps.append(f"{req_id}: destructive-action guard needs confirmation selector, required-text assertion, cancel/Escape no-request evidence, and safe confirmed-mutation binding.")
        test_index += 1

    if "undo" in tags:
        undo_evidence = list(dict.fromkeys([
            "operation_id",
            "undo_action",
            "undo_restoration",
            "api_response",
            "persistence",
            "audit_log",
            *requirement_specific_evidence_layers(text),
        ]))
        undo_test = make_test(
            req_id,
            test_index,
            "undo",
            point,
            "Blocked",
            f"Undo restores the same operation and records evidence for requirement: {text}",
            [
                "Extract the operation_id from the destructive action, trigger undo within the allowed window, then prove the same ids restore to the prior state with audit/log and persistence evidence."
            ],
            undo_evidence,
        )
        req_tests.append(undo_test)
        tests.append(undo_test)
        gaps.append(f"{req_id}: undo probe needs operation_id extraction, same-id restore evidence, undo audit/log event, and safe time-window fixture.")
        test_index += 1
    return test_index

def _apply_foundation_transfer_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    shell_commands: list[str],
    page_path: str | None,
    paths: list[str],
    method_path: tuple[str, str] | None,
) -> int:
    """追加上传、下载、产物内容与文件安全规则。"""
    if has_upload_intent(text):
        upload_method, upload_path = api_target(method_path, paths, text)
        upload_evidence = list(dict.fromkeys([
            "file_fixture",
            "file selector/actionability",
            "upload_request",
            *requirement_specific_evidence_layers(text),
            "redacted request body or metadata",
        ]))
        upload_test = make_test(
            req_id,
            test_index,
            "upload",
            point,
            "Blocked",
            f"Upload flow uses a safe file fixture and request evidence for requirement: {text}",
            [
                f"Provide a safe test file fixture, stable file-input selector, and safe test-data boundary before executing `{upload_method or 'POST'} {upload_path or '<upload endpoint>'}`."
            ],
            upload_evidence,
        )
        req_tests.append(upload_test)
        tests.append(upload_test)
        gaps.append(f"{req_id}: upload probe needs a safe file fixture, stable file input selector, request capture, and safe test-data boundary.")
        test_index += 1

    if has_download_intent(text):
        download_method, download_path = api_target(method_path, paths, text)
        download_evidence = list(dict.fromkeys([
            "download_file",
            "file_hash",
            *requirement_specific_evidence_layers(text),
            "current-run artifact path",
        ]))
        download_test = make_test(
            req_id,
            test_index,
            "download",
            point,
            "Blocked",
            f"Download/export flow produces a verifiable file artifact for requirement: {text}",
            [
                f"Capture the browser download or API response body for `{download_method or 'GET'} {download_path or '<download endpoint>'}` as a current-run file artifact."
            ],
            download_evidence,
        )
        req_tests.append(download_test)
        tests.append(download_test)
        gaps.append(f"{req_id}: download/export probe needs current-run downloaded file artifact, hash, response headers, and source request binding.")
        test_index += 1

    artifact_file_content_intent = has_artifact_generation_intent(text) and has_word(text.lower(), r"\bcontent[_ -]?hash\b", r"\bfile[_ -]?hash\b", r"\bformats?\s+pdf,csv\b", r"\bcsv\b", r"\bcontent-disposition\b")
    if has_download_intent(text) and (has_csv_content_intent(text) or has_pii_redaction_intent(text) or artifact_file_content_intent):
        content_evidence = list(dict.fromkeys([
            "download_file",
            "file_hash",
            *requirement_specific_evidence_layers(text),
            "parsed file content",
        ]))
        content_steps = (
            ["Capture the authorized current-run artifact download, assert Content-Disposition filename, file_hash/content_hash/manifest_hash parity, and prove storage_key/signed_url are absent from response bodies, logs, and report artifacts."]
            if artifact_file_content_intent
            else ["Parse the current-run downloaded file and assert required headers, row count, summary parity, and forbidden text absence."]
        )
        content_test = make_test(
            req_id,
            test_index,
            "file_content",
            point,
            "Blocked",
            f"Downloaded/exported file content satisfies schema, row, parity, and redaction rules for requirement: {text}",
            content_steps,
            content_evidence,
        )
        req_tests.append(content_test)
        tests.append(content_test)
        gaps.append(f"{req_id}: exported file content probe needs parsed file assertions for schema, rows, parity, and forbidden PII absence.")
        test_index += 1

    if "file_security" in tags:
        file_security_evidence = list(dict.fromkeys([
            "file_fixture",
            "upload_request",
            "attachment_id",
            "scan_status",
            "malware_scan",
            "quarantine",
            "scan_engine",
            "scan_version",
            "audit_log",
            "forbidden request absence",
            *requirement_specific_evidence_layers(text),
        ]))
        file_security_test = make_test(
            req_id,
            test_index,
            "file_security",
            point,
            "Blocked",
            f"Attachment scan, quarantine, and file-safety gates satisfy requirement: {text}",
            [
                "Use safe clean and malware fixtures, capture the upload response attachment_id, prove scan_status transitions, quarantine behavior, scan engine/version, no preview/download for unsafe files, and audit/log evidence."
            ],
            file_security_evidence,
        )
        req_tests.append(file_security_test)
        tests.append(file_security_test)
        gaps.append(f"{req_id}: file-security probe needs clean/malware fixtures, upload response binding, scan-status polling, quarantine evidence, no-preview/download proof, and audit/log correlation.")
        test_index += 1
    return test_index

def _apply_foundation_file_lifecycle_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    shell_commands: list[str],
    page_path: str | None,
    paths: list[str],
    method_path: tuple[str, str] | None,
) -> int:
    """追加扫描状态与安全预览规则。"""
    if has_scan_status_intent(text):
        scan_poll_evidence = list(dict.fromkeys([
            "attachment_id",
            "api_poll",
            "scan_status",
            "terminal_status",
            "api_response",
            *requirement_specific_evidence_layers(text),
        ]))
        scan_poll_test = make_test(
            req_id,
            test_index,
            "api_poll",
            point,
            "Blocked",
            f"Attachment scan status reaches the required terminal state for requirement: {text}",
            [
                "Extract the attachment_id from the upload response, then poll the attachment status endpoint until scan_status reaches clean or quarantined as required before allowing preview/download assertions."
            ],
            scan_poll_evidence,
        )
        req_tests.append(scan_poll_test)
        tests.append(scan_poll_test)
        gaps.append(f"{req_id}: scan-status poll needs upload response attachment_id, read-only status endpoint, terminal scan state assertion, and timeout/failure disposition.")
        test_index += 1

    if "file_preview" in tags:
        file_preview_evidence = list(dict.fromkeys([
            "preview_rendering",
            "signed_url",
            "response_headers",
            "content_type",
            "content_disposition",
            "nosniff",
            "permission",
            "workspace_boundary",
            "forbidden text absence",
            *requirement_specific_evidence_layers(text),
        ]))
        file_preview_test = make_test(
            req_id,
            test_index,
            "file_preview",
            point,
            "Blocked",
            f"Secure preview response, signed-token, and workspace boundary satisfy requirement: {text}",
            [
                "After the same attachment reaches clean scan status, use same-workspace and cross-workspace fixtures to prove signed preview token binding, preview rendering, content headers, nosniff, and forbidden filename/storage-key/signed-URL leaks."
            ],
            file_preview_evidence,
        )
        req_tests.append(file_preview_test)
        tests.append(file_preview_test)
        gaps.append(f"{req_id}: file-preview probe needs clean attachment fixture, signed preview token, same/cross-workspace auth states, response headers, rendered preview evidence, and leak guards.")
        test_index += 1
    return test_index

_FOUNDATION_RULE_FAMILIES = (
    _apply_foundation_execution_rule_family,
    _apply_foundation_experience_rule_family,
    _apply_foundation_interaction_rule_family,
    _apply_foundation_transfer_rule_family,
    _apply_foundation_file_lifecycle_rule_family,
)

def apply_foundation_point_rules(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    shell_commands: list[str],
    page_path: str | None,
    paths: list[str],
    method_path: tuple[str, str] | None,
) -> int:
    """按稳定语义族追加规则，并保留原有公开调用契约。"""
    for apply_rules in _FOUNDATION_RULE_FAMILIES:
        test_index = apply_rules(
            point=point,
            req_id=req_id,
            text=text,
            tags=tags,
            tests=tests,
            req_tests=req_tests,
            gaps=gaps,
            test_index=test_index,
            shell_commands=shell_commands,
            page_path=page_path,
            paths=paths,
            method_path=method_path,
        )
    return test_index

def _apply_resilience_negative_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    method_path: tuple[str, str] | None,
    paths: list[str],
    page_path: str | None,
    button_name: str | None,
    negative_request_intent: bool,
    response_method: str | None,
    steps: list[dict[str, Any]],
) -> int:
    """追加负向请求与无副作用规则。"""
    if negative_request_intent:
        _, forbidden_path = api_target(method_path, paths, text)
        forbidden_method = response_method or (method_path[0] if method_path else "GET")
        negative_executable = bool(page_path and button_name and forbidden_path and "{" not in forbidden_path and "}" not in forbidden_path)
        negative_evidence = list(dict.fromkeys([
            "network request log",
            "forbidden request absence",
            "runtime disposition",
            "UI blocked state",
            "ui_interaction",
            *requirement_specific_evidence_layers(text),
        ]))
        negative_test = make_test(
            req_id,
            test_index,
            "runtime",
            point,
            "Untested" if negative_executable else "Blocked",
            f"Invalid, cancelled, or blocked interaction must not trigger `{forbidden_method or ''} {forbidden_path}` for requirement: {text}",
            [
                f"Open `{page_path}`, click `{button_name}`, then assert no `{forbidden_method} {forbidden_path}` request was captured."
                if negative_executable
                else "Capture the browser/network request log around the invalid, cancelled, or blocked interaction and prove the forbidden request was not sent."
            ],
            negative_evidence,
        )
        req_tests.append(negative_test)
        tests.append(negative_test)
        if negative_executable:
            steps.extend([
                {
                    "action": "goto",
                    "id": f"{negative_test['id']}-open",
                    "testIds": [negative_test["id"]],
                    "requirementIds": [req_id],
                    "path": page_path,
                    "evidenceType": "navigation",
                    "proves": f"The generated entry path `{page_path}` opens before checking forbidden request absence for {req_id}.",
                },
                {
                    "action": "click",
                    "id": f"{negative_test['id']}-click",
                    "testIds": [negative_test["id"]],
                    "requirementIds": [req_id],
                    "role": "button",
                    "name": button_name,
                    "evidenceType": "ui_interaction",
                    "proves": f"The `{button_name}` interaction is performed before checking forbidden request absence for {req_id}.",
                },
                {
                    "action": "expectNoRequest",
                    "id": f"{negative_test['id']}-no-request",
                    "testIds": [negative_test["id"]],
                    "requirementIds": [req_id],
                    "method": forbidden_method,
                    "path": forbidden_path,
                    "waitMs": 750,
                    "evidenceType": "forbidden request absence",
                    "proves": f"No `{forbidden_method} {forbidden_path}` browser request was captured after the `{button_name}` interaction for {req_id}.",
                },
            ])
        else:
            gaps.append(f"{req_id}: negative request probe needs an executable invalid/cancel/blocked interaction and request log assertion for `{forbidden_path}`.")
        test_index += 1
    return test_index

def _apply_resilience_client_state_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    method_path: tuple[str, str] | None,
    paths: list[str],
    page_path: str | None,
    button_name: str | None,
    negative_request_intent: bool,
    response_method: str | None,
    steps: list[dict[str, Any]],
) -> int:
    """追加并发、离线与客户端状态恢复规则。"""
    if "concurrency" in tags:
        concurrency_evidence = list(dict.fromkeys([
            "concurrent_requests",
            "atomicity",
            "conflict_response",
            "locking",
            *requirement_specific_evidence_layers(text),
            "winner/loser response correlation",
            "same-object persistence verification",
        ]))
        concurrency_test = make_test(
            req_id,
            test_index,
            "concurrency",
            point,
            "Blocked",
            f"Concurrent execution preserves atomicity and conflict semantics for requirement: {text}",
            [
                "Use safe deterministic fixtures to run the competing requests at the same contention point, correlate winner and loser responses, then verify persisted state, duplicate absence, audit/log evidence, and no forbidden side effect."
            ],
            concurrency_evidence,
        )
        req_tests.append(concurrency_test)
        tests.append(concurrency_test)
        gaps.append(f"{req_id}: concurrency probe needs safe contention fixtures, simultaneous request orchestration, winner/loser response capture, atomicity/lock evidence, and persistence/audit verification.")
        test_index += 1

    if "offline_sync" in tags:
        offline_evidence = list(dict.fromkeys([
            *offline_sync_evidence_layers(),
            *requirement_specific_evidence_layers(text),
        ]))
        offline_test = make_test(
            req_id,
            test_index,
            "offline_sync",
            point,
            "Blocked",
            f"Offline local queue, reconnect sync, idempotency, conflict merge, retry, and permission guard satisfy requirement: {text}",
            [
                "Drive or replay the mobile offline-sync path: force browser offline, create the marked draft, prove no sync POST was sent, inspect encrypted IndexedDB/local outbox pending_sync fields, reconnect, capture background sync POST/response, prove queue drain exactly once, replay idempotency duplicate absence, exercise 409 blocked_conflict and merge If-Match resolution, capture 503 retry scheduling, denied viewer/no-side-effect behavior, leak guards, audit log, persistence, and count-aware runtime disposition."
            ],
            offline_evidence,
        )
        req_tests.append(offline_test)
        tests.append(offline_test)
        gaps.append(f"{req_id}: offline-sync probe needs offline request absence, IndexedDB/local outbox encrypted payload and client_mutation_id, reconnect/background-sync request/response, queue-drain proof, idempotent replay duplicate absence, 409 blocked_conflict evidence, merge dialog and If-Match resolution, retry scheduling, denied actor no-side-effect proof, leak guards, audit log, persistence, and runtime disposition.")
        test_index += 1

    if "local_storage" in tags:
        local_storage_test = make_test(
            req_id,
            test_index,
            "local_storage",
            point,
            "Blocked",
            f"Offline local storage/outbox state satisfies requirement: {text}",
            [
                "Inspect the same browser context's IndexedDB/local outbox while offline and after sync to prove pending_sync fields, encrypted_local_payload, payload_hash, client_mutation_id, and final drained/resolved status."
            ],
            list(dict.fromkeys(["local_queue", "indexeddb", "encrypted_local_payload", "payload_hash", "client_mutation_id", "pending_state", "persistence", *requirement_specific_evidence_layers(text)])),
        )
        req_tests.append(local_storage_test)
        tests.append(local_storage_test)
        gaps.append(f"{req_id}: local-storage probe needs IndexedDB/local outbox inspection for encrypted payload, client_mutation_id, payload_hash, pending/resolved status, and same-browser persistence.")
        test_index += 1

    if "service_worker" in tags:
        service_worker_test = make_test(
            req_id,
            test_index,
            "service_worker",
            point,
            "Blocked",
            f"Service worker offline-sync behavior satisfies requirement: {text}",
            [
                "Capture service-worker/background-sync registration or controlled replay, prove it sends sync only after network returns online, and prove failures are dispositioned rather than reported as success."
            ],
            list(dict.fromkeys(["service_worker", "background_sync", "network_offline", "network_online", "forbidden request absence", "runtime", *requirement_specific_evidence_layers(text)])),
        )
        req_tests.append(service_worker_test)
        tests.append(service_worker_test)
        gaps.append(f"{req_id}: service-worker probe needs service-worker/background-sync evidence, offline request absence, online replay, and runtime disposition.")
        test_index += 1

    if "background_sync" in tags:
        background_sync_test = make_test(
            req_id,
            test_index,
            "background_sync",
            point,
            "Blocked",
            f"Background sync retry and queue behavior satisfies requirement: {text}",
            [
                "Replay the background sync worker path, capture sync batch request/response, retry_count, next_retry_at, backoff_schedule, unchanged pending queue on 503, and duplicate-side-effect absence."
            ],
            list(dict.fromkeys(["background_sync", "service_worker", "sync_batch", "retry_count", "backoff_schedule", "next_retry_at", "local_queue", "duplicate_absence", "runtime", *requirement_specific_evidence_layers(text)])),
        )
        req_tests.append(background_sync_test)
        tests.append(background_sync_test)
        gaps.append(f"{req_id}: background-sync probe needs sync batch evidence, retry_count/next_retry_at/backoff schedule, unchanged pending queue on failure, duplicate absence, and runtime disposition.")
        test_index += 1

    if "conflict_resolution" in tags:
        conflict_resolution_test = make_test(
            req_id,
            test_index,
            "conflict_resolution",
            point,
            "Blocked",
            f"Offline sync conflict resolution satisfies requirement: {text}",
            [
                "Trigger the 409 version_conflict, prove blocked_conflict queue retention, inspect server/local values in the merge dialog, send the If-Match resolve-conflict request, and verify resolved/synced state plus conflict_resolved audit log."
            ],
            list(dict.fromkeys(["conflict_response", "conflict_id", "server_version", "client_version", "blocked_conflict", "merge_dialog", "merge_resolution", "if_match", "sync_version", "audit_log", "api_response", *requirement_specific_evidence_layers(text)])),
        )
        req_tests.append(conflict_resolution_test)
        tests.append(conflict_resolution_test)
        gaps.append(f"{req_id}: conflict-resolution probe needs 409 conflict_id/server/client version evidence, blocked_conflict queue retention, merge dialog parity, If-Match resolve request, resolved/synced status, and audit log.")
        test_index += 1
    return test_index

def _apply_resilience_job_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    method_path: tuple[str, str] | None,
    paths: list[str],
    page_path: str | None,
    button_name: str | None,
    negative_request_intent: bool,
    response_method: str | None,
    steps: list[dict[str, Any]],
) -> int:
    """追加调度、产物、后台任务与 Worker 规则。"""
    if "scheduled_job" in tags:
        scheduled_evidence = list(dict.fromkeys([
            "command",
            "stdout_json",
            "scheduled_job",
            "schedule_expression",
            "scheduler_run",
            "run_key",
            "job_id",
            "next_run_at",
            "timezone",
            "dst_boundary",
            "due_window",
            "catch_up",
            "scheduler_lock",
            "concurrent_requests",
            "duplicate_absence",
            "dry_run",
            "no_persistence_side_effect",
            "invoice_rows",
            "outbox",
            "no_real_email",
            "audit_log",
            "persistence",
            "runtime",
            *requirement_specific_evidence_layers(text),
        ]))
        scheduled_test = make_test(
            req_id,
            test_index,
            "scheduled_job",
            point,
            "Blocked",
            f"Scheduled job cron/window, run key, catch-up, lock, dry-run, and side-effect evidence satisfy requirement: {text}",
            [
                "Use the project-approved scheduler command or helper to capture stdout JSON, schedule expression, schedule_id, run_key, job_id, next_run_at, timezone/DST due window, scheduler_runs terminal row, missed-run catch-up behavior, concurrent scheduler_lock/advisory-lock winner and duplicate-skipped loser, invoice-row duplicate absence, dry-run no-persistence proof, no-real-email/outbox boundary, audit log, persistence, and count-aware runtime disposition."
            ],
            scheduled_evidence,
        )
        req_tests.append(scheduled_test)
        tests.append(scheduled_test)
        gaps.append(f"{req_id}: scheduled-job probe needs schedule expression, schedule_id/run_key/job_id/next_run_at stdout JSON, timezone/DST due-window fixtures, scheduler_runs terminal proof, catch-up duplicate absence, advisory-lock winner/loser evidence, dry-run no-persistence proof, invoice/outbox/audit boundaries, no-real-email proof, persistence, and runtime disposition.")
        test_index += 1

    if "artifact_generation" in tags:
        artifact_evidence = list(dict.fromkeys([
            *artifact_generation_evidence_layers(),
            *requirement_specific_evidence_layers(text),
        ]))
        artifact_test = make_test(
            req_id,
            test_index,
            "artifact_generation",
            point,
            "Blocked",
            f"Async artifact generation, manifest, resume, cancellation, partial failure, and download guard satisfy requirement: {text}",
            [
                "Use safe report/export fixtures to create the artifact job, capture the request body, job_id, resume_token, idempotency_key, ordered SSE progress events through artifact_ready, artifact_manifest row, manifest_id/hash, content/file hash, retention/schema/row-count fields, worker checkpoint resume with duplicate absence, cancellation temp-object cleanup, partial_failed failed_sections and diagnostic artifact, denied-viewer download 403 with leak/no-audit guard, authorized download headers/file hash, audit log, persistence, and count-aware runtime disposition."
            ],
            artifact_evidence,
        )
        req_tests.append(artifact_test)
        tests.append(artifact_test)
        gaps.append(f"{req_id}: artifact-generation probe needs safe report job fixtures, ordered progress/artifact_ready stream, manifest/hash/persistence evidence, resume checkpoint duplicate-absence proof, cancel cleanup, partial-failure diagnostics, download authorization/leak guards, audit log, and runtime disposition.")
        test_index += 1

    if "background_job" in tags:
        cache_revalidation_background = "cache_consistency" in tags and not has_background_job_intent(text) and not has_worker_intent(text)
        if cache_revalidation_background:
            background_evidence = list(dict.fromkeys([
                "api_response",
                "response_headers",
                "cache_consistency",
                "cache_invalidation",
                "stale_revalidation",
                "stale_response_guard",
                "origin_fetch",
                "cache_status",
                "trace_id",
                "persistence",
                *requirement_specific_evidence_layers(text),
            ]))
            background_expected = f"Cache revalidation or invalidation background path satisfies requirement without treating stale cache as fresh: {text}"
            background_steps = [
                "Capture the cache invalidation event or revalidation trace, correlate response headers/status to the same trace id or cache key, then prove stale responses are bounded and fresh ETag/version data becomes authoritative."
            ]
            background_gap = f"{req_id}: cache revalidation probe needs invalidation/revalidation trace, cache-status transition, origin-fetch evidence, bounded stale-response proof, fresh ETag/version correlation, and persistence/audit evidence where required."
        else:
            background_evidence = list(dict.fromkeys([
                "queued_status",
                "job_id",
                "api_response",
                "background_worker",
                "terminal_status",
                *requirement_specific_evidence_layers(text),
            ]))
            background_expected = f"Background job enqueue and same-job worker boundary satisfy requirement: {text}"
            background_steps = [
                "Capture the enqueue response, extract the same job id, then correlate it to worker execution and terminal state without treating the queued response as completion."
            ]
            background_gap = f"{req_id}: background-job probe needs enqueue response, same job id, worker execution/log evidence, and terminal status correlation."
        background_test = make_test(
            req_id,
            test_index,
            "background_job",
            point,
            "Blocked",
            background_expected,
            background_steps,
            background_evidence,
        )
        req_tests.append(background_test)
        tests.append(background_test)
        gaps.append(background_gap)
        test_index += 1

    if "worker" in tags:
        worker_evidence = list(dict.fromkeys([
            "worker_log",
            "background_worker",
            "job_id",
            "terminal_status",
            "persistence",
            *requirement_specific_evidence_layers(text),
        ]))
        worker_test = make_test(
            req_id,
            test_index,
            "worker",
            point,
            "Blocked",
            f"Worker processing and side-effect boundary satisfy requirement: {text}",
            [
                "Use a current-run worker log, queue/job state read, or read-only helper to prove the named worker processed the same job id and reached the expected terminal state."
            ],
            worker_evidence,
        )
        req_tests.append(worker_test)
        tests.append(worker_test)
        gaps.append(f"{req_id}: worker probe needs current-run worker log or queue-state helper, same job id correlation, terminal status, and side-effect boundary evidence.")
        test_index += 1
    return test_index

def _apply_resilience_delivery_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    method_path: tuple[str, str] | None,
    paths: list[str],
    page_path: str | None,
    button_name: str | None,
    negative_request_intent: bool,
    response_method: str | None,
    steps: list[dict[str, Any]],
) -> int:
    """追加重试、特性开关与灰度发布规则。"""
    if "retry" in tags:
        analytics_retry_only = "analytics" in tags and "background_job" not in tags and "worker" not in tags
        retry_evidence = list(dict.fromkeys([
            "retry_count",
            "backoff_schedule",
            *([] if analytics_retry_only else ["worker_log"]),
            "runtime",
            *requirement_specific_evidence_layers(text),
        ]))
        retry_test = make_test(
            req_id,
            test_index,
            "retry",
            point,
            "Blocked",
            (
                f"Analytics retry/backoff and queued telemetry state satisfy requirement: {text}"
                if analytics_retry_only
                else f"Worker retry/backoff and failure routing satisfy requirement: {text}"
            ),
            [
                (
                    "Use a safe analytics fault-injection fixture or captured failed-response replay to prove retry_count, next_retry_at, backoff_schedule, queue_status, duplicate-side-effect absence, and no committed attribution/exposure until retry success."
                    if analytics_retry_only
                    else "Use a safe fault-injection fixture or captured failure replay to prove retry count, next retry/backoff schedule, duplicate-side-effect absence, and final dead-letter or terminal status."
                )
            ],
            retry_evidence,
        )
        req_tests.append(retry_test)
        tests.append(retry_test)
        if analytics_retry_only:
            gaps.append(f"{req_id}: analytics retry/backoff probe needs safe fault injection, retry_count, next_retry_at/backoff_schedule/queue_status evidence, duplicate-side-effect absence, and no committed attribution/exposure before retry success.")
        else:
            gaps.append(f"{req_id}: retry/backoff probe needs safe fault injection, retry_count, next_retry/backoff evidence, duplicate-side-effect absence, and terminal/dead-letter correlation.")
        test_index += 1

    if "feature_flag" in tags:
        feature_flag_evidence = list(dict.fromkeys([
            "feature_flag",
            "flag_evaluation",
            "evaluation_id",
            "config_version",
            "api_response",
            *requirement_specific_evidence_layers(text),
        ]))
        feature_flag_test = make_test(
            req_id,
            test_index,
            "feature_flag",
            point,
            "Blocked",
            f"Feature flag evaluation satisfies requirement: {text}",
            [
                "Capture the feature-flag evaluation response or log for the same account/user, including enabled state, evaluation id, variant, reason, and config version before treating UI/API behavior as enabled."
            ],
            feature_flag_evidence,
        )
        req_tests.append(feature_flag_test)
        tests.append(feature_flag_test)
        gaps.append(f"{req_id}: feature-flag probe needs same-account flag evaluation evidence, evaluation_id, variant/reason, config_version, and UI/API binding.")
        test_index += 1

    if "rollout" in tags:
        rollout_evidence = list(dict.fromkeys([
            "cohort_targeting",
            "variant",
            "feature_flag",
            "direct_api_denial",
            "default_off",
            *requirement_specific_evidence_layers(text),
        ]))
        rollout_test = make_test(
            req_id,
            test_index,
            "rollout",
            point,
            "Blocked",
            f"Rollout cohort, control-group, and default-off boundaries satisfy requirement: {text}",
            [
                "Use enabled-cohort, control-cohort, and anonymous/disabled fixtures to prove targeting, variant, direct API denial, default-off fallback, stale-flag guard, and no unintended persistence side effect."
            ],
            rollout_evidence,
        )
        req_tests.append(rollout_test)
        tests.append(rollout_test)
        gaps.append(f"{req_id}: rollout probe needs beta/control/anonymous fixtures, cohort-targeting evidence, direct API denial, default-off fallback, stale-flag guard, and no-side-effect proof.")
        test_index += 1
    return test_index

_RESILIENCE_RULE_FAMILIES = (
    _apply_resilience_negative_rule_family,
    _apply_resilience_client_state_rule_family,
    _apply_resilience_job_rule_family,
    _apply_resilience_delivery_rule_family,
)

def apply_resilience_point_rules(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    method_path: tuple[str, str] | None,
    paths: list[str],
    page_path: str | None,
    button_name: str | None,
    negative_request_intent: bool,
    response_method: str | None,
    steps: list[dict[str, Any]],
) -> int:
    """按稳定语义族追加规则，并保留原有公开调用契约。"""
    for apply_rules in _RESILIENCE_RULE_FAMILIES:
        test_index = apply_rules(
            point=point,
            req_id=req_id,
            text=text,
            tags=tags,
            tests=tests,
            req_tests=req_tests,
            gaps=gaps,
            test_index=test_index,
            method_path=method_path,
            paths=paths,
            page_path=page_path,
            button_name=button_name,
            negative_request_intent=negative_request_intent,
            response_method=response_method,
            steps=steps,
        )
    return test_index

def _apply_authentication_session_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    """追加 CSRF、会话与 Cookie 安全规则。"""
    if "csrf" in tags:
        csrf_evidence = list(dict.fromkeys([
            "csrf_token",
            "csrf_header",
            "csrf_denial",
            "request_headers",
            "api_response",
            "no_persistence_side_effect",
            *requirement_specific_evidence_layers(text),
        ]))
        csrf_test = make_test(
            req_id,
            test_index,
            "csrf",
            point,
            "Blocked",
            f"CSRF token binding and denial behavior satisfy requirement: {text}",
            [
                "Capture the current CSRF token and active session, prove the protected mutation sends the expected X-CSRF-Token header, then replay missing/stale/cross-origin token attempts and prove denial plus no persistence side effect."
            ],
            csrf_evidence,
        )
        req_tests.append(csrf_test)
        tests.append(csrf_test)
        gaps.append(f"{req_id}: CSRF probe needs active-session auth state, captured token/header evidence, missing/stale/cross-origin denial fixtures, no-write proof, and audit/log correlation when required.")
        test_index += 1

    if "session_security" in tags:
        session_evidence = list(dict.fromkeys([
            "session_cookie",
            "session_rotation",
            "logout_invalidation",
            "api_response",
            "permission",
            *requirement_specific_evidence_layers(text),
        ]))
        session_test = make_test(
            req_id,
            test_index,
            "session_security",
            point,
            "Blocked",
            f"Session lifecycle security satisfies requirement: {text}",
            [
                "Use controlled old/current session cookies to prove rotation invalidates the old session, logout invalidates the current session, and protected APIs reject invalidated sessions without unintended writes."
            ],
            session_evidence,
        )
        req_tests.append(session_test)
        tests.append(session_test)
        gaps.append(f"{req_id}: session-security probe needs old/current session fixtures, rotation evidence, logout invalidation evidence, rejected protected API calls, and no-write verification.")
        test_index += 1

    if "cookie_security" in tags:
        cookie_evidence = list(dict.fromkeys([
            "session_cookie",
            "cookie_flags",
            "response_headers",
            *requirement_specific_evidence_layers(text),
        ]))
        cookie_test = make_test(
            req_id,
            test_index,
            "cookie_security",
            point,
            "Blocked",
            f"Session cookie security attributes satisfy requirement: {text}",
            [
                "Capture Set-Cookie headers for the current run and assert session cookie name, value boundary, HttpOnly, Secure, SameSite, and redaction/no-leak requirements."
            ],
            cookie_evidence,
        )
        req_tests.append(cookie_test)
        tests.append(cookie_test)
        gaps.append(f"{req_id}: cookie-security probe needs captured Set-Cookie headers, HttpOnly/Secure/SameSite assertions, and secret redaction/no-leak evidence.")
        test_index += 1
    return test_index

def _apply_authentication_federation_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    """追加 OAuth、重定向与 SAML 联邦认证规则。"""
    if "oauth" in tags:
        oauth_evidence = list(dict.fromkeys([
            "redirect_location",
            "oauth_state",
            "oauth_nonce",
            "pkce_challenge",
            "pkce_verifier",
            "authorization_code",
            "code_exchange",
            "api_response",
            "session_creation",
            "oauth_account",
            "session_cookie",
            "cookie_flags",
            "duplicate_absence",
            "no_session_created",
            "no_persistence_side_effect",
            "audit_log",
            "forbidden text absence",
            *requirement_specific_evidence_layers(text),
        ]))
        oauth_test = make_test(
            req_id,
            test_index,
            "oauth",
            point,
            "Blocked",
            f"OAuth/OIDC PKCE callback security satisfies requirement: {text}",
            [
                "Use safe identity-provider fixtures to capture the authorize redirect, state/nonce/PKCE challenge, server-side code exchange, session and oauth_account creation, then replay wrong or reused state/code/verifier attempts and prove denial, no session/link side effect, audit evidence, and token redaction."
            ],
            oauth_evidence,
        )
        req_tests.append(oauth_test)
        tests.append(oauth_test)
        gaps.append(f"{req_id}: OAuth/PKCE probe needs IDP fixture, authorize redirect capture, state/nonce/PKCE binding, server-side code-exchange evidence, replay/mismatch denial, session/account persistence, and token/no-leak guards.")
        test_index += 1

    if "redirect_security" in tags:
        redirect_evidence = list(dict.fromkeys([
            "redirect_location",
            "redirect_uri_allowlist",
            "open_redirect_guard",
            "api_response",
            "permission",
            "forbidden request absence",
            *requirement_specific_evidence_layers(text),
        ]))
        redirect_test = make_test(
            req_id,
            test_index,
            "redirect_security",
            point,
            "Blocked",
            f"Redirect URI allowlist and open-redirect guard satisfy requirement: {text}",
            [
                "Exercise allowlisted and disallowed redirect_uri/return_to values, capture Location/header or navigation evidence, prove external-domain redirects are rejected, and bind safe fallback behavior to the same auth flow."
            ],
            redirect_evidence,
        )
        req_tests.append(redirect_test)
        tests.append(redirect_test)
        gaps.append(f"{req_id}: redirect-security probe needs allowlisted and malicious redirect_uri/return_to fixtures, Location/navigation capture, external open-redirect denial, and safe fallback evidence.")
        test_index += 1

    if "saml" in tags:
        saml_evidence = list(dict.fromkeys([
            "request body",
            "redirect_location",
            "saml_authn_request",
            "saml_request",
            "relay_state",
            "acs_url",
            "sp_entity_id",
            "saml_response",
            "saml_assertion",
            "xml_signature",
            "x509_certificate",
            "issuer",
            "audience_restriction",
            "destination",
            "recipient",
            "in_response_to",
            "assertion_time_window",
            "name_id",
            "attribute_mapping",
            "request_consumption",
            "api_response",
            "session_creation",
            "session_cookie",
            "cookie_flags",
            "no_session_created",
            "duplicate_absence",
            "no_persistence_side_effect",
            "audit_log",
            "forbidden text absence",
            *requirement_specific_evidence_layers(text),
        ]))
        saml_test = make_test(
            req_id,
            test_index,
            "saml",
            point,
            "Blocked",
            f"SAML SSO AuthnRequest, ACS validation, assertion mapping, and replay security satisfy requirement: {text}",
            [
                "Use safe SAML IdP fixtures to capture AuthnRequest/SAMLRequest, RelayState, ACS URL and SP entityID, then post signed and negative SAMLResponse fixtures to ACS and prove XML signature/x509 validation, issuer, AudienceRestriction, Destination/Recipient, InResponseTo, NotBefore/NotOnOrAfter, NameID and group attribute mapping, request consumption, replay/wrong RelayState/unsigned/expired/wrong audience/wrong recipient/unknown certificate denial, session creation only after validation, audit evidence, and secret redaction."
            ],
            saml_evidence,
        )
        req_tests.append(saml_test)
        tests.append(saml_test)
        gaps.append(f"{req_id}: SAML probe needs safe IdP fixture, AuthnRequest/SAMLRequest and RelayState capture, ACS URL/SP entityID binding, signed/negative SAMLResponse fixtures, XML signature/x509, audience/recipient/InResponseTo/time-window checks, NameID/group mapping, request consumption/replay denial, session/no-session proof, and secret leak guards.")
        test_index += 1
    return test_index

def _apply_authentication_challenge_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    """追加 WebAuthn、MFA 与一次性令牌规则。"""
    if "webauthn" in tags:
        webauthn_evidence = list(dict.fromkeys([
            "request body",
            "webauthn_challenge",
            "rp_id",
            "origin",
            "credential_id",
            "client_data_json",
            "authenticator_data",
            "signature_verification",
            "user_verification",
            "sign_count",
            "challenge_consumption",
            "attestation_object",
            "credential_public_key",
            "api_response",
            "session_creation",
            "session_cookie",
            "cookie_flags",
            "no_session_created",
            "duplicate_absence",
            "no_persistence_side_effect",
            "audit_log",
            "forbidden text absence",
            *requirement_specific_evidence_layers(text),
        ]))
        webauthn_test = make_test(
            req_id,
            test_index,
            "webauthn",
            point,
            "Blocked",
            f"WebAuthn/passkey challenge, assertion, attestation, and replay security satisfy requirement: {text}",
            [
                "Use safe WebAuthn/passkey fixtures to capture challenge options, rpId/origin binding, credential id lookup, clientDataJSON and authenticatorData, public-key signature verification, user verification policy, signCount increase, challenge consumption, replay/wrong-origin/wrong-rpId/unknown-credential denial, passkey registration attestation/public-key storage, session creation only after verification, audit evidence, and secret redaction."
            ],
            webauthn_evidence,
        )
        req_tests.append(webauthn_test)
        tests.append(webauthn_test)
        gaps.append(f"{req_id}: WebAuthn probe needs safe authenticator/passkey fixture, challenge options, rpId/origin/clientDataJSON/authenticatorData capture, public-key signature verification, signCount/replay denial, attestation/public-key storage proof, session/no-session proof, and secret leak guards.")
        test_index += 1

    if "mfa" in tags:
        mfa_evidence = list(dict.fromkeys([
            "request body",
            "mfa_challenge",
            "mfa_pending",
            "totp_code",
            "totp_time_window",
            "clock_skew",
            "mfa_verification",
            "recovery_code",
            "recovery_code_consumption",
            "mfa_required_denial",
            "api_response",
            "session_creation",
            "session_cookie",
            "cookie_flags",
            "no_session_created",
            "direct_api_denial",
            "no_persistence_side_effect",
            "audit_log",
            "forbidden text absence",
            *requirement_specific_evidence_layers(text),
        ]))
        mfa_test = make_test(
            req_id,
            test_index,
            "mfa",
            point,
            "Blocked",
            f"MFA/TOTP challenge, recovery-code, and pending-session security satisfy requirement: {text}",
            [
                "Use safe MFA fixtures to capture password-to-challenge behavior, pending-session state, TOTP time-window and clock-skew verification, wrong/expired/replayed code denial, one-time recovery-code consumption, direct API mfa_required denial, session creation only after MFA, audit evidence, and secret redaction."
            ],
            mfa_evidence,
        )
        req_tests.append(mfa_test)
        tests.append(mfa_test)
        gaps.append(f"{req_id}: MFA probe needs safe account fixture, challenge id, TOTP time-window/clock-skew fixture, wrong/expired/replay denial evidence, recovery-code consumption, pending-session direct API denial, session/no-session proof, and secret leak guards.")
        test_index += 1

    if "one_time_token" in tags:
        one_time_token_evidence = list(dict.fromkeys([
            "request body",
            "generic_success_copy",
            "account_enumeration_guard",
            "one_time_token",
            "token_hash",
            "token_purpose",
            "token_expiry",
            "token_consumption",
            "token_replay_denial",
            "email_outbox",
            "email_link",
            "api_response",
            "password_hash_update",
            "session_invalidation",
            "no_session_created",
            "duplicate_absence",
            "no_persistence_side_effect",
            "audit_log",
            "forbidden text absence",
            *requirement_specific_evidence_layers(text),
        ]))
        one_time_token_test = make_test(
            req_id,
            test_index,
            "one_time_token",
            point,
            "Blocked",
            f"One-time token lifecycle, email link, replay denial, and no-enumeration security satisfy requirement: {text}",
            [
                "Use safe password-reset, magic-link, email-verification, or invite-token fixtures to compare existing and unknown-account request copy, capture current-run outbox/link evidence, prove only token hashes are stored with purpose and expiry, validate and consume the token once, deny replay/expired/tampered/wrong-purpose/wrong-tenant/unknown tokens without session or persistence side effects, verify password/session side effects when required, audit both success and denial, and assert raw token/password/session material is redacted."
            ],
            one_time_token_evidence,
        )
        req_tests.append(one_time_token_test)
        tests.append(one_time_token_test)
        gaps.append(f"{req_id}: one-time-token probe needs safe reset/link fixtures, existing-vs-unknown account comparison, outbox/link evidence, token hash/purpose/expiry proof, one-time consumption and replay/expired/tampered/wrong-purpose/wrong-tenant denial, password/session side-effect proof, audit evidence, and secret leak guards.")
        test_index += 1
    return test_index

def _apply_authentication_credential_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    """追加 API 密钥与审计完整性规则。"""
    if "api_key" in tags:
        api_key_evidence = list(dict.fromkeys([
            "request body",
            "api_key_secret_once",
            "api_key_hash",
            "api_key_prefix",
            "api_key_scopes",
            "api_key_expiry",
            "api_key_last_used",
            "api_key_revocation",
            "api_key_auth_success",
            "api_key_scope_denial",
            "api_key_replay_denial",
            "api_response",
            "no_persistence_side_effect",
            "duplicate_absence",
            "audit_log",
            "forbidden text absence",
            *requirement_specific_evidence_layers(text),
        ]))
        api_key_test = make_test(
            req_id,
            test_index,
            "api_key",
            point,
            "Blocked",
            f"API key/PAT lifecycle, scoped access, revocation, and leak guards satisfy requirement: {text}",
            [
                "Use safe admin/auth fixtures and env-backed API key material to create the key, capture secret-once display, prove persisted/listed records expose only hash-safe prefix metadata, verify scoped success and insufficient-scope denial with no mutation, update last_used_at only on valid use, revoke the key, deny revoked/expired/unknown/tampered keys without side effects, audit create/revoke/denial, and assert raw bearer/key/hash material is redacted."
            ],
            api_key_evidence,
        )
        req_tests.append(api_key_test)
        tests.append(api_key_test)
        gaps.append(f"{req_id}: API-key probe needs safe admin/auth fixture, env-backed secret material, create/list/use/scope-denial/revoke/expired/tampered fixtures, last_used_at/revoked_at/audit proof, no-mutation side-effect checks, and secret leak guards.")
        test_index += 1

    if "audit_integrity" in tags:
        audit_integrity_evidence = list(dict.fromkeys([
            "request body",
            "audit_event",
            "audit_log",
            "audit_sequence",
            "append_only",
            "hash_chain",
            "previous_hash",
            "event_hash",
            "canonical_json",
            "tamper_denial",
            "retention_policy",
            "legal_hold",
            "pii_redaction",
            "api_response",
            "no_persistence_side_effect",
            "duplicate_absence",
            "forbidden text absence",
            *requirement_specific_evidence_layers(text),
        ]))
        audit_integrity_test = make_test(
            req_id,
            test_index,
            "audit_integrity",
            point,
            "Blocked",
            f"Audit log append-only integrity, hash-chain, tamper denial, and retention rules satisfy requirement: {text}",
            [
                "Use safe audit fixtures to create or read the current-run audit event, prove ordered monotonic sequence, append-only storage, previous_hash/event_hash hash-chain recomputation from canonical JSON, deny PATCH/DELETE tamper attempts without mutating event fields, verify retention/legal-hold behavior after privacy deletion, prove actor pseudonymization and PII/raw-IP absence, and disposition runtime failures without treating visible audit rows as integrity proof."
            ],
            audit_integrity_evidence,
        )
        req_tests.append(audit_integrity_test)
        tests.append(audit_integrity_test)
        gaps.append(f"{req_id}: audit-integrity probe needs safe audit event fixture, hash-chain recomputation helper, append-only/tamper-denial attempts, retention/legal-hold proof, pseudonym/PII-redaction checks, no-mutation side-effect evidence, and runtime disposition.")
        test_index += 1
    return test_index

_AUTHENTICATION_RULE_FAMILIES = (
    _apply_authentication_session_rule_family,
    _apply_authentication_federation_rule_family,
    _apply_authentication_challenge_rule_family,
    _apply_authentication_credential_rule_family,
)

def apply_authentication_point_rules(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    """按稳定语义族追加规则，并保留原有公开调用契约。"""
    for apply_rules in _AUTHENTICATION_RULE_FAMILIES:
        test_index = apply_rules(
            point=point,
            req_id=req_id,
            text=text,
            tags=tags,
            tests=tests,
            req_tests=req_tests,
            gaps=gaps,
            test_index=test_index,
        )
    return test_index

def _apply_integrity_schema_policy_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    """追加模式迁移与授权策略完整性规则。"""
    if "schema_migration" in tags:
        schema_migration_evidence = list(dict.fromkeys([
            "command",
            "stdout_json",
            "schema_migration",
            "migration_plan",
            "migration_dry_run",
            "schema_version",
            "schema_diff",
            "backfill_count",
            "batch_checkpoint",
            "index_concurrently",
            "foreign_key_constraint",
            "not_null_constraint",
            "zero_null_verification",
            "rollback_plan",
            "backward_compatibility",
            "api_response",
            "forbidden text absence",
            "persistence",
            *requirement_specific_evidence_layers(text),
        ]))
        schema_migration_test = make_test(
            req_id,
            test_index,
            "schema_migration",
            point,
            "Blocked",
            f"Schema migration expand-contract, backfill, constraints, rollback, and compatibility satisfy requirement: {text}",
            [
                "Use a safe migration fixture to run the dry-run plan, apply, compatibility checks, and rollback dry-run; capture migration_id, expand/contract order, stdout JSON, schema_version transitions, schema diff, exact backfill row count and batch checkpoints, concurrent index, validated foreign key, zero-null/NOT NULL proof, old/new client API responses, forbidden metadata absence, rollback affected rows, and runtime disposition."
            ],
            schema_migration_evidence,
        )
        req_tests.append(schema_migration_test)
        tests.append(schema_migration_test)
        gaps.append(f"{req_id}: schema-migration probe needs safe migration fixture, dry-run/apply/rollback helpers, schema diff/version proof, exact backfill and batch checkpoint evidence, concurrent-index/FK/NOT NULL constraint proof, old/new client compatibility checks, metadata leak guards, persistence evidence, and runtime disposition.")
        test_index += 1

    if "authorization_policy" in tags:
        authorization_policy_evidence = list(dict.fromkeys([
            "request body",
            "authorization_policy",
            "policy_matrix",
            "policy_decision",
            "matched_rule",
            "deny_precedence",
            "role_inheritance",
            "resource_scope",
            "obligation",
            "direct_api_denial",
            "api_response",
            "forbidden request absence",
            "no_persistence_side_effect",
            "data_isolation",
            "cross_tenant_denial",
            "forbidden text absence",
            "policy_cache_key",
            "stale_policy_guard",
            "audit_log",
            "persistence",
            *requirement_specific_evidence_layers(text),
        ]))
        authorization_policy_test = make_test(
            req_id,
            test_index,
            "authorization_policy",
            point,
            "Blocked",
            f"Authorization policy matrix, deny precedence, scoped resources, direct API denial, and audit evidence satisfy requirement: {text}",
            [
                "Use safe role/resource fixtures to evaluate the policy matrix, capture actor/resource/action/tenant request body, policy decision, matched rule, explicit deny precedence over inherited roles, resource-scope and obligation evidence, hidden/disabled UI affordance, direct API denial with no export/outbox side effect, cross-tenant denial and forbidden text absence, policy cache-key and stale-allow invalidation after policy version change, audit log, persistence, and runtime disposition."
            ],
            authorization_policy_evidence,
        )
        req_tests.append(authorization_policy_test)
        tests.append(authorization_policy_test)
        gaps.append(f"{req_id}: authorization-policy probe needs safe role/resource fixtures, policy-evaluate helper, matched-rule/deny-precedence proof, role-inheritance and resource-scope evidence, obligation checks, denied UI/direct API evidence, no-side-effect proof, tenant leak guards, policy cache invalidation, audit evidence, and runtime disposition.")
        test_index += 1
    return test_index

def _apply_integrity_financial_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    """追加账本、配额、事务与订阅计费规则。"""
    if "financial_ledger" in tags:
        financial_ledger_evidence = list(dict.fromkeys([
            "request body",
            "api_response",
            "financial_ledger",
            "ledger_entry",
            "double_entry",
            "ledger_balance",
            "immutable_ledger",
            "reversal_entry",
            "minor_unit_amount",
            "no_float_drift",
            "idempotency_key",
            "duplicate_absence",
            "over_refund_denial",
            "forbidden request absence",
            "no_persistence_side_effect",
            "settlement_event",
            "payout_reconciliation",
            "audit_log",
            "persistence",
            *requirement_specific_evidence_layers(text),
        ]))
        financial_ledger_test = make_test(
            req_id,
            test_index,
            "financial_ledger",
            point,
            "Blocked",
            f"Financial ledger double-entry, immutable reversal, idempotency, denial, settlement, and reconciliation satisfy requirement: {text}",
            [
                "Use safe payment/refund fixtures to capture request body, refund API response, original ledger immutability, exactly balanced debit/credit reversal entries linked to the original transaction, minor-unit cents arithmetic with no float drift, idempotent replay duplicate absence, over-refund 409 with no ledger/outbox side effect, provider settlement event, payout reconciliation row, audit log, persistence, and runtime disposition."
            ],
            financial_ledger_evidence,
        )
        req_tests.append(financial_ledger_test)
        tests.append(financial_ledger_test)
        gaps.append(f"{req_id}: financial-ledger probe needs safe payment/refund fixtures, double-entry balance proof, immutable original-entry and reversal-link evidence, minor-unit/no-float-drift checks, idempotent duplicate absence, over-refund no-side-effect proof, settlement-event reconciliation, audit evidence, persistence, and runtime disposition.")
        test_index += 1

    if "quota_metering" in tags:
        quota_evidence = list(dict.fromkeys([
            "request body",
            "api_response",
            "quota_metering",
            "usage_counter",
            "quota_window",
            "quota_remaining",
            "atomic_increment",
            "counter_version",
            "concurrent_requests",
            "conflict_response",
            "quota_exceeded_denial",
            "no_negative_remaining",
            "idempotency_key",
            "duplicate_absence",
            "billing_usage_event",
            "forbidden request absence",
            "no_persistence_side_effect",
            "reset_boundary",
            "audit_log",
            "persistence",
            *requirement_specific_evidence_layers(text),
        ]))
        quota_test = make_test(
            req_id,
            test_index,
            "quota_metering",
            point,
            "Blocked",
            f"Usage quota metering, atomic counter updates, denial side effects, idempotency, billing event, and reset boundary satisfy requirement: {text}",
            [
                "Use safe tenant/meter/window fixtures to capture request body and quota API response, prove the same usage_counter row moves used/remaining/counter_version correctly, race two usage events to show exactly one accepted and one quota_exceeded denial with non-negative remaining, replay the idempotency key without counter or billing side effects, prove over-quota denial creates no downstream job/outbox/billing event, run the reset-boundary worker at the exact quota-window boundary, verify previous-period carryover and audit log, persistence, and runtime disposition."
            ],
            quota_evidence,
        )
        req_tests.append(quota_test)
        tests.append(quota_test)
        gaps.append(f"{req_id}: quota-metering probe needs safe tenant/meter/window fixtures, usage-counter and counter-version proof, concurrent winner/loser requests, quota_exceeded denial with no downstream job/outbox/billing side effect, idempotent duplicate absence, billing-event exactness, reset-boundary worker/audit evidence, persistence, and runtime disposition.")
        test_index += 1

    if "transaction_integrity" in tags:
        transaction_evidence = list(dict.fromkeys([
            "request body",
            "api_response",
            "transaction_integrity",
            "transaction_id",
            "atomic_commit",
            "order_state",
            "payment_authorization",
            "inventory_reservation",
            "outbox_event",
            "outbox_dispatch",
            "post_commit_publish",
            "publish_exactly_once",
            "idempotency_key",
            "duplicate_absence",
            "saga_compensation",
            "compensation_event",
            "inventory_release",
            "authorization_void",
            "forbidden request absence",
            "no_persistence_side_effect",
            "correlation_id",
            "trace_id",
            "audit_log",
            "persistence",
            *requirement_specific_evidence_layers(text),
        ]))
        transaction_test = make_test(
            req_id,
            test_index,
            "transaction_integrity",
            point,
            "Blocked",
            f"Checkout transaction, outbox dispatch, idempotency, and saga compensation evidence satisfy requirement: {text}",
            [
                "Use safe checkout/payment/inventory fixtures to capture request body and response, prove order/payment_authorization/inventory_reservation/outbox_event rows share the same transaction_id and commit atomically, replay the idempotency key with no duplicate rows, force payment-timeout and inventory-reservation-failure paths to prove saga compensation, inventory release, authorization void, failed order state, no order.confirmed outbox or receipt side effect, post-commit outbox publish exactly once, trace/correlation continuity, audit log, persistence, and runtime disposition."
            ],
            transaction_evidence,
        )
        req_tests.append(transaction_test)
        tests.append(transaction_test)
        gaps.append(f"{req_id}: transaction-integrity probe needs safe checkout/payment/inventory fixtures, same transaction_id and atomic-commit proof across order/payment/inventory/outbox, idempotent duplicate absence, saga compensation with inventory release/authorization void, no confirmed outbox or receipt side effect on failure, post-commit exactly-once dispatch, trace/correlation continuity, audit evidence, persistence, and runtime disposition.")
        test_index += 1

    if "subscription_billing" in tags:
        subscription_evidence = list(dict.fromkeys([
            "request body",
            "api_response",
            "subscription_billing",
            "subscription_id",
            "current_plan",
            "target_plan",
            "subscription_version",
            "billing_cycle",
            "billing_anchor",
            "proration_behavior",
            "invoice_preview",
            "proration_line_item",
            "unused_credit",
            "prorated_charge",
            "tax_jurisdiction",
            "tax_rate",
            "tax_amount",
            "invoice_total",
            "calculation_version",
            "payment_intent",
            "scheduled_capture",
            "scheduled_change",
            "idempotency_key",
            "duplicate_absence",
            "authorization_denial",
            "forbidden request absence",
            "forbidden text absence",
            "no_persistence_side_effect",
            "audit_log",
            "persistence",
            "runtime",
            *requirement_specific_evidence_layers(text),
        ]))
        subscription_test = make_test(
            req_id,
            test_index,
            "subscription_billing",
            point,
            "Blocked",
            f"Subscription plan-change preview, proration, tax, scheduled capture/change, idempotency, and authorization denial satisfy requirement: {text}",
            [
                "Use safe subscription/billing fixtures to capture request body and API response for the preview, prove preview_id calculation with subscription_id/current_plan/target_plan/subscription_version, unused credit, prorated charge, tax jurisdiction/rate/amount, invoice total, calculation version, and no subscription/invoice/payment/receipt mutation; confirm the preview to prove subscription_version transition, invoice line items, payment_intent scheduled capture, audit log, and persistence; replay the idempotency key to prove duplicate absence; request a downgrade to prove scheduled_change at billing anchor with no immediate invoice/refund/payment side effect; attempt the change as the denied support actor to prove 403 authorization_denial, forbidden text absence, and no billing.plan_changed mutation; disposition runtime issues."
            ],
            subscription_evidence,
        )
        req_tests.append(subscription_test)
        tests.append(subscription_test)
        gaps.append(f"{req_id}: subscription-billing probe needs safe subscription/account fixtures, preview no-mutation evidence, proration/tax calculation proof, confirmed subscription_version/invoice/payment schedule evidence, idempotent duplicate absence, downgrade scheduled-change boundary proof, denied support actor no-side-effect evidence, audit/persistence evidence, no receipt email proof, and runtime disposition.")
        test_index += 1
    return test_index

def _apply_integrity_observability_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    """追加 Agent 工具与分析可观测性规则。"""
    if "agent_tool" in tags:
        agent_tool_evidence = list(dict.fromkeys([
            "request body",
            "api_response",
            "stream",
            "websocket",
            "agent_tool",
            "agent_session_id",
            "tool_call_event",
            "tool_call_id",
            "tool_name",
            "tool_args_redaction",
            "args_hash",
            "approval_gate",
            "approval_id",
            "tool_result_event",
            "tool_result_id",
            "cancellation_event",
            "tool_execution_absence",
            "idempotency_key",
            "duplicate_absence",
            "authorization_denial",
            "handoff_required",
            "handoff_id",
            "audit_log",
            "persistence",
            "forbidden text absence",
            "runtime",
            *requirement_specific_evidence_layers(text),
        ]))
        agent_tool_test = make_test(
            req_id,
            test_index,
            "agent_tool",
            point,
            "Blocked",
            f"Agent tool-call orchestration, approval, cancellation, redaction, idempotency, authorization denial, and handoff evidence satisfy requirement: {text}",
            [
                "Use safe agent/session/tool fixtures to capture the prompt request body, WebSocket stream, approval/cancel API responses, and persistence/audit state; prove agent_session_id binding, tool_call_requested with tool_call_id/tool_name/args_hash and redacted tool_args, approval_required/approval_id before tool execution and disabled final answer, approved tool_result/tool_result_id followed by answer_done, idempotent replay duplicate absence, cancellation event with no executor invocation or outbound side effects, denied viewer 403 authorization_denial with no audit/tool execution, timeout handoff_required/handoff_id with needs_human_review persistence and no successful answer_done, forbidden text absence, and count-aware runtime disposition."
            ],
            agent_tool_evidence,
        )
        req_tests.append(agent_tool_test)
        tests.append(agent_tool_test)
        gaps.append(f"{req_id}: agent-tool probe needs safe agent/session/tool fixtures, WebSocket stream and approval/cancel API evidence, tool_call_requested id/name/args_hash with redacted args, approval gate before execution, tool_result and answer_done binding, idempotent duplicate absence, cancellation no-execution/no-side-effect proof, denied viewer no-side-effect proof, handoff_required timeout persistence, audit evidence, forbidden text absence, and runtime disposition.")
        test_index += 1
        if "interaction" in tags:
            agent_tool_interaction_test = make_test(
                req_id,
                test_index,
                "interaction",
                point,
                "Blocked",
                f"Agent tool approval/cancel UI interaction state satisfies requirement: {text}",
                [
                    "Use the agent runbook UI with safe agent/session/tool fixtures to prove prompt submission, approval gate actionability, final-answer disabled state before approval, approve and cancel controls bound to the correct tool_call_id/approval_id, and visible state changes matched to the WebSocket event chain."
                ],
                [
                    "ui_interaction",
                    "approval_gate",
                    "approval_id",
                    "tool_call_id",
                    "tool_call_event",
                    "cancellation_event",
                    "tool_execution_absence",
                    "stream",
                    "runtime",
                ],
            )
            req_tests.append(agent_tool_interaction_test)
            tests.append(agent_tool_interaction_test)
            gaps.append(f"{req_id}: agent-tool UI interaction probe needs stable runbook selectors, safe prompt/tool fixtures, approval/cancel controls, disabled final-answer state, and event-chain binding before execution.")
            test_index += 1

    if "analytics" in tags:
        analytics_evidence = list(dict.fromkeys([
            *analytics_evidence_layers(),
            *requirement_specific_evidence_layers(text),
        ]))
        analytics_test = make_test(
            req_id,
            test_index,
            "analytics",
            point,
            "Blocked",
            f"Analytics telemetry event, consent, attribution, experiment exposure, retry, dedupe, persistence, and leak guards satisfy requirement: {text}",
            [
                "Drive or replay the checkout telemetry path with safe analytics fixtures: capture the checkout success response, prove no checkout_completed event is sent before paid status, capture the POST /api/v1/analytics/events request body with event_name/event_id/schema_version/consent_version/session_id/user_pseudonym_id/order_id/transaction_id/attribution_id/campaign_id/experiment_id/variant/dedupe_key/event_time/qa_marker, prove consent=false or missing consent_version emits no analytics request or rows, replay event_id/dedupe_key for duplicate_ignored duplicate absence, force 503 to prove retry_count/next_retry_at/backoff_schedule/queue_status pending_retry without committed attribution/exposure, verify attribution_mismatch denial for wrong session or expired window, verify experiment_exposure exposure_id persisted before conversion attribution, assert analytics_event/conversion/attribution_credit/experiment_exposure persistence, and assert raw email/phone/shipping_address/card_last4/access_token/cookie absence in requests, rows, logs, and report artifacts."
            ],
            analytics_evidence,
        )
        req_tests.append(analytics_test)
        tests.append(analytics_test)
        gaps.append(f"{req_id}: analytics telemetry probe needs safe checkout/analytics fixtures, captured event payload and schema, consent gate, no-early-event proof, duplicate replay absence, 503 retry queue evidence, attribution mismatch denial, experiment exposure persistence, analytics/conversion/attribution persistence, PII/token/cookie leak guards, and runtime disposition.")
        test_index += 1
        if "interaction" in tags:
            analytics_interaction_test = make_test(
                req_id,
                test_index,
                "interaction",
                point,
                "Blocked",
                f"Checkout consent and telemetry-triggering UI interaction state satisfies requirement: {text}",
                [
                    "Use stable checkout and consent controls to prove the shopper can open checkout, accept or deny analytics consent, complete checkout, and that UI interactions are bound to analytics request ordering: no checkout_completed event before paid checkout response, no tracking-success copy when consent is false or missing, and actionability/loading/disabled states remain correct while analytics is queued or retried."
                ],
                [
                    "ui_interaction",
                    "consent_state",
                    "consent_version",
                    "analytics",
                    "analytics_event",
                    "api_response",
                    "forbidden request absence",
                    "runtime",
                ],
            )
            req_tests.append(analytics_interaction_test)
            tests.append(analytics_interaction_test)
            gaps.append(f"{req_id}: analytics interaction probe needs stable checkout/consent selectors, paid-checkout ordering, no-event-before-paid proof, consent-denied no-tracking-success UI proof, loading/disabled/actionability checks, and analytics request binding.")
            test_index += 1
    return test_index

def _apply_integrity_delivery_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    """追加缓存一致性与 Webhook 安全规则。"""
    if "cache_consistency" in tags:
        cache_evidence = list(dict.fromkeys([
            "request body",
            "api_response",
            "response_headers",
            "cache_consistency",
            "etag",
            "cache_control",
            "if_none_match",
            "not_modified_denial",
            "cache_invalidation",
            "cache_key",
            "surrogate_key_purge",
            "stale_revalidation",
            "stale_response_guard",
            "origin_fetch",
            "cache_status",
            "version_token",
            "ui_stale_absence",
            "trace_id",
            "audit_log",
            "persistence",
            *requirement_specific_evidence_layers(text),
        ]))
        cache_test = make_test(
            req_id,
            test_index,
            "cache_consistency",
            point,
            "Blocked",
            f"HTTP/cache consistency, revalidation, purge, stale-response, and visible freshness evidence satisfy requirement: {text}",
            [
                "Use safe catalog/cache fixtures to capture request body, response body, and response headers before and after mutation; prove ETag and Cache-Control values, If-None-Match revalidation, no 304 for stale validators after mutation, cache_key invalidation, surrogate-key purge, origin fetch, bounded stale-while-revalidate response with Warning header, MISS-to-HIT cache_status transition after revalidation, version-token freshness, UI stale-value absence, trace continuity, audit log, persistence, and runtime disposition."
            ],
            cache_evidence,
        )
        req_tests.append(cache_test)
        tests.append(cache_test)
        gaps.append(f"{req_id}: cache-consistency probe needs safe catalog/cache fixtures, ETag/Cache-Control/If-None-Match header capture, stale-validator 304 denial after mutation, cache-key invalidation, surrogate-key purge, bounded stale-while-revalidate proof, origin fetch and MISS/HIT transition, version-token and UI stale-absence evidence, trace/audit/persistence evidence, and runtime disposition.")
        test_index += 1

    if "webhook_security" in tags:
        webhook_evidence = list(dict.fromkeys([
            "api_response",
            "request_headers",
            "request body",
            "webhook_security",
            "signature_validation",
            "hmac_signature",
            "raw_body_integrity",
            "timestamp_tolerance",
            "replay_window",
            "signature_version",
            "idempotency_key",
            "duplicate_absence",
            "no_persistence_side_effect",
            "forbidden text absence",
            "audit_log",
            "persistence",
            *requirement_specific_evidence_layers(text),
        ]))
        webhook_test = make_test(
            req_id,
            test_index,
            "webhook_security",
            point,
            "Blocked",
            f"Webhook raw-body signature, timestamp, replay-window, and no-leak evidence satisfy requirement: {text}",
            [
                "Use safe webhook fixtures and env-backed signing secret to capture exact raw request body, request headers, signature verification result, invalid reordered-body rejection, timestamp-out-of-tolerance denial, replay-window duplicate_ignored behavior, no persistence/outbox side effects for rejected or duplicate deliveries, audit evidence, secret/digest/raw-body leak absence, persistence, and runtime disposition."
            ],
            webhook_evidence,
        )
        req_tests.append(webhook_test)
        tests.append(webhook_test)
        gaps.append(f"{req_id}: webhook-security probe needs safe provider fixture, env-backed signing secret, exact raw-body HMAC proof, invalid reordered-body and timestamp-denial evidence, replay-window duplicate absence, no side effects, audit/persistence evidence, secret leak guards, and runtime disposition.")
        test_index += 1
    return test_index

def _apply_integrity_privacy_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    """追加隐私合规与数据生命周期规则。"""
    if "privacy_compliance" in tags:
        analytics_privacy_only = "analytics" in tags and not has_privacy_compliance_intent(text)
        if analytics_privacy_only:
            privacy_evidence = list(dict.fromkeys([
                "api_response",
                "request body",
                "privacy_compliance",
                "analytics",
                "analytics_event",
                "event_name",
                "event_id",
                "consent_state",
                "user_pseudonym_id",
                "pii_redaction",
                "forbidden text absence",
                "persistence",
                "runtime",
                *requirement_specific_evidence_layers(text),
            ]))
            privacy_test = make_test(
                req_id,
                test_index,
                "privacy_compliance",
                point,
                "Blocked",
                f"Analytics privacy leak guard evidence satisfies requirement: {text}",
                [
                    "Use safe analytics fixtures to capture the analytics request body, stored analytics_event/conversion rows, logs, and report artifacts; assert raw email, phone, shipping_address, card_last4, access_token, cookie, and other direct identifiers are absent while user_pseudonym_id is preserved and bound to the same event."
                ],
                privacy_evidence,
            )
            gaps.append(f"{req_id}: analytics privacy leak guard needs captured analytics request, stored rows, logs/report artifacts, pseudonym binding, and forbidden raw PII/token/cookie absence.")
        else:
            privacy_evidence = list(dict.fromkeys([
                "api_response",
                "request body",
                "privacy_compliance",
                "privacy_export",
                "export_artifact",
                "export_manifest",
                "encrypted_export",
                "data_hash",
                "erasure_request",
                "pseudonymization",
                "pii_redaction",
                "session_invalidation",
                "api_key_revocation",
                "search_index_removal",
                "cache_invalidation",
                "legal_hold",
                "retention_policy",
                "idempotency_key",
                "duplicate_absence",
                "data_isolation",
                "tenant_boundary",
                "forbidden text absence",
                "audit_log",
                "persistence",
                *requirement_specific_evidence_layers(text),
            ]))
            privacy_test = make_test(
                req_id,
                test_index,
                "privacy_compliance",
                point,
                "Blocked",
                f"Privacy DSAR export, erasure, legal-hold, revocation, index/cache cleanup, and no-PII-leak evidence satisfy requirement: {text}",
                [
                    "Use safe privacy fixtures to capture the export/erasure request body, same export_job_id or erasure_job_id, encrypted export artifact and manifest, data_hash, tenant-scoped DSAR contents, pseudonymized actor_ref/profile fields, active-session deletion, API-key revocation, search-index removal, cache purge, legal-hold blocked behavior with required retention preserved, idempotent replay duplicate absence, audit log, persistence, and forbidden raw PII/token/encryption-key text absence."
                ],
                privacy_evidence,
            )
            gaps.append(f"{req_id}: privacy-compliance probe needs safe DSAR/erasure fixtures, export artifact and manifest evidence, encrypted export/data_hash proof, tenant-scoped contents, pseudonymization, session/API-key revocation, search-index and cache purge proof, legal-hold blocked behavior, idempotent duplicate absence, audit/persistence evidence, and PII/token/encryption-key leak guards.")
        req_tests.append(privacy_test)
        tests.append(privacy_test)
        test_index += 1
    return test_index

_INTEGRITY_RULE_FAMILIES = (
    _apply_integrity_schema_policy_rule_family,
    _apply_integrity_financial_rule_family,
    _apply_integrity_observability_rule_family,
    _apply_integrity_delivery_rule_family,
    _apply_integrity_privacy_rule_family,
)

def apply_integrity_point_rules(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    """按稳定语义族追加规则，并保留原有公开调用契约。"""
    for apply_rules in _INTEGRITY_RULE_FAMILIES:
        test_index = apply_rules(
            point=point,
            req_id=req_id,
            text=text,
            tags=tags,
            tests=tests,
            req_tests=req_tests,
            gaps=gaps,
            test_index=test_index,
        )
    return test_index

def _apply_knowledge_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    if "graphql" in tags:
        graphql_evidence = graphql_evidence_layers(text)
        graphql_test = make_test(
            req_id,
            test_index,
            "graphql",
            point,
            "Blocked",
            f"GraphQL BFF evidence satisfies requirement: {text}",
            [graphql_probe_instruction(text)],
            graphql_evidence,
        )
        req_tests.append(graphql_test)
        tests.append(graphql_test)
        gaps.append(f"{req_id}: GraphQL probe needs safe BFF fixtures, {graphql_probe_focus(text)}, and runtime disposition.")
        test_index += 1

    if "rag_grounding" in tags:
        rag_evidence = list(dict.fromkeys([
            "ui_interaction",
            "api_response",
            "request body",
            "stream",
            "terminal_status",
            "rag_grounding",
            "retrieval_trace",
            "retrieved_source_ids",
            "vector_index",
            "embedding_model",
            "top_k",
            "score_threshold",
            "query_hash",
            "source_citation",
            "citation_span",
            "source_excerpt_match",
            "document_version",
            "stale_source_guard",
            "hallucination_guard",
            "prompt_injection_guard",
            "safety_trace",
            "abstention",
            "insufficient_sources",
            "tenant_boundary",
            "data_isolation",
            "forbidden text absence",
            "audit_log",
            "persistence",
            *requirement_specific_evidence_layers(text),
        ]))
        rag_test = make_test(
            req_id,
            test_index,
            "rag_grounding",
            point,
            "Blocked",
            f"RAG retrieval trace, grounded citations, injection guard, abstention, tenant isolation, and terminal stream evidence satisfy requirement: {text}",
            [
                "Use safe RAG fixtures to capture the request body, answer_id, same answer_delta/answer_done stream, retrieval_trace with query_hash/vector_index/embedding_model/top_k/score_threshold/source_ids, citation spans and source excerpt matches for every factual sentence, current document_version with stale-source denial, hallucination guard, prompt-injection safety_trace, tenant/corpus isolation, insufficient-sources abstention with no citation rows, audit log, persistence, forbidden secret/foreign-tenant text absence, and runtime disposition."
            ],
            rag_evidence,
        )
        req_tests.append(rag_test)
        tests.append(rag_test)
        gaps.append(f"{req_id}: RAG grounding probe needs safe knowledge fixtures, request body, same answer_id stream terminal event, retrieval_trace/query_hash/vector index evidence, retrieved source ids, citation spans with source excerpt matches, current document version and stale-source denial, hallucination and prompt-injection guards, tenant isolation, abstention/no-citation-row proof, audit/persistence evidence, forbidden text absence, and runtime disposition.")
        test_index += 1

        if "stream" in tags:
            rag_stream_test = make_test(
                req_id,
                test_index,
                "stream",
                point,
                "Blocked",
                f"RAG answer stream reaches a terminal answer_done event for the same answer_id: {text}",
                [
                    "Capture answer_delta messages and answer_done for the same answer_id, then bind the terminal stream event to the request body, retrieval_trace, citations, and runtime disposition instead of treating a single chunk as completion."
                ],
                [
                    "stream",
                    "terminal_status",
                    "answer_id",
                    "request body",
                    "retrieval_trace",
                    "source_citation",
                    "runtime",
                ],
            )
            req_tests.append(rag_stream_test)
            tests.append(rag_stream_test)
            gaps.append(f"{req_id}: RAG stream probe needs answer_delta and same-answer_id answer_done evidence bound to retrieval/citation/runtime proof.")
            test_index += 1

    if "search_relevance" in tags:
        search_evidence = list(dict.fromkeys([
            "ui_interaction",
            "api_response",
            "request body",
            "query_params",
            "search_relevance",
            "search_id",
            "result_order",
            "result_position",
            "relevance_score",
            "ranking_model",
            "query_rewrite",
            "canonical_query",
            "typo_tolerance",
            "synonym_expansion",
            "facet_counts",
            "total_count",
            "sponsored_disclosure",
            "stale_result_guard",
            "error_state",
            "tenant_boundary",
            "data_isolation",
            "forbidden text absence",
            "runtime",
            *requirement_specific_evidence_layers(text),
        ]))
        search_test = make_test(
            req_id,
            test_index,
            "search_relevance",
            point,
            "Blocked",
            f"Search relevance, ranking, query rewrite, facets, sponsored disclosure, and stale-result guards satisfy requirement: {text}",
            [
                "Use safe search fixtures to capture the request query params, search_id, API result ids and positions, relevance_score ordering, ranking_model, query_rewrite_id/canonical_query for typo and synonym inputs, facet_counts and total_count from the same filtered result set, sponsored_disclosure placement rules, forbidden hidden/out-of-tenant product absence, retryable-error UI, stale popular/previous-result absence, and runtime disposition."
            ],
            search_evidence,
        )
        req_tests.append(search_test)
        tests.append(search_test)
        gaps.append(f"{req_id}: search-relevance probe needs safe search fixtures, query-param capture, search_id, ordered result ids/positions/scores, ranking_model, query rewrite/canonical query evidence, facet_counts/total_count parity, sponsored disclosure proof, tenant/hidden-product leak guards, stale-result absence, error-state proof, and runtime disposition.")
        test_index += 1

        if "pagination" in tags:
            pagination_test = make_test(
                req_id,
                test_index,
                "pagination",
                point,
                "Blocked",
                f"Search pagination preserves filtered relevance order without duplicate result ids: {text}",
                [
                    "Capture page=1 and page=2 result ids for the same query/filter/ranking model, prove page=2 has no duplicate ids from page=1, and bind the UI rows to the API response and total_count evidence."
                ],
                [
                    "api_response",
                    "query_params",
                    "pagination",
                    "result_order",
                    "duplicate_absence",
                    "total_count",
                    "ui_interaction",
                ],
            )
            req_tests.append(pagination_test)
            tests.append(pagination_test)
            gaps.append(f"{req_id}: search pagination probe needs page=1/page=2 result id capture with duplicate absence and total_count binding.")
            test_index += 1
    return test_index


def _apply_distributed_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    if "optimistic_ui" in tags:
        optimistic_evidence = list(dict.fromkeys([
            "request body",
            "optimistic_update",
            "temp_id",
            "pending_state",
            "api_response",
            "rollback",
            "failed_state",
            "retry_action",
            "cache_invalidation",
            "stale_data_guard",
            "no_success_toast",
            "no_persistence_side_effect",
            "duplicate_absence",
            *requirement_specific_evidence_layers(text),
        ]))
        optimistic_test = make_test(
            req_id,
            test_index,
            "optimistic_ui",
            point,
            "Blocked",
            f"Optimistic UI rollback, cache invalidation, retry, and server-state reconciliation satisfy requirement: {text}",
            [
                "Use a safe failed-response fixture followed by a retry-success fixture to capture the temporary optimistic state, failed rollback or failed-state UI, absent success toast, cache invalidation/refetch evidence, no persisted side effect after the failed request, retry idempotency, replacement of temp_id with the server id, duplicate absence after reload, and runtime disposition."
            ],
            optimistic_evidence,
        )
        req_tests.append(optimistic_test)
        tests.append(optimistic_test)
        gaps.append(f"{req_id}: optimistic-UI probe needs safe failed-response and retry-success fixtures, temp-id capture, rollback/failed-state evidence, no-success-toast assertion, cache invalidation/refetch proof, no-persistence side-effect evidence, idempotent retry proof, duplicate absence, and runtime disposition.")
        test_index += 1

    if "rate_limit" in tags:
        rate_limit_evidence = list(dict.fromkeys([
            "request body",
            "attempt_count",
            "rate_limit_key",
            "rate_limit_window",
            "rate_limited_response",
            "retry_after_header",
            "lockout_state",
            "lockout_expiry",
            "no_session_created",
            "generic_error_copy",
            "account_enumeration_guard",
            "audit_log",
            "persistence",
            *requirement_specific_evidence_layers(text),
        ]))
        rate_limit_test = make_test(
            req_id,
            test_index,
            "rate_limit",
            point,
            "Blocked",
            f"Rate-limit, lockout, and no-session security behavior satisfy requirement: {text}",
            [
                "Use safe auth fixtures to repeat the same account/client request through the configured window, capture attempts before and at the limiting threshold, assert 429 plus Retry-After, prove no session/token was created, compare unknown-account copy/timing, and verify persisted lockout/reset/audit evidence."
            ],
            rate_limit_evidence,
        )
        req_tests.append(rate_limit_test)
        tests.append(rate_limit_test)
        gaps.append(f"{req_id}: rate-limit probe needs safe repeated-login fixture, same account/client key, threshold attempt evidence, Retry-After header, no-session proof, enumeration guard, lockout/reset persistence, and audit/log correlation.")
        test_index += 1

    if "realtime" in tags:
        realtime_evidence = list(dict.fromkeys([
            "realtime",
            "broadcast_event",
            "stream",
            "websocket",
            "api_response",
            *requirement_specific_evidence_layers(text),
        ]))
        realtime_test = make_test(
            req_id,
            test_index,
            "realtime",
            point,
            "Blocked",
            f"Realtime broadcast behavior satisfies requirement: {text}",
            [
                "Use current-run live event evidence to prove the named update is broadcast to the expected recipient client, with event type, payload marker, actor, and timing captured."
            ],
            realtime_evidence,
        )
        req_tests.append(realtime_test)
        tests.append(realtime_test)
        gaps.append(f"{req_id}: realtime broadcast probe needs safe live-event fixtures, sender/recipient auth, captured event payload, timing, and runtime disposition.")
        test_index += 1

    if "multi_client" in tags:
        multi_client_evidence = list(dict.fromkeys([
            "multi_client",
            "broadcast_event",
            "stream",
            "websocket",
            *requirement_specific_evidence_layers(text),
            "sender/recipient client correlation",
        ]))
        multi_client_test = make_test(
            req_id,
            test_index,
            "multi_client",
            point,
            "Blocked",
            f"Multi-client collaboration behavior satisfies requirement: {text}",
            [
                "Connect at least two independently identified clients, perform the action from the sender, then prove the recipient observed the same event without relying on the sender's local state."
            ],
            multi_client_evidence,
        )
        req_tests.append(multi_client_test)
        tests.append(multi_client_test)
        gaps.append(f"{req_id}: multi-client probe needs two authenticated client contexts, recipient-side event evidence, and same-workspace boundary confirmation.")
        test_index += 1

    if "ordering" in tags:
        ordering_evidence = list(dict.fromkeys([
            "sequence_order",
            "duplicate_absence",
            "stream",
            "websocket",
            *requirement_specific_evidence_layers(text),
        ]))
        ordering_test = make_test(
            req_id,
            test_index,
            "ordering",
            point,
            "Blocked",
            f"Realtime event ordering satisfies requirement: {text}",
            [
                "Capture the ordered event sequence for the same stream/client and prove the required sequence values arrive in order with no duplicate sequence."
            ],
            ordering_evidence,
        )
        req_tests.append(ordering_test)
        tests.append(ordering_test)
        gaps.append(f"{req_id}: ordering probe needs captured sequence values, ordered arrival evidence, duplicate absence, and same-stream correlation.")
        test_index += 1

    if "reconnect" in tags:
        reconnect_evidence = list(dict.fromkeys([
            "reconnect_replay",
            "sequence_order",
            "duplicate_absence",
            "stream",
            "websocket",
            *requirement_specific_evidence_layers(text),
        ]))
        reconnect_test = make_test(
            req_id,
            test_index,
            "reconnect",
            point,
            "Blocked",
            f"Reconnect replay behavior satisfies requirement: {text}",
            [
                "Disconnect and reconnect with the specified cursor, prove exactly-once catch-up replay for the missing sequence, then prove live events resume without duplicates."
            ],
            reconnect_evidence,
        )
        req_tests.append(reconnect_test)
        tests.append(reconnect_test)
        gaps.append(f"{req_id}: reconnect replay probe needs cursor-aware reconnect fixture, replayed sequence evidence, duplicate absence, and resumed-live-event evidence.")
        test_index += 1
    return test_index


def _apply_operation_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    if has_idempotency_intent(text) or ("idempotency" in tags and has_scheduled_job_intent(text)):
        idempotency_evidence = list(dict.fromkeys([
            "idempotency_key",
            "duplicate_absence",
            "api_response",
            "persistence",
            "audit_log",
            *requirement_specific_evidence_layers(text),
        ]))
        idempotency_test = make_test(
            req_id,
            test_index,
            "idempotency",
            point,
            "Blocked",
            f"Idempotent replay behavior satisfies requirement: {text}",
            ["Replay the same safe event/request id, assert the duplicate response, and prove no duplicate persisted row or side effect was created."],
            idempotency_evidence,
        )
        req_tests.append(idempotency_test)
        tests.append(idempotency_test)
        gaps.append(f"{req_id}: idempotency probe needs a safe replay fixture, idempotency key/event id, duplicate-response assertion, and no-duplicate persistence/audit evidence.")
        test_index += 1

    if has_cleanup_intent(text):
        cleanup_evidence = list(dict.fromkeys([
            "cleanup",
            "cleanup_api",
            "extracted runtime id",
            "same runtime id",
            "always_run_teardown",
            "cleanup_verification",
            "deletion_absence",
            "cascade_cleanup",
            "outbox_absence",
            "audit_log",
            "persistence",
            "runtime",
            *requirement_specific_evidence_layers(text),
        ]))
        cleanup_test = make_test(
            req_id,
            test_index,
            "cleanup",
            point,
            "Blocked",
            f"Created test data is cleaned up and verified for requirement: {text}",
            [
                "Capture the runtime id from the create step, run a project-approved cleanup request with alwaysRun/skip-if-missing semantics, then verify the same object is absent or marked deleted and related membership/outbox/audit side effects are clean."
            ],
            cleanup_evidence,
        )
        req_tests.append(cleanup_test)
        tests.append(cleanup_test)
        gaps.append(f"{req_id}: cleanup probe needs safe test data, extracted runtime id binding, always-run teardown, DELETE/cleanup response evidence, absence/deleted verification, related-row cleanup, outbox absence, audit evidence, and runtime disposition.")
        test_index += 1

    if has_notification_intent(text):
        notification_steps = (
            ["Use a safe outbox/worker fixture or dry-run command to prove notification enqueue/send-preview behavior without contacting real recipients."]
            if has_background_job_intent(text) or has_worker_intent(text)
            else ["Use a safe outbox fixture or dry-run command to prove notification/outbox records or absence, recipient-safe preview boundaries, and no contact with real recipients."]
        )
        notification_gap = (
            f"{req_id}: notification probe needs outbox/worker evidence, safe recipient boundary, and no-real-email proof when dry-run is required."
            if has_background_job_intent(text) or has_worker_intent(text)
            else f"{req_id}: notification probe needs outbox evidence or absence proof, safe recipient boundary, and no-real-email proof when dry-run is required."
        )
        notification_evidence = list(dict.fromkeys([
            "notification",
            "outbox",
            *requirement_specific_evidence_layers(text),
            "recipient-safe preview",
        ]))
        notification_test = make_test(
            req_id,
            test_index,
            "notification",
            point,
            "Blocked",
            f"Notification/outbox behavior satisfies requirement: {text}",
            notification_steps,
            notification_evidence,
        )
        req_tests.append(notification_test)
        tests.append(notification_test)
        gaps.append(notification_gap)
        test_index += 1

    if "notification_policy" in tags:
        policy_evidence = list(dict.fromkeys([
            "notification_policy",
            "notification_preferences",
            "preference_version",
            "consent_state",
            "consent_source",
            "suppression_reason",
            "unsubscribe_token",
            "token_hash",
            "token_consumption",
            "token_replay_denial",
            "quiet_hours",
            "send_after",
            "timezone",
            "urgent_override",
            "digest_key",
            "digest_dedupe",
            "event_count",
            "email_outbox",
            "outbox",
            "no_real_email",
            "idempotency_key",
            "duplicate_absence",
            "forbidden text absence",
            "audit_log",
            "persistence",
            "runtime",
            *requirement_specific_evidence_layers(text),
        ]))
        policy_test = make_test(
            req_id,
            test_index,
            "notification_policy",
            point,
            "Blocked",
            f"Notification preference, consent, suppression, quiet-hours, digest, and unsubscribe policy satisfy requirement: {text}",
            [
                "Use safe notification preference, campaign dry-run, quiet-hours, digest, and unsubscribe-token fixtures to capture preference_version/consent_source, suppression_reason, transactional allowlist, quiet-hours send_after and urgent override, digest dedupe/event_count, token hash/consumption/replay denial, no-real-email proof, outbox/audit persistence, leak guards, and count-aware runtime disposition."
            ],
            policy_evidence,
        )
        req_tests.append(policy_test)
        tests.append(policy_test)
        gaps.append(f"{req_id}: notification-policy probe needs preference_version and consent_source, suppression_reason and transactional allowlist evidence, quiet-hours send_after with timezone and urgent override proof, digest_key/event_count dedupe proof, unsubscribe token hash/consumption/replay denial, no-real-email proof, outbox/audit persistence, leak guards, and runtime disposition.")
        test_index += 1
    return test_index


def _apply_boundary_rule_family(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    if has_tenant_isolation_intent(text) or has_cross_tenant_denial_intent(text):
        isolation_evidence = list(dict.fromkeys([
            "tenant_boundary",
            "data_isolation",
            *requirement_specific_evidence_layers(text),
            "same-tenant row-set parity",
            "foreign-tenant absence",
        ]))
        isolation_steps = (
            ["Use safe same-tenant and cross-tenant search fixtures to prove same-tenant result ids and facet counts match the request scope, foreign-tenant products are absent from UI/API/facets, and no hidden tenant values leak in responses, logs, or report evidence."]
            if has_search_relevance_intent(text)
            else ["Use safe same-tenant and cross-tenant fixtures to prove same-tenant rows match the request scope, cross-tenant reads are denied, forbidden foreign-tenant values are absent, and no access grant or side effect was persisted."]
        )
        isolation_gap = (
            f"{req_id}: search tenant/data-isolation probe needs same-tenant and cross-tenant search fixtures, scoped result ids, facet-count parity, and forbidden foreign-tenant absence."
            if has_search_relevance_intent(text)
            else f"{req_id}: tenant/data-isolation probe needs same-tenant fixture, cross-tenant fixture, denial status, forbidden foreign-tenant absence, and persistence/audit boundary evidence."
        )
        isolation_test = make_test(
            req_id,
            test_index,
            "data_isolation",
            point,
            "Blocked",
            f"Tenant/data isolation behavior satisfies requirement: {text}",
            isolation_steps,
            isolation_evidence,
        )
        req_tests.append(isolation_test)
        tests.append(isolation_test)
        gaps.append(isolation_gap)
        test_index += 1

    if ("time_boundary" in tags or has_time_boundary_intent(text)) and not has_audit_integrity_intent(text):
        boundary_evidence = list(dict.fromkeys([
            "date_range_boundary",
            "timezone",
            *requirement_specific_evidence_layers(text),
            "timezone-aware request URL",
            "boundary fixture rows",
            "UI/API row-set parity",
        ]))
        boundary_test = make_test(
            req_id,
            test_index,
            "time_boundary",
            point,
            "Blocked",
            f"Timezone-aware date/time boundary behavior satisfies requirement: {text}",
            [
                "Use safe fixture rows exactly at the inclusive start, exactly at the exclusive end, and around DST transitions; capture the timezone-aware request URL plus API/UI row inclusion and exclusion evidence."
            ],
            boundary_evidence,
        )
        req_tests.append(boundary_test)
        tests.append(boundary_test)
        gaps.append(f"{req_id}: time-boundary probe needs timezone-aware boundary fixtures, inclusive-start evidence, exclusive-end absence, DST handling evidence, and UI/API row parity.")
        test_index += 1

    if "calculation" in tags or has_money_precision_intent(text):
        calculation_evidence = list(dict.fromkeys([
            "money_precision",
            "calculation_parity",
            *requirement_specific_evidence_layers(text),
            "decimal reference calculation",
            "UI/API total parity",
            "persisted total parity",
        ]))
        calculation_test = make_test(
            req_id,
            test_index,
            "calculation",
            point,
            "Blocked",
            f"Monetary calculation behavior satisfies requirement: {text}",
            [
                "Use safe deterministic monetary fixtures and a documented decimal reference calculation to prove request-body values, rounding boundaries, tax/discount/currency calculations, UI/API parity, and persisted total parity."
            ],
            calculation_evidence,
        )
        req_tests.append(calculation_test)
        tests.append(calculation_test)
        gaps.append(f"{req_id}: monetary calculation probe needs decimal fixtures, expected rounding formula, request-body evidence, UI/API total parity, and persistence parity.")
        test_index += 1
    return test_index


_ADVANCED_RULE_FAMILIES = (
    _apply_knowledge_rule_family,
    _apply_distributed_rule_family,
    _apply_operation_rule_family,
    _apply_boundary_rule_family,
)

def apply_advanced_point_rules(
    *,
    point: dict[str, Any],
    req_id: str,
    text: str,
    tags: set[str],
    tests: list[dict[str, Any]],
    req_tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    """按稳定领域族追加高级探针规则。"""
    for apply_rules in _ADVANCED_RULE_FAMILIES:
        test_index = apply_rules(
            point=point,
            req_id=req_id,
            text=text,
            tags=tags,
            tests=tests,
            req_tests=req_tests,
            gaps=gaps,
            test_index=test_index,
        )
    return test_index

@dataclass(slots=True)
class ScaffoldCursor:
    """记录相邻需求点之间可继承的 API、UI 与点击响应上下文。"""

    last_api_context: tuple[str, str] | None = None
    last_ui_context: str | None = None
    last_click_context: dict[str, str] | None = None
    last_click_response_context: dict[str, Any] | None = None

@dataclass(slots=True)
class ScaffoldPoint:
    """单个需求点完成分类后供各规则层消费的稳定上下文。"""

    point: dict[str, Any]
    req_id: str
    text: str
    point_source_base: str
    paths: list[str]
    method_path: tuple[str, str] | None
    response_method: str | None
    response_path: str | None
    inherited_api_context: bool
    followup_method_path: tuple[str, str] | None
    tags: set[str]
    req_tests: list[dict[str, Any]]
    click_intent: bool
    list_interaction_intent: bool
    edit_interaction_intent: bool
    policy_visibility_intent: bool
    cache_ui_stale_intent: bool
    graphql_dashboard_interaction_intent: bool
    rag_answer_interaction_intent: bool
    notification_policy_interaction_intent: bool
    interaction_intent: bool
    button_name: str | None
    explicit_page_path: str | None
    inherited_ui_context: bool
    page_path: str | None
    inherited_click_response_context: bool
    negative_request_intent: bool
    visible_text_targets: list[str]
    forbidden_visible_text_targets: list[str]
    post_action_visible_text: bool
    post_action_forbidden_visible_text: bool
    shell_commands: list[str]
    click_response_generated: bool = False
    followup_generated: bool = False

def build_scaffold_point(
    req_index: int,
    point: dict[str, Any],
    *,
    cursor: ScaffoldCursor,
    default_entry_path: str | None,
) -> ScaffoldPoint:
    """从需求文本与前序游标构建一次性的点级上下文。"""
    last_api_context = cursor.last_api_context
    last_ui_context = cursor.last_ui_context
    last_click_context = cursor.last_click_context
    req_id = f"R{req_index}"
    text = point["text"]
    point_source_base = re.sub(r"\s+clause\s+\d+$", "", str(point.get("source") or ""))
    paths = extract_paths(text)
    method_paths = extract_method_paths(text)
    method_path = method_paths[0] if method_paths else extract_method_path(text)
    response_method, response_path = api_target(method_path, paths, text)
    inherited_api_context = False
    classification_text = text
    classification_paths = list(paths)
    if (
        not response_path
        and last_api_context
        and not paths
        and has_api_response_context_intent(text)
    ):
        inherited_api_context = True
        response_method, response_path = last_api_context
        classification_route = re.split(r"[?#]", response_path, maxsplit=1)[0] or response_path
        classification_text = f"API endpoint {classification_route}. {text}"
        classification_paths = [response_path]
    followup_method_path = next(
        (
            (method, path)
            for method, path in method_paths
            if method in {"GET", "HEAD"} and path_placeholders(path)
        ),
        None,
    )
    tags = classify(classification_text, classification_paths)
    req_tests: list[dict[str, Any]] = []
    click_intent = has_click_intent(text)
    list_interaction_intent = has_list_interaction_intent(text)
    edit_interaction_intent = has_word(text.lower(), r"\bedits?\b", r"\btypes?\b", r"\bfills?\b", r"\bselects?\b", r"\binput\b", r"\btext\b") or has_chinese(text, "编辑", "输入", "选择")
    policy_visibility_intent = has_authorization_policy_intent(text) and has_word(text.lower(), r"\bbutton\b", r"\bhides?\b", r"\bhidden\b", r"\bui\b")
    cache_ui_stale_intent = has_ui_stale_absence_intent(text)
    graphql_dashboard_interaction_intent = has_graphql_intent(text) and "ui" in tags
    rag_answer_interaction_intent = has_rag_grounding_intent(text) and "ui" in tags
    notification_policy_interaction_intent = has_notification_policy_intent(text) and "ui" in tags and (
        has_word(text.lower(), r"\bturns?\b", r"\btoggles?\b", r"\bswitch(?:es|ed|ing)?\b", r"\bselects?\b", r"\bsettings?\b", r"\bpreferences?\b", r"\boff\b", r"\bon\b")
        or has_chinese(text, "开关", "关闭", "开启", "设置", "偏好")
    )
    interaction_intent = click_intent or list_interaction_intent or edit_interaction_intent or notification_policy_interaction_intent or policy_visibility_intent or cache_ui_stale_intent or graphql_dashboard_interaction_intent or rag_answer_interaction_intent or (has_disabled_state_intent(text) and "ui" in tags) or has_lockout_intent(text)
    button_name = infer_button_name(text) if (click_intent or policy_visibility_intent or has_disabled_state_intent(text) or has_lockout_intent(text)) else None
    explicit_page_path = ui_path(paths, text)
    inherited_ui_context = False
    if explicit_page_path:
        page_path = explicit_page_path
    elif last_ui_context and ("ui" in tags or "responsive" in tags):
        page_path = last_ui_context
        inherited_ui_context = True
    else:
        page_path = default_entry_path
    inherited_click_response_context = False
    if (
        response_path
        and not click_intent
        and last_click_context
        and last_click_context.get("source_base") == point_source_base
    ):
        button_name = button_name or last_click_context.get("button_name")
        page_path = page_path or last_click_context.get("page_path")
        inherited_ui_context = bool(page_path and not explicit_page_path)
        inherited_click_response_context = bool(button_name and page_path)
    negative_request_intent = has_negative_request_intent(text)
    visible_text_targets = explicit_visible_text_targets(text)
    forbidden_visible_text_targets = explicit_forbidden_visible_text_targets(text)
    post_action_visible_text = bool(
        visible_text_targets
        and (click_intent or inherited_click_response_context or (response_path and button_name))
    )
    post_action_forbidden_visible_text = bool(
        forbidden_visible_text_targets
        and (click_intent or inherited_click_response_context or (response_path and button_name))
    )
    click_response_generated = False
    followup_generated = False
    shell_commands = extract_shell_commands(text)
    return ScaffoldPoint(
        point=point,
        req_id=req_id,
        text=text,
        point_source_base=point_source_base,
        paths=paths,
        method_path=method_path,
        response_method=response_method,
        response_path=response_path,
        inherited_api_context=inherited_api_context,
        followup_method_path=followup_method_path,
        tags=tags,
        req_tests=req_tests,
        click_intent=click_intent,
        list_interaction_intent=list_interaction_intent,
        edit_interaction_intent=edit_interaction_intent,
        policy_visibility_intent=policy_visibility_intent,
        cache_ui_stale_intent=cache_ui_stale_intent,
        graphql_dashboard_interaction_intent=graphql_dashboard_interaction_intent,
        rag_answer_interaction_intent=rag_answer_interaction_intent,
        notification_policy_interaction_intent=notification_policy_interaction_intent,
        interaction_intent=interaction_intent,
        button_name=button_name,
        explicit_page_path=explicit_page_path,
        inherited_ui_context=inherited_ui_context,
        page_path=page_path,
        inherited_click_response_context=inherited_click_response_context,
        negative_request_intent=negative_request_intent,
        visible_text_targets=visible_text_targets,
        forbidden_visible_text_targets=forbidden_visible_text_targets,
        post_action_visible_text=post_action_visible_text,
        post_action_forbidden_visible_text=post_action_forbidden_visible_text,
        shell_commands=shell_commands,
        click_response_generated=click_response_generated,
        followup_generated=followup_generated,
    )

_UIRuleState = tuple[int, bool, bool, dict[str, Any] | None]

def _apply_ui_visibility_rule_family(
    *,
    context: ScaffoldPoint,
    tests: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    gaps: list[str],
    allow_mutating_api: bool,
    state: _UIRuleState,
) -> _UIRuleState:
    """追加页面可见性、文本断言、截图与控制台探针。"""
    test_index, click_response_generated, followup_generated, last_click_response_context = state
    point = context.point
    req_id = context.req_id
    text = context.text
    tags = context.tags
    req_tests = context.req_tests
    click_intent = context.click_intent
    page_path = context.page_path
    visible_text_targets = context.visible_text_targets
    forbidden_visible_text_targets = context.forbidden_visible_text_targets
    post_action_visible_text = context.post_action_visible_text
    post_action_forbidden_visible_text = context.post_action_forbidden_visible_text
    if ("ui" in tags or "logic" in tags) and not has_decision_table_logic_intent(text):
        path = page_path
        status = "Untested" if path else "Blocked"
        ui_evidence = ["screenshot", "UI assertion", "console/network summary"] + requirement_specific_evidence_layers(text)
        if click_intent:
            ui_evidence.append("separate clickability evidence")
        test = make_test(
            req_id,
            test_index,
            "ui" if "ui" in tags else "logic",
            point,
            status,
            f"User-visible behavior matches requirement: {text}",
            [f"Open `{path}` and capture visible state."] if path else ["Identify the user-facing entry path before execution."],
            ui_evidence,
        )
        req_tests.append(test)
        tests.append(test)
        if path:
            steps.append({
                "action": "goto",
                "id": f"{test['id']}-open",
                "testIds": [test["id"]],
                "requirementIds": [req_id],
                "path": path,
                "evidenceType": "navigation",
                "proves": f"The generated entry path `{path}` opens for {req_id}.",
            })
            if visible_text_targets and not post_action_visible_text:
                append_visible_text_assertion_steps(
                    steps,
                    test_id=test["id"],
                    req_id=req_id,
                    texts=visible_text_targets,
                    id_prefix=test["id"],
                )
            if forbidden_visible_text_targets and not post_action_forbidden_visible_text:
                append_forbidden_visible_text_assertion_steps(
                    steps,
                    test_id=test["id"],
                    req_id=req_id,
                    texts=forbidden_visible_text_targets,
                    id_prefix=test["id"],
                )
            steps.extend([
                {
                    "action": "screenshot",
                    "id": f"{test['id']}-screenshot",
                    "testIds": [test["id"]],
                    "requirementIds": [req_id],
                    "name": f"{req_id.lower()}-{test['id'].lower()}",
                    "evidenceType": "screenshot",
                    "proves": f"The visible state for {req_id} has current-run screenshot evidence.",
                },
                {
                    "action": "expectNoConsoleErrors",
                    "id": f"{test['id']}-console-clean",
                    "testIds": [test["id"]],
                    "requirementIds": [req_id],
                    "evidenceType": "runtime",
                    "proves": f"No unignored browser console errors were observed while checking {req_id}.",
                },
            ])
        else:
            gaps.append(f"{req_id}: missing UI entry path.")
        test_index += 1
    return test_index, click_response_generated, followup_generated, last_click_response_context

def _apply_ui_actionability_rule_family(
    *,
    context: ScaffoldPoint,
    tests: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    gaps: list[str],
    allow_mutating_api: bool,
    state: _UIRuleState,
) -> _UIRuleState:
    """追加禁用态、列表、编辑器与点击命中探针。"""
    test_index, click_response_generated, followup_generated, last_click_response_context = state
    point = context.point
    req_id = context.req_id
    text = context.text
    tags = context.tags
    req_tests = context.req_tests
    list_interaction_intent = context.list_interaction_intent
    edit_interaction_intent = context.edit_interaction_intent
    policy_visibility_intent = context.policy_visibility_intent
    cache_ui_stale_intent = context.cache_ui_stale_intent
    graphql_dashboard_interaction_intent = context.graphql_dashboard_interaction_intent
    rag_answer_interaction_intent = context.rag_answer_interaction_intent
    notification_policy_interaction_intent = context.notification_policy_interaction_intent
    interaction_intent = context.interaction_intent
    button_name = context.button_name
    path = context.page_path
    if ("ui" in tags or "logic" in tags) and not has_decision_table_logic_intent(text) and interaction_intent:
        disabled_state_probe = (has_disabled_state_intent(text) and "disabled" in text.lower()) or has_lockout_intent(text)
        interaction_status = "Blocked" if (disabled_state_probe or list_interaction_intent or edit_interaction_intent or notification_policy_interaction_intent or policy_visibility_intent or graphql_dashboard_interaction_intent or rag_answer_interaction_intent) else ("Untested" if path and button_name else "Blocked")
        if disabled_state_probe:
            interaction_steps = [
                f"Prove the `{button_name}` button is disabled for the invalid/blocked state before any click is attempted."
                if path and button_name
                else "Identify the blocked-state control selector and prove the target stays disabled during the invalid, cooldown, or lockout state before any click is attempted."
            ]
            interaction_evidence = ["disabled_state", "ui_interaction", "blocked state", "cooldown_ui", "forbidden click/request absence"]
            interaction_expected = f"Disabled/validation state is proven without treating the target as clickable for requirement: {text}"
        elif list_interaction_intent:
            interaction_steps = [
                "Identify stable selectors for the search/filter/sort/page controls, execute the list interaction, and bind the resulting table, empty, or error state to the captured request URL."
            ]
            interaction_evidence = ["ui_interaction"] + requirement_specific_evidence_layers(text) + ["request URL", "rendered row or state assertion"]
            interaction_expected = f"List controls drive the expected query, rendered rows, empty state, or error state for requirement: {text}"
        elif edit_interaction_intent:
            interaction_steps = [
                "Identify a stable editor/input selector, enter the required text or state change, and bind the resulting UI state to API or persistence/state evidence."
            ]
            interaction_evidence = ["ui_interaction", "input/edit action", "post-edit state assertion"] + requirement_specific_evidence_layers(text)
            interaction_expected = f"Input or editor interaction drives the expected state change for requirement: {text}"
        elif notification_policy_interaction_intent:
            interaction_steps = [
                "Identify the notification preference control, toggle the named setting, and bind the visible state to the captured preference PATCH response, preference_version, consent_source, audit event, and persisted preference row."
            ]
            interaction_evidence = list(dict.fromkeys([
                "ui_interaction",
                "notification preference toggle",
                "notification_preferences",
                "preference_version",
                "consent_state",
                "consent_source",
                "api_response",
                "audit_log",
                "persistence",
                *requirement_specific_evidence_layers(text),
            ]))
            interaction_expected = f"Notification preference UI interaction is bound to preference, consent, audit, and persistence evidence for requirement: {text}"
        elif policy_visibility_intent:
            interaction_steps = [
                "Identify the policy-controlled button or control, prove its hidden or disabled state for the denied actor, and bind that UI state to direct API denial and policy-decision evidence."
            ]
            interaction_evidence = ["ui_interaction", "policy-controlled UI state", "forbidden request absence"] + requirement_specific_evidence_layers(text)
            interaction_expected = f"Policy-controlled UI affordance matches the authorization decision for requirement: {text}"
        elif cache_ui_stale_intent:
            interaction_steps = [
                "Identify stable row selectors, refresh or reload the catalog view after mutation/revalidation, prove the stale value is absent, and bind the visible row to the returned version token and response headers."
            ]
            interaction_evidence = ["ui_interaction", "ui_stale_absence", "rendered row or state assertion"] + requirement_specific_evidence_layers(text)
            interaction_expected = f"Cache-backed UI state is refreshed and stale fallback data is absent for requirement: {text}"
        elif graphql_dashboard_interaction_intent:
            interaction_steps = [
                "Identify stable dashboard row/count selectors, drive or reload the GraphQL-backed view, and bind the visible data to the captured operationName, variables, and response data/errors shape."
            ]
            interaction_evidence = ["ui_interaction", "rendered row or state assertion"] + requirement_specific_evidence_layers(text)
            interaction_expected = f"GraphQL-backed UI state is bound to captured operation, variables, and response data/errors for requirement: {text}"
        elif rag_answer_interaction_intent:
            interaction_steps = [
                "Identify stable question input, answer, citation, and source-panel selectors, submit the safe RAG question, and bind the visible answer/citations to captured retrieval trace and source evidence."
            ]
            interaction_evidence = ["ui_interaction", "rendered answer", "visible citations"] + requirement_specific_evidence_layers(text)
            interaction_expected = f"RAG answer UI is bound to retrieval trace, citations, and source-grounding evidence for requirement: {text}"
        elif path and button_name:
            interaction_steps = [f"Verify the `{button_name}` button receives pointer events before any click."]
            interaction_evidence = ["ui_interaction", "center-point hit-test", "actionability check", "blocker evidence on failure"]
            interaction_expected = f"Click target is actionable and not blocked by overlays for requirement: {text}"
        else:
            interaction_steps = ["Identify a stable button label, role/name, selector, or test id before clickability can be proven."]
            interaction_evidence = ["ui_interaction", "center-point hit-test", "actionability check", "blocker evidence on failure"]
            interaction_expected = f"Click target is actionable and not blocked by overlays for requirement: {text}"
        interaction_test = make_test(
            req_id,
            test_index,
            "interaction",
            point,
            interaction_status,
            interaction_expected,
            interaction_steps,
            interaction_evidence,
        )
        req_tests.append(interaction_test)
        tests.append(interaction_test)
        if path and button_name and not disabled_state_probe and not list_interaction_intent and not edit_interaction_intent and not notification_policy_interaction_intent and not policy_visibility_intent and not graphql_dashboard_interaction_intent and not rag_answer_interaction_intent:
            steps.append({
                "action": "expectClickable",
                "id": f"{interaction_test['id']}-clickable",
                "testIds": [interaction_test["id"]],
                "requirementIds": [req_id],
                "role": "button",
                "name": button_name,
                "evidenceType": "ui_interaction",
                "proves": f"The `{button_name}` button for {req_id} is visible, enabled, and receives pointer events at its center point.",
            })
        else:
            if not path:
                gaps.append(f"{req_id}: clickability probe needs a UI entry path.")
            if not button_name and not edit_interaction_intent and not notification_policy_interaction_intent and not policy_visibility_intent and not graphql_dashboard_interaction_intent and not rag_answer_interaction_intent:
                gaps.append(f"{req_id}: clickability probe needs a stable button label, role/name, selector, or test id.")
            if disabled_state_probe:
                gaps.append(f"{req_id}: disabled-state probe for `{button_name}` needs a selector-aware enabled/disabled assertion before execution.")
            if list_interaction_intent:
                gaps.append(f"{req_id}: list interaction probe needs selector-aware search/filter/sort/page controls and request/query binding before execution.")
            if edit_interaction_intent:
                gaps.append(f"{req_id}: editor/input interaction probe needs a stable field/editor selector, safe input fixture, and post-edit API/stream/state binding.")
            if notification_policy_interaction_intent:
                gaps.append(f"{req_id}: notification-preference interaction probe needs a stable preference-control selector, captured preference PATCH response, preference_version, consent_source, audit event, and persisted preference-row evidence.")
            if graphql_dashboard_interaction_intent:
                gaps.append(f"{req_id}: GraphQL dashboard interaction probe needs stable row/count selectors plus network binding to operationName, variables, and response data/errors evidence.")
            if rag_answer_interaction_intent:
                gaps.append(f"{req_id}: RAG answer interaction probe needs stable question, answer, citation, and source-panel selectors plus retrieval/source evidence binding.")
            if policy_visibility_intent:
                gaps.append(f"{req_id}: policy-controlled UI probe needs denied-actor auth state, stable control selector, hidden/disabled assertion, direct API denial, and policy-decision evidence.")
        test_index += 1
    return test_index, click_response_generated, followup_generated, last_click_response_context

def _apply_ui_response_rule_family(
    *,
    context: ScaffoldPoint,
    tests: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    gaps: list[str],
    allow_mutating_api: bool,
    state: _UIRuleState,
) -> _UIRuleState:
    """追加点击响应、同对象跟进与清理探针。"""
    test_index, click_response_generated, followup_generated, last_click_response_context = state
    point = context.point
    req_id = context.req_id
    text = context.text
    point_source_base = context.point_source_base
    response_method = context.response_method
    response_path = context.response_path
    followup_method_path = context.followup_method_path
    tags = context.tags
    req_tests = context.req_tests
    list_interaction_intent = context.list_interaction_intent
    edit_interaction_intent = context.edit_interaction_intent
    policy_visibility_intent = context.policy_visibility_intent
    notification_policy_interaction_intent = context.notification_policy_interaction_intent
    interaction_intent = context.interaction_intent
    button_name = context.button_name
    path = context.page_path
    negative_request_intent = context.negative_request_intent
    visible_text_targets = context.visible_text_targets
    forbidden_visible_text_targets = context.forbidden_visible_text_targets
    disabled_state_probe = (has_disabled_state_intent(text) and "disabled" in text.lower()) or has_lockout_intent(text)
    if ("ui" in tags or "logic" in tags) and not has_decision_table_logic_intent(text) and interaction_intent:
        if response_path and not negative_request_intent and not disabled_state_probe and not list_interaction_intent and not edit_interaction_intent and not notification_policy_interaction_intent and not policy_visibility_intent:
            mutating_response = response_method in {"POST", "PUT", "PATCH", "DELETE"}
            auth_redirect_or_callback = has_oauth_intent(text) or has_redirect_security_intent(text) or has_saml_intent(text) or has_webauthn_intent(text) or has_one_time_token_intent(text) or has_api_key_intent(text)
            saml_auth_only = has_saml_intent(text) and not (has_oauth_intent(text) or has_webauthn_intent(text))
            webauthn_auth_only = has_webauthn_intent(text) and not (has_oauth_intent(text) or has_saml_intent(text))
            one_time_token_auth_only = has_one_time_token_intent(text) and not (has_oauth_intent(text) or has_saml_intent(text) or has_webauthn_intent(text))
            api_key_auth_only = has_api_key_intent(text) and not (has_oauth_intent(text) or has_saml_intent(text) or has_webauthn_intent(text) or has_one_time_token_intent(text))
            click_response_executable = bool(path and button_name and "{" not in response_path and "}" not in response_path and (not mutating_response or allow_mutating_api) and not auth_redirect_or_callback)
            extra_click_response_tests = 0
            if path and button_name and auth_redirect_or_callback:
                click_response_reason = (
                    f"Click-to-response probe for `{response_method} {response_path}` needs controlled SAML IdP fixtures, AuthnRequest/RelayState binding, signed/negative SAMLResponse inputs, and secret redaction checks before execution."
                    if saml_auth_only
                    else f"Click-to-response probe for `{response_method} {response_path}` needs controlled WebAuthn/passkey fixtures, challenge binding, assertion/replay inputs, and secret redaction checks before execution."
                    if webauthn_auth_only
                    else f"Click-to-response probe for `{response_method} {response_path}` needs controlled one-time-token fixtures, outbox/link evidence, token hash/expiry/consumption/replay inputs, session side-effect checks, and secret redaction before execution."
                    if one_time_token_auth_only
                    else f"Click-to-response probe for `{response_method} {response_path}` needs controlled admin/auth fixture, env-backed API key material, secret-once/hash/scope/revocation fixtures, and secret redaction checks before execution."
                    if api_key_auth_only
                    else f"Click-to-response probe for `{response_method} {response_path}` needs controlled IDP/redirect fixtures, state/nonce/PKCE binding, and token redaction assertions before execution."
                )
            elif path and button_name and mutating_response and not allow_mutating_api:
                click_response_reason = f"Click-to-response probe for `{response_method} {response_path}` needs safe test data or --allow-mutating-api."
            elif path and button_name:
                click_response_reason = f"Click `{button_name}` and capture the `{response_method + ' ' if response_method else ''}{response_path}` response."
            else:
                click_response_reason = "Identify the entry path and stable click target before binding the click to an API response."
            click_response_test = make_test(
                req_id,
                test_index,
                "ui_to_api",
                point,
                "Untested" if click_response_executable else "Blocked",
                f"Clicking the target triggers the expected API response for requirement: {text}",
                [click_response_reason],
                ["ui_to_api", "click hit-test", "HTTP status", "response body", "checked JSON when schema is known"],
            )
            req_tests.append(click_response_test)
            tests.append(click_response_test)
            click_response_generated = True
            if click_response_executable:
                step = {
                    "action": "clickAndWaitForResponse",
                    "id": f"{click_response_test['id']}-click-response",
                    "testIds": [click_response_test["id"]],
                    "requirementIds": [req_id],
                    "role": "button",
                    "name": button_name,
                    "responseUrlContains": response_path,
                    **http_status_expectation_fields_for_target(text, response_method, response_path),
                    "captureBody": True,
                    "evidenceType": "ui_to_api",
                    "proves": f"Clicking `{button_name}` triggers `{response_method + ' ' if response_method else ''}{response_path}` and returns a successful response for {req_id}.",
                }
                if response_method:
                    step["method"] = response_method
                if followup_method_path:
                    _, followup_path = followup_method_path
                    placeholders = path_placeholders(followup_path)
                    if placeholders:
                        step["extractJson"] = {name: extract_json_spec(name) for name in placeholders}
                steps.append(step)
                if visible_text_targets:
                    append_visible_text_assertion_steps(
                        steps,
                        test_id=click_response_test["id"],
                        req_id=req_id,
                        texts=visible_text_targets,
                        id_prefix=click_response_test["id"],
                    )
                if forbidden_visible_text_targets:
                    append_forbidden_visible_text_assertion_steps(
                        steps,
                        test_id=click_response_test["id"],
                        req_id=req_id,
                        texts=forbidden_visible_text_targets,
                        id_prefix=click_response_test["id"],
                    )
                producer_identifier_names = returned_identifier_names(text)
                if followup_method_path:
                    for placeholder in path_placeholders(followup_method_path[1]):
                        if not any(identifier_can_bind_placeholder(identifier, placeholder) for identifier in producer_identifier_names):
                            producer_identifier_names.append(placeholder)
                if response_method == "POST" and producer_identifier_names:
                    last_click_response_context = {
                        "source_base": point_source_base,
                        "producer_method": response_method,
                        "producer_path": response_path,
                        "producer_step": step,
                        "identifier_names": producer_identifier_names,
                    }
                if followup_method_path:
                    followup_method, followup_path = followup_method_path
                    placeholders = path_placeholders(followup_path)
                    if placeholders:
                        async_followup = has_async_status_intent(text)
                        status_value = terminal_status_value(text) if async_followup else None
                        followup_action = "pollApi" if async_followup else "api"
                        followup_test = make_test(
                            req_id,
                            test_index + 1,
                            "api_poll" if async_followup else "api_followup",
                            point,
                            "Untested",
                            (
                                f"The same runtime object from `{response_method} {response_path}` reaches terminal status through `{followup_method} {followup_path}` for requirement: {text}"
                                if async_followup
                                else f"The same runtime object from `{response_method} {response_path}` is readable through `{followup_method} {followup_path}` for requirement: {text}"
                            ),
                            (
                                [f"Extract `{', '.join(placeholders)}` from the click response, then poll `{followup_method} {followup_path}` until the status and same-object assertions pass."]
                                if async_followup
                                else [f"Extract `{', '.join(placeholders)}` from the click response, then call `{followup_method} {followup_path}` using the extracted value."]
                            ),
                            ["extracted runtime id", "HTTP status", "response body for the same object"] + (["poll attempts", "terminal status"] if async_followup else []),
                        )
                        req_tests.append(followup_test)
                        tests.append(followup_test)
                        extra_click_response_tests += 1
                        followup_step = {
                            "action": followup_action,
                            "id": f"{followup_test['id']}-api-followup",
                            "testIds": [followup_test["id"]],
                            "requirementIds": [req_id],
                            "method": followup_method,
                            "pathTemplate": followup_path,
                            **http_status_expectation_fields_for_target(text, followup_method, followup_path),
                            "expectJsonAny": expect_json_any_for_placeholders(placeholders, status_value),
                            "captureBody": True,
                            "evidenceType": "api_response",
                            "proves": (
                                f"`{followup_method} {followup_path}` is polled with the id extracted from the preceding click response until it returns the same object id and terminal status for {req_id}."
                                if async_followup
                                else f"`{followup_method} {followup_path}` resolves with the id extracted from the preceding click response and returns the same object id for {req_id}."
                            ),
                        }
                        if async_followup:
                            followup_step.update(async_poll_config(text))
                        steps.append(followup_step)
                        if mutating_response and response_method == "POST" and followup_method == "GET":
                            cleanup_test = make_test(
                                req_id,
                                test_index + 1 + extra_click_response_tests,
                                "cleanup",
                                point,
                                "Untested",
                                f"Test data created by `{response_method} {response_path}` is cleaned up through `{followup_path}` for requirement: {text}",
                                [f"Use the extracted `{', '.join(placeholders)}` value to call a project-approved cleanup request after assertions run."],
                                ["cleanup HTTP status", "same runtime id", "teardown runs after earlier failures"],
                            )
                            req_tests.append(cleanup_test)
                            tests.append(cleanup_test)
                            cleanup_step = {
                                "action": "cleanupApi",
                                "id": f"{cleanup_test['id']}-cleanup",
                                "testIds": [cleanup_test["id"]],
                                "requirementIds": [req_id],
                                "method": "DELETE",
                                "pathTemplate": followup_path,
                                "expectStatusAny": [200, 202, 204, 404],
                                "alwaysRun": True,
                                "skipIfMissingVars": True,
                                "evidenceType": "cleanup",
                                "proves": f"`DELETE {followup_path}` is attempted with the id extracted from the test flow so created test data does not remain after {req_id}.",
                            }
                            steps.append(cleanup_step)
                            extra_click_response_tests += 1
                        test_index += extra_click_response_tests
            else:
                if not path:
                    gaps.append(f"{req_id}: click-to-response probe needs a UI entry path.")
                if not button_name:
                    gaps.append(f"{req_id}: click-to-response probe needs a stable button label, role/name, selector, or test id.")
                if "{" in response_path or "}" in response_path:
                    gaps.append(f"{req_id}: click-to-response API path contains runtime placeholders: `{response_path}`.")
                if mutating_response and not allow_mutating_api:
                    gaps.append(f"{req_id}: click-to-response for mutating API `{response_method} {response_path}` needs safe test data or explicit authorization.")
                if auth_redirect_or_callback:
                    if saml_auth_only:
                        gaps.append(f"{req_id}: click-to-response for SAML API `{response_method} {response_path}` needs controlled IdP fixtures, AuthnRequest/RelayState binding, signed/negative SAMLResponse inputs, and secret redaction assertions before execution.")
                    elif webauthn_auth_only:
                        gaps.append(f"{req_id}: click-to-response for WebAuthn API `{response_method} {response_path}` needs controlled passkey fixtures, challenge binding, assertion/replay inputs, and secret redaction assertions before execution.")
                    elif one_time_token_auth_only:
                        gaps.append(f"{req_id}: click-to-response for one-time-token API `{response_method} {response_path}` needs controlled reset/link fixtures, outbox/link evidence, token hash/expiry/consumption/replay inputs, session side-effect checks, and secret redaction assertions before execution.")
                    elif api_key_auth_only:
                        gaps.append(f"{req_id}: click-to-response for API-key API `{response_method} {response_path}` needs controlled admin/auth fixture, env-backed key material, secret-once/hash/scope/revocation fixtures, no-mutation side-effect proof, and secret redaction assertions before execution.")
                    else:
                        gaps.append(f"{req_id}: click-to-response for OAuth/redirect API `{response_method} {response_path}` needs controlled IDP/redirect fixtures, state/nonce/PKCE binding, and token redaction assertions before execution.")
            test_index += 1
    return test_index, click_response_generated, followup_generated, last_click_response_context

_UI_INTERACTION_RULE_FAMILIES = (
    _apply_ui_visibility_rule_family,
    _apply_ui_actionability_rule_family,
    _apply_ui_response_rule_family,
)

def apply_ui_interaction_rules(
    *,
    context: ScaffoldPoint,
    cursor: ScaffoldCursor,
    tests: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    allow_mutating_api: bool,
) -> tuple[int, bool, bool, dict[str, Any] | None]:
    """通过稳定状态元组依次追加 UI 规则族。"""
    state: _UIRuleState = (
        test_index,
        context.click_response_generated,
        context.followup_generated,
        cursor.last_click_response_context,
    )
    for apply_rules in _UI_INTERACTION_RULE_FAMILIES:
        state = apply_rules(
            context=context,
            tests=tests,
            steps=steps,
            gaps=gaps,
            allow_mutating_api=allow_mutating_api,
            state=state,
        )
    return state

def apply_followup_interaction_rules(
    *,
    context: ScaffoldPoint,
    tests: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    allow_mutating_api: bool,
    click_response_generated: bool,
    followup_generated: bool,
    last_click_response_context: dict[str, Any] | None,
) -> tuple[int, bool, bool, dict[str, Any] | None]:
    """追加读取跟进与点击响应探针。"""
    point = context.point
    req_id = context.req_id
    text = context.text
    point_source_base = context.point_source_base
    response_method = context.response_method
    response_path = context.response_path
    req_tests = context.req_tests
    button_name = context.button_name
    page_path = context.page_path
    inherited_click_response_context = context.inherited_click_response_context
    negative_request_intent = context.negative_request_intent
    visible_text_targets = context.visible_text_targets
    forbidden_visible_text_targets = context.forbidden_visible_text_targets
    followup_placeholders = path_placeholders(response_path or "")
    if (
        response_path
        and (response_method or "GET") in {"GET", "HEAD"}
        and followup_placeholders
        and last_click_response_context
        and last_click_response_context.get("source_base") == point_source_base
    ):
        producer_identifier_names = [
            str(identifier)
            for identifier in last_click_response_context.get("identifier_names", [])
            if isinstance(identifier, str)
        ]
        placeholders_bound = bool(producer_identifier_names) and all(
            any(identifier_can_bind_placeholder(identifier, placeholder) for identifier in producer_identifier_names)
            for placeholder in followup_placeholders
        )
        producer_step = last_click_response_context.get("producer_step")
        if placeholders_bound and isinstance(producer_step, dict):
            producer_extract_json = producer_step.setdefault("extractJson", {})
            if isinstance(producer_extract_json, dict):
                for placeholder in followup_placeholders:
                    producer_extract_json[placeholder] = extract_json_spec(placeholder)
            producer_method = str(last_click_response_context.get("producer_method") or "POST")
            producer_path = str(last_click_response_context.get("producer_path") or "<producer endpoint>")
            followup_method = response_method or "GET"
            async_followup = has_async_status_intent(text)
            status_value = terminal_status_value(text) if async_followup else None
            followup_action = "pollApi" if async_followup else "api"
            followup_test = make_test(
                req_id,
                test_index,
                "api_poll" if async_followup else "api_followup",
                point,
                "Untested",
                (
                    f"The same runtime object from `{producer_method} {producer_path}` reaches terminal status through `{followup_method} {response_path}` for requirement: {text}"
                    if async_followup
                    else f"The same runtime object from `{producer_method} {producer_path}` is readable through `{followup_method} {response_path}` for requirement: {text}"
                ),
                (
                    [f"Extract `{', '.join(followup_placeholders)}` from the preceding click response, then poll `{followup_method} {response_path}` until the status and same-object assertions pass."]
                    if async_followup
                    else [f"Extract `{', '.join(followup_placeholders)}` from the preceding click response, then call `{followup_method} {response_path}` using the extracted value."]
                ),
                ["extracted runtime id", "HTTP status", "response body for the same object"] + (["poll attempts", "terminal status"] if async_followup else []),
            )
            req_tests.append(followup_test)
            tests.append(followup_test)
            followup_step = {
                "action": followup_action,
                "id": f"{followup_test['id']}-api-followup",
                "testIds": [followup_test["id"]],
                "requirementIds": [req_id],
                "method": followup_method,
                "pathTemplate": response_path,
                **http_status_expectation_fields_for_target(text, followup_method, response_path),
                "expectJsonAny": expect_json_any_for_placeholders(followup_placeholders, status_value),
                "captureBody": True,
                "evidenceType": "api_response",
                "proves": (
                    f"`{followup_method} {response_path}` is polled with the id extracted from the preceding click response until it returns the same object id and terminal status for {req_id}."
                    if async_followup
                    else f"`{followup_method} {response_path}` resolves with the id extracted from the preceding click response and returns the same object id for {req_id}."
                ),
            }
            if async_followup:
                followup_step.update(async_poll_config(text))
            steps.append(followup_step)
            test_index += 1
            if producer_method == "POST" and followup_method == "GET":
                cleanup_test = make_test(
                    req_id,
                    test_index,
                    "cleanup",
                    point,
                    "Untested",
                    f"Test data created by `{producer_method} {producer_path}` is cleaned up through `{response_path}` for requirement: {text}",
                    [f"Use the extracted `{', '.join(followup_placeholders)}` value to call a project-approved cleanup request after assertions run."],
                    ["cleanup HTTP status", "same runtime id", "teardown runs after earlier failures"],
                )
                req_tests.append(cleanup_test)
                tests.append(cleanup_test)
                steps.append({
                    "action": "cleanupApi",
                    "id": f"{cleanup_test['id']}-cleanup",
                    "testIds": [cleanup_test["id"]],
                    "requirementIds": [req_id],
                    "method": "DELETE",
                    "pathTemplate": response_path,
                    "expectStatusAny": [200, 202, 204, 404],
                    "alwaysRun": True,
                    "skipIfMissingVars": True,
                    "evidenceType": "cleanup",
                    "proves": f"`DELETE {response_path}` is attempted with the id extracted from the test flow so created test data does not remain after {req_id}.",
                })
                test_index += 1
            followup_generated = True

    if response_path and inherited_click_response_context and not negative_request_intent and not click_response_generated and not followup_generated:
        mutating_response = response_method in {"POST", "PUT", "PATCH", "DELETE"}
        auth_redirect_or_callback = has_oauth_intent(text) or has_redirect_security_intent(text) or has_saml_intent(text) or has_webauthn_intent(text) or has_one_time_token_intent(text) or has_api_key_intent(text)
        click_response_executable = bool(page_path and button_name and "{" not in response_path and "}" not in response_path and (not mutating_response or allow_mutating_api) and not auth_redirect_or_callback)
        if page_path and button_name and mutating_response and not allow_mutating_api:
            click_response_reason = f"Click-to-response probe for `{response_method} {response_path}` needs safe test data or --allow-mutating-api."
        elif page_path and button_name:
            click_response_reason = f"Click `{button_name}` and capture the `{response_method + ' ' if response_method else ''}{response_path}` response."
        else:
            click_response_reason = "Identify the entry path and stable click target before binding the click to an API response."
        click_response_test = make_test(
            req_id,
            test_index,
            "ui_to_api",
            point,
            "Untested" if click_response_executable else "Blocked",
            f"Clicking the previous same-source target triggers the expected API response for requirement: {text}",
            [click_response_reason],
            ["ui_to_api", "click hit-test", "HTTP status", "response body", "checked JSON when schema is known"],
        )
        req_tests.append(click_response_test)
        tests.append(click_response_test)
        click_response_generated = True
        if click_response_executable:
            step = {
                "action": "clickAndWaitForResponse",
                "id": f"{click_response_test['id']}-click-response",
                "testIds": [click_response_test["id"]],
                "requirementIds": [req_id],
                "role": "button",
                "name": button_name,
                "responseUrlContains": response_path,
                **http_status_expectation_fields_for_target(text, response_method, response_path),
                "captureBody": True,
                "evidenceType": "ui_to_api",
                "proves": f"Clicking `{button_name}` triggers `{response_method + ' ' if response_method else ''}{response_path}` and returns a successful response for {req_id}.",
            }
            if response_method:
                step["method"] = response_method
            producer_identifier_names = returned_identifier_names(text)
            if producer_identifier_names:
                step["extractJson"] = {name: extract_json_spec(name) for name in producer_identifier_names}
            steps.append(step)
            if visible_text_targets:
                append_visible_text_assertion_steps(
                    steps,
                    test_id=click_response_test["id"],
                    req_id=req_id,
                    texts=visible_text_targets,
                    id_prefix=click_response_test["id"],
                )
            if forbidden_visible_text_targets:
                append_forbidden_visible_text_assertion_steps(
                    steps,
                    test_id=click_response_test["id"],
                    req_id=req_id,
                    texts=forbidden_visible_text_targets,
                    id_prefix=click_response_test["id"],
                )
            if response_method == "POST" and producer_identifier_names:
                last_click_response_context = {
                    "source_base": point_source_base,
                    "producer_method": response_method,
                    "producer_path": response_path,
                    "producer_step": step,
                    "identifier_names": producer_identifier_names,
                }
        else:
            if not page_path:
                gaps.append(f"{req_id}: click-to-response probe needs a UI entry path.")
            if not button_name:
                gaps.append(f"{req_id}: click-to-response probe needs a stable button label, role/name, selector, or test id.")
            if "{" in response_path or "}" in response_path:
                gaps.append(f"{req_id}: click-to-response API path contains runtime placeholders: `{response_path}`.")
            if mutating_response and not allow_mutating_api:
                gaps.append(f"{req_id}: click-to-response for mutating API `{response_method} {response_path}` needs safe test data or explicit authorization.")
            if auth_redirect_or_callback:
                gaps.append(f"{req_id}: click-to-response for auth API `{response_method} {response_path}` needs controlled auth fixtures and secret redaction assertions before execution.")
        test_index += 1
    return test_index, click_response_generated, followup_generated, last_click_response_context

def apply_interaction_point_rules(
    *,
    context: ScaffoldPoint,
    cursor: ScaffoldCursor,
    tests: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    allow_mutating_api: bool,
) -> int:
    """按页面交互和响应跟进两个阶段追加探针。"""
    test_index, click_response_generated, followup_generated, last_click_response_context = apply_ui_interaction_rules(
        context=context,
        cursor=cursor,
        tests=tests,
        steps=steps,
        gaps=gaps,
        test_index=test_index,
        allow_mutating_api=allow_mutating_api,
    )
    test_index, click_response_generated, followup_generated, last_click_response_context = apply_followup_interaction_rules(
        context=context,
        tests=tests,
        steps=steps,
        gaps=gaps,
        test_index=test_index,
        allow_mutating_api=allow_mutating_api,
        click_response_generated=click_response_generated,
        followup_generated=followup_generated,
        last_click_response_context=last_click_response_context,
    )
    context.click_response_generated = click_response_generated
    context.followup_generated = followup_generated
    cursor.last_click_response_context = last_click_response_context
    return test_index

def apply_api_transport_rules(
    *,
    context: ScaffoldPoint,
    tests: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    allow_mutating_api: bool,
) -> int:
    """追加直接 API 探针。"""
    point = context.point
    req_id = context.req_id
    text = context.text
    response_method = context.response_method
    response_path = context.response_path
    tags = context.tags
    req_tests = context.req_tests
    negative_request_intent = context.negative_request_intent
    click_response_generated = context.click_response_generated
    followup_generated = context.followup_generated
    if "api" in tags and not negative_request_intent:
        method, path = (response_method or "GET"), response_path
        safe_method = method in {"GET", "HEAD"}
        error_state_probe = has_error_state_intent(text)
        auth_redirect_or_callback = has_oauth_intent(text) or has_redirect_security_intent(text) or has_saml_intent(text) or has_webauthn_intent(text) or has_one_time_token_intent(text) or has_api_key_intent(text)
        saml_auth_only = has_saml_intent(text) and not (has_oauth_intent(text) or has_webauthn_intent(text))
        webauthn_auth_only = has_webauthn_intent(text) and not (has_oauth_intent(text) or has_saml_intent(text))
        one_time_token_auth_only = has_one_time_token_intent(text) and not (has_oauth_intent(text) or has_saml_intent(text) or has_webauthn_intent(text))
        api_key_auth_only = has_api_key_intent(text) and not (has_oauth_intent(text) or has_saml_intent(text) or has_webauthn_intent(text) or has_one_time_token_intent(text))
        async_poll_probe = bool(path and safe_method and path_placeholders(path) and has_async_status_intent(text))
        executable = bool(path) and "{" not in path and safe_method and not error_state_probe and not async_poll_probe and not auth_redirect_or_callback
        status = "Untested" if executable else "Blocked"
        if executable:
            reason = "Call the API endpoint and assert a successful status, captured body, and requirement-specific response semantics."
        elif auth_redirect_or_callback:
            reason = (
                "Provide controlled SAML IdP fixtures, AuthnRequest/RelayState binding, signed/negative SAMLResponse inputs, XML signature/audience/recipient/time-window checks, and secret redaction assertions before executing this auth endpoint."
                if saml_auth_only
                else "Provide controlled WebAuthn/passkey fixtures, challenge binding, assertion/replay inputs, origin/rpId/signature checks, signCount evidence, and secret redaction assertions before executing this auth endpoint."
                if webauthn_auth_only
                else "Provide controlled one-time-token fixtures, existing-vs-unknown account comparison, outbox/link evidence, token hash/purpose/expiry/consumption/replay inputs, session side-effect checks, audit proof, and secret redaction assertions before executing this endpoint."
                if one_time_token_auth_only
                else "Provide controlled admin/auth fixture, env-backed API key material, secret-once/hash/prefix/scope/revocation fixtures, no-mutation side-effect proof, audit evidence, and secret redaction assertions before executing this endpoint."
                if api_key_auth_only
                else "Provide controlled IDP/redirect fixtures, state/nonce/PKCE binding, replay or mismatch inputs, and token redaction assertions before executing this auth endpoint."
            )
        elif async_poll_probe:
            reason = "Extract the runtime id from the creating step, then poll this read endpoint until the same object reaches terminal status."
        elif error_state_probe:
            reason = "Provide fault injection, stubbed backend state, or captured failed-response fixture before asserting the error-state path."
        else:
            reason = "Identify a safe read-only endpoint or provide reversible test data."
        if followup_generated:
            pass
        elif click_response_generated:
            if not executable and method and method not in {"GET", "HEAD"} and not allow_mutating_api:
                gaps.append(f"{req_id}: direct API probe for mutating `{method} {path}` skipped; use click-to-response with safe test data when authorized.")
        else:
            api_evidence = ["HTTP status", "response body", "checked JSON when schema is known"] + requirement_specific_evidence_layers(text)
            if error_state_probe:
                api_evidence.extend(["failed HTTP status", "error response body", "fault-injection or captured failure fixture"])
            if async_poll_probe:
                api_evidence.extend(["poll attempts", "same runtime id", "terminal_status"])
            test = make_test(
                req_id,
                test_index,
                "api_poll" if async_poll_probe else "api",
                point,
                status,
                f"{method} {path or '<endpoint>'} satisfies requirement: {text}",
                [reason],
                api_evidence,
            )
            req_tests.append(test)
            tests.append(test)
            if executable:
                steps.append({
                    "action": "api",
                    "id": f"{test['id']}-api",
                    "testIds": [test["id"]],
                    "requirementIds": [req_id],
                    "method": method,
                    "path": path,
                    **http_status_expectation_fields_for_target(text, method, path),
                    "captureBody": True,
                    "evidenceType": "api_response",
                    "proves": f"`{method} {path}` returns a successful response for {req_id}.",
                })
            else:
                if method and method not in {"GET", "HEAD"} and not allow_mutating_api:
                    gaps.append(f"{req_id}: mutating API `{method} {path}` needs safe test data or explicit authorization.")
                elif async_poll_probe:
                    gaps.append(f"{req_id}: async poll probe for `{method} {path}` needs an extracted runtime id from the creating step before execution.")
                elif error_state_probe:
                    gaps.append(f"{req_id}: error-state API probe for `{method} {path}` needs a safe way to produce or replay the expected failed response.")
                elif auth_redirect_or_callback:
                    if saml_auth_only:
                        gaps.append(f"{req_id}: SAML API `{method} {path}` needs controlled IdP fixtures, AuthnRequest/RelayState evidence, signed/negative SAMLResponse fixtures, XML signature/audience/recipient/time-window proof, no-session side-effect proof, and secret redaction before execution.")
                    elif webauthn_auth_only:
                        gaps.append(f"{req_id}: WebAuthn API `{method} {path}` needs controlled passkey fixtures, challenge/assertion replay evidence, origin/rpId/signature/signCount proof, no-session side-effect proof, and secret redaction before execution.")
                    elif one_time_token_auth_only:
                        gaps.append(f"{req_id}: one-time-token API `{method} {path}` needs controlled reset/link fixtures, existing-vs-unknown account comparison, outbox/link evidence, token lifecycle/replay inputs, session side-effect proof, audit evidence, and secret redaction before execution.")
                    elif api_key_auth_only:
                        gaps.append(f"{req_id}: API-key API `{method} {path}` needs controlled admin/auth fixture, env-backed key material, secret-once/hash/prefix/scope/revocation fixtures, no-mutation side-effect proof, audit evidence, and secret redaction before execution.")
                    else:
                        gaps.append(f"{req_id}: OAuth/redirect API `{method} {path}` needs controlled IDP/redirect fixtures, state/nonce/PKCE/replay assertions, no-session/no-link side-effect proof, and token redaction before execution.")
                else:
                    gaps.append(f"{req_id}: API endpoint is missing or contains runtime placeholders.")
            test_index += 1
    return test_index

def apply_stream_transport_rules(
    *,
    context: ScaffoldPoint,
    tests: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    allow_live_stream: bool,
) -> int:
    """追加流式协议探针。"""
    point = context.point
    req_id = context.req_id
    text = context.text
    paths = context.paths
    tags = context.tags
    req_tests = context.req_tests
    if "stream" in tags:
        stream_path = next((item for item in paths if path_is_stream(item)), "")
        path = stream_path or api_path(paths, text) or next((item for item in paths if "ws" in item.lower()), "")
        stream_test_type = "sse" if (stream_path and ("sse" in stream_path.lower() or "events" in stream_path.lower())) or has_artifact_progress_intent(text) else "websocket"
        executable = bool(path) and allow_live_stream and "{" not in path and stream_test_type == "websocket"
        status = "Untested" if executable else "Blocked"
        test = make_test(
            req_id,
            test_index,
            stream_test_type,
            point,
            status,
            f"The stream emits a terminal success event for: {text}",
            ["Open stream and require a terminal success event such as answer_done."] if executable else ["Provide stream endpoint, auth, and safe payload before execution."],
            list(dict.fromkeys(["captured stream messages", "terminal event", "runtime errors", *requirement_specific_evidence_layers(text)])),
        )
        req_tests.append(test)
        tests.append(test)
        if executable:
            steps.append({
                "action": "websocket",
                "id": f"{test['id']}-stream",
                "testIds": [test["id"]],
                "requirementIds": [req_id],
                "path": path,
                "send": {"question": f"QA_STREAM_PROBE_{datetime.now().strftime('%Y%m%d%H%M%S')}"},
                "expectMessageTextContains": "answer_done",
                "captureMessages": True,
                "timeoutMs": 60000,
                "evidenceType": "websocket",
                "proves": f"The stream for {req_id} emits `answer_done`.",
            })
        else:
            gaps.append(f"{req_id}: stream probe needs endpoint/auth/safe payload or --allow-live-stream.")
        test_index += 1
    return test_index

def apply_persistence_transport_rules(
    *,
    context: ScaffoldPoint,
    tests: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    persistence_command: str | None,
) -> int:
    """追加持久化验证探针。"""
    point = context.point
    req_id = context.req_id
    text = context.text
    tags = context.tags
    req_tests = context.req_tests
    if "persistence" in tags:
        executable = bool(persistence_command)
        status = "Untested" if executable else "Blocked"
        test = make_test(
            req_id,
            test_index,
            "persistence",
            point,
            status,
            f"Persistence/log state satisfies requirement: {text}",
            ["Run project-approved read-only persistence helper."] if executable else ["Provide project-approved read-only persistence/log helper."],
            list(dict.fromkeys(["command stdout/stderr", "persisted terminal state", "event/log trail", *requirement_specific_evidence_layers(text)])),
        )
        req_tests.append(test)
        tests.append(test)
        if executable:
            steps.append({
                "action": "command",
                "id": f"{test['id']}-persistence",
                "testIds": [test["id"]],
                "requirementIds": [req_id],
                "command": shlex.split(persistence_command),
                "expectExitCode": 0,
                "captureStdout": True,
                "captureStderr": True,
                "evidenceType": "command",
                "proves": f"The project-approved persistence helper verifies {req_id}.",
            })
        else:
            gaps.append(f"{req_id}: persistence/log verification helper is missing.")
        test_index += 1
    return test_index

def apply_permission_transport_rules(
    *,
    context: ScaffoldPoint,
    tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    """追加权限边界探针。"""
    point = context.point
    req_id = context.req_id
    text = context.text
    tags = context.tags
    req_tests = context.req_tests
    if "permission" in tags:
        denial_evidence = "UI/API denial evidence" if "ui" in tags else "API denial evidence"
        test = make_test(
            req_id,
            test_index,
            "permission",
            point,
            "Blocked",
            f"Permission behavior satisfies requirement: {text}",
            ["Provide roles/accounts or auth state before execution."],
            list(dict.fromkeys(["authorized status", "unauthorized status", denial_evidence, *requirement_specific_evidence_layers(text)])),
        )
        req_tests.append(test)
        tests.append(test)
        gaps.append(f"{req_id}: permission test needs role/account fixtures.")
        test_index += 1
    return test_index

def _runtime_rule_applies(context: ScaffoldPoint) -> bool:
    """判断需求点是否需要独立运行时处置规则。"""
    text = context.text
    tags = context.tags
    req_tests = context.req_tests
    return bool("runtime" in tags and (has_error_state_intent(text) or has_retry_backoff_intent(text) or has_dead_letter_intent(text) or has_background_job_intent(text) or has_scheduled_job_intent(text) or has_worker_intent(text) or has_cleanup_intent(text) or has_flag_default_off_intent(text) or has_stale_flag_guard_intent(text) or has_direct_api_denial_intent(text) or has_authorization_policy_intent(text) or has_financial_ledger_intent(text) or has_quota_metering_intent(text) or has_transaction_integrity_intent(text) or has_subscription_billing_intent(text) or has_agent_tool_intent(text) or has_artifact_generation_intent(text) or has_offline_sync_intent(text) or has_analytics_intent(text) or has_cache_consistency_intent(text) or has_webhook_security_intent(text) or has_privacy_compliance_intent(text) or has_graphql_intent(text) or has_rag_grounding_intent(text) or has_search_relevance_intent(text) or has_localization_intent(text) or has_csrf_intent(text) or has_session_security_intent(text) or has_cookie_security_intent(text) or has_oauth_intent(text) or has_redirect_security_intent(text) or has_saml_intent(text) or has_webauthn_intent(text) or has_mfa_intent(text) or has_one_time_token_intent(text) or has_api_key_intent(text) or has_audit_integrity_intent(text) or has_schema_migration_intent(text) or has_optimistic_ui_intent(text) or has_rate_limit_intent(text) or has_file_security_intent(text) or has_file_preview_intent(text) or has_destructive_confirmation_intent(text) or has_bulk_action_intent(text) or has_undo_intent(text) or has_realtime_intent(text) or has_multi_client_intent(text) or has_ordering_intent(text) or has_reconnect_replay_intent(text) or has_dst_boundary_intent(text) or has_float_drift_guard_intent(text) or not any(test["type"] == "ui" and test["status"] == "Untested" for test in req_tests)))

def _runtime_evidence_layers(text: str) -> list[str]:
    """按需求语义收集运行时证据层。"""
    runtime_evidence = ["console errors", "request failures", "failed responses", "logs"]
    if has_rag_grounding_intent(text):
        for layer in [
            "request body",
            "stream",
            "terminal_status",
            "rag_grounding",
            "retrieval_trace",
            "retrieved_source_ids",
            "vector_index",
            "embedding_model",
            "top_k",
            "score_threshold",
            "query_hash",
            "source_citation",
            "citation_span",
            "source_excerpt_match",
            "document_version",
            "stale_source_guard",
            "hallucination_guard",
            "prompt_injection_guard",
            "safety_trace",
            "abstention",
            "insufficient_sources",
            "tenant_boundary",
            "data_isolation",
            "forbidden text absence",
            "audit_log",
            "persistence",
        ]:
            if layer not in runtime_evidence:
                runtime_evidence.append(layer)
    if has_search_relevance_intent(text):
        for layer in [
            "request body",
            "query_params",
            "search_relevance",
            "search_id",
            "result_order",
            "result_position",
            "relevance_score",
            "ranking_model",
            "query_rewrite",
            "canonical_query",
            "typo_tolerance",
            "synonym_expansion",
            "facet_counts",
            "total_count",
            "pagination",
            "duplicate_absence",
            "sponsored_disclosure",
            "stale_result_guard",
            "error_state",
            "tenant_boundary",
            "data_isolation",
            "forbidden text absence",
        ]:
            if layer not in runtime_evidence:
                runtime_evidence.append(layer)
    if has_cleanup_intent(text):
        for layer in [
            "request body",
            "extracted runtime id",
            "same runtime id",
            "cleanup",
            "cleanup_api",
            "cleanup_verification",
            "always_run_teardown",
            "deletion_absence",
            "cascade_cleanup",
            "outbox_absence",
            "audit_log",
            "persistence",
        ]:
            if layer not in runtime_evidence:
                runtime_evidence.append(layer)
    if has_scheduled_job_intent(text):
        for layer in [
            "command",
            "stdout_json",
            "scheduled_job",
            "schedule_expression",
            "scheduler_run",
            "run_key",
            "job_id",
            "next_run_at",
            "timezone",
            "dst_boundary",
            "due_window",
            "catch_up",
            "scheduler_lock",
            "concurrent_requests",
            "duplicate_absence",
            "dry_run",
            "no_persistence_side_effect",
            "invoice_rows",
            "outbox",
            "no_real_email",
            "audit_log",
            "persistence",
        ]:
            if layer not in runtime_evidence:
                runtime_evidence.append(layer)
    if has_decision_table_logic_intent(text):
        for layer in [
            "logic",
            "command",
            "stdout_json",
            "decision_table",
            "rule_matrix",
            "rule_precedence",
            "boundary_cases",
            "negative_cases",
            "fixture_inputs",
            "expected_outputs",
            "terminal_status",
        ]:
            if layer not in runtime_evidence:
                runtime_evidence.append(layer)
    if has_localization_intent(text):
        for layer in [
            "localization",
            "locale_switch",
            "translation_catalog",
            "catalog_version",
            "translation_key_absence",
            "fallback_absence",
            "plural_rules",
            "rtl_layout",
            "lang_attribute",
            "dir_attribute",
            "currency_format",
            "date_time_format",
            "timezone",
            "stale_locale_guard",
            "api_response",
            "query_params",
            "responsive",
        ]:
            if layer not in runtime_evidence:
                runtime_evidence.append(layer)
    if has_artifact_generation_intent(text):
        for layer in artifact_generation_evidence_layers():
            if layer not in runtime_evidence:
                runtime_evidence.append(layer)
    if has_offline_sync_intent(text):
        for layer in offline_sync_evidence_layers():
            if layer not in runtime_evidence:
                runtime_evidence.append(layer)
    if has_analytics_intent(text):
        for layer in analytics_evidence_layers():
            if layer not in runtime_evidence:
                runtime_evidence.append(layer)
    for layer in requirement_specific_evidence_layers(text):
        if layer in {"error_state", "stale_data_guard", "optimistic_update", "temp_id", "pending_state", "rollback", "failed_state", "retry_action", "cache_invalidation", "no_success_toast", "schema_migration", "migration_plan", "migration_dry_run", "schema_version", "schema_diff", "backfill_count", "batch_checkpoint", "index_concurrently", "foreign_key_constraint", "not_null_constraint", "zero_null_verification", "rollback_plan", "backward_compatibility", "authorization_policy", "policy_matrix", "policy_decision", "matched_rule", "deny_precedence", "role_inheritance", "resource_scope", "obligation", "policy_cache_key", "stale_policy_guard", "financial_ledger", "ledger_entry", "double_entry", "ledger_balance", "immutable_ledger", "reversal_entry", "minor_unit_amount", "no_float_drift", "over_refund_denial", "settlement_event", "payout_reconciliation", "quota_metering", "usage_counter", "quota_window", "quota_remaining", "atomic_increment", "counter_version", "quota_exceeded_denial", "no_negative_remaining", "billing_usage_event", "reset_boundary", "transaction_integrity", "transaction_id", "atomic_commit", "order_state", "payment_authorization", "inventory_reservation", "outbox_event", "outbox_dispatch", "post_commit_publish", "publish_exactly_once", "saga_compensation", "compensation_event", "inventory_release", "authorization_void", "subscription_billing", "subscription_id", "current_plan", "target_plan", "subscription_version", "billing_cycle", "billing_anchor", "proration_behavior", "invoice_preview", "proration_line_item", "unused_credit", "prorated_charge", "tax_jurisdiction", "tax_rate", "tax_amount", "invoice_total", "calculation_version", "payment_intent", "scheduled_capture", "scheduled_change", "agent_tool", "agent_session_id", "tool_call_event", "tool_call_id", "tool_name", "tool_args_redaction", "args_hash", "approval_gate", "approval_id", "tool_result_event", "tool_result_id", "cancellation_event", "tool_execution_absence", "authorization_denial", "handoff_required", "handoff_id", "cache_consistency", "etag", "cache_control", "if_none_match", "not_modified_denial", "cache_key", "surrogate_key_purge", "stale_revalidation", "stale_response_guard", "origin_fetch", "cache_status", "version_token", "ui_stale_absence", "trace_id", "signature_validation", "webhook_security", "hmac_signature", "raw_body_integrity", "timestamp_tolerance", "replay_window", "signature_version", "graphql_operation", "graphql_variables", "persisted_query_hash", "graphql_errors", "partial_data", "field_authorization", "dataloader_batch", "resolver_trace", "n_plus_one_guard", "graphql_mutation", "graphql_subscription", "subscription_event", "privacy_compliance", "privacy_export", "export_artifact", "export_manifest", "encrypted_export", "data_hash", "erasure_request", "pseudonymization", "search_index_removal", "csrf_token", "csrf_header", "csrf_denial", "session_cookie", "session_rotation", "logout_invalidation", "cookie_flags", "redirect_location", "redirect_uri_allowlist", "open_redirect_guard", "oauth_state", "oauth_nonce", "pkce_challenge", "pkce_verifier", "authorization_code", "code_exchange", "saml_authn_request", "saml_request", "relay_state", "acs_url", "sp_entity_id", "saml_response", "saml_assertion", "xml_signature", "x509_certificate", "issuer", "audience_restriction", "destination", "recipient", "in_response_to", "assertion_time_window", "name_id", "attribute_mapping", "request_consumption", "webauthn_challenge", "rp_id", "origin", "credential_id", "client_data_json", "authenticator_data", "signature_verification", "user_verification", "sign_count", "challenge_consumption", "attestation_object", "credential_public_key", "mfa_challenge", "mfa_pending", "totp_code", "totp_time_window", "clock_skew", "mfa_verification", "recovery_code", "recovery_code_consumption", "mfa_required_denial", "one_time_token", "token_hash", "token_purpose", "token_expiry", "token_consumption", "token_replay_denial", "email_outbox", "email_link", "password_hash_update", "session_invalidation", "api_key_secret_once", "api_key_hash", "api_key_prefix", "api_key_scopes", "api_key_expiry", "api_key_last_used", "api_key_revocation", "api_key_auth_success", "api_key_scope_denial", "api_key_replay_denial", "audit_event", "audit_sequence", "append_only", "hash_chain", "previous_hash", "event_hash", "canonical_json", "tamper_denial", "retention_policy", "legal_hold", "pii_redaction", "session_creation", "oauth_account", "attempt_count", "rate_limit_key", "rate_limit_window", "rate_limited_response", "retry_after_header", "lockout_state", "lockout_expiry", "no_session_created", "generic_error_copy", "generic_success_copy", "account_enumeration_guard", "response_headers", "file_fixture", "upload_request", "attachment_id", "scan_status", "malware_scan", "quarantine", "scan_engine", "scan_version", "preview_rendering", "signed_url", "nosniff", "storage_key_redaction", "file_size_validation", "selection_state", "selected_count", "selected_scope", "unselected_unchanged", "confirmation_modal", "destructive_action_guard", "soft_delete", "deleted_at", "deleted_by", "operation_id", "undo_action", "undo_restoration", "no_real_email", "audit_log", "outbox", "notification", "queued_status", "job_id", "background_worker", "worker_log", "retry_count", "backoff_schedule", "dead_letter", "alert_outbox", "correlation_id", "feature_flag", "flag_evaluation", "cohort_targeting", "variant", "evaluation_id", "config_version", "default_off", "direct_api_denial", "forbidden request absence", "no_persistence_side_effect", "stale_flag_guard", "cross_tenant_denial", "data_isolation", "tenant_boundary", "workspace_boundary", "realtime", "multi_client", "broadcast_event", "sequence_order", "reconnect_replay", "duplicate_absence", "date_range_boundary", "timezone", "dst_boundary", "money_precision", "calculation_parity", "rounding_rule", "currency_conversion"} and layer not in runtime_evidence:
            runtime_evidence.append(layer)
    return runtime_evidence

def _runtime_probe_steps(text: str) -> list[str]:
    """选择与需求语义匹配的运行时执行说明。"""
    runtime_steps = (
        ["Drive or replay the RAG grounded-answer path, capture request body, same answer_id stream terminal event, retrieval trace, source/citation spans, current document version, prompt-injection safety trace, tenant isolation, abstention, audit/persistence, forbidden text absence, and count-aware runtime disposition."]
        if has_rag_grounding_intent(text)
        else
        ["Drive or replay the search relevance path, capture query params, search_id, ordered result ids/positions/scores, ranking model, query rewrite/canonical query, facet counts, total_count, pagination duplicate absence, sponsored disclosure, tenant leak guards, stale-result absence, retryable error state, and count-aware runtime disposition."]
        if has_search_relevance_intent(text)
        else
        [graphql_runtime_probe_instruction(text)]
        if has_graphql_intent(text)
        else
        ["Drive or replay the privacy export/erasure path, capture DSAR export artifact and manifest, encrypted export/data_hash, same erasure job, pseudonymization, session and API-key revocation, search-index removal, cache purge, legal-hold blocked behavior, idempotent replay duplicate absence, audit/persistence evidence, and count-aware runtime disposition."]
        if has_privacy_compliance_intent(text)
        else
        ["Drive or replay the create-and-cleanup path, capture the create request body and extracted runtime id, prove same-object readback, run always-on cleanup with the same id, verify deleted/absent state plus related-row and outbox absence, audit project.testdata_deleted or equivalent, and count-aware runtime disposition."]
        if has_cleanup_intent(text)
        else
        ["Drive or replay the scheduled job path, capture command/stdout JSON, schedule expression, schedule_id/run_key/job_id/next_run_at, timezone/DST due window, scheduler_runs terminal state, catch-up duplicate absence, scheduler_lock/advisory-lock winner and duplicate-skipped loser, dry-run no-persistence proof, invoice/outbox/audit boundaries, no-real-email proof, and count-aware runtime disposition."]
        if has_scheduled_job_intent(text)
        else
        ["Drive or replay the decision-table rule evaluation, capture command/stdout JSON, fixture input rows, expected_decisions, rule_hits, boundary and negative rows, precedence override proof, terminal status, and count-aware runtime disposition without accepting UI screenshots, API 200, or exit code alone."]
        if has_decision_table_logic_intent(text)
        else
        ["Drive or replay the localization path, capture locale switch, catalog API version, missing_keys/fallback_count and raw-key absence, html lang/dir, plural-rule rows, RTL layout/no-overflow evidence, Intl currency/date timezone parity, stale-catalog guard, and count-aware runtime disposition."]
        if has_localization_intent(text)
        else
        ["Drive or replay the analytics telemetry path, capture checkout success and no-early-event ordering, analytics event request body/schema/consent/session/pseudonym/attribution/experiment/dedupe/event_time fields, consent-false no-event proof, duplicate replay absence, 503 retry queue state, attribution mismatch denial, experiment exposure persistence, PII/token/cookie leak guards, analytics persistence, and count-aware runtime disposition."]
        if has_analytics_intent(text)
        else
        ["Drive or replay the async artifact-generation path, capture request body, job_id/resume_token/idempotency_key, ordered progress events through artifact_ready, artifact manifest id/hash/content hash, worker checkpoint resume, cancel cleanup, partial-failure diagnostics, download authorization/leak guards, audit/persistence evidence, and count-aware runtime disposition."]
        if has_artifact_generation_intent(text)
        else
        ["Drive or replay the offline sync path, capture offline request absence, IndexedDB/local outbox fields, background sync request/response, queue drain, idempotent replay, conflict merge, retry scheduling, denied actor no-side-effect proof, leak guards, audit/persistence evidence, and count-aware runtime disposition."]
        if has_offline_sync_intent(text)
        else
        ["Drive or replay the background job path, capture enqueue/job id, worker log or queue-state evidence, retry/dead-letter state when applicable, and disposition runtime failures without treating queued as complete."]
        if (has_background_job_intent(text) or has_worker_intent(text) or has_retry_backoff_intent(text) or has_dead_letter_intent(text))
        else ["Drive or replay the SAML SSO path, capture AuthnRequest/SAMLRequest, RelayState, ACS URL, SP entityID, signed and negative SAMLResponse fixtures, XML signature/x509, issuer, AudienceRestriction, Destination/Recipient, InResponseTo, NotBefore/NotOnOrAfter, NameID/group mapping, request consumption/replay denial, no-session side effects, and secret leak guards with count-aware runtime disposition."]
        if has_saml_intent(text)
        else ["Drive or replay the OAuth/PKCE callback path, capture redirect, state/nonce/PKCE/code-exchange/session evidence, replay and mismatch denials, open-redirect rejection, no-persistence side effects, and token leak guards with count-aware runtime disposition."]
        if (has_oauth_intent(text) or has_redirect_security_intent(text))
        else ["Drive or replay the WebAuthn/passkey path, capture challenge options, rpId/origin/clientDataJSON/authenticatorData, public-key signature verification, user verification, signCount increase, challenge consumption, replay/wrong-origin/wrong-rpId/unknown-credential denials, attestation/public-key storage, no-session side effects, and secret leak guards with count-aware runtime disposition."]
        if has_webauthn_intent(text)
        else ["Drive or replay the MFA/TOTP path, capture challenge, pending-session, TOTP time-window/clock-skew, recovery-code consumption, wrong/expired/replay denials, direct API mfa_required denial, no-session/no-transfer side effects, and secret leak guards with count-aware runtime disposition."]
        if has_mfa_intent(text)
        else ["Drive or replay the one-time-token path, capture existing-vs-unknown account copy, outbox/link evidence, token hash/purpose/expiry/consumption, replay/expired/tampered/wrong-purpose/wrong-tenant denials, password/session side effects, audit records, no-session proof, and secret leak guards with count-aware runtime disposition."]
        if has_one_time_token_intent(text)
        else ["Drive or replay the API key/PAT lifecycle path with env-backed secret material, capture secret-once creation, hash/prefix/scope/expiry/list evidence, scoped success and insufficient-scope denial, last_used_at update, revocation and revoked/expired/tampered denials, no-mutation side effects, audit records, and secret leak guards with count-aware runtime disposition."]
        if has_api_key_intent(text)
        else ["Drive or replay the audit integrity path, capture current-run audit event ordering, append-only write evidence, hash-chain recomputation, tamper-denial attempts, retention/legal-hold state, PII/raw-IP redaction, no-mutation side effects, and count-aware runtime disposition."]
        if has_audit_integrity_intent(text)
        else ["Drive or replay the schema migration dry-run/apply/rollback path, capture schema_version transitions, schema diff, exact backfill count and batch checkpoints, concurrent-index/FK/NOT NULL proof, old/new client API compatibility, forbidden metadata absence, persistence, and count-aware runtime disposition."]
        if has_schema_migration_intent(text)
        else ["Drive or replay the authorization policy path, capture policy-evaluate request/response, matched rule, deny precedence over inherited roles, resource scope, obligation, denied UI state, direct API denial, no side effects, tenant leak guards, policy cache invalidation, audit evidence, and count-aware runtime disposition."]
        if has_authorization_policy_intent(text)
        else ["Drive or replay the financial ledger refund path, capture refund API response, double-entry reversal rows, ledger balance, original-entry immutability, idempotent replay duplicate absence, over-refund denial with no side effect, settlement worker event, payout reconciliation, audit evidence, and count-aware runtime disposition."]
        if has_financial_ledger_intent(text)
        else ["Drive or replay the usage quota metering path, capture same-tenant meter/window request and response evidence, usage_counter used/remaining/counter_version transitions, concurrent winner/loser requests, quota_exceeded denial with no downstream side effects, idempotent replay, billing usage event exactness, reset-boundary worker/audit evidence, and count-aware runtime disposition."]
        if has_quota_metering_intent(text)
        else ["Drive or replay the checkout transaction/saga path, capture order/payment/inventory/outbox rows with the same transaction_id and atomic commit proof, idempotent replay duplicate absence, payment-timeout and inventory-failure compensation, post-commit outbox exactly-once dispatch, trace/correlation continuity, and count-aware runtime disposition."]
        if has_transaction_integrity_intent(text)
        else ["Drive or replay the agent tool-call path, capture prompt request body, WebSocket stream, approval/cancel API responses, tool_call_requested id/name/args_hash with redacted args, approval_required before execution, tool_result or tool_call_cancelled events, idempotent duplicate absence, denied-actor no-side-effect proof, handoff_required timeout persistence, absence of successful answer_done on handoff, audit evidence, and count-aware runtime disposition."]
        if has_agent_tool_intent(text)
        else ["Drive or replay the subscription plan-change path, capture preview request/response, preview no-mutation evidence, proration/tax/invoice-preview calculation proof, confirm subscription_version/invoice/payment schedule evidence, idempotent replay duplicate absence, downgrade scheduled-change boundary proof, denied support-actor no-side-effect proof, audit/persistence evidence, no receipt email proof, and count-aware runtime disposition."]
        if has_subscription_billing_intent(text)
        else ["Drive or replay the cache consistency path, capture ETag/Cache-Control/If-None-Match response headers, stale-validator 304 denial after mutation, cache-key invalidation, surrogate-key purge, bounded stale-while-revalidate response, origin fetch, MISS-to-HIT transition, UI stale-absence, and count-aware runtime disposition."]
        if has_cache_consistency_intent(text)
        else ["Drive or replay the webhook security path, capture exact raw-body HMAC verification, request headers, invalid reordered-body rejection, timestamp-out-of-tolerance denial, replay-window duplicate handling, no side effects, audit/persistence evidence, and count-aware runtime disposition."]
        if has_webhook_security_intent(text)
        else ["Drive or replay the optimistic UI failure and retry path, capture temp-id pending state, failed-response rollback or failed-state UI, absent success toast, cache invalidation/refetch, no persisted side effect, idempotent retry success, duplicate absence, and count-aware runtime disposition."]
        if has_optimistic_ui_intent(text)
        else ["Drive or replay the rate-limit path with safe repeated attempts, capture threshold 401/429 responses, Retry-After headers, no-session evidence, enumeration guard checks, lockout/reset persistence, and count-aware runtime disposition."]
        if has_rate_limit_intent(text)
        else ["Drive or replay the CSRF/session-cookie security path, capture denial responses, old-session/logout failures, cookie headers, no-write checks, and no-secret-leak evidence with count-aware runtime disposition."]
        if (has_csrf_intent(text) or has_session_security_intent(text) or has_cookie_security_intent(text))
        else ["Drive or replay the attachment security path with clean/malware/oversized fixtures, capture scan/quarantine/preview-header evidence, no-preview/download denial, leak guards, and count-aware runtime disposition."]
        if (has_file_security_intent(text) or has_file_preview_intent(text))
        else ["Drive or replay the bulk destructive action path with safe fixtures, capture selected-count/scope evidence, cancel/Escape no-request behavior, soft-delete/undo evidence, and count-aware runtime disposition."]
        if (has_bulk_action_intent(text) or has_destructive_confirmation_intent(text) or has_undo_intent(text))
        else ["Drive or replay the feature-flag timeout/default-off/direct-denial path, capture flag evaluation or log evidence, prove no stale cached flag data was reused, and disposition runtime failures without treating beta UI success as full rollout proof."]
        if (has_flag_default_off_intent(text) or has_stale_flag_guard_intent(text) or (has_direct_api_denial_intent(text) and (has_feature_flag_intent(text) or has_rollout_intent(text))))
        else ["Drive or replay the realtime collaboration path, capture multi-client stream/runtime evidence, and disposition failed connections, dropped messages, duplicate events, or ordering violations explicitly."]
        if (has_realtime_intent(text) or has_multi_client_intent(text) or has_ordering_intent(text) or has_reconnect_replay_intent(text))
        else
        ["Drive or replay the failed-response condition, capture the failed response/runtime issue, and assert the retryable UI state without stale cached success data."]
        if has_error_state_intent(text)
        else ["Drive or replay the timezone/DST boundary condition, capture warning/error/runtime disposition evidence, and prove invalid local times are not silently shifted into successful results."]
        if has_dst_boundary_intent(text)
        else ["Drive the monetary calculation edge case and prove no floating-point drift, unrounded intermediate leak, or undispositioned runtime issue appears in API/UI/log evidence."]
        if has_float_drift_guard_intent(text)
        else ["Attach runtime checks to an executable parent probe."]
    )
    return runtime_steps

def _append_runtime_gap(*, req_id: str, text: str, gaps: list[str]) -> None:
    """记录运行时规则仍需补齐的真实输入与证据。"""
    if has_rag_grounding_intent(text):
        gaps.append(f"{req_id}: RAG runtime probe needs safe knowledge fixtures, same answer_id stream terminal event, retrieval trace, source/citation span evidence, current document version, prompt-injection safety trace, tenant isolation, abstention/no-citation-row proof, forbidden text absence, audit/persistence checks, and count-aware runtime disposition.")
    elif has_search_relevance_intent(text):
        gaps.append(f"{req_id}: search-relevance runtime probe needs safe search fixtures, query/response binding, ranking/facet/pagination evidence, tenant leak guards, stale-result absence, retryable error-state proof, and count-aware runtime disposition.")
    elif has_graphql_intent(text):
        gaps.append(f"{req_id}: GraphQL runtime probe needs safe BFF fixtures, {graphql_probe_focus(text)}, and count-aware runtime disposition.")
    elif has_privacy_compliance_intent(text):
        gaps.append(f"{req_id}: privacy-compliance runtime probe needs safe DSAR/erasure fixtures, export artifact/manifest and encrypted data_hash proof, tenant-scoped content evidence, pseudonymization, session/API-key revocation, search-index/cache purge proof, legal-hold blocked behavior, idempotent duplicate absence, audit/persistence evidence, PII/token/encryption-key leak guards, and count-aware runtime disposition.")
    elif has_cleanup_intent(text):
        gaps.append(f"{req_id}: cleanup runtime probe needs safe create/teardown fixture, extracted runtime id, same-object readback, always-run cleanup, deleted/absent verification, related-row and outbox absence, cleanup audit evidence, and count-aware runtime disposition.")
    elif has_scheduled_job_intent(text):
        gaps.append(f"{req_id}: scheduled-job runtime probe needs safe scheduler fixtures, command/stdout JSON, schedule_id/run_key/job_id/next_run_at binding, timezone/DST due-window proof, scheduler_runs terminal state, catch-up duplicate absence, scheduler_lock winner/loser evidence, dry-run no-persistence proof, invoice/outbox/audit boundaries, no-real-email proof, and count-aware runtime disposition.")
    elif has_decision_table_logic_intent(text):
        gaps.append(f"{req_id}: decision-table runtime probe needs rule-evaluation stdout JSON, fixture input rows, expected_decisions per branch, rule_hits, boundary/negative rows, precedence override proof, terminal status, and count-aware runtime disposition.")
    elif has_localization_intent(text):
        gaps.append(f"{req_id}: localization runtime probe needs locale switch, catalog API version, missing_keys/fallback_count and raw-key absence, plural-rule fixtures, html lang/dir and RTL no-overflow proof, Intl currency/date timezone parity, stale-catalog guard, and count-aware runtime disposition.")
    elif has_analytics_intent(text):
        gaps.append(f"{req_id}: analytics runtime probe needs safe checkout/telemetry fixtures, no-early-event ordering, captured event payload/schema/consent/session/pseudonym/attribution/experiment/dedupe/event_time fields, consent-false no-event proof, duplicate replay absence, 503 retry queue state, attribution mismatch denial, experiment exposure persistence, PII/token/cookie leak guards, analytics persistence, and count-aware runtime disposition.")
    elif has_artifact_generation_intent(text):
        gaps.append(f"{req_id}: artifact-generation runtime probe needs safe report job fixtures, request/job/resume/idempotency binding, ordered progress/artifact_ready events, manifest/hash/persistence evidence, checkpoint resume duplicate-absence proof, cancel cleanup, partial-failure diagnostics, download guard/leak proof, audit evidence, and count-aware runtime disposition.")
    elif has_offline_sync_intent(text):
        gaps.append(f"{req_id}: offline-sync runtime probe needs offline request absence, IndexedDB/local outbox inspection, background sync request/response, queue-drain proof, idempotent replay, conflict merge, retry scheduling, denied actor no-side-effect proof, leak guards, audit/persistence evidence, and count-aware runtime disposition.")
    elif has_background_job_intent(text) or has_worker_intent(text) or has_retry_backoff_intent(text) or has_dead_letter_intent(text):
        gaps.append(f"{req_id}: background worker/runtime probe needs safe job fixture, worker/queue evidence, retry/dead-letter evidence when required, and count-aware runtime disposition.")
    elif has_saml_intent(text):
        gaps.append(f"{req_id}: SAML runtime probe needs safe IdP fixture, AuthnRequest/SAMLRequest and RelayState evidence, signed/negative SAMLResponse fixtures, XML signature/x509, audience/recipient/InResponseTo/time-window proof, NameID/group mapping, request consumption/replay denial, no-session side effects, secret leak guards, and count-aware runtime disposition.")
    elif has_oauth_intent(text) or has_redirect_security_intent(text):
        gaps.append(f"{req_id}: OAuth/redirect runtime probe needs IDP and redirect fixtures, state/nonce/PKCE/code replay evidence, open-redirect denial, no session/account side effect, token leak guards, and count-aware runtime disposition.")
    elif has_webauthn_intent(text):
        gaps.append(f"{req_id}: WebAuthn runtime probe needs safe authenticator/passkey fixture, challenge options, rpId/origin/clientDataJSON/authenticatorData capture, signature/user-verification/signCount evidence, replay/wrong-origin/wrong-rpId denial, attestation/public-key storage proof, no-session side effects, secret leak guards, and count-aware runtime disposition.")
    elif has_mfa_intent(text):
        gaps.append(f"{req_id}: MFA runtime probe needs safe MFA account fixture, challenge/pending state, TOTP clock-skew and replay fixtures, recovery-code replay denial, mfa_required direct API denial, no-session/no-transfer proof, secret leak guards, and count-aware runtime disposition.")
    elif has_one_time_token_intent(text):
        gaps.append(f"{req_id}: one-time-token runtime probe needs safe reset/link fixtures, existing-vs-unknown account comparison, outbox/link evidence, token hash/purpose/expiry/consumption proof, replay/expired/tampered/wrong-purpose/wrong-tenant denial, password/session side-effect checks, audit evidence, secret leak guards, and count-aware runtime disposition.")
    elif has_api_key_intent(text):
        gaps.append(f"{req_id}: API-key runtime probe needs safe admin/auth fixture, env-backed API key material, secret-once/hash/prefix/scope/expiry/list evidence, scoped allow/deny proof, last_used_at/revoked_at transitions, revoked/expired/tampered denial, no-mutation side effects, audit evidence, secret leak guards, and count-aware runtime disposition.")
    elif has_audit_integrity_intent(text):
        gaps.append(f"{req_id}: audit-integrity runtime probe needs safe current-run audit event fixture, sequence/hash-chain recomputation helper, tamper-denial attempts, retention/legal-hold proof, PII/raw-IP redaction checks, no-mutation side effects, and count-aware runtime disposition.")
    elif has_schema_migration_intent(text):
        gaps.append(f"{req_id}: schema-migration runtime probe needs safe migration fixture, dry-run/apply/rollback runtime evidence, schema version/diff checks, backfill and constraint proof, compatibility responses, metadata leak guards, and count-aware runtime disposition.")
    elif has_authorization_policy_intent(text):
        gaps.append(f"{req_id}: authorization-policy runtime probe needs safe role/resource fixtures, policy-evaluate request/response, matched-rule/deny-precedence proof, direct API denial/no-side-effect checks, cache invalidation evidence, audit records, and count-aware runtime disposition.")
    elif has_financial_ledger_intent(text):
        gaps.append(f"{req_id}: financial-ledger runtime probe needs safe payment/refund fixtures, refund API response, double-entry reversal rows, ledger balance, immutability proof, idempotent replay duplicate absence, over-refund no-side-effect evidence, settlement reconciliation, audit records, and count-aware runtime disposition.")
    elif has_quota_metering_intent(text):
        gaps.append(f"{req_id}: quota-metering runtime probe needs safe tenant/meter/window fixtures, usage-counter transitions, concurrent winner/loser evidence, quota_exceeded no-side-effect proof, idempotent replay, billing-event exactness, reset-boundary worker/audit evidence, and count-aware runtime disposition.")
    elif has_transaction_integrity_intent(text):
        gaps.append(f"{req_id}: transaction-integrity runtime probe needs safe checkout/payment/inventory fixtures, same transaction_id/atomic commit evidence, idempotent duplicate absence, saga compensation side-effect checks, post-commit exactly-once dispatch, trace/correlation continuity, audit evidence, and count-aware runtime disposition.")
    elif has_agent_tool_intent(text):
        gaps.append(f"{req_id}: agent-tool runtime probe needs safe agent/session/tool fixtures, prompt request body, WebSocket event chain, approval/cancel API evidence, tool args redaction, idempotent duplicate absence, denied/cancel no-side-effect proof, timeout handoff persistence, no successful answer_done on handoff, audit evidence, and count-aware runtime disposition.")
    elif has_subscription_billing_intent(text):
        gaps.append(f"{req_id}: subscription-billing runtime probe needs safe subscription/account fixtures, preview no-mutation evidence, proration/tax calculation proof, confirmed subscription_version/invoice/payment schedule evidence, idempotent duplicate absence, downgrade scheduled-change boundary proof, denied support actor no-side-effect evidence, audit/persistence evidence, no receipt email proof, and count-aware runtime disposition.")
    elif has_cache_consistency_intent(text):
        gaps.append(f"{req_id}: cache-consistency runtime probe needs safe cache/origin fixture, ETag/Cache-Control/If-None-Match capture, stale-validator 304 denial, cache invalidation and surrogate purge proof, stale revalidation bounds, MISS/HIT transition, UI stale-absence proof, trace/audit evidence, and count-aware runtime disposition.")
    elif has_webhook_security_intent(text):
        gaps.append(f"{req_id}: webhook-security runtime probe needs safe provider fixture, env-backed signing secret, exact raw-body HMAC proof, invalid reordered-body and timestamp-denial evidence, replay-window duplicate absence, no side effects, audit/persistence evidence, secret leak guards, and count-aware runtime disposition.")
    elif has_optimistic_ui_intent(text):
        gaps.append(f"{req_id}: optimistic-UI runtime probe needs safe failed-response and retry-success fixtures, temp-id pending-state capture, rollback/failed-state evidence, absent success toast, cache invalidation/refetch proof, no persisted side effect, duplicate absence, and count-aware runtime disposition.")
    elif has_rate_limit_intent(text):
        gaps.append(f"{req_id}: rate-limit runtime probe needs safe repeated-attempt fixture, threshold 401/429 evidence, Retry-After header, no-session proof, enumeration guard, lockout/reset state, and count-aware runtime disposition.")
    elif has_csrf_intent(text) or has_session_security_intent(text) or has_cookie_security_intent(text):
        gaps.append(f"{req_id}: CSRF/session runtime probe needs token/cookie fixtures, denial responses, old-session/logout failure evidence, no-write proof, no-leak checks, and count-aware runtime disposition.")
    elif has_file_security_intent(text) or has_file_preview_intent(text):
        gaps.append(f"{req_id}: file-security runtime probe needs clean/malware/oversized fixtures, scan/quarantine state, preview-header evidence, denied preview/download proof, leak guards, and count-aware runtime disposition.")
    elif has_bulk_action_intent(text) or has_destructive_confirmation_intent(text) or has_undo_intent(text):
        gaps.append(f"{req_id}: bulk destructive-action runtime probe needs safe fixture ids, selection scope, no-request cancel/Escape evidence, soft-delete/undo proof, and count-aware runtime disposition.")
    elif has_flag_default_off_intent(text) or has_stale_flag_guard_intent(text) or (has_direct_api_denial_intent(text) and (has_feature_flag_intent(text) or has_rollout_intent(text))):
        gaps.append(f"{req_id}: feature-flag runtime probe needs flag-service timeout/default-off fixture, direct API denial evidence, stale-flag guard, and count-aware runtime disposition.")
    elif has_realtime_intent(text) or has_multi_client_intent(text) or has_ordering_intent(text) or has_reconnect_replay_intent(text):
        gaps.append(f"{req_id}: realtime runtime probe needs multi-client stream fixture, reconnect/order/duplicate evidence when required, and count-aware runtime disposition.")
    elif has_error_state_intent(text):
        gaps.append(f"{req_id}: error-state runtime probe needs a safe failed-response fixture or fault-injection path plus stale-data assertions.")
    elif has_dst_boundary_intent(text):
        gaps.append(f"{req_id}: DST runtime probe needs a safe nonexistent/ambiguous local-time fixture, visible warning or normalization evidence, and runtime disposition.")
    elif has_float_drift_guard_intent(text):
        gaps.append(f"{req_id}: monetary runtime probe needs floating-point drift guards in API/UI/log evidence.")
    else:
        gaps.append(f"{req_id}: runtime checks need an executable parent probe.")

def apply_runtime_transport_rules(
    *,
    context: ScaffoldPoint,
    tests: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
) -> int:
    """追加运行时探针，并把证据、步骤和缺口选择委托给私有助手。"""
    if _runtime_rule_applies(context):
        point = context.point
        req_id = context.req_id
        text = context.text
        req_tests = context.req_tests
        runtime_evidence = _runtime_evidence_layers(text)
        runtime_steps = _runtime_probe_steps(text)
        test = make_test(
            req_id,
            test_index,
            "runtime",
            point,
            "Blocked",
            f"Runtime errors are absent or explicitly dispositioned for: {text}",
            runtime_steps,
            runtime_evidence,
        )
        req_tests.append(test)
        tests.append(test)
        _append_runtime_gap(req_id=req_id, text=text, gaps=gaps)
        test_index += 1
    return test_index

def apply_transport_point_rules(
    *,
    context: ScaffoldPoint,
    tests: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    gaps: list[str],
    test_index: int,
    allow_live_stream: bool,
    allow_mutating_api: bool,
    persistence_command: str | None,
) -> int:
    """按传输与领域边界依次追加探针。"""
    test_index = apply_api_transport_rules(
        context=context,
        tests=tests,
        steps=steps,
        gaps=gaps,
        test_index=test_index,
        allow_mutating_api=allow_mutating_api,
    )
    test_index = apply_stream_transport_rules(
        context=context,
        tests=tests,
        steps=steps,
        gaps=gaps,
        test_index=test_index,
        allow_live_stream=allow_live_stream,
    )
    test_index = apply_persistence_transport_rules(
        context=context,
        tests=tests,
        steps=steps,
        gaps=gaps,
        test_index=test_index,
        persistence_command=persistence_command,
    )
    test_index = apply_permission_transport_rules(
        context=context,
        tests=tests,
        gaps=gaps,
        test_index=test_index,
    )
    return apply_runtime_transport_rules(
        context=context,
        tests=tests,
        gaps=gaps,
        test_index=test_index,
    )

def finalize_scaffold_point(
    context: ScaffoldPoint,
    cursor: ScaffoldCursor,
    requirements: list[dict[str, Any]],
) -> None:
    """推进继承游标并写入需求矩阵行。"""
    point = context.point
    req_id = context.req_id
    text = context.text
    point_source_base = context.point_source_base
    response_method = context.response_method
    response_path = context.response_path
    inherited_api_context = context.inherited_api_context
    tags = context.tags
    req_tests = context.req_tests
    click_intent = context.click_intent
    button_name = context.button_name
    explicit_page_path = context.explicit_page_path
    inherited_ui_context = context.inherited_ui_context
    page_path = context.page_path
    last_api_context = cursor.last_api_context
    last_ui_context = cursor.last_ui_context
    last_click_context = cursor.last_click_context
    if explicit_page_path and not response_path:
        last_api_context = None
    if response_path and not inherited_api_context:
        last_api_context = (response_method or "GET", response_path)
    if explicit_page_path:
        last_ui_context = explicit_page_path
    if page_path and button_name and click_intent:
        last_click_context = {
            "source_base": point_source_base,
            "page_path": page_path,
            "button_name": button_name,
        }

    requirements.append({
        "id": req_id,
        "source": f"requirement.md {point['source']}",
        "text": text,
        "risk": ", ".join(sorted(tags)),
        "test_ids": [test["id"] for test in req_tests],
        "status": status_for_tests(req_tests),
        **({"inherited_api_paths": [response_path], "inherited_api_method": response_method or "GET"} if inherited_api_context and response_path else {}),
        **({"inherited_entry_points": [page_path]} if inherited_ui_context and page_path else {}),
        **({"notes": "Generated requirement has no executable probe yet; see coverage gaps."} if status_for_tests(req_tests) == "Blocked" else {}),
    })
    cursor.last_api_context = last_api_context
    cursor.last_ui_context = last_ui_context
    cursor.last_click_context = last_click_context
