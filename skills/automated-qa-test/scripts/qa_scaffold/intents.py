"""需求意图、领域信号与端点识别。"""

import re
from typing import Any, Callable

from .support import (
    HTTP_STATUS_REASON_WORDS,
    METHOD_PATH_RE,
    PATH_RE,
    STREAM_PATH_SEGMENTS,
    extract_code_file_paths,
    extract_method_path,
    extract_method_paths,
    extract_paths,
    extract_point_validation_command_candidates,
    path_is_code_file,
)


def method_endpoint_paths(text: str) -> set[str]:
    return {path for _, path in extract_method_paths(text)}

def path_is_code_file_for_text(text: str, path: str) -> bool:
    if str(path or "") in method_endpoint_paths(text):
        return False
    return path_is_code_file(path)

def has_explicit_runtime_acceptance(text: str) -> bool:
    for _, path in extract_method_paths(text):
        if not path_is_code_file_for_text(text, path):
            return True
    return any(not path_is_code_file_for_text(text, path) for path in extract_paths(text))

def point_is_code_pr_source_context(text: str) -> bool:
    if not point_is_code_pr_file_context(text):
        return False
    lower = text.lower()
    return (
        has_word(
            lower,
            r"\bupdates?\b",
            r"\badds?\b",
            r"\bchanges?\b",
            r"\bmodifies?\b",
            r"\brefactors?\b",
            r"\btouches?\b",
            r"\bfixes?\b",
            r"\btests?\b",
            r"\bcoverage\b",
        )
        or has_chinese(text, "更新", "新增", "修改", "重构", "测试", "覆盖")
    )

def point_is_code_pr_file_context(text: str) -> bool:
    return bool(extract_code_file_paths(text) and not has_explicit_runtime_acceptance(text))

def point_is_code_pr_validation_context(text: str) -> bool:
    return bool(extract_point_validation_command_candidates(text))

def path_placeholders(path: str) -> list[str]:
    seen: set[str] = set()
    names: list[str] = []
    for name in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", path or ""):
        if name not in seen:
            names.append(name)
            seen.add(name)
    return names

def extract_json_spec(name: str) -> dict[str, Any]:
    candidates = [name]
    if name.endswith("_id"):
        candidates.append("id")
    elif name == "id":
        candidates.extend(["data.id", "result.id"])
    return {"paths": candidates}

def returned_identifier_names(text: str) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    patterns = [
        r"\breturns?\s+(?:an?\s+)?`?([A-Za-z_][A-Za-z0-9_]*_id|id)`?\b",
        r"\b(?:response|body|json)\s+(?:contains|includes|has)\s+(?:an?\s+)?`?([A-Za-z_][A-Za-z0-9_]*_id|id)`?\b",
        r"\b(?:contains|includes|has)\s+(?:an?\s+)?`?([A-Za-z_][A-Za-z0-9_]*_id|id)`?\b",
    ]
    for pattern in patterns:
        for match in re.findall(pattern, text, flags=re.IGNORECASE):
            name = str(match).strip("`'\"")
            lowered = name.lower()
            if lowered not in seen:
                names.append(name)
                seen.add(lowered)
    for match in re.findall(r"\breturns?\s+(?:an?\s+)?([A-Za-z][A-Za-z0-9]*)\s+id\b", text, flags=re.IGNORECASE):
        name = f"{match}_id"
        lowered = name.lower()
        if lowered != "an_id" and lowered not in seen:
            names.append(name)
            seen.add(lowered)
    return names

def identifier_can_bind_placeholder(identifier: str, placeholder: str) -> bool:
    identifier_lower = identifier.lower()
    placeholder_lower = placeholder.lower()
    return (
        identifier_lower == placeholder_lower
        or (identifier_lower == "id" and placeholder_lower.endswith("_id"))
        or (placeholder_lower == "id" and identifier_lower.endswith("_id"))
    )

def terminal_status_value(text: str) -> str | None:
    lower = text.lower()
    if re.search(r"\b(completed|complete|done)\b", lower) or has_chinese(text, "完成", "已完成"):
        return "completed"
    if re.search(r"\b(ready)\b", lower) or has_chinese(text, "就绪"):
        return "ready"
    if re.search(r"\b(succeeded|successful|success)\b", lower) or has_chinese(text, "成功"):
        return "succeeded"
    if re.search(r"\b(failed|failure|dead[_ -]?letter)\b", lower) or has_chinese(text, "失败", "死信"):
        return "failed"
    return None

def has_async_status_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bpoll(?:ing)?\b", r"\beventually\b", r"\buntil\b", r"\bstatus\b", r"\bjob\b", r"\btask\b", r"\bqueue(?:d)?\b", r"\bcomplete(?:d)?\b", r"\bdone\b", r"\bprocessing\b", r"\bsucceeded\b", r"\bfailed\b", r"\bdead[_ -]?letter\b")
        or has_chinese(text, "轮询", "异步", "状态", "完成", "任务", "作业", "队列", "入队", "死信")
    )

def expect_json_any_for_placeholders(placeholders: list[str], status_value: str | None = None) -> list[dict[str, Any]]:
    status_paths = ["status", "data.status", "result.status"] if status_value else []
    if len(placeholders) == 1:
        name = placeholders[0]
        id_alternatives = [{path: {"var": name}} for path in extract_json_spec(name)["paths"]]
    else:
        id_alternatives = [{name: {"var": name} for name in placeholders}]
    if not status_paths:
        return id_alternatives
    combined: list[dict[str, Any]] = []
    for id_expectation in id_alternatives:
        for status_path in status_paths:
            expectation = dict(id_expectation)
            expectation[status_path] = status_value
            combined.append(expectation)
    return combined

def async_poll_config(text: str) -> dict[str, Any]:
    return {
        "pollIntervalMs": 1000,
        "pollTimeoutMs": 30000,
        "maxAttempts": 31,
    }

def consume_http_status_reason(value: str, index: int) -> int:
    match = re.match(rf"\s+{HTTP_STATUS_REASON_WORDS}\b", value[index:], flags=re.IGNORECASE)
    return index + match.end() if match else index

def unique_http_statuses(statuses: list[int]) -> list[int]:
    seen: set[int] = set()
    unique: list[int] = []
    for status in statuses:
        if status in seen:
            continue
        seen.add(status)
        unique.append(status)
    return unique

def collect_http_status_sequence(value: str, match: re.Match[str]) -> list[int]:
    statuses = [int(match.group(1))]
    tail = value[match.end():]
    position = consume_http_status_reason(tail, 0)
    while True:
        alternative = re.match(r"\s*(?:or|/|,)\s*(?:HTTP\s*)?([1-5][0-9]{2})\b", tail[position:], flags=re.IGNORECASE)
        if not alternative:
            break
        statuses.append(int(alternative.group(1)))
        position += alternative.end()
        position = consume_http_status_reason(tail, position)
    return unique_http_statuses(statuses)

def explicit_http_statuses(text: str, default: int | None = 200) -> list[int]:
    value = str(text or "")
    patterns = [
        r"\b(?:returns?|return|responds?\s+with|status(?:\s+code)?|http)\s*(?:either\s*)?(?:HTTP\s*)?([1-5][0-9]{2})\b",
        rf"\b([1-5][0-9]{{2}})\s+{HTTP_STATUS_REASON_WORDS}\b",
    ]
    statuses: list[int] = []
    for pattern in patterns:
        for match in re.finditer(pattern, value, flags=re.IGNORECASE):
            statuses.extend(collect_http_status_sequence(value, match))
    unique = unique_http_statuses(statuses)
    if unique:
        return unique
    return [default] if default is not None else []

def explicit_http_status(text: str, default: int = 200) -> int:
    statuses = explicit_http_statuses(text, default)
    return statuses[0] if statuses else default

def explicit_http_statuses_for_target(text: str, method: str | None, path: str | None, default: int | None = 200) -> list[int]:
    value = str(text or "")
    method_value = str(method or "").strip()
    path_value = str(path or "").strip()
    if path_value:
        target_end = r"(?=$|[\s.,;:，。；])"
        target_re = (
            re.compile(rf"\b{re.escape(method_value)}\s+{re.escape(path_value)}{target_end}", re.IGNORECASE)
            if method_value
            else re.compile(rf"{re.escape(path_value)}{target_end}", re.IGNORECASE)
        )
        match = target_re.search(value)
        if match:
            tail = value[match.end():match.end() + 180]
            tail = re.split(r"\b(?:GET|HEAD|POST|PUT|PATCH|DELETE)\s+/", tail, maxsplit=1, flags=re.IGNORECASE)[0]
            return explicit_http_statuses(tail, default)
    return explicit_http_statuses(value, default)

def explicit_http_status_for_target(text: str, method: str | None, path: str | None, default: int = 200) -> int:
    statuses = explicit_http_statuses_for_target(text, method, path, default)
    return statuses[0] if statuses else default

def http_status_expectation_fields_for_target(
    text: str,
    method: str | None,
    path: str | None,
    default: int = 200,
) -> dict[str, Any]:
    statuses = explicit_http_statuses_for_target(text, method, path, default)
    if len(statuses) > 1:
        return {"expectStatusAny": statuses}
    return {"expectStatus": statuses[0] if statuses else default}

def has_word(text: str, *patterns: str) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)

def has_chinese(text: str, *terms: str) -> bool:
    return any(term in text for term in terms)

def has_offline_sync_intent(text: str) -> bool:
    lower = text.lower()
    explicit_offline_signal = has_word(
        lower,
        r"\boffline\s+sync\b",
        r"\boffline\s+queue\b",
        r"\bbrowser\s+goes\s+offline\b",
        r"\bnetwork\s+offline\b",
        r"\breconnect(?:s|ed|ing)?\b",
        r"\bindexeddb\b",
        r"\blocal\s+outbox\b",
        r"\blocal\s+queue\b",
        r"\bservice\s+worker\b",
        r"\bbackground\s+sync\b",
    )
    sync_contract_signal = has_word(
        lower,
        r"\bclient[_ -]?mutation[_ -]?id\b",
        r"\bidempotency[_ -]?key\b",
        r"\bpayload[_ -]?hash\b",
        r"\bencrypted[_ -]?local[_ -]?payload\b",
        r"\bpending[_ -]?sync\b",
        r"\bsync[_ -]?version\b",
        r"\bserver[_ -]?visit[_ -]?id\b",
        r"\bblocked[_ -]?conflict\b",
        r"\bsync[_ -]?forbidden\b",
        r"/field-visits/sync\b",
    )
    conflict_or_retry_signal = has_word(
        lower,
        r"\bversion[_ -]?conflict\b",
        r"\bconflict[_ -]?id\b",
        r"\bresolve-conflict\b",
        r"\bif-match\b",
        r"\bmerge\s+dialog\b",
        r"\bsync[_ -]?attempt[_ -]?id\b",
        r"\bnext[_ -]?retry[_ -]?at\b",
        r"\bbackoff[_ -]?schedule\b",
    )
    return (
        (explicit_offline_signal and (sync_contract_signal or conflict_or_retry_signal))
        or (has_word(lower, r"/field-visits/sync\b") and sync_contract_signal)
        or (has_word(lower, r"\bresolve-conflict\b") and has_word(lower, r"\bconflict[_ -]?id\b", r"\bsync[_ -]?version\b", r"\boutbox\s+status\b"))
        or (has_word(lower, r"\boutbox\s+status\b") and has_word(lower, r"\bsync[_ -]?version\b", r"\bconflict[_ -]?id\b"))
    )

def has_offline_local_storage_intent(text: str) -> bool:
    lower = text.lower()
    return has_offline_sync_intent(text) and has_word(
        lower,
        r"\bindexeddb\b",
        r"\blocal\s+outbox\b",
        r"\blocal\s+queue\b",
        r"\bencrypted[_ -]?local[_ -]?payload\b",
        r"\bpending[_ -]?sync\b",
    )

def has_background_sync_intent(text: str) -> bool:
    lower = text.lower()
    return has_offline_sync_intent(text) and has_word(lower, r"\bbackground\s+sync\b", r"\bsync\s+worker\b")

def has_service_worker_intent(text: str) -> bool:
    lower = text.lower()
    return has_offline_sync_intent(text) and has_word(lower, r"\bservice\s+worker\b")

def has_offline_conflict_resolution_intent(text: str) -> bool:
    lower = text.lower()
    return has_offline_sync_intent(text) and has_word(
        lower,
        r"\bversion[_ -]?conflict\b",
        r"\bconflict[_ -]?id\b",
        r"\bblocked[_ -]?conflict\b",
        r"\bmerge\s+dialog\b",
        r"\bresolve-conflict\b",
        r"\bif-match\b",
        r"\bmerged[_ -]?note[_ -]?hash\b",
    )

def offline_sync_evidence_layers() -> list[str]:
    return [
        "ui",
        "ui_interaction",
        "api_response",
        "request body",
        "offline_sync",
        "network_offline",
        "network_online",
        "local_queue",
        "indexeddb",
        "service_worker",
        "background_sync",
        "client_mutation_id",
        "idempotency_key",
        "payload_hash",
        "encrypted_local_payload",
        "forbidden request absence",
        "sync_batch",
        "server_visit_id",
        "sync_version",
        "queue_drain",
        "duplicate_absence",
        "conflict_response",
        "conflict_id",
        "server_version",
        "client_version",
        "merge_dialog",
        "merge_resolution",
        "if_match",
        "retry_count",
        "backoff_schedule",
        "next_retry_at",
        "authorization_denial",
        "forbidden text absence",
        "audit_log",
        "persistence",
        "runtime",
    ]

def has_analytics_intent(text: str) -> bool:
    lower = text.lower()
    direct_signal = has_word(
        lower,
        r"\banalytics\b",
        r"\btelemetry\b",
        r"\btracking\s+event\b",
        r"\bevent[_ -]?name\b",
        r"\bevent[_ -]?id\b",
        r"\bevent[_ -]?schema\b",
        r"\banalytics[_ -]?event\b",
        r"\bconversion\s+row\b",
        r"\battribution[_ -]?id\b",
        r"\battribution[_ -]?credit\b",
        r"\bexperiment[_ -]?exposure\b",
        r"\bexposure[_ -]?id\b",
        r"\bdedupe[_ -]?key\b",
        r"\buser[_ -]?pseudonym[_ -]?id\b",
    )
    event_contract = has_word(lower, r"\bpost\s+/api/v1/analytics/events\b", r"/api/v1/analytics/events\b") or (
        has_word(lower, r"\bevent[_ -]?name\b", r"\bevent[_ -]?id\b", r"\bschema[_ -]?version\b")
        and has_word(lower, r"\bconsent[_ -]?version\b", r"\battribution[_ -]?id\b", r"\bexperiment[_ -]?id\b", r"\bdedupe[_ -]?key\b")
    )
    return direct_signal or event_contract

def has_analytics_consent_intent(text: str) -> bool:
    lower = text.lower()
    return has_analytics_intent(text) and has_word(lower, r"\banalytics[_ -]?consent\b", r"\bconsent[_ -]?version\b", r"\bconsent\s*=\s*false\b", r"\bconsent[_ -]?state\b")

def has_analytics_attribution_intent(text: str) -> bool:
    lower = text.lower()
    return has_analytics_intent(text) and has_word(lower, r"\battribution[_ -]?id\b", r"\bcampaign[_ -]?id\b", r"\battribution[_ -]?credit\b", r"\battribution[_ -]?mismatch\b", r"\battribution\s+window\b")

def has_analytics_experiment_intent(text: str) -> bool:
    lower = text.lower()
    return has_analytics_intent(text) and has_word(lower, r"\bexperiment[_ -]?id\b", r"\bexperiment[_ -]?exposure\b", r"\bexposure[_ -]?id\b", r"\bvariant\b", r"\btreatment\b", r"\bcontrol\b")

def analytics_evidence_layers() -> list[str]:
    return [
        "ui",
        "ui_interaction",
        "api_response",
        "request body",
        "analytics",
        "analytics_event",
        "event_name",
        "event_id",
        "event_schema",
        "consent_state",
        "consent_version",
        "session_id",
        "user_pseudonym_id",
        "attribution_id",
        "campaign_id",
        "experiment_id",
        "variant",
        "dedupe_key",
        "event_time",
        "event_batch",
        "duplicate_absence",
        "pii_redaction",
        "forbidden text absence",
        "retry_count",
        "backoff_schedule",
        "next_retry_at",
        "queue_status",
        "attribution_credit",
        "attribution_mismatch",
        "experiment_exposure",
        "exposure_id",
        "persistence",
        "runtime",
    ]

def has_explicit_background_worker_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(
        lower,
        r"\bbackground\s+job\b",
        r"\bbackground[_ -]?worker\b",
        r"\bqueue\s+worker\b",
        r"\bworker\s+log\b",
        r"\bjob[_ -]?id\b",
        r"\bdead[_ -]?letter\b",
    )

def filter_analytics_context_layers(text: str, layers: list[str]) -> list[str]:
    if not has_analytics_intent(text) or has_explicit_background_worker_intent(text):
        return layers
    background_layers = {"queued_status", "job_id", "background_worker", "worker_log", "dead_letter", "alert_outbox"}
    return [layer for layer in layers if layer not in background_layers]

def has_explicit_privacy_lifecycle_intent(text: str) -> bool:
    return (
        has_privacy_export_intent(text)
        or has_privacy_erasure_intent(text)
        or has_privacy_session_invalidation_intent(text)
        or has_privacy_search_index_removal_intent(text)
        or has_privacy_cache_purge_intent(text)
        or has_privacy_legal_hold_intent(text)
        or has_api_key_revocation_intent(text)
    )

def has_analytics_privacy_leak_guard_intent(text: str) -> bool:
    lower = text.lower()
    leak_signal = has_word(
        lower,
        r"\bmust\s+not\s+leak\b",
        r"\bnot\s+leak\b",
        r"\bno\s+leak\b",
        r"\bwithout\s+exposing\b",
        r"\bpii\s+redaction\b",
        r"\braw\s+email\b",
    )
    sensitive_signal = has_word(
        lower,
        r"\braw\s+email\b",
        r"\bemail\b",
        r"\bphone\b",
        r"\bshipping[_ -]?address\b",
        r"\bcard[_ -]?last4\b",
        r"\baccess[_ -]?token\b",
        r"\bcookie\b",
        r"\bpii\b",
    )
    return has_analytics_intent(text) and (
        has_pii_redaction_intent(text)
        or has_secret_leak_guard_intent(text)
        or (leak_signal and sensitive_signal)
    )

def filter_analytics_privacy_context_layers(text: str, layers: list[str]) -> list[str]:
    if not has_analytics_privacy_leak_guard_intent(text) or has_explicit_privacy_lifecycle_intent(text):
        return layers
    privacy_lifecycle_layers = {
        "privacy_export",
        "export_artifact",
        "export_manifest",
        "encrypted_export",
        "data_hash",
        "erasure_request",
        "pseudonymization",
        "session_invalidation",
        "api_key_revocation",
        "search_index_removal",
        "cache_invalidation",
        "legal_hold",
        "retention_policy",
        "idempotency_key",
        "data_isolation",
        "tenant_boundary",
        "audit_log",
    }
    return [layer for layer in layers if layer not in privacy_lifecycle_layers]

def filter_contextual_evidence_layers(text: str, layers: list[str]) -> list[str]:
    filtered = filter_analytics_context_layers(text, layers)
    filtered = filter_analytics_privacy_context_layers(text, filtered)
    if has_static_reference_only_intent(text):
        static_content_layers = {
            "ui",
            "ui_interaction",
            "responsive",
            "keyboard_navigation",
            "focus_management",
            "aria_semantics",
            "accessible_name",
            "localization",
            "forbidden request absence",
            "runtime",
        }
        filtered = [layer for layer in filtered if layer in static_content_layers]
    return list(dict.fromkeys(filtered))

def has_click_intent(text: str) -> bool:
    lower = text.lower()
    lower_without_paths = PATH_RE.sub(" ", lower)
    return (
        has_word(
            lower_without_paths,
            r"\bclick(?:s|able|ed|ing)?\b",
            r"\bpress(?:ed|ing)?\b",
            r"\btap(?:ped|ping)?\b",
            r"\bsubmit(?:s|ted|ting)?\b",
            r"\bsav(?:e|es|ed|ing)\b",
            r"\bsend\b",
            r"\benable[sd]?\b",
            r"\bdisabled?\b",
        )
        or has_chinese(text, "点击", "可点", "按钮", "提交", "保存", "发送", "上传", "确认")
    )

def has_responsive_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(
            lower,
            r"\bresponsive\b",
            r"\bmobile\b",
            r"\bdesktop\b",
            r"\bviewport\b",
            r"\boverflow\b",
            r"\bhorizontal\s+overflow\b",
            r"\b\d{3,4}x\d{3,4}\b",
        )
        or has_chinese(text, "移动端", "桌面端", "响应式", "横向滚动", "溢出")
    )

def has_localization_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(
            lower,
            r"\bi18n\b",
            r"\blocali[sz]ation\b",
            r"\blocale\b",
            r"\btranslation(?:[_ -]?catalog)?\b",
            r"\btranslation[_ -]?catalog[_ -]?version\b",
            r"\bmissing[_ -]?keys?\b",
            r"\bfallback[_ -]?count\b",
            r"\blang\s*=",
            r"\bdir\s*=",
            r"\brtl\b",
            r"\bltr\b",
            r"\bplural[_ -]?rules?\b",
            r"\bIntl\.NumberFormat\b",
            r"\blocalized\b",
        )
        or has_chinese(text, "本地化", "国际化", "多语言", "翻译", "语言环境")
    )

def has_locale_switch_intent(text: str) -> bool:
    lower = text.lower()
    return has_localization_intent(text) and has_word(lower, r"\bswitch(?:ing)?\s+locale\b", r"\bselects?\s+locale\b", r"\blocale\s+to\b", r"\bar-EG\b", r"\ben-US\b")

def has_translation_catalog_intent(text: str) -> bool:
    lower = text.lower()
    return has_localization_intent(text) and has_word(lower, r"\btranslation[_ -]?catalog\b", r"\btranslation[_ -]?catalog[_ -]?version\b", r"\bcatalog\s+version\b", r"\bi18n_\d{4}_\d{2}\b")

def has_translation_fallback_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_localization_intent(text) and has_word(lower, r"\bmissing[_ -]?keys?\b", r"\bfallback[_ -]?count\b", r"\braw\s+translation\s+keys?\b", r"\btranslation\s+fallback\b", r"\bcheckout\.total_label\b")

def has_plural_rules_intent(text: str) -> bool:
    lower = text.lower()
    return has_localization_intent(text) and has_word(lower, r"\bplural[_ -]?rules?\b", r"\bsingular\b", r"\bdual\b", r"\bmany\b", r"\bitem[_ -]?count\b")

def has_rtl_layout_intent(text: str) -> bool:
    lower = text.lower()
    return has_localization_intent(text) and has_word(lower, r"\brtl\b", r"\bltr\b", r"\bdir\s*=\s*rtl\b", r"\bdir\s*=\s*ltr\b", r"\bmirrors?\b")

def has_lang_attribute_intent(text: str) -> bool:
    lower = text.lower()
    return has_localization_intent(text) and has_word(lower, r"\blang\s*=", r"\bhtml\s+lang\b")

def has_locale_format_intent(text: str) -> bool:
    lower = text.lower()
    return has_localization_intent(text) and has_word(lower, r"\bIntl\.NumberFormat\b", r"\bcurrency/date\s+formatting\b", r"\bcurrency\s+formatting\b", r"\bdate\s+formatting\b", r"\blocalized\s+arabic\s+numerals\b", r"\bamount_cents\b", r"\bdelivery\s+date\b")

def has_stale_locale_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_localization_intent(text) and has_word(lower, r"\bstale\s+(?:locale|catalog)\b", r"\bcached\s+formatted\s+values?\b", r"\breuse\s+stale\b")

def has_localized_format_only_intent(text: str) -> bool:
    lower = text.lower()
    return has_locale_format_intent(text) and not has_word(
        lower,
        r"\bdecimal\s+arithmetic\b",
        r"\bround(?:ed|ing)?\b",
        r"\bhalf[- ]up\b",
        r"\btax\b",
        r"\bdiscount\b",
        r"\bcurrency\s+conversion\b",
        r"\bfx\s+rate\b",
        r"\brate_id\b",
        r"\bfloating[- ]point\b",
        r"\bfloat(?:ing)?\s+drift\b",
        r"\bno\s+float\s+drift\b",
        r"\bledger\b",
        r"\bpayment\b",
        r"\brefund\b",
        r"\bpayout\b",
        r"\binvoice\b",
        r"\bdate\s+range\b",
        r"\btime\s+range\b",
        r"\btime\s+boundary\b",
        r"\bdate\s+boundary\b",
        r"\binclusive\b",
        r"\bexclusive\b",
        r"\bdst\b",
        r"\bdaylight\s+saving\b",
    )

def has_negative_request_intent(text: str) -> bool:
    lower = text.lower()
    _, target_path = api_target(extract_method_path(text), extract_paths(text), text)
    return bool(
        target_path and path_is_api_for_text(text, target_path)
        and has_word(lower, r"\bmust\s+not\s+call\b", r"\bshould\s+not\s+call\b", r"\bnot\s+call\b", r"\bno\s+request\b", r"\bwithout\s+sending\b")
    )

def has_disabled_state_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bdisabled?\b", r"\benable[sd]?\b")
        or (
            has_word(lower, r"\binvalid\b", r"\bvalidation\b")
            and has_word(lower, r"\bbutton\b", r"\binput\b", r"\bform\b", r"\bemail\b", r"\bsubmit\b", r"\bcontinue\b")
        )
        or has_chinese(text, "禁用", "启用", "无效", "校验", "验证")
    )

def has_query_param_intent(text: str) -> bool:
    lower = text.lower()
    endpoint_paths = method_endpoint_paths(text)
    return (
        any("?" in path for path in extract_paths(text) if path_is_api_for_text(text, path) or path in endpoint_paths)
        or has_word(lower, r"\bquery\s*(?:params?|parameters?|string)\b", r"\bfilters?\b", r"\bsearch(?:es|ing|ed)?\b", r"\bsame\s+item\s+ids?\b", r"\bsame\s+rows?\b")
        or has_chinese(text, "查询参数", "筛选", "过滤", "搜索", "同一批", "相同")
    )

def has_search_relevance_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(
            lower,
            r"\bsearch\s+relevance\b",
            r"\brelevance[_ -]?score\b",
            r"\branking[_ -]?model\b",
            r"\brank(?:s|ed|ing)?\b",
            r"\bresult\s+order\b",
            r"\bresult[_ -]?position\b",
            r"\bquery[_ -]?rewrite\b",
            r"\bcanonical[_ -]?query\b",
            r"\bfacet(?:s|ed)?\b",
            r"\bfacet[_ -]?counts?\b",
            r"\btotal[_ -]?count\b",
            r"\bsponsored[_ -]?disclosure\b",
            r"\bstale\s+(?:result|popular|previous)",
        )
        or (
            has_word(lower, r"\bsearch(?:es|ing|ed)?\b", r"\bquery\b")
            and has_word(lower, r"\brelevance\b", r"\branking\b", r"\bfacet\b", r"\bcanonical\b", r"\btypo\b", r"\bsynonym\b")
        )
    )

def has_search_ranking_intent(text: str) -> bool:
    lower = text.lower()
    return has_search_relevance_intent(text) and has_word(lower, r"\branking[_ -]?model\b", r"\brelevance[_ -]?score\b", r"\bresult\s+order\b", r"\bresult[_ -]?position\b", r"\bposition=\d+\b", r"\brank(?:s|ed|ing)?\b")

def has_search_query_rewrite_intent(text: str) -> bool:
    lower = text.lower()
    return has_search_relevance_intent(text) and has_word(lower, r"\bquery[_ -]?rewrite(?:_id)?\b", r"\bcanonical[_ -]?query\b", r"\btypo\b", r"\bsynonym\b", r"\bwirless\b", r"\bcordless\b")

def has_search_facet_intent(text: str) -> bool:
    lower = text.lower()
    return has_search_relevance_intent(text) and has_word(lower, r"\bfacet(?:s|ed)?\b", r"\bfacet[_ -]?counts?\b", r"\baggregation\b", r"\btotal[_ -]?count\b", r"\bprice[_ -]?bucket\b", r"\bavailability\b")

def has_search_sponsored_intent(text: str) -> bool:
    lower = text.lower()
    return has_search_relevance_intent(text) and has_word(lower, r"\bsponsored\b", r"\bsponsored[_ -]?disclosure\b")

def has_search_stale_result_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_search_relevance_intent(text) and has_word(lower, r"\bstale\s+(?:result|popular|previous)", r"\bpopular\s+products\b", r"\bprevious[_ -]?query\b", r"\bprevious\s+rows?\b")

def has_sort_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bsort(?:s|ed|ing)?\b", r"\border\s+by\b", r"\bascending\b", r"\bdescending\b", r"\basc\b", r"\bdesc\b", r"\bsort=")
        or has_chinese(text, "排序", "升序", "降序")
    )

def has_pagination_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bpaginat(?:e|ion|ed|ing)\b", r"\bpage\s+\d+\b", r"\bpage=\d+\b", r"\bnext\s+page\b", r"\bprevious\s+page\b", r"\bmoving\s+to\s+page\b")
        or has_chinese(text, "分页", "翻页", "第2页", "第二页", "下一页", "上一页")
    )

def has_empty_state_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bempty\s+state\b", r"\bno\s+(?:items?|results?|matches?|records?)\b", r"\b0\s+(?:items?|results?|matches?|records?)\b", r"\bno_match\b")
        or has_chinese(text, "空状态", "无结果", "没有结果", "暂无数据", "无匹配")
    )

def has_error_state_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\berror\s+state\b", r"\bretryable\s+error\b", r"\bretry\b", r"\breturns?\s+5\d\d\b", r"\b5\d\d\b", r"\bfailed\s+responses?\b")
        or has_chinese(text, "错误状态", "可重试", "重试", "服务端错误")
    )

def has_stale_data_guard_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bstale\b", r"\bcached?\b", r"\bprevious\s+(?:search|rows?|results?)\b", r"\bold\s+(?:rows?|results?|data)\b", r"\bsilently\s+display\b", r"\bfallback\b")
        or has_chinese(text, "陈旧", "缓存", "上一轮", "旧数据", "降级文案", "不能只依赖")
    )

def has_optimistic_ui_intent(text: str) -> bool:
    lower = text.lower()
    optimistic_ui_signal = has_word(
        lower,
        r"\boptimistic\s+(?:ui|update|comment|row|item|message)\b",
        r"\boptimistically\s+(?:show|render|display|add|insert)",
        r"\btemporary\s+optimistic\b",
        r"\btemp[_ -]?id\b",
        r"\bpending\s+status\b",
    )
    rollback_signal = has_word(lower, r"\brollback\b", r"\broll\s+back\b") and has_word(
        lower,
        r"\boptimistic\b",
        r"\btemp[_ -]?id\b",
        r"\bpending\s+(?:state|status)\b",
        r"\bfailed\s+state\b",
        r"\bretry\s+action\b",
        r"\bno\s+success\s+toast\b",
        r"\bcache\s+invalidation\b",
    )
    return (
        optimistic_ui_signal
        or rollback_signal
        or (
            has_word(lower, r"\boptimistic\b")
            and has_word(lower, r"\bui\b", r"\bcomment\b", r"\btemp[_ -]?id\b", r"\bpending\b", r"\brollback\b", r"\bretry\b")
        )
        or has_chinese(text, "乐观更新", "乐观 UI", "临时状态")
    )

def has_optimistic_pending_intent(text: str) -> bool:
    lower = text.lower()
    return has_optimistic_ui_intent(text) and (
        has_word(lower, r"\btemp[_ -]?id\b", r"\btemporary\b", r"\bpending\b", r"\bpending\s+status\b")
        or has_chinese(text, "临时", "待处理", "pending")
    )

def has_optimistic_rollback_intent(text: str) -> bool:
    lower = text.lower()
    return has_optimistic_ui_intent(text) and (
        has_word(lower, r"\brollback\b", r"\broll\s+back\b", r"\bfailed\b", r"\bfailed\s+state\b", r"\bretry\s+action\b", r"\bmust\s+not\s+appear\b")
        or has_chinese(text, "回滚", "失败状态", "重试")
    )

def has_cache_invalidation_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bcache\s+invalidation\b", r"\binvalidate\s+(?:the\s+)?cache\b", r"\brefetch\b", r"\brefresh\b.*\bstale\b", r"\bstale\s+cached\b")
        or has_chinese(text, "缓存失效", "刷新缓存", "重新拉取")
    )

def has_cache_consistency_intent(text: str) -> bool:
    lower = text.lower()
    http_cache_signal = has_word(
        lower,
        r"\betag\b",
        r"\bif-none-match\b",
        r"\bcache-control\b",
        r"\bstale-while-revalidate\b",
        r"\bsurrogate-key\b",
        r"\bcache_status\b",
        r"\b304\s+not\s+modified\b",
        r"\bnot\s+modified\b",
        r"\borigin_fetch\b",
        r"\bcdn\b",
        r"\bedge\s+cache\b",
    )
    consistency_signal = has_word(
        lower,
        r"\bcache\s+consistency\b",
        r"\bcache_consistency\b",
        r"\bcache[_ -]?invalidation[_ -]?event\b",
        r"\bcache[_ -]?key\b",
        r"\bpurge\s+surrogate\b",
        r"\bsurrogate[_ -]?key\b",
        r"\bstale\s+response\b",
        r"\bstale=true\b",
        r"\bitem[_ -]?version\b",
        r"\bversion\s+token\b",
    )
    data_signal = has_word(lower, r"\bapi\b", r"\bget\b", r"\bpatch\b", r"\bitem\b", r"\bcatalog\b", r"\bprice[_ -]?cents\b", r"\bversion\b")
    return (http_cache_signal and (consistency_signal or data_signal)) or has_chinese(text, "缓存一致性", "ETag", "边缘缓存")

def has_etag_intent(text: str) -> bool:
    return has_cache_consistency_intent(text) and has_word(text.lower(), r"\betag\b", r"\bcatalog-v\d+\b")

def has_cache_control_intent(text: str) -> bool:
    return has_cache_consistency_intent(text) and has_word(text.lower(), r"\bcache-control\b", r"\bmax-age\b", r"\bstale-while-revalidate\b")

def has_if_none_match_intent(text: str) -> bool:
    return has_cache_consistency_intent(text) and has_word(text.lower(), r"\bif-none-match\b")

def has_not_modified_denial_intent(text: str) -> bool:
    return has_cache_consistency_intent(text) and has_word(text.lower(), r"\b304\s+not\s+modified\b", r"\bnot\s+return\s+304\b", r"\bmust\s+not\s+return\s+304\b")

def has_cache_invalidation_event_intent(text: str) -> bool:
    return has_cache_consistency_intent(text) and has_word(text.lower(), r"\bcache[_ -]?invalidation(?:_event)?\b", r"\binvalidat(?:e|es|ed|ion)\s+(?:the\s+)?cache\b", r"\binv_cache_")

def has_cache_key_intent(text: str) -> bool:
    return has_cache_consistency_intent(text) and has_word(text.lower(), r"\bcache[_ -]?key\b", r"\bcatalog:[a-z0-9_:-]+\b")

def has_surrogate_key_purge_intent(text: str) -> bool:
    return has_cache_consistency_intent(text) and has_word(text.lower(), r"\bsurrogate-key\b", r"\bsurrogate[_ -]?key\b", r"\bpurge(?:s|d)?\b")

def has_stale_revalidation_intent(text: str) -> bool:
    return has_cache_consistency_intent(text) and has_word(text.lower(), r"\bstale-while-revalidate\b", r"\brevalidat(?:e|es|ed|ion)\b")

def has_stale_response_guard_intent(text: str) -> bool:
    return has_cache_consistency_intent(text) and has_word(text.lower(), r"\bstale=true\b", r"\bstale\s+response\b", r"\bstale_age_seconds\b", r"\bwarning=110\b", r"\bstale\s+price\b")

def has_origin_fetch_intent(text: str) -> bool:
    return has_cache_consistency_intent(text) and has_word(text.lower(), r"\borigin_fetch\b", r"\borigin\s+fetch\b", r"\borigin\s+service\b")

def has_cache_status_intent(text: str) -> bool:
    return has_cache_consistency_intent(text) and has_word(text.lower(), r"\bcache_status\b", r"\bmiss\b", r"\bhit\b")

def has_version_token_intent(text: str) -> bool:
    return has_cache_consistency_intent(text) and has_word(text.lower(), r"\bitem[_ -]?version\b", r"\bversion\s+token\b", r"\bv\d+\b")

def has_ui_stale_absence_intent(text: str) -> bool:
    lower = text.lower()
    return has_cache_consistency_intent(text) and has_word(lower, r"\bui\b", r"\b/catalog\b", r"\bmust\s+not\s+show\s+stale\b", r"\bstale\s+price\b", r"\bcached\s+fallback\b")

def has_no_success_toast_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(
            lower,
            r"\bsuccess\s+toast\s+must\s+not\s+appear\b",
            r"\bmust\s+not\s+show\s+(?:a\s+)?success\s+toast\b",
            r"\bno\s+success\s+(?:toast|message)\b",
        )
        or has_chinese(text, "不能显示成功提示", "不得显示成功提示", "不显示成功提示", "不出现成功提示", "不显示成功 toast")
    )

def has_static_reference_only_intent(text: str) -> bool:
    """判断安全或 API 术语是否仅为展示内容，而非产品行为。"""
    lower = text.lower()
    reference_content = (
        has_word(
            lower,
            r"\bglossar(?:y|ies)\b",
            r"\bterminology\b",
            r"\bstatic\s+(?:help|reference|documentation|content)\b",
            r"\bread[- ]only\s+(?:help|reference|documentation|content)\b",
        )
        or has_chinese(text, "术语表", "术语解释", "术语的文字解释", "名词解释", "静态帮助", "静态说明", "只读文档", "参考文档")
    )
    effect_free = (
        has_word(
            lower,
            r"\bno\s+(?:api|network|http)\s+(?:call|request)s?\b",
            r"\bwithout\s+(?:an?\s+)?(?:api|network|http)\s+(?:call|request)\b",
            r"\bno\s+(?:authentication|authorization|login|storage|persistence)\b",
            r"\bstatic[- ]only\b",
        )
        or has_chinese(text, "纯静态", "不调用接口", "不发送请求", "不发网络请求", "无需登录", "无需鉴权", "不写入数据库", "不做持久化")
    )
    return reference_content and effect_free

def has_validation_error_ux_intent(text: str) -> bool:
    lower = text.lower()
    validation_error = (
        has_word(lower, r"\b422\b", r"\bvalidation\s+error\b", r"\bfield[- ]level\s+error\b", r"\binline\s+error\b")
        or has_chinese(text, "校验错误", "字段错误", "表单错误", "参数错误")
    )
    form_context = has_word(lower, r"\bform\b", r"\bfield\b", r"\binput\b", r"\bedit(?:s|ed|ing)?\b", r"\bsav(?:e|es|ed|ing)\b") or has_chinese(text, "表单", "字段", "输入", "编辑", "保存")
    return validation_error and form_context

def has_field_error_intent(text: str) -> bool:
    lower = text.lower()
    return has_validation_error_ux_intent(text) and (
        has_word(lower, r"\bfield[- ]level\s+error\b", r"\binline\s+error\b", r"\berror\s+(?:under|below|beside|next\s+to)\s+(?:the\s+)?field\b")
        or has_chinese(text, "字段错误", "字段下方", "字段旁", "行内错误")
    )

def has_input_value_preserved_intent(text: str) -> bool:
    lower = text.lower()
    return has_validation_error_ux_intent(text) and (
        has_word(lower, r"\b(?:retain|preserve|keep)s?\s+(?:the\s+)?(?:input|value|form\s+values?)\b", r"\binput\s+(?:is\s+)?not\s+(?:cleared|lost)\b")
        or has_chinese(text, "保留输入", "保留原值", "输入值不丢失", "不清空输入", "表单值不丢失")
    )

def has_error_clear_on_edit_intent(text: str) -> bool:
    lower = text.lower()
    clear_on_edit = (
        has_word(lower, r"\berror\s+(?:clears?|disappears?|is\s+removed)\s+(?:when|after|on)\s+(?:edit|change|input)", r"\bedit(?:ing)?\s+the\s+field\s+clears?\s+the\s+error\b")
        or (
            has_chinese(text, "修改", "编辑", "重新输入")
            and (
                has_chinese(text, "错误消失", "清除错误", "错误清除", "提示消失")
                or (has_chinese(text, "错误提示") and has_chinese(text, "消失"))
            )
        )
    )
    return clear_on_edit and (has_validation_error_ux_intent(text) or has_word(lower, r"\berror\b", r"\bfield\b") or has_chinese(text, "错误", "字段", "提示"))

def has_browser_scroll_state_intent(text: str) -> bool:
    lower = text.lower()
    scroll = has_word(lower, r"\bscroll(?:s|ed|ing)?\b", r"\bscroll[_ -]?position\b", r"\bscroll[_ -]?offset\b") or has_chinese(text, "滚动", "滚动位置")
    reload = has_word(lower, r"\brefresh(?:es|ed|ing)?\b", r"\breload(?:s|ed|ing)?\b") or has_chinese(text, "刷新", "重载", "重新加载")
    restore = has_word(lower, r"\brestore(?:s|d)?\b", r"\bretain(?:s|ed)?\b", r"\bpreserve(?:s|d)?\b", r"\bsame\s+(?:scroll\s+)?position\b") or has_chinese(text, "恢复", "保留", "相同位置", "原滚动位置")
    return scroll and reload and restore

def has_frontend_local_state_only_intent(text: str) -> bool:
    lower = text.lower()
    frontend_state = has_word(lower, r"\bfront[- ]?end\s+(?:page\s+)?state\b", r"\bbrowser\s+state\b", r"\bclient[- ]side\s+state\b") or has_chinese(text, "前端页面状态", "浏览器状态", "仅前端状态")
    no_backend = (
        has_word(lower, r"\bno\s+(?:api|network|backend|database)\s+(?:call|request|write)s?\b", r"\bwithout\s+(?:api|network|backend|database)\s+(?:calls?|requests?|writes?)\b")
        or has_chinese(text, "不调用保存接口", "不调用接口", "不写数据库", "无需登录", "不要求登录")
    )
    return frontend_state and no_backend

def has_business_revocation_intent(text: str) -> bool:
    lower = text.lower()
    business_object = has_word(lower, r"\bcoupons?\b", r"\bpromotions?\b", r"\bcampaigns?\b", r"\bvouchers?\b") or has_chinese(text, "优惠券", "优惠活动", "促销", "活动")
    revocation = has_word(lower, r"\brevok(?:e|es|ed|ing|ation)\b", r"\binvalidat(?:e|es|ed|ion)\b", r"\bcancel(?:s|led|ing|lation)?\b") or has_chinese(text, "撤销", "作废", "停用")
    return business_object and revocation

def has_revocation_budget_intent(text: str) -> bool:
    lower = text.lower()
    return has_business_revocation_intent(text) and (has_word(lower, r"\bbudget(?:_remaining)?\b", r"\bbalance\b", r"\bcredit\b", r"\brelease(?:s|d)?\b") or has_chinese(text, "预算", "额度", "余额", "返还", "释放"))

def has_revocation_link_status_intent(text: str) -> bool:
    lower = text.lower()
    return has_business_revocation_intent(text) and (has_word(lower, r"\bpromotion[_ -]?link\b", r"\blink(?:ed)?\s+(?:record|status)\b", r"\bstatus\s*=\s*(?:inactive|revoked|disabled)\b") or has_chinese(text, "关联状态", "关联记录", "关联关系"))

def has_schema_migration_intent(text: str) -> bool:
    lower = text.lower()
    migration_context = has_word(
        lower,
        r"\bschema\s+migration\b",
        r"\bmigration\s+\d{8}",
        r"\bmigrate\b",
        r"\bschema_version\b",
        r"\bexpand[- ]contract\b",
        r"\bbackfill\b",
        r"\bdown\s+migration\b",
    )
    schema_signal = has_word(
        lower,
        r"\bforeign\s+key\b",
        r"\bnot\s+null\b",
        r"\bnullable\b",
        r"\bindex\s+concurrently\b",
        r"\bcreate\s+index\b",
        r"\bconstraint\b",
        r"\brollback\b",
        r"\bbackward\s+compat",
    )
    return (migration_context and schema_signal) or has_chinese(text, "数据库迁移", "表结构迁移", "回填", "外键", "回滚")

def has_migration_plan_intent(text: str) -> bool:
    lower = text.lower()
    return has_schema_migration_intent(text) and has_word(lower, r"\bmigration\s+plan\b", r"\b--plan\b", r"\bexpand[_ -]?step\b", r"\bcontract[_ -]?step\b")

def has_migration_dry_run_intent(text: str) -> bool:
    lower = text.lower()
    return has_schema_migration_intent(text) and has_word(lower, r"\bdry[- ]run\b", r"\bwithout\s+modifying\b")

def has_schema_version_intent(text: str) -> bool:
    lower = text.lower()
    return has_schema_migration_intent(text) and has_word(lower, r"\bschema[_ -]?version\b", r"\bfrom\s+\d+\s+to\s+\d+\b", r"\brestored\s+schema[_ -]?version\b")

def has_migration_schema_diff_intent(text: str) -> bool:
    lower = text.lower()
    return has_schema_migration_intent(text) and has_word(lower, r"\bschema\s+diff\b", r"\badd\s+nullable\b", r"\bcreate\s+index\b", r"\bforeign\s+key\b", r"\bnot\s+null\b")

def has_migration_backfill_intent(text: str) -> bool:
    lower = text.lower()
    return has_schema_migration_intent(text) and has_word(lower, r"\bbackfill\b", r"\bestimated_rows\b", r"\baffected\s+row\s+count\b")

def has_migration_batch_checkpoint_intent(text: str) -> bool:
    lower = text.lower()
    return has_schema_migration_intent(text) and has_word(lower, r"\bbatches?\b", r"\bbatch[_ -]?size\b", r"\bbatch\s+checkpoints?\b")

def has_migration_concurrent_index_intent(text: str) -> bool:
    lower = text.lower()
    return has_schema_migration_intent(text) and has_word(lower, r"\bindex\s+concurrently\b", r"\bconcurrent\s+index\b", r"\bidx_[a-z0-9_]+\b")

def has_migration_foreign_key_intent(text: str) -> bool:
    lower = text.lower()
    return has_schema_migration_intent(text) and has_word(lower, r"\bforeign\s+key\b", r"\bfk_[a-z0-9_]+\b", r"\bvalidate\s+foreign\s+key\b")

def has_migration_not_null_intent(text: str) -> bool:
    lower = text.lower()
    return has_schema_migration_intent(text) and has_word(lower, r"\bnot\s+null\b", r"\bzero[- ]null\b", r"\bzero\s+null\b", r"\bnullable\b")

def has_migration_rollback_intent(text: str) -> bool:
    lower = text.lower()
    return has_schema_migration_intent(text) and has_word(lower, r"\brollback\b", r"\bdown\s+migration\b", r"\b--rollback\b", r"\brollback_available\b")

def has_backward_compatibility_intent(text: str) -> bool:
    lower = text.lower()
    return has_schema_migration_intent(text) and has_word(lower, r"\bbackward\s+compat", r"\bold\s+client\b", r"\bnew\s+client\b", r"\b/api/v1\b", r"\b/api/v2\b")

def has_migration_metadata_leak_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_schema_migration_intent(text) and has_word(lower, r"\bmust\s+not\s+expose\b", r"\bno\s+response\s+may\s+expose\b", r"\binternal\s+migration\s+metadata\b")

def has_list_interaction_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(
            lower,
            r"\bsearch(?:es|ing|ed)?\b",
            r"\bfilters?\b",
            r"\bsort(?:s|ed|ing)?\b",
            r"\bpaginat(?:e|ion|ed|ing)\b",
            r"\bpage\s+\d+\b",
            r"\bmoving\s+to\s+page\b",
        )
        or has_chinese(text, "搜索", "筛选", "过滤", "排序", "分页", "翻页")
    )

def has_upload_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(
            lower,
            r"\bmultipart/form-data\b",
            r"\bselects?\s+(?:a\s+|an\s+)?(?:safe\s+test\s+)?(?:csv\s+)?(?:file|fixture)\b",
            r"\bselects?\s+.*\.(?:csv|json|txt|xlsx|exe|pdf)\b",
            r"\buploads?\s+(?:safe\s+)?(?:test\s+)?fixture\b",
            r"\buploads?\s+.*\.(?:csv|json|txt|xlsx|exe|pdf)\b",
            r"\bclicks?\s+(?:the\s+)?upload\b",
            r"\bupload\s+(?:button|file|csv|fixture)\b",
            r"\bpost\s+/[^\s`]*upload\b",
            r"\bpost\s+/[^\s`]*(?:attachments?|files?)\b",
        )
        or has_chinese(text, "上传", "导入文件", "文件上传", "测试文件")
    )

def has_file_validation_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bfile\s+type\s+validation\b", r"\bfile\s+size\s+validation\b", r"\bfile\s+larger\s+than\b", r"\blarger\s+than\s+\d+\s*(?:mb|gb)\b", r"\bsize\s+limit\b", r"\binvalid\s+[^.]{0,20}\.[a-z0-9]{2,5}\b", r"\b\.(?:exe|bat|sh|cmd|app)\b", r"\ballowed\s+file\b", r"\bfile\s+extension\b")
        or has_chinese(text, "文件类型", "无效文件", "非法文件", "扩展名")
    )

def has_progress_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bprogress\b", r"\bprogress\s+bar\b", r"\bpercent(?:age)?\b") or has_chinese(text, "进度", "进度条")

def has_request_marker_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bqa_marker\b", r"\bqa[-_ ]?marker\b", r"\bmarker\b") or has_chinese(text, "标记")

def has_download_intent(text: str) -> bool:
    lower = text.lower()
    if has_privacy_compliance_intent(text) and not has_word(lower, r"\bdownload[_ -]?file\b", r"\bcontent-disposition\b", r"\bdownload\s+(?:button|file|csv|artifact)\b", r"\bbrowser\s+download\b"):
        return False
    return (
        has_word(
            lower,
            r"\bdownload(?:s|ed|ing)?\b",
            r"\bexport\s+(?:csv|file|report|download)\b",
            r"\b(?:downloaded|exported)\s+(?:csv\s+)?file\b",
        )
        or has_chinese(text, "下载", "导出")
    )

def has_artifact_generation_intent(text: str) -> bool:
    lower = text.lower()
    direct_signal = has_word(
        lower,
        r"\bartifact[_ -]?generation\b",
        r"\bartifact[_ -]?job\b",
        r"\bartifact_manifest\b",
        r"\bmanifest[_ -]?id\b",
        r"\bmanifest[_ -]?hash\b",
        r"\bartifact[_ -]?ready\b",
        r"\breport[_ -]?jobs?\b",
        r"\breport-artifacts?\b",
        r"\bdiagnostic[_ -]?artifact\b",
        r"\bstorage[_ -]?key[_ -]?redacted\b",
        r"\bpartial[_ -]?failed\b",
    )
    combined_signal = (
        has_word(lower, r"\bartifact(?:s)?\b", r"\bmanifest\b")
        and has_word(lower, r"\breport\b", r"\bexport\b", r"\bjob[_ -]?id\b", r"\bworker\b", r"\bdownload\b")
    )
    if (has_offline_sync_intent(text) or has_analytics_intent(text)) and not direct_signal:
        return False
    return direct_signal or combined_signal or has_chinese(text, "报告工件", "导出工件", "制品清单")

def has_artifact_progress_intent(text: str) -> bool:
    lower = text.lower()
    return has_artifact_generation_intent(text) and has_word(
        lower,
        r"\bprogress\s+events?\b",
        r"\bartifact[_ -]?ready\b",
        r"\b/events\b",
        r"\bsse\b",
        r"\b0,\s*45,\s*(?:and\s*)?100\b",
    )

def has_artifact_manifest_intent(text: str) -> bool:
    lower = text.lower()
    return has_artifact_generation_intent(text) and has_word(
        lower,
        r"\bartifact_manifest\b",
        r"\bmanifest[_ -]?id\b",
        r"\bmanifest[_ -]?hash\b",
        r"\bcontent[_ -]?hash\b",
        r"\bfile[_ -]?hash\b",
        r"\bfile[_ -]?count\b",
        r"\brow[_ -]?count\b",
        r"\bschema[_ -]?version\b",
        r"\bstorage[_ -]?key[_ -]?redacted\b",
    )

def has_artifact_resume_intent(text: str) -> bool:
    lower = text.lower()
    return has_artifact_generation_intent(text) and has_word(
        lower,
        r"\bresume[_ -]?token\b",
        r"\bcheckpoint[_ -]?page\b",
        r"\bcheckpoint\b",
        r"\b/resume\b",
        r"\bresumes?\b",
    )

def has_artifact_cancellation_intent(text: str) -> bool:
    lower = text.lower()
    return has_artifact_generation_intent(text) and has_word(
        lower,
        r"\b/cancel\b",
        r"\bcancel(?:s|led|ling)?\b",
        r"\btemp[_ -]?object[_ -]?count\s*=\s*0\b",
        r"\bno\s+artifact_manifest\b",
    )

def has_artifact_partial_failure_intent(text: str) -> bool:
    lower = text.lower()
    return has_artifact_generation_intent(text) and has_word(
        lower,
        r"\bpartial[_ -]?failed\b",
        r"\bfailed[_ -]?sections?\b",
        r"\bdiagnostic[_ -]?artifact\b",
        r"\bchart[_ -]?\d+\b",
        r"\bpartial\s+failure\b",
    )

def has_artifact_download_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_artifact_generation_intent(text) and has_word(
        lower,
        r"\bartifact[_ -]?download[_ -]?forbidden\b",
        r"\bdownload\s+guard\b",
        r"\b403\b",
        r"\bviewer\b",
        r"\bsigned[_ -]?url\b",
        r"\bstorage[_ -]?key\b",
        r"\bcontent-disposition\b",
    )

def has_artifact_retention_intent(text: str) -> bool:
    lower = text.lower()
    return has_artifact_generation_intent(text) and has_word(lower, r"\bretention[_ -]?expires[_ -]?at\b", r"\bretention\b")

def artifact_generation_evidence_layers() -> list[str]:
    return [
        "request body",
        "api_response",
        "stream",
        "terminal_status",
        "artifact_generation",
        "artifact_job",
        "job_id",
        "progress_event",
        "artifact_ready",
        "artifact_manifest",
        "manifest_id",
        "manifest_hash",
        "artifact_id",
        "content_hash",
        "file_hash",
        "schema_version",
        "row_count",
        "retention_policy",
        "storage_key_redaction",
        "resume_token",
        "checkpoint",
        "duplicate_absence",
        "cancellation_event",
        "temp_object_absence",
        "no_persistence_side_effect",
        "partial_failure",
        "failed_sections",
        "diagnostic_artifact",
        "download_file",
        "response_headers",
        "content_disposition",
        "authorization_denial",
        "forbidden text absence",
        "audit_log",
        "persistence",
        "runtime",
    ]

def has_response_header_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bcontent-type\b", r"\bcontent-disposition\b", r"\bx-content-type-options\b", r"\bnosniff\b", r"\bset-cookie\b", r"\bfilename\b", r"\bretry-after\b", r"\blocation\s+header\b", r"\bresponse\s+headers?\b", r"\betag\b", r"\bif-none-match\b", r"\bcache-control\b", r"\bsurrogate-key\b", r"\bwarning\b", r"\bage\b") or has_chinese(text, "响应头", "文件名")

def has_csv_content_intent(text: str) -> bool:
    lower = re.sub(r"\bresponse\s+headers?\b", " ", text.lower())
    return (
        has_word(
            lower,
            r"\b(?:downloaded|exported)\s+csv\b",
            r"\bcsv\s+(?:file|content|headers?|rows?|schema|must\s+contain)\b",
            r"\bcsv\s+headers?\b",
            r"\bdata\s+rows?\b",
            r"\brow\s+count\b",
            r"\bat\s+least\s+one\s+data\s+row\b",
            r"\btotals?\s+match(?:ing)?\b",
        )
        or has_chinese(text, "表头", "数据行", "行数")
    )

def has_pii_redaction_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bpii\b", r"\bphone\b", r"\bssn\b", r"\bredact(?:ed|ion)?\b")
        or (has_word(lower, r"\bemail\b") and has_word(lower, r"\bmust\s+not\s+include\b", r"\bforbidden\b", r"\bpii\b"))
        or has_chinese(text, "个人信息", "手机号", "脱敏")
    )

def has_request_header_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bheaders?\b", r"\bstripe-signature\b", r"\bx-hub-signature-256\b", r"\bx-github-delivery\b", r"\bx-github-event\b", r"\bx-hub-signature-timestamp\b", r"\bx-csrf-token\b", r"\bidempotency[_ -]?key\b", r"\b[a-z0-9-]+-signature\b")

def has_signature_validation_intent(text: str) -> bool:
    lower = text.lower()
    signature_signal = has_word(lower, r"\bsignature\b", r"\bstripe-signature\b", r"\bx-hub-signature-256\b", r"\binvalid\s+signatures?\b")
    return signature_signal or has_chinese(text, "签名", "验签")

def has_webhook_security_intent(text: str) -> bool:
    lower = text.lower()
    webhook_signal = has_word(lower, r"\bwebhook\b", r"\bwebhooks\b", r"\bx-github-delivery\b", r"\bx-hub-signature")
    security_signal = has_word(
        lower,
        r"\bhmac\b",
        r"\bhmac-sha256\b",
        r"\braw[_ -]?body\b",
        r"\braw\s+body\s+bytes\b",
        r"\bsignature[_ -]?mismatch\b",
        r"\btimestamp[_ -]?out[_ -]?of[_ -]?tolerance\b",
        r"\btimestamp\s+tolerance\b",
        r"\breplay\s+window\b",
        r"\bdelivery[_ -]?id\b",
        r"\bsignature[_ -]?version\b",
        r"\bx-hub-signature-256\b",
    )
    strong_security_signal = has_word(
        lower,
        r"\bhmac-sha256\b",
        r"\braw[_ -]?body\b",
        r"\braw\s+body\s+bytes\b",
        r"\bsignature[_ -]?mismatch\b",
        r"\btimestamp[_ -]?out[_ -]?of[_ -]?tolerance\b",
        r"\breplay\s+window\b",
        r"\bdelivery[_ -]?id\b",
    )
    return (webhook_signal and (security_signal or has_signature_validation_intent(text))) or strong_security_signal

def has_hmac_signature_intent(text: str) -> bool:
    lower = text.lower()
    return has_webhook_security_intent(text) and has_word(lower, r"\bhmac\b", r"\bhmac-sha256\b", r"\bsha256=hmac", r"\bx-hub-signature-256\b")

def has_raw_body_integrity_intent(text: str) -> bool:
    lower = text.lower()
    return has_webhook_security_intent(text) and has_word(lower, r"\braw[_ -]?body\b", r"\braw\s+body\s+bytes\b", r"\bbefore\s+json\s+parsing\b", r"\bre-serializ(?:e|ing)\b", r"\bre-ordering\s+json\b")

def has_timestamp_tolerance_intent(text: str) -> bool:
    lower = text.lower()
    return has_webhook_security_intent(text) and has_word(lower, r"\btimestamp[_ -]?out[_ -]?of[_ -]?tolerance\b", r"\btimestamp\s+tolerance\b", r"\bx-hub-signature-timestamp\b", r"\boutside\s+[+-]?\d+\s+seconds\b", r"\b300\s+seconds\b")

def has_replay_window_intent(text: str) -> bool:
    lower = text.lower()
    return has_webhook_security_intent(text) and has_word(lower, r"\breplay\s+window\b", r"\breplaying\b", r"\breplay(?:ed|ing)?\b", r"\bdelivery[_ -]?id\b", r"\bx-github-delivery\b", r"\bduplicate_ignored\b")

def has_signature_version_intent(text: str) -> bool:
    lower = text.lower()
    return has_webhook_security_intent(text) and has_word(lower, r"\bsignature[_ -]?version\b", r"\bv\d+\b")

def has_webhook_secret_leak_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_webhook_security_intent(text) and has_word(lower, r"\bmust\s+not\s+echo\b", r"\bmust\s+not\s+leak\b", r"\bno\s+leak\b", r"\bnot\s+echo\b") and has_word(lower, r"\bhmac\s+secret\b", r"\bcomputed\s+digest\b", r"\bfull\s+raw\s+body\b", r"\braw\s+hmac\b")

def has_csrf_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bcsrf\b", r"\bxsrf\b", r"\bx-csrf-token\b", r"\bcsrf[_ -]?token\b", r"\bcross[- ]origin\s+csrf\b", r"\bcross[- ]site\s+request\s+forgery\b")
        or has_chinese(text, "CSRF", "跨站请求伪造")
    )

def has_csrf_denial_intent(text: str) -> bool:
    lower = text.lower()
    denial_signal = has_word(lower, r"\bmissing\b", r"\bstale\b", r"\bcross[- ]origin\b", r"\binvalid\b", r"\bcsrf_failed\b", r"\b403\b")
    return has_csrf_intent(text) and denial_signal

def has_session_security_intent(text: str) -> bool:
    lower = text.lower()
    session_context = has_word(lower, r"\bsession[_ -]?id\b", r"\bsession\s+cookie\b", r"\bold\s+session\b", r"\bold\s+cookie\b", r"\bstolen\s+cookie\b", r"\bactive\s+session\b", r"\blogout\b", r"\bset-cookie\b", r"\brefresh\s+token\b")
    return (
        session_context
        and has_word(lower, r"\bsession[_ -]?id\b", r"\bsession\s+cookie\b", r"\bold\s+session\b", r"\bold\s+cookie\b", r"\bstolen\s+cookie\b", r"\bactive\s+session\b", r"\blogout\b", r"\binvalidat(?:e|ed|ion)\b", r"\brotat(?:e|es|ed|ion)\s+session", r"\bset-cookie\b", r"\brefresh\s+token\b")
        or has_chinese(text, "会话", "旧会话", "退出登录", "登出", "会话轮换")
    )

def has_session_rotation_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\brotat(?:e|es|ed|ion)\b", r"\bfrom\s+sess_[A-Za-z0-9_-]+\s+to\s+sess_[A-Za-z0-9_-]+\b", r"\bold\s+session\b") and has_word(lower, r"\bsession[_ -]?id\b", r"\bsession\s+cookie\b")

def has_logout_invalidation_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\blogout\b", r"\blogged\s+out\b", r"\binvalidat(?:e|ed|ion)\b") and has_word(lower, r"\bsession[_ -]?id\b", r"\bsession\s+cookie\b", r"\bold\s+cookie\b")

def has_cookie_security_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bset-cookie\b", r"\bcookie\s+flags?\b", r"\bhttponly\b", r"\bsecure\b", r"\bsamesite\b", r"\bsamesite\s*=\s*(?:lax|strict|none)\b", r"\bsession\s+cookie\b")
        or has_chinese(text, "Cookie", "安全 Cookie", "会话 Cookie")
    )

def has_secret_leak_guard_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bmust\s+not\s+leak\b", r"\bno\s+leak\b", r"\bnot\s+leak\b", r"\bwithout\s+leaking\b")
        and has_word(lower, r"\bsession[_ -]?id\b", r"\bcsrf[_ -]?token\b", r"\bset-cookie\b", r"\bcookie\b", r"\btoken\b", r"\breset[_ -]?token\b", r"\btoken[_ -]?hash\b", r"\bapi[_ -]?key\b", r"\bkey[_ -]?hash\b", r"\bsecret[_ -]?once\b", r"\bauthorization\b", r"\bbearer\b", r"\bnew[_ -]?password\b", r"\bpassword\b", r"\brefresh\s+token\b", r"\baccess[_ -]?token\b", r"\bid[_ -]?token\b", r"\bcode[_ -]?verifier\b", r"\bnonce\b", r"\boauth\s+state\b", r"\btotp_secret\b", r"\braw\s+recovery\s+code\b", r"\brecovery\s+code\b", r"\bcredential_private_key\b", r"\braw\s+authenticator\s+secret\b", r"\bclientdatajson\b", r"\bprivate_key\b", r"\braw\s+samlresponse\b", r"\bsamlresponse\s+xml\b", r"\brelaystate\b", r"\bstorage[_ -]?key\b", r"\bsigned\s+(?:url|preview)\b")
    ) or has_chinese(text, "不能泄露", "不得泄露")

def has_api_key_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(
            lower,
            r"\bapi[-_ ]?keys?\b",
            r"\bpersonal\s+access\s+tokens?\b",
            r"\bpat\b",
            r"\baccess\s+keys?\b",
            r"\bkey[_ -]?hash\b",
            r"\bkey[_ -]?prefix\b",
            r"\blast[_ -]?used[_ -]?at\b",
            r"\brevoked[_ -]?at\b",
            r"\binsufficient[_ -]?scope\b",
        )
        or (has_word(lower, r"\bbearer\b", r"\bauthorization\b") and has_word(lower, r"\bscopes?\b", r"\brevok(?:e|ed|ing)\b", r"\bkey[_ -]?hash\b"))
        or has_chinese(text, "API Key", "访问令牌", "个人访问令牌", "密钥")
    )

def has_api_key_secret_once_intent(text: str) -> bool:
    lower = text.lower()
    return has_api_key_intent(text) and has_word(lower, r"\bsecret[_ -]?once\b", r"\bshow(?:n)?\s+once\b", r"\bdisplay(?:ed)?\s+once\b", r"\bonly\s+in\s+the\s+create\s+response\b", r"\bcopy\s+panel\b")

def has_api_key_hash_intent(text: str) -> bool:
    lower = text.lower()
    return has_api_key_intent(text) and has_word(lower, r"\bkey[_ -]?hash\b", r"\bstores?\s+only\b", r"\bhash\s+only\b", r"\bhash[- ]only\b")

def has_api_key_prefix_intent(text: str) -> bool:
    lower = text.lower()
    return has_api_key_intent(text) and has_word(lower, r"\bkey[_ -]?prefix\b", r"\bprefix\b")

def has_api_key_scope_intent(text: str) -> bool:
    lower = text.lower()
    return has_api_key_intent(text) and has_word(lower, r"\bscopes?\b", r"\bread:[a-z0-9_-]+\b", r"\bwrite:[a-z0-9_-]+\b", r"\binsufficient[_ -]?scope\b")

def has_api_key_expiry_intent(text: str) -> bool:
    lower = text.lower()
    return has_api_key_intent(text) and has_word(lower, r"\bexpires[_ -]?at\b", r"\bexpired\b", r"\bexpiry\b", r"\bexpiration\b")

def has_api_key_last_used_intent(text: str) -> bool:
    lower = text.lower()
    return has_api_key_intent(text) and has_word(lower, r"\blast[_ -]?used[_ -]?at\b", r"\bupdates?\s+last[_ -]?used\b")

def has_api_key_revocation_intent(text: str) -> bool:
    lower = text.lower()
    return has_api_key_intent(text) and has_word(lower, r"\brevok(?:e|ed|es|ing)\b", r"\brevoked[_ -]?at\b", r"\bdelete\s+/api.*/api[-_ ]?keys?\b")

def has_api_key_denial_intent(text: str) -> bool:
    lower = text.lower()
    return has_api_key_intent(text) and has_word(lower, r"\b401\b", r"\b403\b", r"\binsufficient[_ -]?scope\b", r"\bunauthorized\b", r"\bexpired\b", r"\bunknown\b", r"\btampered\b", r"\brevoked\b")

def has_api_key_secret_leak_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_api_key_intent(text) and (
        has_secret_leak_guard_intent(text)
        or (
            has_word(lower, r"\bmust\s+not\s+(?:return|expose|leak)\b", r"\bnot\s+return\b", r"\bnot\s+expose\b")
            and has_word(lower, r"\bapi[_ -]?key\b", r"\bkey[_ -]?hash\b", r"\bauthorization\b", r"\bbearer\b", r"\bsecret[_ -]?once\b", r"\bsecret\s+suffix\b")
        )
    )

def has_file_security_intent(text: str) -> bool:
    lower = text.lower()
    if has_artifact_generation_intent(text) and not has_word(lower, r"\bmalware\b", r"\bvirus\b", r"\bscan_status\b", r"\bscan\s+status\b", r"\bscan_engine\b", r"\bscan_version\b", r"\bquarantin(?:e|ed)\b", r"\beicar\b"):
        return False
    return (
        has_word(lower, r"\bmalware\b", r"\bvirus\b", r"\banti[- ]?virus\b", r"\bscan_status\b", r"\bscan\s+status\b", r"\bscan_engine\b", r"\bscan_version\b", r"\bquarantin(?:e|ed)\b", r"\beicar\b", r"\bstorage[_ -]?key\b")
        or has_chinese(text, "病毒扫描", "恶意文件", "隔离文件")
    )

def has_file_preview_intent(text: str) -> bool:
    lower = text.lower()
    billing_preview = has_word(
        lower,
        r"\binvoice\s+preview\b",
        r"\bpreview[_ -]?id\b",
        r"\bpreview[-/]?change\b",
        r"\bsubscription\b",
        r"\bsubscription[_ -]?version\b",
        r"\bpayment[_ -]?intent\b",
        r"\binvoice\s+rows?\b",
        r"\breceipt\s+email\b",
        r"\bproration\b",
    )
    file_context = has_word(
        lower,
        r"\bfile\b",
        r"\bpdf\b",
        r"\battachment\b",
        r"\bdownload\b",
        r"\bsigned\s+(?:preview\s+)?(?:url|token)\b",
        r"\bcontent-disposition\b",
        r"\bapplication/pdf\b",
        r"\bnosniff\b",
    )
    if billing_preview and not file_context:
        return False
    return (
        has_word(lower, r"\bpreview\b", r"\bpreview\s+token\b", r"\bsigned\s+preview\b", r"\bsigned\s+url\b", r"\brender(?:s|ed|ing)?\s+(?:only\s+)?(?:the\s+)?clean\b", r"\bcontent-disposition\s+inline\b", r"\bapplication/pdf\b", r"\bnosniff\b")
        and has_word(lower, r"\bfile\b", r"\bpdf\b", r"\battachment\b", r"\bdownload\b", r"\bpreview\b")
    ) or has_chinese(text, "文件预览", "附件预览", "签名链接")

def has_scan_status_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bscan_status\b", r"\bscan\s+status\b", r"\bpending\b", r"\bclean\b", r"\bquarantin(?:e|ed)\b") and has_word(lower, r"\bscan\b", r"\battachment\b", r"\bfile\b", r"\bmalware\b")

def has_quarantine_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bquarantin(?:e|ed)\b", r"\bfile\.quarantined\b", r"\beicar\b") or has_chinese(text, "隔离")

def has_signed_url_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bsigned\s+(?:preview\s+)?(?:url|token)\b", r"\bpreview\s+token\b", r"\bsigned_url\b") or has_chinese(text, "签名链接", "签名 URL")

def has_storage_key_redaction_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bstorage[_ -]?key\b") and has_word(lower, r"\bredact(?:ed|ion)?\b", r"\bmust\s+not\s+leak\b", r"\bnot\s+leak\b")

def has_nosniff_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bnosniff\b", r"\bx-content-type-options\b")

def has_rate_limit_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(
            lower,
            r"\brate[-_ ]?limit(?:ed|ing)?\b",
            r"\bthrottl(?:e|ed|ing)\b",
            r"\btoo\s+many\s+attempts\b",
            r"\btoo\s+many\s+requests\b",
            r"\b429\b",
            r"\bretry-after\b",
            r"\blockout\b",
            r"\bcooldown\b",
            r"\bfailed_attempt_count\b",
            r"\battempts?\s+\d",
            r"\bbrute[- ]?force\b",
        )
        or has_chinese(text, "限流", "频控", "防刷", "锁定", "冷却")
    )

def has_lockout_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_rate_limit_intent(text)
        and has_word(lower, r"\blockout\b", r"\blockout_expires_at\b", r"\bcooldown\b", r"\blocked\b", r"\bunlock(?:ed)?\b", r"\bwindow\s+expires\b")
    ) or has_chinese(text, "锁定", "冷却")

def has_retry_after_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bretry-after\b", r"\bretry_after\b") or (has_rate_limit_intent(text) and has_word(lower, r"\b429\b"))

def has_account_enumeration_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\baccount\s+enumeration\b", r"\buser\s+enumeration\b", r"\bgeneric\s+error\b", r"\bgeneric\s+copy\b", r"\bgeneric\s+success\b", r"\bgeneric\s+success\s+copy\b", r"\bsame\s+generic\s+error\b", r"\bsame\s+generic\s+success\b", r"\bunknown\s+email\b", r"\bunknown\s+emails\b", r"\btiming\s+class\b") or has_chinese(text, "账号枚举", "通用错误")

def has_no_session_created_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bno\s+session\b", r"\bcreate\s+no\s+session(?:_id)?\b", r"\bdo\s+not\s+create\s+session\b", r"\bmust\s+not\s+create\s+(?:a\s+)?session\b", r"\bmust\s+not\s+create\s+(?:a\s+)?refresh\s+token\b", r"\bno\s+set-cookie\b", r"\bdo\s+not\s+create\s+session_id\b") or has_chinese(text, "不创建会话", "不得创建会话")

def has_one_time_token_intent(text: str) -> bool:
    lower = text.lower()
    explicit_flow = has_word(
        lower,
        r"\bpassword\s+reset\b",
        r"\bforgot(?:ten)?\s+password\b",
        r"\breset[-_ ]password\b",
        r"\breset[_ -]?token\b",
        r"\bmagic\s+link\b",
        r"\bemail\s+verification\b",
        r"\bverify\s+email\b",
        r"\bverification[_ -]?token\b",
        r"\binvite[_ -]?token\b",
        r"\binvitation\s+link\b",
    )
    token_storage = has_word(lower, r"\btoken[_ -]?hash\b", r"\breset_token_hash\b", r"\bverification_token_hash\b", r"\bone[- ]time\s+token\b")
    token_lifecycle = has_word(lower, r"\bused_at\b", r"\bexpires_at\b", r"\bpurpose\b", r"\bconsume(?:d|s)?\b", r"\breplay(?:ed|ing)?\b")
    link_context = has_word(lower, r"\bemail\b", r"\blink\b", r"\baccount\b", r"\bpassword_reset\b", r"\bverification\b", r"\binvite\b", r"\breset\b")
    return explicit_flow or (token_storage and token_lifecycle and link_context) or has_chinese(text, "重置密码", "找回密码", "一次性链接", "魔法链接", "邮箱验证", "邀请链接")

def has_one_time_token_hash_intent(text: str) -> bool:
    lower = text.lower()
    return has_one_time_token_intent(text) and has_word(lower, r"\btoken[_ -]?hash\b", r"\breset_token_hash\b", r"\bverification_token_hash\b", r"\bstores?\s+only\b", r"\bhash\s+only\b")

def has_one_time_token_purpose_intent(text: str) -> bool:
    lower = text.lower()
    return has_one_time_token_intent(text) and has_word(lower, r"\bpurpose\b", r"\bpassword_reset\b", r"\bemail_verification\b", r"\binvite\b", r"\bwrong[-_ ]purpose\b")

def has_one_time_token_expiry_intent(text: str) -> bool:
    lower = text.lower()
    return has_one_time_token_intent(text) and has_word(lower, r"\bexpires_at\b", r"\bexpired\b", r"\bexpiry\b", r"\bexpiration\b", r"\btime\s+window\b")

def has_one_time_token_consumption_intent(text: str) -> bool:
    lower = text.lower()
    return has_one_time_token_intent(text) and has_word(lower, r"\bused_at\b", r"\bconsume(?:d|s|ing)?\b", r"\bone[- ]time\b", r"\bexactly\s+once\b")

def has_one_time_token_replay_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_one_time_token_intent(text) and has_word(lower, r"\breplay(?:ed|ing)?\b", r"\breused?\s+token\b", r"\bexpired\b", r"\btampered\b", r"\bwrong[-_ ]purpose\b", r"\bwrong[-_ ]tenant\b", r"\bunknown\s+token\b")

def has_one_time_token_email_link_intent(text: str) -> bool:
    lower = text.lower()
    return has_one_time_token_intent(text) and has_word(lower, r"\breset\s+email\b", r"\bverification\s+email\b", r"\bemail\s+contains\b", r"\blink\s+to\b", r"\bnotification_outbox\b", r"\bmessage[_ -]?id\b", r"\bemail\s+link\b")

def has_one_time_token_password_update_intent(text: str) -> bool:
    lower = text.lower()
    return has_one_time_token_intent(text) and has_word(lower, r"\bpassword_hash\b", r"\bnew[_ -]?password\b", r"\bupdate\s+password\b", r"\bpassword\s+updated\b")

def has_one_time_token_session_invalidation_intent(text: str) -> bool:
    lower = text.lower()
    return has_one_time_token_intent(text) and has_word(lower, r"\binvalidat(?:e|ed|ion)\b", r"\ball\s+existing\s+sessions\b", r"\bactive\s+sessions\b") and has_word(lower, r"\bsessions?\b", r"\bsession[_ -]?id\b")

def has_one_time_token_secret_leak_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_one_time_token_intent(text) and has_word(lower, r"\bmust\s+not\s+leak\b", r"\bno\s+leak\b", r"\bnot\s+leak\b", r"\bwithout\s+leaking\b") and has_word(lower, r"\braw\s+reset[_ -]?token\b", r"\breset[_ -]?token\b", r"\breset_token_hash\b", r"\btoken[_ -]?hash\b", r"\bnew[_ -]?password\b", r"\bsession[_ -]?id\b", r"\brefresh[_ -]?token\b", r"\bset-cookie\b")

def has_mfa_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(
            lower,
            r"\bmfa\b",
            r"\b2fa\b",
            r"\btwo[- ]factor\b",
            r"\bmulti[- ]factor\b",
            r"\btotp\b",
            r"\btotp_secret\b",
            r"\bone[- ]time\s+(?:passcode|password|code)\b",
            r"\botp\b",
            r"\bauthenticator\s+(?:app|code)\b",
            r"\bmfa_challenge_id\b",
            r"\bmfa_required\b",
            r"\brecovery\s+code\b",
            r"\brecovery_code\b",
        )
        or has_chinese(text, "多因素", "双因素", "一次性验证码", "动态口令")
    )

def has_totp_intent(text: str) -> bool:
    lower = text.lower()
    return has_mfa_intent(text) and has_word(lower, r"\btotp\b", r"\btotp_code\b", r"\botp\b", r"\b30\s+second\s+time\s+window\b", r"\btime\s+window\b")

def has_mfa_pending_intent(text: str) -> bool:
    lower = text.lower()
    return has_mfa_intent(text) and has_word(lower, r"\bmfa_pending\b", r"\bpending\s+state\b", r"\bpending\s+session\b", r"\bpending\b")

def has_mfa_recovery_code_intent(text: str) -> bool:
    lower = text.lower()
    return has_mfa_intent(text) and has_word(lower, r"\brecovery\s+code\b", r"\bbackup\s+code\b", r"\brecovery_code\b", r"\brecovery_code_hash\b", r"\bused_at\b")

def has_mfa_replay_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_mfa_intent(text) and has_word(lower, r"\breplay(?:ed|ing)?\b", r"\breused?\s+challenge\b", r"\bwrong\b", r"\bexpired\b", r"\breused?\s+(?:totp|code|recovery\s+code)\b")

def has_mfa_required_denial_intent(text: str) -> bool:
    lower = text.lower()
    return has_mfa_intent(text) and has_word(lower, r"\bmfa_required\b", r"\bdirect\s+post\b", r"\bdirect\s+api\b", r"\bwhile\s+.*mfa_pending\b", r"\b403\b")

def has_mfa_secret_leak_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_mfa_intent(text) and has_word(lower, r"\bmust\s+not\s+leak\b", r"\bno\s+leak\b", r"\bnot\s+leak\b", r"\bwithout\s+leaking\b") and has_word(lower, r"\btotp_secret\b", r"\braw\s+recovery\s+code\b", r"\brecovery\s+code\b", r"\bsession_id\b", r"\brefresh_token\b", r"\bset-cookie\b")

def has_webauthn_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(
            lower,
            r"\bwebauthn\b",
            r"\bpasskey\b",
            r"\bpasskeys\b",
            r"\bpublickeycredential\b",
            r"\bnavigator\.credentials\b",
            r"\bcredential[_ -]?id\b",
            r"\bclientdatajson\b",
            r"\bauthenticatordata\b",
            r"\battestationobject\b",
            r"\brp[_ -]?id\b",
            r"\brpidhash\b",
            r"\bsigncount\b",
            r"\buserverification\b",
            r"\ballowcredentials\b",
        )
        or has_chinese(text, "通行密钥", "Passkey", "无密码登录")
    )

def has_webauthn_challenge_intent(text: str) -> bool:
    lower = text.lower()
    return has_webauthn_intent(text) and has_word(lower, r"\bchallenge\b", r"\boptions\b", r"\bexpires_at\b", r"\bpending\b")

def has_webauthn_origin_rp_intent(text: str) -> bool:
    lower = text.lower()
    return has_webauthn_intent(text) and has_word(lower, r"\borigin\b", r"\brp[_ -]?id\b", r"\brpidhash\b", r"\brelying\s+party\b")

def has_webauthn_assertion_intent(text: str) -> bool:
    lower = text.lower()
    return has_webauthn_intent(text) and has_word(lower, r"\bassertion\b", r"\bcredential[_ -]?id\b", r"\bclientdatajson\b", r"\bauthenticatordata\b", r"\bsignature\b", r"\bpublic\s+key\b")

def has_webauthn_user_verification_intent(text: str) -> bool:
    lower = text.lower()
    return has_webauthn_intent(text) and has_word(lower, r"\buserverification\b", r"\buser\s+verification\b", r"\buserverified\b", r"\buser\s+verified\b")

def has_webauthn_sign_count_intent(text: str) -> bool:
    lower = text.lower()
    return has_webauthn_intent(text) and has_word(lower, r"\bsigncount\b", r"\bsign\s+count\b", r"\blast_sign_count\b", r"\bcloned\b")

def has_webauthn_attestation_intent(text: str) -> bool:
    lower = text.lower()
    return has_webauthn_intent(text) and has_word(lower, r"\battestationobject\b", r"\battestation\b", r"\bcredential_public_key\b", r"\bcredential\s+public\s+key\b", r"\bbackup_eligible\b", r"\bbackup_state\b")

def has_webauthn_replay_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_webauthn_intent(text) and has_word(lower, r"\breplay(?:ed|ing)?\b", r"\bsame\s+challenge\b", r"\bwrong\s+rpidhash\b", r"\bwrong\s+origin\b", r"\bunknown\s+credential", r"\bcloned\b", r"\bsigncount\s*<=\s*\d+")

def has_webauthn_secret_leak_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_webauthn_intent(text) and has_word(lower, r"\bmust\s+not\s+leak\b", r"\bno\s+leak\b", r"\bnot\s+leak\b", r"\bwithout\s+leaking\b") and has_word(lower, r"\bcredential_private_key\b", r"\bprivate\s+key\b", r"\braw\s+authenticator\s+secret\b", r"\bclientdatajson\b", r"\bsession_id\b", r"\brefresh_token\b", r"\bset-cookie\b")

def has_saml_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(
            lower,
            r"\bsaml\b",
            r"\bsamlrequest\b",
            r"\bsamlresponse\b",
            r"\bauthnrequest\b",
            r"\bassertionconsumer(?:service)?\b",
            r"\bassertion\s+consumer\s+service\b",
            r"\brelaystate\b",
            r"\bnameid\b",
            r"\baudiencerestriction\b",
            r"\binresponseto\b",
            r"\bnotbefore\b",
            r"\bnotonorafter\b",
            r"\bsaml_account\b",
        )
        or has_chinese(text, "SAML", "断言消费", "单点登录断言")
    )

def has_saml_request_intent(text: str) -> bool:
    lower = text.lower()
    return has_saml_intent(text) and has_word(lower, r"\bauthnrequest\b", r"\bsamlrequest\b", r"\bsp\s+entityid\b", r"\bentityid\b", r"\bassertionconsumerserviceurl\b", r"\bacs\b")

def has_saml_response_intent(text: str) -> bool:
    lower = text.lower()
    return has_saml_intent(text) and has_word(lower, r"\bsamlresponse\b", r"\bsaml\s+response\b", r"\bsaml_assertion\b", r"\bassertion\b", r"\bacs\b")

def has_saml_signature_intent(text: str) -> bool:
    lower = text.lower()
    return has_saml_intent(text) and has_word(lower, r"\bxml\s+signature\b", r"\bsignature\b", r"\bsigned\b", r"\bunsigned\b", r"\bx509\b", r"\bcertificate\b", r"\bcert[_ -]")

def has_saml_audience_recipient_intent(text: str) -> bool:
    lower = text.lower()
    return has_saml_intent(text) and has_word(lower, r"\baudiencerestriction\b", r"\baudience\s+restriction\b", r"\bdestination\b", r"\brecipient\b", r"\bsp\s+entityid\b")

def has_saml_in_response_to_intent(text: str) -> bool:
    lower = text.lower()
    return has_saml_intent(text) and has_word(lower, r"\binresponseto\b", r"\bin\s+response\s+to\b")

def has_saml_time_window_intent(text: str) -> bool:
    lower = text.lower()
    return has_saml_intent(text) and has_word(lower, r"\bnotbefore\b", r"\bnotonorafter\b", r"\bexpired\b", r"\btime\s+window\b")

def has_saml_attribute_mapping_intent(text: str) -> bool:
    lower = text.lower()
    return has_saml_intent(text) and has_word(lower, r"\bnameid\b", r"\bgroup\s+attribute\b", r"\battribute\b", r"\bmapped\s+role\b", r"\brole\s*=\s*", r"\bsaml_account\b")

def has_saml_replay_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_saml_intent(text) and has_word(lower, r"\breplay(?:ed|ing)?\b", r"\bsame\s+samlresponse\b", r"\bwrong\s+relaystate\b", r"\bunsigned\b", r"\bwrong\s+audience", r"\bwrong\s+recipient", r"\bunknown\s+certificate\b")

def has_saml_secret_leak_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_saml_intent(text) and has_word(lower, r"\bmust\s+not\s+leak\b", r"\bno\s+leak\b", r"\bnot\s+leak\b", r"\bwithout\s+leaking\b") and has_word(lower, r"\bprivate_key\b", r"\bprivate\s+key\b", r"\braw\s+samlresponse\b", r"\bsamlresponse\s+xml\b", r"\brelaystate\b", r"\bsession_id\b", r"\bset-cookie\b")

def has_oauth_intent(text: str) -> bool:
    lower = text.lower()
    saml_context = has_saml_intent(text)
    explicit = has_word(
        lower,
        r"\boauth\b",
        r"\boidc\b",
        r"\bopenid\b",
        r"\bidentity\s+provider\b",
        r"\bidp\b",
        r"\bauth/oauth\b",
        r"\boauth_account\b",
    )
    pkce_context = has_word(lower, r"\bpkce\b", r"\bcode_challenge\b", r"\bcode_verifier\b", r"\bcode_challenge_method\b")
    callback_context = has_word(lower, r"\bauthorization\s+code\b", r"\bcode\s+exchange\b", r"\boauth\s+callback\b", r"\bauth/callback\b")
    oauth_protocol = has_word(lower, r"\boauth\b", r"\boidc\b", r"\bopenid\b", r"\bauth/oauth\b", r"\boauth_account\b")
    if saml_context and not (oauth_protocol or pkce_context or callback_context):
        return False
    return explicit or pkce_context or callback_context or has_chinese(text, "OAuth", "OIDC", "单点登录", "身份提供商")

def has_pkce_intent(text: str) -> bool:
    lower = text.lower()
    return has_oauth_intent(text) and has_word(lower, r"\bpkce\b", r"\bcode_challenge\b", r"\bcode_verifier\b", r"\bcode_challenge_method\b", r"\bs256\b")

def has_oauth_state_intent(text: str) -> bool:
    lower = text.lower()
    return has_oauth_intent(text) and has_word(lower, r"\bstate\b", r"\bstate_[A-Za-z0-9_-]+\b", r"\bstate\s+replay\b")

def has_oauth_nonce_intent(text: str) -> bool:
    lower = text.lower()
    return has_oauth_intent(text) and has_word(lower, r"\bnonce\b", r"\bnonce_[A-Za-z0-9_-]+\b")

def has_oauth_code_exchange_intent(text: str) -> bool:
    lower = text.lower()
    return has_oauth_intent(text) and has_word(lower, r"\bauthorization\s+code\b", r"\bcode\s+exchange\b", r"\bexchange\s+the\s+authorization\s+code\b", r"\bexchange\s+code\b", r"\bcode=[A-Za-z0-9_-]+\b")

def has_oauth_replay_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_oauth_intent(text) and has_word(lower, r"\breplay(?:ing)?\b", r"\bsame\s+code\b", r"\bsame\s+code/state\b", r"\bwrong\s+state\b", r"\bwrong\s+nonce\b", r"\bwrong\s+code_verifier\b")

def has_redirect_security_intent(text: str) -> bool:
    lower = text.lower()
    redirect_signal = has_word(lower, r"\bredirect_uri\b", r"\breturn_to\b", r"\bopen\s+redirect\b", r"\bexternal\s+redirect\b", r"\bredirect\s+allowlist\b", r"\ballowlisted\s+redirect\b")
    external_target = has_word(lower, r"https?://evil\.", r"\bevil\.example\b", r"\bexternal\s+domain\b")
    return (redirect_signal and (has_oauth_intent(text) or external_target or has_word(lower, r"\ballowlist(?:ed)?\b", r"\breject(?:ed)?\b"))) or has_chinese(text, "开放重定向", "跳转白名单")

def has_open_redirect_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_redirect_security_intent(text) and has_word(lower, r"\bopen\s+redirect\b", r"\breturn_to\b", r"https?://evil\.", r"\bsafe\s+fallback\b", r"\bexternal\s+redirect\b")

def has_oauth_secret_leak_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_oauth_intent(text) and has_word(lower, r"\bmust\s+not\s+leak\b", r"\bno\s+leak\b", r"\bnot\s+leak\b", r"\bwithout\s+leaking\b") and has_word(lower, r"\baccess_token\b", r"\brefresh_token\b", r"\bid_token\b", r"\bcode_verifier\b", r"\bnonce\b", r"\bstate\b", r"\bset-cookie\b")

def has_bulk_action_intent(text: str) -> bool:
    lower = text.lower()
    if has_localization_intent(text) and not has_word(lower, r"\bbulk[- ](?:delete|archive|update|action)\b", r"\bdelete\s+selected\b", r"\bselected_count\b"):
        return False
    return (
        has_word(
            lower,
            r"\bbulk[- ](?:delete|archive|update|action)\b",
            r"\bdelete\s+selected\b",
            r"\bselected\s+(?:count|rows?|ids?|items?)\b",
            r"\bselects?\s+[A-Za-z0-9_-]+(?:\s+and\s+[A-Za-z0-9_-]+)?\b",
            r"\bselected_count\b",
        )
        or has_chinese(text, "批量", "选中")
    )

def has_selected_scope_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bonly\s+selected\b", r"\bselected\s+(?:ids?|rows?|users?|items?)\b", r"\bunselected\b", r"\bno\s+extra\s+ids?\b", r"\bremain\s+active\b", r"\bselected_count\b")
        or (has_word(lower, r"\bids?\b", r"\bselected\b") and has_word(lower, r"\bmust\s+not\s+(?:change|mutate|update)\b", r"\bunchanged\b"))
        or has_chinese(text, "只影响选中", "未选中", "不能多改")
    )

def has_destructive_confirmation_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bdestructive\s+confirmation\b", r"\bconfirmation\s+modal\b", r"\bconfirm(?:ing|ation)?\b", r"\brequires?\s+typing\s+delete\b", r"\btype\s+delete\b", r"\bcancel\b", r"\bescape\b")
        and has_word(lower, r"\bdelete\b", r"\bdestroy\b", r"\barchive\b", r"\bdestructive\b")
    ) or has_chinese(text, "二次确认", "确认删除", "危险操作")

def has_soft_delete_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bsoft[- ]deleted?\b", r"\bsoft\s+delete\b", r"\bdeleted_at\b", r"\bdeleted_by\b", r"\bnot\s+hard[- ]deleted?\b", r"\bno\s+hard\s+delete\b", r"\barchive(?:d)?\b")
        or has_chinese(text, "软删除", "逻辑删除", "不能硬删除")
    )

def has_undo_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bundo\b", r"\brestore(?:s|d|ation)?\b", r"\bundo\s+toast\b", r"\bwithin\s+\d+\s+seconds?\b", r"\bbulk[- ]delete[_/-]undo\b")
        and has_word(lower, r"\bdelete\b", r"\bdeleted\b", r"\bactive\b", r"\boperation[_ -]?id\b", r"\btoast\b")
    ) or has_chinese(text, "撤销", "恢复删除")

def has_operation_id_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\boperation[_ -]?id\b", r"\bop[_ -]?id\b", r"\bbulkdel_[A-Za-z0-9_-]+\b") or has_chinese(text, "操作ID", "操作 id")

def has_idempotency_intent(text: str) -> bool:
    lower = text.lower()
    explicit_idempotency = has_word(lower, r"\bidempot(?:ent|ency)\b", r"\bidempotency[_ -]?key\b", r"\bduplicate_ignored\b")
    replay_id = has_word(lower, r"\breplay(?:ed|ing)?\b") and has_word(lower, r"\bevent[_ -]?id\b", r"\bidempotency[_ -]?key\b", r"\bdelivery[_ -]?id\b")
    no_duplicate_write = has_word(lower, r"\bno\s+duplicate\b", r"\bexactly\s+one\b") and has_word(lower, r"\brow\b", r"\brecord\b", r"\bpayment\b", r"\breservation\b", r"\bside\s+effect\b")
    return explicit_idempotency or replay_id or no_duplicate_write or has_chinese(text, "幂等")

def has_concurrency_intent(text: str) -> bool:
    lower = re.sub(r"\b(?:concurrent\s+index|index\s+concurrently)\b", " ", text.lower())
    return (
        has_word(lower, r"\bconcurr(?:ent|ency)\b", r"\bparallel\b", r"\bsimultaneous(?:ly)?\b", r"\brace\s+condition\b", r"\btwo\s+concurrent\b", r"\bdouble[- ]click\b")
        or has_chinese(text, "并发", "竞态", "同时", "双击")
    )

def has_realtime_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\breal[- ]?time\b", r"\blive\s+(?:event|update|collaboration)\b", r"\bcollaboration\b", r"\bcollaborative\b", r"\bbroadcast(?:s|ed|ing)?\b", r"\bsubscribe\b", r"\bsubscription\b")
        or (has_word(lower, r"\bwebsocket\b", r"\bws\b", r"\bsse\b") and has_word(lower, r"\bwithin\s+\d+\s+seconds?\b", r"\blive\b", r"\bbroadcast\b"))
        or has_chinese(text, "实时", "协作", "广播", "订阅")
    )

def has_multi_client_intent(text: str) -> bool:
    lower = text.lower()
    named_clients = len(set(re.findall(r"\b(?:client[_ -]?id\s+)?([A-Za-z][A-Za-z0-9_-]+)_ws\b", text, re.IGNORECASE))) >= 2
    named_people = len(set(re.findall(r"\b(?:editor|viewer|user|admin|member|owner)\s+([A-Z][A-Za-z0-9_-]+)\b", text))) >= 2
    return (
        named_clients
        or named_people
        or has_word(lower, r"\bmulti[- ]?client\b", r"\btwo\s+clients\b", r"\bboth\s+clients\b", r"\beditor\b.*\bviewer\b", r"\bviewer\b.*\beditor\b", r"\balice\b.*\bbob\b", r"\bbob\b.*\balice\b")
        or has_chinese(text, "多客户端", "两个客户端", "同一工作区", "协作者")
    )

def has_ordering_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bsequence\b", r"\bordering\b", r"\bordered\b", r"\bin\s+order\b", r"\bbefore\b.{0,40}\bafter\b", r"\bbefore\s+\d+\b", r"\b\d+\s+before\s+\d+\b")
        or bool(re.search(r"\bsequence\s+\d+\s+before\s+\d+\b", lower))
        or has_chinese(text, "顺序", "有序", "序号", "先后")
    )

def has_reconnect_replay_intent(text: str) -> bool:
    lower = text.lower()
    if has_offline_sync_intent(text) and not has_word(lower, r"\bwebsocket\b", r"\bsse\b", r"\bcursor\b", r"\blast[_ -]?event[_ -]?id\b", r"\bsequence\b", r"\breplay\s+exactly\b"):
        return False
    return (
        has_word(lower, r"\breconnect(?:s|ed|ing)?\b", r"\bcursor\b", r"\bresume\s+live\b", r"\bresume\s+events\b", r"\breplay\s+exactly\b")
        or (has_word(lower, r"\breplay(?:s|ed|ing)?\b") and has_word(lower, r"\bwebsocket\b", r"\bcursor\b", r"\bsequence\b"))
        or has_chinese(text, "重连", "游标", "补发", "恢复订阅")
    )

def has_conflict_response_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\b409\b", r"\bconflict\b", r"\bversion_conflict\b", r"\bout_of_stock\b", r"\blosing\s+request\b")
        or has_chinese(text, "冲突", "库存不足", "失败请求")
    )

def has_locking_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\block(?:ing)?\b", r"\boptimistic\s+lock\b", r"\brow\s+lock\b", r"\bversion_conflict\b")
        or has_chinese(text, "锁", "乐观锁", "版本冲突")
    )

def has_atomicity_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\batomic(?:ity)?\b", r"\btransaction(?:al)?\b", r"\bexactly\s+one\s+success\b", r"\bone\s+success\b", r"\bmust\s+allow\s+exactly\s+one\b", r"\bmust\s+not\s+decrement\b", r"\bdecrement\s+again\b")
        or has_chinese(text, "原子", "事务", "只能成功一次", "不能再次扣减")
    )

def has_no_negative_inventory_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bno[- ]?oversell\b", r"\boversell\b", r"\bbelow\s+0\b", r"\bbelow\s+zero\b", r"\bnegative\s+inventory\b", r"\bavailable_qty\s+never\s+goes\s+below\b")
        or has_chinese(text, "超卖", "负库存", "小于0")
    )

def has_audit_log_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\baudit\s+logs?\b", r"\baudit\b", r"\bevent\s+trail\b") or has_chinese(text, "审计", "审计日志")

def has_audit_integrity_intent(text: str) -> bool:
    lower = text.lower()
    audit_context = has_audit_log_intent(text) or has_word(lower, r"\baudit[_ -]?events?\b", r"\bevent[_ -]?trail\b")
    strong_integrity_signal = has_word(
        lower,
        r"\bappend[- ]?only\b",
        r"\bimmutable\b",
        r"\btamper(?:ed|ing)?\b",
        r"\baudit_integrity_violation\b",
        r"\bhash[_ -]?chain\b",
        r"\bprevious[_ -]?hash\b",
        r"\bevent[_ -]?hash\b",
        r"\bcanonical\s+json\b",
    )
    integrity_signal = has_word(
        lower,
        r"\bappend[- ]?only\b",
        r"\bimmutable\b",
        r"\btamper(?:ed|ing)?\b",
        r"\baudit_integrity_violation\b",
        r"\bhash[_ -]?chain\b",
        r"\bprevious[_ -]?hash\b",
        r"\bevent[_ -]?hash\b",
        r"\bcanonical\s+json\b",
        r"\blegal[_ -]?hold\b",
        r"\bretention[_ -]?expires[_ -]?at\b",
    )
    if has_artifact_generation_intent(text) and not strong_integrity_signal:
        return False
    return audit_context and (integrity_signal or has_chinese(text, "不可篡改", "保留策略", "法务保留", "哈希链"))

def has_audit_hash_chain_intent(text: str) -> bool:
    lower = text.lower()
    return has_audit_integrity_intent(text) and has_word(lower, r"\bhash[_ -]?chain\b", r"\bprevious[_ -]?hash\b", r"\bevent[_ -]?hash\b", r"\bhash[_ -]?algorithm\b", r"\bsha256\b")

def has_audit_sequence_intent(text: str) -> bool:
    lower = text.lower()
    return has_audit_integrity_intent(text) and has_word(lower, r"\bsequence\b", r"\bordered\b", r"\bmonotonic(?:ally)?\b", r"\bmonotonically\s+increasing\b")

def has_audit_append_only_intent(text: str) -> bool:
    lower = text.lower()
    return has_audit_integrity_intent(text) and has_word(lower, r"\bappend[- ]?only\b", r"\bimmutable\b", r"\bappend\s+exactly\s+one\b", r"\bmust\s+not\s+mutate\b")

def has_audit_canonical_json_intent(text: str) -> bool:
    lower = text.lower()
    return has_audit_integrity_intent(text) and has_word(lower, r"\bcanonical\s+json\b", r"\brecomputed\b", r"\bevent_hash\s+recomputed\b")

def has_audit_tamper_denial_intent(text: str) -> bool:
    lower = text.lower()
    return has_audit_integrity_intent(text) and has_word(lower, r"\btamper(?:ed|ing)?\b", r"\baudit_integrity_violation\b", r"\bpatch\b", r"\bdelete\b", r"\b403\b", r"\b405\b")

def has_audit_retention_intent(text: str) -> bool:
    lower = text.lower()
    return has_audit_integrity_intent(text) and has_word(lower, r"\bretention[_ -]?expires[_ -]?at\b", r"\bretention\b", r"\bretained\b")

def has_audit_legal_hold_intent(text: str) -> bool:
    lower = text.lower()
    return has_audit_integrity_intent(text) and has_word(lower, r"\blegal[_ -]?hold\b", r"\blegal\s+hold\b")

def has_audit_pseudonym_redaction_intent(text: str) -> bool:
    lower = text.lower()
    return has_audit_integrity_intent(text) and has_word(lower, r"\bpseudonym\b", r"\bactor[_ -]?ref\b", r"\bprivacy[- ]?deleted\b", r"\bpii\b", r"\bredact(?:ed|ion)?\b")

def has_audit_integrity_leak_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_audit_integrity_intent(text) and (
        has_secret_leak_guard_intent(text)
        or (
            has_word(lower, r"\bmust\s+not\s+leak\b", r"\bno\s+leak\b", r"\braw\s+ip\b", r"\bemail\b", r"\bphone\b")
            and has_word(lower, r"\bapi\s+responses?\b", r"\blogs?\b", r"\breport\s+artifacts?\b", r"\bpii\b")
        )
    )

def has_privacy_compliance_intent(text: str) -> bool:
    lower = text.lower()
    privacy_signal = has_word(
        lower,
        r"\bprivacy\b",
        r"\bdsar\b",
        r"\bgdpr\b",
        r"\berasure\b",
        r"\bdata\s+subject\b",
        r"\bsubject[_ -]?user[_ -]?id\b",
        r"\blegal[_ -]?hold(?:_blocked)?\b",
        r"\bprivacy\.erasure",
        r"\bexport[_ -]?encryption[_ -]?key\b",
        r"\braw\s+deleted\s+profile\s+json\b",
    )
    compliance_signal = has_word(
        lower,
        r"\bdata\s+export\b",
        r"\bexport[_ -]?job[_ -]?id\b",
        r"\bexport[_ -]?manifest\b",
        r"\bencrypted\s+export\b",
        r"\berasure[_ -]?job\b",
        r"\bgdpr[_ -]?erasure\b",
        r"\bpseudonym(?:ize|ized|ization)?\b",
        r"\bactor[_ -]?ref\b",
        r"\bsearch[_ -]?index\b",
        r"\bcache\s+purge\b",
        r"\bpurge\s+cache\b",
        r"\bdelete\s+active\s+sessions\b",
        r"\brevoke\s+api\s+keys?\b",
        r"\braw\s+deleted\s+profile\s+json\b",
        r"\bpii\b",
    )
    return (privacy_signal and compliance_signal) or has_word(lower, r"\bprivacy_compliance\b", r"\bdsar\b", r"\bgdpr[_ -]?erasure\b", r"\bexport[_ -]?encryption[_ -]?key\b", r"\braw\s+deleted\s+profile\s+json\b")

def has_privacy_export_intent(text: str) -> bool:
    lower = text.lower()
    return has_privacy_compliance_intent(text) and has_word(lower, r"\bdsar\b", r"\bdata\s+export\b", r"\bexports?\b", r"\bexport[_ -]?job[_ -]?id\b", r"\bexport[_ -]?manifest\b", r"\bencrypted\s+export\b", r"\bdata[_ -]?hash\b", r"\.zip\b")

def has_privacy_erasure_intent(text: str) -> bool:
    lower = text.lower()
    return has_privacy_compliance_intent(text) and has_word(lower, r"\berasure\b", r"\bgdpr[_ -]?erasure\b", r"\berase\b", r"\berasure[_ -]?job\b", r"\bpseudonym(?:ize|ized|ization)?\b", r"\bdelete\s+active\s+sessions\b", r"\brevoke\s+api\s+keys?\b")

def has_privacy_pseudonymization_intent(text: str) -> bool:
    lower = text.lower()
    return has_privacy_compliance_intent(text) and has_word(lower, r"\bpseudonym(?:ize|ized|ization)?\b", r"\bactor[_ -]?ref\b")

def has_privacy_session_invalidation_intent(text: str) -> bool:
    lower = text.lower()
    return has_privacy_compliance_intent(text) and has_word(lower, r"\bdelete\s+active\s+sessions\b", r"\bactive\s+sessions?\b", r"\bsession\s+deletion\b", r"\binvalidat(?:e|ed|ion).{0,40}sessions?\b")

def has_privacy_search_index_removal_intent(text: str) -> bool:
    lower = text.lower()
    return has_privacy_compliance_intent(text) and has_word(lower, r"\bsearch[_ -]?index\b", r"\bsearch\s+purge\b", r"\bremove\s+search\b")

def has_privacy_cache_purge_intent(text: str) -> bool:
    lower = text.lower()
    return has_privacy_compliance_intent(text) and has_word(lower, r"\bcache\s+purge\b", r"\bpurge\s+cache\b", r"\bpurge\s+cache\s+entries\b", r"\bcache\s+entries\b")

def has_privacy_legal_hold_intent(text: str) -> bool:
    lower = text.lower()
    return has_privacy_compliance_intent(text) and has_word(lower, r"\blegal[_ -]?hold\b", r"\blegal[_ -]?hold[_ -]?blocked\b")

def has_privacy_secret_leak_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_privacy_compliance_intent(text) and (
        has_secret_leak_guard_intent(text)
        or (
            has_word(lower, r"\bmust\s+not\s+leak\b", r"\bwithout\s+exposing\b", r"\bno\s+leak\b", r"\bnot\s+leak\b")
            and has_word(lower, r"\braw\s+email\b", r"\bphone\b", r"\baddress\b", r"\baccess[_ -]?token\b", r"\bexport[_ -]?encryption[_ -]?key\b", r"\braw\s+deleted\s+profile\s+json\b", r"\bpii\b")
        )
    )

def has_graphql_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(
        lower,
        r"\bgraphql\b",
        r"\b/api/graphql\b",
        r"\boperationname\b",
        r"\bpersistedqueryhash\b",
        r"\bpersisted\s+query\b",
        r"\b__schema\b",
        r"\b__type\b",
        r"\bdataloader\b",
        r"\bresolver[_ -]?trace\b",
        r"\bfield_denied\b",
        r"\bassignorder\b",
        r"\bapollo\s+cache\b",
        r"\borderupdates\b",
    )

def has_graphql_persisted_query_intent(text: str) -> bool:
    lower = text.lower()
    return has_graphql_intent(text) and has_word(lower, r"\bpersistedqueryhash\b", r"\bpersisted\s+query\b", r"\bsha256hash\b")

def has_graphql_operation_variables_intent(text: str) -> bool:
    lower = text.lower()
    return has_graphql_intent(text) and has_word(lower, r"\boperationname\b", r"\borderdashboardquery\b", r"\bvariables\b", r"\btenantid\b")

def has_graphql_field_authorization_intent(text: str) -> bool:
    lower = text.lower()
    return has_graphql_intent(text) and has_word(lower, r"\bfield[- ]?level\s+authorization\b", r"\bfield_denied\b", r"\bforbidden\s+fields?\b", r"\bcustomer\.ssn\b", r"\binternalnotes\b")

def has_graphql_partial_error_intent(text: str) -> bool:
    lower = text.lower()
    return has_graphql_intent(text) and has_word(lower, r"\bgraphql\s+errors?\b", r"\bpartial\s+data\b", r"\bhttp\s+200\s+with\s+errors\b", r"\berrors\s+with\s+code\b")

def has_graphql_batching_intent(text: str) -> bool:
    lower = text.lower()
    return has_graphql_intent(text) and has_word(lower, r"\bdataloader\b", r"\bn\+1\b", r"\bresolver[_ -]?trace\b", r"\bresolver[_ -]?count\b")

def has_graphql_mutation_intent(text: str) -> bool:
    lower = text.lower()
    return has_graphql_intent(text) and has_word(lower, r"\bmutation\b", r"\bassignorder\b")

def has_graphql_cache_version_intent(text: str) -> bool:
    lower = text.lower()
    return has_graphql_intent(text) and has_word(lower, r"\bapollo\s+cache\b", r"\breturned\s+version\b", r"\border[_ -]?version\b", r"\bversion[_ -]?token\b")

def has_graphql_subscription_intent(text: str) -> bool:
    lower = text.lower()
    return has_graphql_intent(text) and has_word(lower, r"\bgraphql\s+subscription\b", r"\bsubscription\b", r"\borderupdates\b")

def has_graphql_introspection_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_graphql_intent(text) and has_word(lower, r"\bintrospection\b", r"\b__schema\b", r"\b__type\b")

def has_graphql_secret_leak_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_graphql_intent(text) and (
        has_secret_leak_guard_intent(text)
        or (
            has_word(lower, r"\bmust\s+not\s+leak\b", r"\bnot\s+leak\b", r"\bno\s+leak\b")
            and has_word(lower, r"\bssn\b", r"\bphone\b", r"\braw\s+email\b", r"\binternalnotes\b", r"\bpii\b")
        )
    )

def graphql_evidence_layers(text: str) -> list[str]:
    return list(dict.fromkeys([
        "ui_interaction",
        *requirement_specific_evidence_layers(text),
    ]))

def graphql_probe_focus(text: str) -> str:
    focus = ["operationName", "variables", "response data/errors shape"]
    if has_graphql_persisted_query_intent(text):
        focus.append("persisted query hash")
    if has_graphql_field_authorization_intent(text):
        focus.append("field-level FIELD_DENIED partial-data behavior")
    elif has_graphql_partial_error_intent(text):
        focus.append("GraphQL errors with allowed partial data")
    if has_graphql_batching_intent(text):
        focus.append("resolver_trace/DataLoader N+1 guard")
    if has_graphql_mutation_intent(text):
        focus.append("mutation side effects and idempotency when required")
    if has_graphql_cache_version_intent(text):
        focus.append("cache/version reconciliation")
    if has_graphql_subscription_intent(text):
        focus.append("subscription delivery, ordering, and reconnect replay")
    if has_tenant_isolation_intent(text) or has_cross_tenant_denial_intent(text):
        focus.append("tenant boundary and cross-tenant denial")
    if has_graphql_introspection_guard_intent(text):
        focus.append("introspection denial")
    if has_graphql_secret_leak_guard_intent(text) or has_forbidden_text_absence_intent(text):
        focus.append("forbidden field/PII leak guards")
    return ", ".join(focus)

def graphql_probe_instruction(text: str) -> str:
    return f"Use safe GraphQL fixtures to capture {graphql_probe_focus(text)} and count-aware runtime disposition."

def graphql_runtime_probe_instruction(text: str) -> str:
    return f"Drive or replay the GraphQL BFF path, capture {graphql_probe_focus(text)}, and count-aware runtime disposition."

def has_rag_grounding_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(
        lower,
        r"\brag\b",
        r"\bretrieval[- ]?augmented\b",
        r"\bgrounded\s+answer\b",
        r"\bgrounding\b",
        r"\bretrieval[_ -]?trace\b",
        r"\bsource[_ -]?ids\b",
        r"\bcitation[_ -]?spans?\b",
        r"\bquote[_ -]?(?:start|end)\b",
        r"\bcitation\s+excerpts?\b",
        r"\bsource\s+document\s+text\b",
        r"\bvector[_ -]?index\b",
        r"\bembedding[_ -]?model\b",
        r"\bprompt[_ -]?injection\b",
        r"\bprompt[_ -]?injection[_ -]?detected\b",
        r"\bretrieved\s+document\b",
        r"\binsufficient[_ -]?sources\b",
    )

def has_rag_retrieval_trace_intent(text: str) -> bool:
    lower = text.lower()
    return has_rag_grounding_intent(text) and has_word(lower, r"\bretrieval[_ -]?trace\b", r"\btrace[_ -]?id\b", r"\bquery[_ -]?hash\b", r"\bretrieved\s+source[_ -]?ids\b")

def has_rag_vector_index_intent(text: str) -> bool:
    lower = text.lower()
    return has_rag_grounding_intent(text) and has_word(lower, r"\bvector[_ -]?index\b", r"\bembedding[_ -]?model\b", r"\btop[_ -]?k\b", r"\bscore[_ -]?threshold\b")

def has_rag_citation_intent(text: str) -> bool:
    lower = text.lower()
    return has_rag_grounding_intent(text) and has_word(lower, r"\bcitations?\b", r"\bcitation[_ -]?spans?\b", r"\bsource[_ -]?ids\b", r"\bquote[_ -]?start\b", r"\bquote[_ -]?end\b", r"\bsource\s+document\s+text\b")

def has_rag_document_version_intent(text: str) -> bool:
    lower = text.lower()
    return has_rag_grounding_intent(text) and has_word(lower, r"\bdocument[_ -]?version\b", r"\bstale\s+document\b", r"\bstale\s+source\b")

def has_rag_hallucination_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_rag_grounding_intent(text) and has_word(lower, r"\bhallucinat", r"\bunsupported\b", r"\bnot\s+cite\s+a\s+source\s+that\s+was\s+not\s+retrieved\b")

def has_rag_prompt_injection_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_rag_grounding_intent(text) and has_word(lower, r"\bprompt[_ -]?injection\b", r"\bprompt[_ -]?injection[_ -]?detected\b", r"\bignore\s+previous\s+instructions\b", r"\bsystem[_ -]?prompt\b", r"\btool[_ -]?credentials\b")

def has_rag_abstention_intent(text: str) -> bool:
    lower = text.lower()
    return has_rag_grounding_intent(text) and has_word(lower, r"\babstain\b", r"\binsufficient[_ -]?sources\b", r"\bno\s+source\s+passes\b", r"\bno\s+answer\s+citation\s+rows\b")

def has_rag_secret_leak_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_rag_grounding_intent(text) and (
        has_secret_leak_guard_intent(text)
        or (
            has_word(lower, r"\bmust\s+not\s+reveal\b", r"\bmust\s+not\s+leak\b", r"\bnot\s+leak\b")
            and has_word(lower, r"\bsystem[_ -]?prompt\b", r"\btool[_ -]?credentials\b", r"\bhidden\s+policy\b", r"\bforeign\s+embeddings?\b")
        )
    )

def has_notification_intent(text: str) -> bool:
    lower = text.lower()
    negative_outbox = has_word(
        lower,
        r"\b(?:create|creates|created)\s+no\s+[a-z0-9_]*_?outbox\s+rows?\b",
        r"\b(?:create|creates|created)\s+no\s+.{0,80}[a-z0-9_]*outbox\s+rows?\b",
        r"\bno\s+[a-z0-9_]*_?outbox\s+rows?\b",
        r"\bno\s+.{0,80}[a-z0-9_]*outbox\s+rows?\b",
        r"\bmust\s+not\s+(?:write|create|enqueue|append).{0,80}[a-z0-9_]*_?outbox\s+rows?\b",
        r"\bmust\s+not\s+(?:write|create|enqueue|append).{0,80}\boutbox\b",
        r"\bmust\s+not\s+(?:write|create|enqueue|append).{0,120}\bnotification_outbox\b",
        r"\bmust\s+not\s+(?:write|create|enqueue|append).{0,120}\b[a-z0-9_]*_?outbox\b",
        r"\bwithout\s+(?:writing|creating).{0,80}\boutbox\b",
    )
    negative_notification = negative_outbox or has_word(
        lower,
        r"\bmust\s+not\b.{0,140}\bsend\s+(?:a\s+)?receipt\s+email\b",
        r"\bmust\s+not\s+send\s+(?:a\s+)?receipt\s+email\b",
        r"\bmust\s+not\s+send\s+.{0,40}\bemail\b",
        r"\bmust\s+not\b.{0,140}\breceipt\s+email\s+outbox\s+rows?\b",
        r"\bno\s+receipt\s+email\b",
        r"\bno\s+.{0,40}\breceipt\b.{0,40}\bside\s+effect\b",
        r"\bmust\s+not\s+publish\s+order\.confirmed\b",
    )
    if negative_notification and (has_webhook_security_intent(text) or has_privacy_compliance_intent(text) or has_authorization_policy_intent(text) or has_financial_ledger_intent(text) or has_quota_metering_intent(text) or has_transaction_integrity_intent(text) or has_subscription_billing_intent(text)):
        return False
    if has_offline_sync_intent(text) and not has_word(lower, r"\bnotification\b", r"\bnotification_outbox\b", r"\bemail\b", r"\breceipt\b", r"\balert\b"):
        return False
    if has_transaction_integrity_intent(text) and not has_word(lower, r"\bnotification\b", r"\bemail\b", r"\breceipt\b", r"\balert\b"):
        return False
    positive_notification = has_word(
        lower,
        r"\bnotification\b",
        r"\bnotification_outbox\b",
        r"\b[a-z0-9_]*_outbox\b",
        r"\boutbox\b",
        r"\bnotification_outbox\s+status\b",
        r"\b[a-z0-9_]*_outbox\s+status\b",
        r"\benqueue(?:s|d)?\b.{0,40}\b(?:notification|outbox|email)\b",
        r"\boutbox\b.{0,40}\b(?:pending|sent|preview|worker)\b",
        r"\balert(?:s|ed|ing)?\b",
        r"\breceipt\b",
        r"\bsend_receipts\b",
    )
    return positive_notification or has_chinese(text, "通知", "告警", "回执")

def has_notification_policy_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(
            lower,
            r"\bnotification\s+preferences?\b",
            r"\bnotification[-_]preferences?\b",
            r"\bnotification[_ -]?policy\b",
            r"\bpreference[_ -]?version\b",
            r"\bconsent[_ -]?source\b",
            r"\bmarketing[_ -]?email\b",
            r"\btransactional[_ -]?email\b",
            r"\bsuppressed[_ -]?reason\b",
            r"\bunsubscribed\b",
            r"\bquiet\s+hours?\b",
            r"\bsend[_ -]?after\b",
            r"\bdigest[_ -]?key\b",
            r"\bunsubscribe\s+token\b",
            r"\btoken_already_used\b",
        )
        or has_chinese(text, "通知偏好", "退订", "免打扰", "勿扰", "摘要通知")
    )

def has_notification_preference_intent(text: str) -> bool:
    lower = text.lower()
    return has_notification_policy_intent(text) and has_word(lower, r"\bnotification\s+preferences?\b", r"\bnotification[-_]preferences?\b", r"\bpreference[_ -]?version\b", r"\bmarketing[_ -]?email\b", r"\btransactional[_ -]?email\b")

def has_notification_consent_intent(text: str) -> bool:
    lower = text.lower()
    return has_notification_policy_intent(text) and has_word(lower, r"\bconsent[_ -]?source\b", r"\buser_setting\b", r"\bmarketing[_ -]?email\s*=\s*false\b", r"\btransactional[_ -]?email\s*=\s*true\b")

def has_notification_suppression_intent(text: str) -> bool:
    lower = text.lower()
    return has_notification_policy_intent(text) and has_word(lower, r"\bsuppressed[_ -]?reason\b", r"\bunsubscribed\b", r"\bmust\s+not\s+create\s+marketing\b", r"\bsuppression\b")

def has_notification_quiet_hours_intent(text: str) -> bool:
    lower = text.lower()
    return has_notification_policy_intent(text) and has_word(lower, r"\bquiet\s+hours?\b", r"\bsend[_ -]?after\b", r"\bdefer(?:s|red)?\b", r"\bnon[- ]urgent\b")

def has_notification_urgent_override_intent(text: str) -> bool:
    lower = text.lower()
    return has_notification_policy_intent(text) and has_word(lower, r"\burgent[_ -]?security\b", r"\burgent[_ -]?override\b", r"\bbypasses?\s+quiet\s+hours?\b")

def has_notification_digest_intent(text: str) -> bool:
    lower = text.lower()
    return has_notification_policy_intent(text) and has_word(lower, r"\bdigest[_ -]?key\b", r"\bdigest\s+email\b", r"\bevent[_ -]?count\b", r"\bweekly[_ -]?digest\b")

def has_unsubscribe_token_intent(text: str) -> bool:
    lower = text.lower()
    return has_notification_policy_intent(text) and has_word(lower, r"\bunsubscribe\s+token\b", r"\bunsub[_ -]?token\b", r"\btoken_hash\b", r"\bunsubscribed_at\b", r"\btoken_already_used\b")

def has_background_job_intent(text: str) -> bool:
    lower = text.lower()
    if has_offline_sync_intent(text) and has_word(lower, r"\bbackground\s+sync\b", r"\bservice\s+worker\b") and not has_word(lower, r"\bbackground\s+job\b", r"\bjob[_ -]?id\b", r"\bqueued\s+job\b"):
        return False
    queue_signal = has_word(lower, r"\benqueue(?:d|s|ing)?\b", r"\bqueue(?:d|s|ing)?\b", r"\bjob[_ -]?id\b", r"\bbackground\s+(?:job|task|worker)\b")
    worker_signal = has_word(lower, r"\bworker\b", r"\b[a-z0-9_-]+-worker\b", r"\bprocess(?:es|ed|ing)\s+(?:job|task)\b")
    return queue_signal or (worker_signal and has_word(lower, r"\bjob\b", r"\btask\b", r"\bstatus\b")) or has_chinese(text, "后台任务", "队列", "入队", "作业")

def has_scheduled_job_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(
            lower,
            r"\bscheduled?\s+(?:job|task|run|worker|invoice|generation)\b",
            r"\bscheduler\b",
            r"\bscheduler[_ -]?runs?\b",
            r"\brun_scheduled_[a-z0-9_]+\b",
            r"\bcron\b",
            r"\bschedule[_ -]?id\b",
            r"\bnext[_ -]?run[_ -]?at\b",
            r"\brun[_ -]?key\b",
            r"\bcatch[- ]?up\s+generation\b",
            r"\bprevious\s+schedule\s+was\s+missed\b",
            r"\bone\s+invoice\s+per\s+account\b",
        )
        or (
            has_word(lower, r"\bschedule\b", r"\bscheduled\b")
            and has_word(lower, r"\bcron\b", r"\bworker\b", r"\bjob\b", r"\brun[_ -]?key\b", r"\bnext[_ -]?run[_ -]?at\b", r"\badvisory\s+lock\b")
        )
        or has_chinese(text, "定时任务", "调度任务", "调度器", "计划任务", "补跑")
    )

def has_schedule_expression_intent(text: str) -> bool:
    lower = text.lower()
    return has_scheduled_job_intent(text) and has_word(lower, r"\bcron\b", r"\bschedule\b", r"--schedule\b", r"\bschedule[_ -]?id\b", r"\bnext[_ -]?run[_ -]?at\b", r"\b\d+\s+\d+\s+\*\s+\*\s+\*\b")

def has_scheduler_run_intent(text: str) -> bool:
    lower = text.lower()
    return has_scheduled_job_intent(text) and has_word(lower, r"\bscheduler[_ -]?runs?\b", r"\bschedule[_ -]?id\b", r"\bjob[_ -]?id\b", r"\bstarted[_ -]?at\b", r"\bcompleted[_ -]?at\b", r"\bstatus\s+completed\b")

def has_run_key_intent(text: str) -> bool:
    return has_scheduled_job_intent(text) and has_word(text.lower(), r"\brun[_ -]?key\b")

def has_due_window_intent(text: str) -> bool:
    lower = text.lower()
    return has_scheduled_job_intent(text) and has_word(lower, r"\bschedule\s+window\b", r"\bdue\s+before\b", r"\bdue_count\b", r"\bdue\s+window\b", r"\bbefore\s+\d{4}-\d{2}-\d{2}")

def has_catch_up_intent(text: str) -> bool:
    lower = text.lower()
    return has_scheduled_job_intent(text) and has_word(lower, r"\bcatch[- ]?up\b", r"\bmissed\s+(?:schedule|run|job)\b", r"\bprevious\s+schedule\s+was\s+missed\b", r"\bmissed\b")

def has_scheduler_lock_intent(text: str) -> bool:
    lower = text.lower()
    return has_scheduled_job_intent(text) and has_word(lower, r"\badvisory\s+lock\b", r"\bscheduler[_ -]?lock\b", r"\block[_ -]?acquired\b", r"\balready[_ -]?running\b", r"\bduplicate[_ -]?skipped\b")

def has_scheduled_dry_run_intent(text: str) -> bool:
    return has_scheduled_job_intent(text) and has_word(text.lower(), r"\bdry[- ]?run\b", r"--dry-run\b")

def has_invoice_rows_intent(text: str) -> bool:
    lower = text.lower()
    return has_scheduled_job_intent(text) and has_word(lower, r"\binvoice\s+rows?\b", r"\binvoices?\b", r"\binvoice[_ -]?month\b", r"\bgenerated[_ -]?invoice[_ -]?ids\b")

def has_worker_intent(text: str) -> bool:
    lower = text.lower()
    if has_offline_sync_intent(text) and has_word(lower, r"\bbackground\s+sync\b", r"\bservice\s+worker\b") and not has_word(lower, r"\bworker\s+log\b", r"\bbackground\s+worker\b"):
        return False
    return has_word(lower, r"\bworker\b", r"\b[a-z0-9_-]+-worker\b", r"\bbackground\s+worker\b", r"\bprocess(?:es|ed|ing)\s+(?:job|task)\b") or has_chinese(text, "后台worker", "工作进程")

def has_retry_backoff_intent(text: str) -> bool:
    lower = text.lower()
    lower_without_retry_after = re.sub(r"\bretry[-_ ]?after\b", " ", lower)
    retry_signal = has_word(lower_without_retry_after, r"\bretr(?:y|ies|ied|ying)\b", r"\bretry_count\b", r"\bmax\s+retr(?:y|ies)\b")
    backoff_signal = has_word(lower, r"\bbackoff\b", r"\bexponential\s+backoff\b", r"\bnext_retry_at\b")
    if has_optimistic_ui_intent(text) and not (backoff_signal or has_word(lower, r"\bretry_count\b", r"\bmax\s+retr(?:y|ies)\b", r"\bworker\b", r"\bqueue\b", r"\bdead[_ -]?letter\b")):
        return False
    return retry_signal or backoff_signal or has_chinese(text, "重试", "退避")

def has_dead_letter_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bdead[_ -]?letter\b", r"\bdeadletter\b", r"\bdlq\b", r"\bmax\s+retr(?:y|ies)\b") or has_chinese(text, "死信")

def has_alert_outbox_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\balert[_ -]?outbox\b", r"\balert(?:s|ed|ing)?\b")
        or (has_word(lower, r"\bcorrelation[_ -]?id\b") and has_word(lower, r"\balert\b", r"\boutbox\b"))
        or has_chinese(text, "告警", "通知表")
    )

def has_feature_flag_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bfeature[-_ ]?flags?\b", r"\bfeature[-_ ]?flag[-_ ]?service\b", r"\bflag\s+service\b", r"\bflag\s+evaluat(?:e|ed|ion)\b", r"\benabled\s*=\s*true\b", r"\benabled\s*=\s*false\b")
        or has_chinese(text, "功能开关", "灰度开关")
    )

def has_rollout_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\brollout\b", r"\bcohort\b", r"\bcohort[_ -]?match\b", r"\bvariant\b", r"\btreatment\b", r"\bcontrol\s+(?:customer|user|group)\b", r"\bbeta\s+(?:customer|user|cohort)\b")
        or has_chinese(text, "灰度", "分群", "实验组", "对照组")
    )

def has_flag_default_off_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bdefault[-_ ]?off\b", r"\bfeature_flag_default_off\b", r"\bflag\s+service\s+(?:timeout|times?\s+out|unavailable)\b", r"\bdefaults?\s+off\b")
        or has_chinese(text, "默认关闭", "降级关闭")
    )

def has_direct_api_denial_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bdirect\s+(?:get|post|put|patch|delete)\b", r"\bdirect\s+api\b", r"\bfeature_disabled\b")
        and has_word(lower, r"\b403\b", r"\b404\b", r"\bden(?:y|ied|ial)\b", r"\bforbidden\b", r"\bfeature_disabled\b")
    )

def has_stale_flag_guard_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bstale\s+cached\s+flag\b", r"\bstale\s+flag\b", r"\bcached\s+flag\s+data\b", r"\bflag\s+data\b", r"\bchanges?\s+from\s+enabled\s+to\s+disabled\b")
        or (has_feature_flag_intent(text) and has_stale_data_guard_intent(text))
    )

def has_authorization_policy_intent(text: str) -> bool:
    lower = text.lower()
    strong_authz_signal = has_word(
        lower,
        r"\bauthorization\s+policy\b",
        r"\bpolicy\s+matrix\b",
        r"\bpolicy[_ -]?evaluate\b",
        r"\bpolicy/evaluate\b",
        r"\bmatched[_ -]?rule[_ -]?id\b",
        r"\bdeny[_ -]?precedence\b",
        r"\bpolicy_denied\b",
        r"\bresource[_ -]?scope\b",
        r"\bobligation\b",
        r"\babac\b",
        r"\brbac\b",
        r"\bdirect\s+api\s+denial\b",
    )
    if has_decision_table_logic_intent(text) and not strong_authz_signal:
        return False
    policy_signal = has_word(
        lower,
        r"\bauthorization\s+policy\b",
        r"\bpolicy\s+matrix\b",
        r"\bpolicy[_ -]?id\b",
        r"\bpolicy[_ -]?evaluate\b",
        r"\bpolicy/evaluate\b",
        r"\bmatched[_ -]?rule[_ -]?id\b",
        r"\bdeny[_ -]?precedence\b",
        r"\bpolicy_denied\b",
        r"\bpolicy\s+decision\s+cache\b",
        r"\bpolicy[_ -]?cache[_ -]?key\b",
        r"\bpolicy[_ -]?version\b",
        r"\bstale\s+allow\b",
        r"\babac\b",
        r"\brbac\b",
    )
    authz_signal = has_word(lower, r"\ballow=false\b", r"\bdecision\s*=\s*deny\b", r"\bexplicitly\s+den(?:y|ies)\b", r"\bresource[_ -]?scope\b", r"\bobligation\b")
    return policy_signal or (has_word(lower, r"\bpolicy\b") and authz_signal)

def has_policy_matrix_intent(text: str) -> bool:
    lower = text.lower()
    return has_authorization_policy_intent(text) and has_word(lower, r"\bpolicy\s+matrix\b", r"\bgrants?\b", r"\broles?\b", r"\bresource\s+scope\b", r"\bsame[- ]org\b")

def has_policy_decision_intent(text: str) -> bool:
    lower = text.lower()
    return has_authorization_policy_intent(text) and has_word(lower, r"\bpolicy[_ -]?evaluate\b", r"\bpolicy/evaluate\b", r"\bdecision\b", r"\ballow=false\b", r"\ballow=true\b", r"\bpolicy_denied\b")

def has_policy_matched_rule_intent(text: str) -> bool:
    lower = text.lower()
    return has_authorization_policy_intent(text) and has_word(lower, r"\bmatched[_ -]?rule[_ -]?id\b", r"\bdeny_pii_export_contractors\b")

def has_deny_precedence_intent(text: str) -> bool:
    lower = text.lower()
    return has_authorization_policy_intent(text) and has_word(lower, r"\bdeny[_ -]?precedence\b", r"\bexplicitly\s+den(?:y|ies)\b", r"\bexplicit\s+deny\b", r"\binherits?\b")

def has_role_inheritance_intent(text: str) -> bool:
    lower = text.lower()
    return has_authorization_policy_intent(text) and has_word(lower, r"\binherits?\b", r"\brole\s+inheritance\b", r"\binherited\s+role\b", r"\breport_admin\b")

def has_resource_scope_intent(text: str) -> bool:
    lower = text.lower()
    return has_authorization_policy_intent(text) and has_word(lower, r"\bresource[_ -]?scope\b", r"\bsame[- ]org\b", r"\bsame\s+org\b", r"\bassigned\s+tickets?\b", r"\btenant[_ -]?id\b")

def has_policy_obligation_intent(text: str) -> bool:
    lower = text.lower()
    return has_authorization_policy_intent(text) and has_word(lower, r"\bobligation\b", r"\bmask_pii\b")

def has_policy_cache_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_authorization_policy_intent(text) and has_word(lower, r"\bpolicy\s+decision\s+cache\b", r"\bcache[_ -]?key\b", r"\bstale\s+allow\b", r"\bstale\s+policy\b", r"\bpolicy[_ -]?version\b")

def has_financial_ledger_intent(text: str) -> bool:
    lower = text.lower()
    ledger_signal = has_word(
        lower,
        r"\bfinancial\s+ledger\b",
        r"\bledger\b",
        r"\bledger[_ -]?transaction\b",
        r"\bledger[_ -]?entries?\b",
        r"\bdouble[- ]entry\b",
        r"\bdebits?\b",
        r"\bcredits?\b",
        r"\breversal\s+ledger\b",
        r"\bpayout[_ -]?reconciliation\b",
    )
    money_flow_signal = has_word(lower, r"\brefund\b", r"\bpayment\b", r"\bsettlement\b", r"\bamount[_ -]?cents\b", r"\bcurrency\b")
    return ledger_signal and money_flow_signal

def has_double_entry_intent(text: str) -> bool:
    lower = text.lower()
    return has_financial_ledger_intent(text) and has_word(lower, r"\bdouble[- ]entry\b", r"\bbalanced\s+debits?\b", r"\bdebit_total_cents\b", r"\bcredit_total_cents\b", r"\bdebits?\s+and\s+credits?\b")

def has_immutable_ledger_intent(text: str) -> bool:
    lower = text.lower()
    return has_financial_ledger_intent(text) and has_word(lower, r"\bimmutable\b", r"\bmust\s+not\s+mutate\b", r"\bmust\s+not\s+modify\b", r"\bmust\s+not\s+change\b")

def has_reversal_ledger_intent(text: str) -> bool:
    lower = text.lower()
    return has_financial_ledger_intent(text) and has_word(lower, r"\breversal\b", r"\blinked\s+to\s+tx_", r"\boriginal\s+ledger\b", r"\brefund\s+ledger\b")

def has_ledger_balance_intent(text: str) -> bool:
    lower = text.lower()
    return has_financial_ledger_intent(text) and has_word(lower, r"\bledger\s+balance\b", r"\bnet\s+ledger\s+balance\b", r"\bbalance\s+by\s+currency\b", r"\bdebit_total_cents\s*=\s*credit_total_cents\b", r"\bzero\b")

def has_minor_unit_amount_intent(text: str) -> bool:
    lower = text.lower()
    return has_financial_ledger_intent(text) and has_word(lower, r"\bminor[- ]unit\b", r"\bamount_cents\b", r"\bcents\b", r"\bno\s+float\s+drift\b", r"\bfloat\s+drift\b")

def has_over_refund_denial_intent(text: str) -> bool:
    lower = text.lower()
    return has_financial_ledger_intent(text) and has_word(lower, r"\bover[_ -]?refund(?:ed|s|ing)?\b", r"\bover_refund_denied\b", r"\b409\b")

def has_settlement_reconciliation_intent(text: str) -> bool:
    lower = text.lower()
    return has_financial_ledger_intent(text) and has_word(lower, r"\bsettlement\s+worker\b", r"\brefund\.settled\b", r"\bsettled\b", r"\bpayout[_ -]?reconciliation\b", r"\breconciliation\b")

def has_quota_metering_intent(text: str) -> bool:
    lower = text.lower()
    quota_signal = has_word(
        lower,
        r"\busage\s+quota\b",
        r"\bquota\s+metering\b",
        r"\bquota[_ -]?limit\b",
        r"\bquota[_ -]?window\b",
        r"\busage[_ -]?counter\b",
        r"\busage[_ -]?event[_ -]?id\b",
        r"\bmeter[_ -]?key\b",
        r"\bbilling[_ -]?usage[_ -]?event\b",
        r"\bbilling[_ -]?usage[_ -]?event[_ -]?id\b",
        r"\bcounter[_ -]?version\b",
    )
    usage_signal = has_word(lower, r"\bapi_calls\b", r"\busage[_ -]?events?\b", r"\bquantity\b", r"\bremaining\b", r"\bused\s*=", r"\bquota[_ -]?exceeded\b")
    return (quota_signal and usage_signal) or has_chinese(text, "用量配额", "计量扣减", "配额窗口")

def has_quota_window_intent(text: str) -> bool:
    lower = text.lower()
    return has_quota_metering_intent(text) and has_word(lower, r"\bquota[_ -]?window\b", r"\bmonthly\s+quota\b", r"\bquota\s+window\b", r"\bstarts?\s+at\b", r"\bends?\s+at\b")

def has_usage_counter_intent(text: str) -> bool:
    lower = text.lower()
    return has_quota_metering_intent(text) and has_word(lower, r"\busage[_ -]?counter\b", r"\bcounter[_ -]?version\b", r"\bused\s*=", r"\bremaining\s*=")

def has_quota_remaining_intent(text: str) -> bool:
    lower = text.lower()
    return has_quota_metering_intent(text) and has_word(lower, r"\bremaining\b", r"\bquota[_ -]?remaining\b")

def has_atomic_usage_increment_intent(text: str) -> bool:
    lower = text.lower()
    return has_quota_metering_intent(text) and has_word(lower, r"\batomic\b", r"\bconcurrent\b", r"\bcounter[_ -]?version\b", r"\bversion\b")

def has_quota_exceeded_denial_intent(text: str) -> bool:
    lower = text.lower()
    return has_quota_metering_intent(text) and has_word(lower, r"\bquota[_ -]?exceeded\b", r"\bover\s+quota\b", r"\bremaining\s*=\s*0\b", r"\b409\b", r"\b402\b")

def has_no_negative_quota_intent(text: str) -> bool:
    lower = text.lower()
    return has_quota_metering_intent(text) and has_word(lower, r"\bnever\s+go\s+negative\b", r"\bmust\s+not\s+go\s+negative\b", r"\bno\s+negative\s+remaining\b", r"\bremaining\s+must\s+never\b")

def has_billing_usage_event_intent(text: str) -> bool:
    lower = text.lower()
    return has_quota_metering_intent(text) and has_word(lower, r"\bbilling[_ -]?usage[_ -]?event\b", r"\bbill_usage_")

def has_quota_reset_boundary_intent(text: str) -> bool:
    lower = text.lower()
    return has_quota_metering_intent(text) and has_word(lower, r"\breset\s+boundary\b", r"\bwindow[_ -]?reset\b", r"\busage\.window_reset\b", r"\bquota\s+reset\s+worker\b", r"\bmust\s+not\s+reset\s+before\b")

def has_transaction_integrity_intent(text: str) -> bool:
    lower = text.lower()
    transaction_signal = has_word(
        lower,
        r"\bcheckout\s+transaction\b",
        r"\btransaction\s+integrity\b",
        r"\btransaction_integrity\b",
        r"\btransaction[_ -]?id\b",
        r"\bdbtx_[A-Za-z0-9_]+\b",
        r"\batomic\s+commit\b",
        r"\bdb\s+transaction\s+commits\b",
        r"\bpost[- ]?commit\b",
        r"\boutbox[_ -]?event\b",
        r"\border\.confirmed\b",
        r"\boutbox\s+dispatcher\b",
        r"\bexactly\s+once\b",
        r"\bsaga\s+compensation\b",
        r"\bcompensation[_ -]?event\b",
    )
    side_effect_signal = has_word(
        lower,
        r"\border\b",
        r"\bpayment[_ -]?authorization\b",
        r"\binventory[_ -]?reservation\b",
        r"\boutbox\b",
        r"\bpublish[_ -]?count\b",
        r"\bpayment\s+provider\b",
        r"\binventory\b",
        r"\bpayment\b",
    )
    return (transaction_signal and side_effect_signal) or has_chinese(text, "事务完整性", "事务提交", "补偿事务")

def has_transaction_id_intent(text: str) -> bool:
    lower = text.lower()
    return has_transaction_integrity_intent(text) and has_word(lower, r"\btransaction[_ -]?id\b", r"\bdbtx_[A-Za-z0-9_]+\b")

def has_atomic_commit_intent(text: str) -> bool:
    lower = text.lower()
    return has_transaction_integrity_intent(text) and has_word(lower, r"\batomic\s+commit\b", r"\bcommit\s+rows?\s+atomically\b", r"\batomically\b", r"\bafter\s+db\s+transaction\s+commits\b")

def has_payment_authorization_intent(text: str) -> bool:
    lower = text.lower()
    return has_transaction_integrity_intent(text) and has_word(lower, r"\bpayment[_ -]?authorization\b", r"\bauthorization\s+auth_", r"\bauth_tx_", r"\bpayment\s+authorized\b")

def has_inventory_reservation_intent(text: str) -> bool:
    lower = text.lower()
    return has_transaction_integrity_intent(text) and has_word(lower, r"\binventory[_ -]?reservation\b", r"\breserve\s+inventory\b", r"\breserved\b", r"\bstock_reserved\b", r"\bres_tx_")

def has_transaction_outbox_intent(text: str) -> bool:
    lower = text.lower()
    return has_transaction_integrity_intent(text) and has_word(lower, r"\boutbox[_ -]?event\b", r"\border\.confirmed\b", r"\boutbox_tx_", r"\bevent_id\b")

def has_outbox_dispatch_intent(text: str) -> bool:
    lower = text.lower()
    return has_transaction_integrity_intent(text) and has_word(lower, r"\boutbox\s+dispatcher\b", r"\bdispatcher\s+retry\b", r"\bpublishes?\b", r"\bpublish\s+exactly\s+once\b", r"\bpost[- ]?commit\b", r"\bafter\s+db\s+transaction\s+commits\b")

def has_saga_compensation_intent(text: str) -> bool:
    lower = text.lower()
    return has_transaction_integrity_intent(text) and has_word(lower, r"\bsaga\s+compensation\b", r"\bcompensation\s+worker\b", r"\bcompensation[_ -]?event\b", r"\binventory\.release\b", r"\bcheckout\.compensated\b")

def has_inventory_release_intent(text: str) -> bool:
    lower = text.lower()
    return has_saga_compensation_intent(text) and has_word(lower, r"\breleases?\s+inventory\b", r"\binventory\.release\b", r"\binventory[_ -]?release\b", r"\breleases?\s+inventory[_ -]?reservation\b")

def has_authorization_void_intent(text: str) -> bool:
    lower = text.lower()
    return has_saga_compensation_intent(text) and has_word(lower, r"\bvoids?\s+authorization\b", r"\bauthorization[_ -]?void\b", r"\bvoid\s+authorization\b")

def has_publish_exactly_once_intent(text: str) -> bool:
    lower = text.lower()
    return has_transaction_integrity_intent(text) and has_word(lower, r"\bpublish(?:es)?\s+(?:[A-Za-z0-9_.-]+\s+){0,8}exactly\s+once\b", r"\bexactly\s+once\b", r"\bpublish[_ -]?count\b", r"\bmust\s+not\s+duplicate\b")

def has_trace_correlation_intent(text: str) -> bool:
    lower = text.lower()
    return has_transaction_integrity_intent(text) and has_word(lower, r"\btrace[_ -]?id\b", r"\bcorrelation[_ -]?id\b")

def has_subscription_billing_intent(text: str) -> bool:
    lower = text.lower()
    subscription_signal = has_word(
        lower,
        r"\bsubscription[_ -]?id\b",
        r"\bsubscriptions?/",
        r"\bsubscription\s+billing\b",
        r"\bplan\s+change\b",
        r"\bcurrent[_ -]?plan\b",
        r"\btarget[_ -]?plan\b",
        r"\bsubscription[_ -]?version\b",
        r"\bbilling[_ -]?anchor\b",
        r"\bproration\b",
        r"\bpreview[-/]?change\b",
    )
    billing_signal = has_word(
        lower,
        r"\bbilling\b",
        r"\binvoice\b",
        r"\bpayment[_ -]?intent\b",
        r"\breceipt\s+email\b",
        r"\bproration[_ -]?behavior\b",
        r"\bscheduled[_ -]?capture\b",
        r"\btax[_ -]?jurisdiction\b",
        r"\bseat[_ -]?count\b",
    )
    return (subscription_signal and billing_signal) or has_chinese(text, "订阅计费", "套餐变更", "按比例计费")

def has_subscription_proration_intent(text: str) -> bool:
    lower = text.lower()
    return has_subscription_billing_intent(text) and has_word(lower, r"\bproration\b", r"\bproration[_ -]?behavior\b", r"\bunused[_ -]?credit\b", r"\bprorated[_ -]?charge\b")

def has_subscription_invoice_preview_intent(text: str) -> bool:
    lower = text.lower()
    return has_subscription_billing_intent(text) and has_word(lower, r"\binvoice\s+preview\b", r"\bpreview[_ -]?id\b", r"\bpreview[-/]?change\b", r"\bpreview\b")

def has_subscription_tax_intent(text: str) -> bool:
    lower = text.lower()
    return has_subscription_billing_intent(text) and has_word(lower, r"\btax[_ -]?jurisdiction\b", r"\btax[_ -]?rate\b", r"\btax[_ -]?cents\b", r"\btax\b")

def has_subscription_scheduled_capture_intent(text: str) -> bool:
    lower = text.lower()
    return has_subscription_billing_intent(text) and has_word(lower, r"\bscheduled[_ -]?capture\b", r"\brequires[_ -]?capture\b", r"\bpayment[_ -]?intent\b")

def has_subscription_scheduled_change_intent(text: str) -> bool:
    lower = text.lower()
    return has_subscription_billing_intent(text) and has_word(lower, r"\bscheduled[_ -]?change\b", r"\bdowngrade\b", r"\brenewal\b", r"\bbilling[_ -]?anchor\b")

def has_subscription_authorization_denial_intent(text: str) -> bool:
    lower = text.lower()
    return has_subscription_billing_intent(text) and has_word(lower, r"\b403\b", r"\bforbidden\b", r"\bplan[_ -]?change[_ -]?forbidden\b", r"\bsupport[_ -]?agent\b")

def has_agent_tool_intent(text: str) -> bool:
    lower = text.lower()
    agent_signal = has_word(
        lower,
        r"\bagent[_ -]?session[_ -]?id\b",
        r"\bagent\s+tool\b",
        r"\bagent\s+tool[- ]?call\b",
        r"\btool[_ -]?call[_ -]?id\b",
        r"\btool[_ -]?name\b",
        r"\btool[_ -]?call[_ -]?requested\b",
        r"\btool[_ -]?call[_ -]?approved\b",
        r"\btool[_ -]?result\b",
        r"\bhandoff[_ -]?required\b",
        r"/agent-tools/",
        r"/agents/run/ws",
    )
    tool_signal = has_word(
        lower,
        r"\bapproval[_ -]?required\b",
        r"\bapproval[_ -]?id\b",
        r"\bapprove\b",
        r"\bcancel\b",
        r"\btool[_ -]?args\b",
        r"\bargs[_ -]?hash\b",
        r"\btool[_ -]?executor\b",
        r"\btool[_ -]?timeout\b",
        r"\bhuman[_ -]?review[_ -]?queue\b",
        r"\banswer[_ -]?done\b",
    )
    return (agent_signal and tool_signal) or has_chinese(text, "智能体工具", "工具调用审批", "人工接管")

def has_agent_tool_approval_intent(text: str) -> bool:
    lower = text.lower()
    return has_agent_tool_intent(text) and has_word(lower, r"\bapproval[_ -]?required\b", r"\bapproval[_ -]?id\b", r"\bapprove(?:s|d)?\b", r"/approve\b", r"\btool[_ -]?call[_ -]?approved\b")

def has_agent_tool_cancellation_intent(text: str) -> bool:
    lower = text.lower()
    return has_agent_tool_intent(text) and has_word(lower, r"\bcancel(?:s|led|lation)?\b", r"/cancel\b", r"\btool[_ -]?call[_ -]?cancelled\b", r"\bmust\s+not\s+invoke\b")

def has_agent_tool_redaction_intent(text: str) -> bool:
    lower = text.lower()
    return has_agent_tool_intent(text) and has_word(lower, r"\bredact(?:ed|ion)?\b", r"\bargs[_ -]?hash\b", r"\btool[_ -]?args\b", r"\bssn\b", r"\bpayment[_ -]?token\b", r"\bmust\s+not\s+(?:include|leak|show|return)\b")

def has_agent_tool_handoff_intent(text: str) -> bool:
    lower = text.lower()
    return has_agent_tool_intent(text) and has_word(lower, r"\bhandoff[_ -]?required\b", r"\bhandoff[_ -]?id\b", r"\bhuman[_ -]?review[_ -]?queue\b", r"\bneeds[_ -]?human[_ -]?review\b", r"\btool[_ -]?timeout\b")

def has_agent_tool_authorization_denial_intent(text: str) -> bool:
    lower = text.lower()
    return has_agent_tool_intent(text) and has_word(lower, r"\b403\b", r"\bforbidden\b", r"\btool[_ -]?approval[_ -]?forbidden\b", r"\bviewer\b", r"\bmust\s+not\s+execute\b")

def has_no_real_email_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bwithout\s+sending\s+(?:a\s+)?real\s+email\b", r"\bno\s+real\s+email\b") or (
        has_word(lower, r"\bdry[- ]run\b") and has_word(lower, r"\bemail\b", r"\breceipt\b", r"\bsend_receipts\b")
    )

def has_no_write_or_duplicate_absence_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bmust\s+not\s+write\b", r"\bno[- ]write\b", r"\brow\s+count\b", r"\bno\s+duplicate\b", r"\bexactly\s+one\b", r"\bduplicate_count\s*=\s*0\b") or has_chinese(text, "不能写入", "不得写入", "不能重复", "不得重复", "不重复")

def has_tenant_isolation_intent(text: str) -> bool:
    lower = text.lower()
    tenant_signal = has_word(lower, r"\btenant\b", r"\btenant[_ -]?id\b", r"\borg[_ -]?id\b", r"\borganization\b", r"\borg\b", r"\bworkspace\b")
    isolation_signal = has_word(lower, r"\bonly\b", r"\bsame\s+account\s+ids?\b", r"\bsame\s+workspace\b", r"\banother\s+tenant\b", r"\banother\s+workspace\b", r"\bcross[- ]tenant\b", r"\bcross[- ]workspace\b", r"\bdata\s+isolation\b", r"\btenant\s+isolation\b", r"\bworkspace\s+boundary\b", r"\bexclude\b", r"\bno\s+\w+\s+rows?\b", r"\bmust\s+not\s+include\b", r"\bmust\s+not\s+leak\b")
    return bool(tenant_signal and isolation_signal) or has_chinese(text, "租户隔离", "跨租户", "组织隔离")

def has_cross_tenant_denial_intent(text: str) -> bool:
    lower = text.lower()
    explicit_cross_tenant = has_word(lower, r"\banother\s+tenant\b", r"\banother\s+workspace\b", r"\bcross[- ]tenant\b", r"\bcross[- ]workspace\b", r"\bblocked\s+cross[- ]tenant\b", r"\bblocked\s+cross[- ]workspace\b", r"\btenant\.access[_ .-]?denied\b", r"\bmust\s+not\s+read\s+another\s+tenant\b", r"\bmust\s+not\s+subscribe\b")
    tenant_denial_status = has_word(lower, r"\btenant\b", r"\borg[_ -]?id\b", r"\borganization\b", r"\borg\b", r"\bworkspace\b") and has_word(lower, r"\b403\b", r"\b404\b", r"\baccess[_ .-]?denied\b", r"\bdenied\s+attempt\b", r"\bmust\s+not\s+read\b", r"\bmust\s+not\s+subscribe\b")
    return explicit_cross_tenant or tenant_denial_status or has_chinese(text, "跨租户", "组织隔离拒绝")

def has_forbidden_text_absence_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(
        lower,
        r"\b(?:must|should|shall|can|could|does|do|did|will|would)\s+not\s+(?:show|display|render|include|contain|appear|leak)\b",
        r"\b(?:must|should|shall)\s+not\s+be\s+(?:shown|displayed|rendered|visible)\b",
        r"\bnot\s+(?:shown|displayed|rendered|visible)\b",
        r"\bforbidden\s+text\b",
        r"\bno\s+\w+\s+rows?\b",
        r"\bexclude(?:s|d)?\b",
        r"\bwithout\s+(?:showing|displaying|rendering|returning|including|appearing|leaking)\b",
    ) or has_chinese(text, "不得包含", "不能包含", "不能出现", "不得泄露", "不能泄露", "不能显示", "不得显示", "不要显示", "不应显示", "不能展示")

def has_no_persistence_side_effect_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bwithout\s+persisting\b", r"\bmust\s+not\s+write\b", r"\bmust\s+not\s+update\b", r"\bmust\s+not\s+change\b", r"\bmust\s+not\s+mutate\b", r"\bno\s+access\s+grant\b", r"\bnot\s+persist\b", r"\bno\s+side\s+effect\b", r"\bwithout\s+creating\b", r"\bmust\s+not\s+create\b", r"\bcreate\s+no\s+(?:session(?:_id)?|oauth_account|account\s+link)\b", r"\bno\s+\w+\s+(?:is\s+)?created\b", r"\bno\s+extra\s+ids?\b", r"\bunselected\b.*\bunchanged\b", r"\bnot\s+hard[- ]deleted?\b", r"\bmust\s+not\s+hard[- ]delete\b", r"\bdo\s+not\s+create\s+session\b", r"\bmust\s+not\s+create\s+(?:a\s+)?session\b", r"\bmust\s+not\s+create\s+(?:a\s+)?refresh\s+token\b") or has_oauth_replay_guard_intent(text) or has_chinese(text, "不能写入", "不得持久化", "不能创建", "不能更新", "不能多改", "未选中不变", "不创建会话")

def has_cleanup_intent(text: str) -> bool:
    lower = text.lower()
    cleanup_signal = has_word(
        lower,
        r"\bcleanup\b",
        r"\bclean\s+up\b",
        r"\bteardown\b",
        r"\bdelete\s+created\s+test\s+data\b",
        r"\btestdata_deleted\b",
        r"\bqa_cleanup\b",
    )
    safety_or_verification_signal = has_word(
        lower,
        r"\balways\s+run\b",
        r"\balwaysrun\b",
        r"\beven\s+if\s+an\s+earlier\s+assertion\s+fails\b",
        r"\bafter\s+assertions\b",
        r"\bcleanup\s+verification\b",
        r"\bcreated\s+test\s+data\b",
        r"\bdelete\s+created\b",
        r"\bdelete\b.{0,80}\b(?:reason=qa_cleanup|qa_cleanup)\b",
        r"\bno\s+rows?\b",
        r"\bdeleted\s*=\s*true\b",
        r"\breturns?\s+404\b",
    )
    return (cleanup_signal and safety_or_verification_signal) or has_chinese(text, "清理测试数据", "测试数据清理", "清理验证", "清理必须运行")

def has_cleanup_verification_intent(text: str) -> bool:
    lower = text.lower()
    return has_cleanup_intent(text) and has_word(
        lower,
        r"\bcleanup\s+verification\b",
        r"\bverify\s+cleanup\b",
        r"\breturns?\s+404\b",
        r"\bdeleted\s*=\s*true\b",
        r"\bno\s+rows?\b",
        r"\btestdata_deleted\b",
    )

def has_always_run_cleanup_intent(text: str) -> bool:
    lower = text.lower()
    return has_cleanup_intent(text) and has_word(
        lower,
        r"\balways\s+run\b",
        r"\balwaysrun\b",
        r"\balwaysrun\s*=\s*true\b",
        r"\beven\s+if\s+an\s+earlier\s+assertion\s+fails\b",
        r"\bafter\s+assertions\b",
    )

def has_same_runtime_object_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(
        lower,
        r"\bsame[- ]object\b",
        r"\bsame\s+runtime\s+object\b",
        r"\bextracted\s+[a-z0-9_]*id\b",
        r"\busing\s+the\s+extracted\s+[a-z0-9_]*id\b",
        r"\bread\s+the\s+same\b",
    )

def has_resource_creation_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bcreate\b", r"\bcreation\b", r"\bcreates?\b", r"\bcreated\b", r"\bsubmits?\b")
        or (has_word(lower, r"\bpost\b") and has_word(lower, r"\breturn(?:s)?\s+[a-z0-9_]*id\b", r"\bstatus\s*=\s*active\b"))
    )

def has_cleanup_deletion_absence_intent(text: str) -> bool:
    lower = text.lower()
    return has_cleanup_intent(text) and has_word(lower, r"\breturns?\s+404\b", r"\bdeleted\s*=\s*true\b", r"\bno\s+rows?\b", r"\babsence\b")

def has_cleanup_cascade_intent(text: str) -> bool:
    lower = text.lower()
    return has_cleanup_intent(text) and has_word(lower, r"\bproject_members\b", r"\bmembership\s+rows?\b", r"\bchild\s+rows?\b", r"\brelated\s+rows?\b", r"\bcascade\b")

def has_cleanup_outbox_absence_intent(text: str) -> bool:
    lower = text.lower()
    return has_cleanup_intent(text) and has_word(lower, r"\bnotification_outbox\b", r"\boutbox\b") and has_word(lower, r"\bno\s+rows?\b", r"\bno\s+.{0,40}\boutbox\b")

def has_decision_table_logic_intent(text: str) -> bool:
    lower = text.lower()
    decision_signal = has_word(
        lower,
        r"\bdecision\s+table\b",
        r"\brule\s+matrix\b",
        r"\bbusiness\s+rules?\b",
        r"\brouting\s+logic\b",
        r"\bapproval\s+routing\b",
        r"\beval_approval_rules\b",
    )
    rule_signal = has_word(
        lower,
        r"\brule\s+precedence\b",
        r"\bexpected[_ -]?decisions?\b",
        r"\bfixture\s+input\s+rows?\b",
        r"\bexpected\s+output\s+decisions?\b",
        r"\bfor\s+every\s+branch\b",
        r"\bbranch(?:es)?\b",
        r"\bboundary\s+rows?\b",
        r"\bnegative\s+rows?\b",
    )
    approval_routing_row = (
        has_word(lower, r"\broutes?\s+from\s+pending\s+to\b", r"\broute\s+pending\s+to\b")
        and has_word(lower, r"\brequester_", r"\bvendor_risk\b", r"\bmissing_tax_id\b", r"\bsanction_match\b", r"\bapprover_group\b", r"\bcontractor\b", r"\bauto_approved\b", r"\bmanual_review\b", r"\brejected\b")
    )
    precedence_fixture_row = (
        has_word(lower, r"\brule\s+precedence\b", r"\bblocklist\b", r"\bdo_not_auto_approve\b", r"\boverrides?\b")
        and has_word(lower, r"\bfixture\s+input\s+rows?\b", r"\bexpected\s+output\s+decisions?\b", r"\bexpected[_ -]?decisions?\b", r"\bfor\s+every\s+branch\b")
    )
    return bool(decision_signal and rule_signal) or approval_routing_row or precedence_fixture_row or has_chinese(text, "决策表", "规则矩阵", "规则优先级")

def has_rule_precedence_intent(text: str) -> bool:
    lower = text.lower()
    return has_decision_table_logic_intent(text) and has_word(
        lower,
        r"\brule\s+precedence\b",
        r"\bprecedence\b",
        r"\boverrides?\b",
        r"\bexplicit\b",
        r"\bblocklist\b",
        r"\bdo_not_auto_approve\b",
    )

def has_logic_boundary_case_intent(text: str) -> bool:
    lower = text.lower()
    return has_decision_table_logic_intent(text) and has_word(
        lower,
        r"\bboundary\s+rows?\b",
        r"\bboundary\s+cases?\b",
        r"\bamount\s*=\s*1000\b",
        r"\b1000\.01\b",
    )

def has_logic_negative_case_intent(text: str) -> bool:
    lower = text.lower()
    return has_decision_table_logic_intent(text) and has_word(
        lower,
        r"\bnegative\s+rows?\b",
        r"\bnegative\s+cases?\b",
        r"\bsanction_match\b",
        r"\bcontractor\b",
        r"\brejected\b",
    )

def has_fixture_io_intent(text: str) -> bool:
    lower = text.lower()
    return has_decision_table_logic_intent(text) and has_word(
        lower,
        r"\bfixture\b",
        r"\bfixture\s+input\s+rows?\b",
        r"\bexpected[_ -]?decisions?\b",
        r"\bexpected\s+output\s+decisions?\b",
        r"\bstdout\s+json\b",
        r"\bstdout_json\b",
    )

def has_timezone_intent(text: str) -> bool:
    lower = text.lower()
    iana_prefixes = (
        "Africa", "America", "Antarctica", "Arctic", "Asia", "Atlantic",
        "Australia", "Europe", "Indian", "Pacific", "Etc",
    )
    iana_zone = bool(re.search(rf"\b(?:{'|'.join(iana_prefixes)})/[A-Za-z_]+(?:/[A-Za-z_]+)?\b", text))
    return (
        iana_zone
        or has_word(lower, r"\btimezone\b", r"\btime\s+zone\b", r"\btz=", r"\butc\b", r"[+-]\d{2}:\d{2}")
        or has_chinese(text, "时区", "本地时间")
    )

def has_time_boundary_intent(text: str) -> bool:
    lower = text.lower()
    if has_localized_format_only_intent(text):
        return False
    date_signal = bool(re.search(r"\b\d{4}-\d{2}-\d{2}(?:[t\s]\d{2}:\d{2}(?::\d{2})?)?", lower))
    range_signal = has_word(lower, r"\bdate\s+range\b", r"\btime\s+range\b", r"\bstart[_ -]?at\b", r"\bend[_ -]?at\b", r"\bcreated[_ -]?at\b", r"\bboundary\b") or bool(re.search(r"\bfrom\b.{0,120}\bto\b", lower, re.DOTALL))
    boundary_signal = has_word(lower, r"\binclusive\b", r"\bexclusive\b", r"\bexactly\s+at\b", r"\bmust\s+(?:appear|not\s+appear)\b", r"\bdst\b", r"\bdaylight\s+saving")
    return (date_signal and (range_signal or boundary_signal or has_timezone_intent(text))) or has_chinese(text, "日期范围", "时间范围", "边界", "包含边界", "排除边界", "夏令时")

def has_inclusive_start_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bstart\s+boundary\s+is\s+inclusive\b", r"\binclusive\s+start\b", r"\bstart[_ -]?at\b.*\binclusive\b", r"\bcreated\s+exactly\s+at\b.*\bmust\s+appear\b")
        or (has_word(lower, r"\binclusive\b") and has_word(lower, r"\bstart\b", r"\bfrom\b"))
        or has_chinese(text, "起始边界", "包含起始", "包含边界")
    )

def has_exclusive_end_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bend\s+boundary\s+is\s+exclusive\b", r"\bexclusive\s+end\b", r"\bend[_ -]?at\b.*\bexclusive\b", r"\bcreated\s+exactly\s+at\b.*\bmust\s+not\s+appear\b")
        or (has_word(lower, r"\bexclusive\b") and has_word(lower, r"\bend\b", r"\bto\b"))
        or has_chinese(text, "结束边界", "排除结束", "排除边界")
    )

def has_dst_boundary_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bdst\b", r"\bdaylight\s+saving\b", r"\bnonexistent\s+(?:dst\s+)?local\s+time\b", r"\bspring[- ]forward\b", r"\bfall[- ]back\b") or has_chinese(text, "夏令时", "不存在时间")

def has_money_precision_intent(text: str) -> bool:
    lower = text.lower()
    if has_localized_format_only_intent(text):
        return False
    money_signal = has_word(
        lower,
        r"\b(?:usd|eur|gbp|cny|jpy)\b",
        r"\bsubtotal_[a-z]{3}\b",
        r"\btotal_[a-z]{3}\b",
        r"\bmonetary\b",
        r"\bmoney\b",
        r"\bcents?\b",
        r"\bcurrency\b",
        r"\binvoice_totals\b",
        r"\bline\s+items?\b",
    )
    calculation_signal = has_word(
        lower,
        r"\bdecimal\s+arithmetic\b",
        r"\bround(?:ed|ing)?\b",
        r"\bhalf[- ]up\b",
        r"\btax\b",
        r"\bdiscount\b",
        r"\bfloating[- ]point\b",
        r"\bfloat(?:ing)?\s+drift\b",
        r"\btotal\b",
        r"\brate_id\b",
    )
    return bool(money_signal and calculation_signal) or has_chinese(text, "金额", "货币", "税费", "折扣", "四舍五入", "精度")

def has_rounding_rule_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bround(?:ed|ing)?\b", r"\bhalf[- ]up\b", r"\bcents?\b", r"\b2\s+decimals?\b") or has_chinese(text, "四舍五入", "保留两位", "分")

def has_discount_calculation_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bdiscount\b", r"\bdiscount_[a-z]{3}\b") or has_chinese(text, "折扣")

def has_tax_calculation_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\btax\b", r"\btax_[a-z]{3}\b") or has_chinese(text, "税", "税费")

def has_currency_conversion_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bcurrency\s+conversion\b", r"\bswitching\s+currency\b", r"\bconverted\b", r"\bfx[-_ ]?rates?\b", r"\brate_id\b", r"\bquote=\w{3}\b", r"\bbase=\w{3}\b")
        or (has_word(lower, r"\busd\b") and has_word(lower, r"\beur\b", r"\bgbp\b", r"\bcny\b", r"\bjpy\b"))
        or has_chinese(text, "汇率", "币种转换", "货币转换")
    )

def has_float_drift_guard_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bfloating[- ]point\s+drift\b", r"\bfloat(?:ing)?\s+drift\b", r"\b0\.3000000004\b", r"\bno\s+floating[- ]point\b") or has_chinese(text, "浮点误差")

def has_keyboard_navigation_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bkeyboard[- ]only\b", r"\bkeyboard\b", r"\btabs?\s+to\b", r"\btab\s+order\b", r"\bpress(?:es|ing)?\s+(?:enter|escape|tab)\b", r"\bwithout\s+using\s+a\s+mouse\b")
        or has_chinese(text, "键盘", "Tab", "回车", "无需鼠标")
    )

def has_focus_management_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bfocus\b", r"\bfocus\s+must\b", r"\breturn\s+to\s+the\b", r"\bfocus\s+restoration\b", r"\bfocused\b")
        or has_chinese(text, "焦点")
    )

def has_focus_trap_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bfocus\s+trap\b", r"\btrapped\b", r"\bremain\s+trapped\b", r"\btrap\s+focus\b")
        or has_chinese(text, "焦点陷阱", "焦点保持")
    )

def has_aria_semantics_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\baria[-_][a-z0-9_-]+\b", r"\baria\b", r"\brole\s*=\s*(?:dialog|button|menu|alertdialog)\b", r"\baccessible\s+names?\b", r"\blabeled\b", r"\blabelled\b", r"\bscreen\s+reader\b")
        or has_chinese(text, "无障碍", "可访问", "辅助技术", "屏幕阅读器")
    )

def has_accessibility_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\baccessibility\b", r"\ba11y\b")
        or has_keyboard_navigation_intent(text)
        or has_focus_management_intent(text)
        or has_aria_semantics_intent(text)
    )

def has_escape_close_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\besc(?:ape)?\b.*\bclos", r"\bpress(?:es|ing)?\s+escape\b", r"\bescape\s+closes\b")
        or has_chinese(text, "Escape", "关闭弹窗")
    )

def has_success_toast_intent(text: str) -> bool:
    lower = text.lower()
    return has_word(lower, r"\bsuccess\s+toast\b", r"\btoast\b.*\bsuccess\b", r"\bsuccess\s+message\b") or has_chinese(text, "成功提示")

def _collect_data_and_integrity_evidence(text: str, layers: list[str]) -> None:
    if has_analytics_intent(text):
        layers.extend(analytics_evidence_layers())
    if has_offline_sync_intent(text):
        layers.extend(offline_sync_evidence_layers())
    if has_schema_migration_intent(text):
        layers.extend(["schema_migration", "migration_plan", "schema_diff", "api_response"])
    if has_migration_dry_run_intent(text):
        layers.extend(["migration_dry_run", "stdout_json"])
    if has_schema_version_intent(text):
        layers.append("schema_version")
    if has_migration_backfill_intent(text):
        layers.append("backfill_count")
    if has_migration_batch_checkpoint_intent(text):
        layers.append("batch_checkpoint")
    if has_migration_concurrent_index_intent(text):
        layers.append("index_concurrently")
    if has_migration_foreign_key_intent(text):
        layers.append("foreign_key_constraint")
    if has_migration_not_null_intent(text):
        layers.extend(["not_null_constraint", "zero_null_verification"])
    if has_migration_rollback_intent(text):
        layers.append("rollback_plan")
    if has_backward_compatibility_intent(text):
        layers.append("backward_compatibility")
    if has_migration_metadata_leak_guard_intent(text):
        layers.append("forbidden text absence")
    if has_optimistic_ui_intent(text):
        layers.extend(["request body", "optimistic_update", "api_response"])
    if has_optimistic_pending_intent(text):
        layers.extend(["temp_id", "pending_state"])
    if has_optimistic_rollback_intent(text):
        layers.extend(["rollback", "failed_state", "retry_action", "no_persistence_side_effect"])
    if has_cache_invalidation_intent(text):
        layers.extend(["cache_invalidation", "stale_data_guard"])
    if has_no_success_toast_intent(text):
        layers.append("no_success_toast")
    if has_audit_integrity_intent(text):
        layers.extend(["request body", "audit_event", "audit_log", "api_response"])
    if has_audit_sequence_intent(text):
        layers.append("audit_sequence")
    if has_audit_append_only_intent(text):
        layers.append("append_only")
    if has_audit_hash_chain_intent(text):
        layers.extend(["hash_chain", "previous_hash", "event_hash"])
    if has_audit_canonical_json_intent(text):
        layers.append("canonical_json")
    if has_audit_tamper_denial_intent(text):
        layers.extend(["tamper_denial", "no_persistence_side_effect", "duplicate_absence"])
    if has_audit_retention_intent(text):
        layers.append("retention_policy")
    if has_audit_legal_hold_intent(text):
        layers.append("legal_hold")
    if has_audit_pseudonym_redaction_intent(text):
        layers.append("pii_redaction")
    if has_audit_integrity_leak_guard_intent(text):
        layers.append("forbidden text absence")
    if has_privacy_compliance_intent(text):
        layers.extend(["request body", "privacy_compliance", "api_response"])
    if has_privacy_export_intent(text):
        layers.extend(["privacy_export", "export_artifact", "export_manifest", "encrypted_export", "data_hash"])
    if has_privacy_erasure_intent(text):
        layers.extend(["erasure_request", "pseudonymization", "pii_redaction"])
    if has_privacy_session_invalidation_intent(text):
        layers.append("session_invalidation")
    if has_privacy_search_index_removal_intent(text):
        layers.append("search_index_removal")
    if has_privacy_cache_purge_intent(text):
        layers.append("cache_invalidation")
    if has_privacy_legal_hold_intent(text):
        layers.extend(["legal_hold", "retention_policy", "no_persistence_side_effect"])
    if has_privacy_secret_leak_guard_intent(text):
        layers.append("forbidden text absence")
    if has_graphql_intent(text):
        layers.extend(["request body", "graphql_operation", "graphql_variables", "api_response"])
    if has_graphql_persisted_query_intent(text):
        layers.append("persisted_query_hash")
    if has_graphql_field_authorization_intent(text):
        layers.extend(["field_authorization", "graphql_errors", "partial_data", "forbidden text absence"])
    if has_graphql_partial_error_intent(text):
        layers.extend(["graphql_errors", "partial_data"])
    if has_graphql_batching_intent(text):
        layers.extend(["dataloader_batch", "resolver_trace", "n_plus_one_guard"])
    if has_graphql_mutation_intent(text):
        layers.extend(["graphql_mutation", "idempotency_key"])
    if has_graphql_cache_version_intent(text):
        layers.extend(["optimistic_update", "version_token"])
    if has_graphql_subscription_intent(text):
        layers.extend(["graphql_subscription", "subscription_event", "sequence_order", "reconnect_replay", "duplicate_absence"])
    if has_graphql_introspection_guard_intent(text):
        layers.append("forbidden text absence")
    if has_graphql_secret_leak_guard_intent(text):
        layers.extend(["pii_redaction", "forbidden text absence"])
    if has_rag_grounding_intent(text):
        layers.extend(["request body", "rag_grounding", "api_response"])
    if has_rag_retrieval_trace_intent(text):
        layers.extend(["retrieval_trace", "retrieved_source_ids", "query_hash"])
    if has_rag_vector_index_intent(text):
        layers.extend(["vector_index", "embedding_model", "top_k", "score_threshold"])
    if has_rag_citation_intent(text):
        layers.extend(["source_citation", "citation_span", "source_excerpt_match"])
    if has_rag_document_version_intent(text):
        layers.extend(["document_version", "stale_source_guard"])
    if has_rag_hallucination_guard_intent(text):
        layers.append("hallucination_guard")
    if has_rag_prompt_injection_guard_intent(text):
        layers.extend(["prompt_injection_guard", "safety_trace", "forbidden text absence"])
    if has_rag_abstention_intent(text):
        layers.extend(["abstention", "insufficient_sources", "no_persistence_side_effect"])
    if has_rag_secret_leak_guard_intent(text):
        layers.append("forbidden text absence")


def _collect_identity_evidence(text: str, layers: list[str]) -> None:
    if has_api_key_intent(text):
        layers.extend(["request body", "api_key_secret_once", "api_response"])
    if has_api_key_hash_intent(text):
        layers.append("api_key_hash")
    if has_api_key_prefix_intent(text):
        layers.append("api_key_prefix")
    if has_api_key_scope_intent(text):
        layers.extend(["api_key_scopes", "api_key_scope_denial"])
    if has_api_key_expiry_intent(text):
        layers.append("api_key_expiry")
    if has_api_key_last_used_intent(text):
        layers.append("api_key_last_used")
    if has_api_key_revocation_intent(text):
        layers.extend(["api_key_revocation", "duplicate_absence"])
    if has_api_key_denial_intent(text):
        layers.extend(["api_key_replay_denial", "no_persistence_side_effect"])
    if has_api_key_intent(text) and has_word(text.lower(), r"\bsucceeds?\b", r"\breturn(?:s)?\s+200\b", r"\busing\s+the\s+env[- ]backed\s+api\s+key\b"):
        layers.append("api_key_auth_success")
    if has_api_key_secret_leak_guard_intent(text):
        layers.append("forbidden text absence")
    if has_one_time_token_intent(text):
        layers.extend(["request body", "one_time_token", "api_response"])
    if has_one_time_token_intent(text) and has_account_enumeration_guard_intent(text):
        layers.extend(["generic_success_copy", "account_enumeration_guard"])
    if has_one_time_token_hash_intent(text):
        layers.append("token_hash")
    if has_one_time_token_purpose_intent(text):
        layers.append("token_purpose")
    if has_one_time_token_expiry_intent(text):
        layers.append("token_expiry")
    if has_one_time_token_consumption_intent(text):
        layers.append("token_consumption")
    if has_one_time_token_replay_guard_intent(text):
        layers.extend(["token_replay_denial", "duplicate_absence", "no_persistence_side_effect"])
    if has_one_time_token_email_link_intent(text):
        layers.extend(["email_outbox", "email_link"])
    if has_one_time_token_password_update_intent(text):
        layers.append("password_hash_update")
    if has_one_time_token_session_invalidation_intent(text):
        layers.append("session_invalidation")
    if has_one_time_token_intent(text) and has_no_session_created_intent(text):
        layers.append("no_session_created")
    if has_one_time_token_secret_leak_guard_intent(text):
        layers.append("forbidden text absence")
    if has_saml_intent(text):
        layers.extend(["request body", "saml_response", "api_response"])
    if has_saml_request_intent(text):
        layers.extend(["redirect_location", "saml_authn_request", "saml_request", "relay_state", "acs_url", "sp_entity_id"])
    if has_saml_response_intent(text):
        layers.extend(["saml_assertion", "relay_state"])
    if has_saml_signature_intent(text):
        layers.extend(["xml_signature", "x509_certificate"])
    if has_saml_audience_recipient_intent(text):
        layers.extend(["audience_restriction", "destination", "recipient"])
    if has_saml_in_response_to_intent(text):
        layers.append("in_response_to")
    if has_saml_time_window_intent(text):
        layers.append("assertion_time_window")
    if has_saml_attribute_mapping_intent(text):
        layers.extend(["issuer", "name_id", "attribute_mapping"])
    if has_saml_replay_guard_intent(text):
        layers.extend(["request_consumption", "duplicate_absence", "no_persistence_side_effect"])
    if has_saml_intent(text) and has_word(text.lower(), r"\bcreate\s+session[_ -]?id\b", r"\bcreates?\s+(?:a\s+)?session\b", r"\bsession_id\s*="):
        layers.append("session_creation")
    if has_saml_secret_leak_guard_intent(text):
        layers.append("forbidden text absence")
    if has_webauthn_intent(text):
        layers.extend(["request body", "webauthn_challenge", "api_response"])
    if has_webauthn_origin_rp_intent(text):
        layers.extend(["rp_id", "origin"])
    if has_webauthn_assertion_intent(text):
        layers.extend(["credential_id", "client_data_json", "authenticator_data", "signature_verification"])
    if has_webauthn_user_verification_intent(text):
        layers.append("user_verification")
    if has_webauthn_sign_count_intent(text):
        layers.append("sign_count")
    if has_webauthn_challenge_intent(text) and has_word(text.lower(), r"\bconsume(?:d|s)?\b", r"\bconsumed\b", r"\breplay\b"):
        layers.extend(["challenge_consumption", "duplicate_absence"])
    if has_webauthn_attestation_intent(text):
        layers.extend(["attestation_object", "credential_public_key"])
    if has_webauthn_replay_guard_intent(text):
        layers.extend(["duplicate_absence", "no_persistence_side_effect"])
    if has_webauthn_intent(text) and has_word(text.lower(), r"\bcreate\s+session[_ -]?id\b", r"\bcreates?\s+(?:a\s+)?session\b", r"\bsession_id\s*="):
        layers.append("session_creation")
    if has_webauthn_secret_leak_guard_intent(text):
        layers.append("forbidden text absence")
    if has_mfa_intent(text):
        layers.extend(["request body", "mfa_challenge", "api_response"])
    if has_mfa_pending_intent(text):
        layers.append("mfa_pending")
    if has_totp_intent(text):
        layers.extend(["totp_code", "totp_time_window", "mfa_verification"])
    if has_mfa_intent(text) and has_word(text.lower(), r"\bclock_skew_seconds\b", r"\bclock\s+skew\b", r"\b30\s+second\b"):
        layers.append("clock_skew")
    if has_mfa_recovery_code_intent(text):
        layers.extend(["recovery_code", "recovery_code_consumption"])
    if has_mfa_required_denial_intent(text):
        layers.extend(["mfa_required_denial", "direct_api_denial", "no_persistence_side_effect"])
    if has_mfa_replay_guard_intent(text):
        layers.extend(["duplicate_absence", "no_persistence_side_effect"])
    if has_mfa_intent(text) and has_word(text.lower(), r"\bcreate\s+session[_ -]?id\b", r"\bcreates?\s+(?:full\s+)?session\b", r"\bsession_id\s*="):
        layers.append("session_creation")
    if has_mfa_secret_leak_guard_intent(text):
        layers.append("forbidden text absence")
    if has_oauth_intent(text):
        layers.extend(["redirect_location", "api_response"])
    if has_redirect_security_intent(text):
        layers.extend(["redirect_location", "redirect_uri_allowlist"])
    if has_open_redirect_guard_intent(text):
        layers.append("open_redirect_guard")
    if has_oauth_state_intent(text):
        layers.append("oauth_state")
    if has_oauth_nonce_intent(text):
        layers.append("oauth_nonce")
    if has_pkce_intent(text):
        layers.extend(["pkce_challenge", "pkce_verifier"])
    if has_oauth_code_exchange_intent(text):
        layers.extend(["authorization_code", "code_exchange"])
    if has_oauth_intent(text) and has_word(text.lower(), r"\bcreate\s+session[_ -]?id\b", r"\bcreates?\s+(?:a\s+)?session\b", r"\bsession_id\s*="):
        layers.append("session_creation")
    if has_oauth_intent(text) and has_word(text.lower(), r"\boauth_account\b", r"\baccount\s+link\b", r"\blink\b"):
        layers.append("oauth_account")
    if has_oauth_replay_guard_intent(text):
        layers.extend(["duplicate_absence", "no_persistence_side_effect"])
    if has_oauth_secret_leak_guard_intent(text):
        layers.append("forbidden text absence")
    if has_rate_limit_intent(text):
        layers.extend(["request body", "attempt_count", "rate_limit_key", "rate_limit_window", "rate_limited_response"])
    if has_retry_after_intent(text):
        layers.extend(["response_headers", "retry_after_header"])
    if has_lockout_intent(text):
        layers.extend(["lockout_state", "lockout_expiry", "cooldown_ui"])


def _collect_workflow_and_policy_evidence(text: str, layers: list[str]) -> None:
    if has_background_job_intent(text):
        layers.extend(["queued_status", "job_id", "background_worker"])
    if has_worker_intent(text):
        layers.append("worker_log")
    if has_artifact_generation_intent(text):
        layers.extend(artifact_generation_evidence_layers())
    if has_retry_backoff_intent(text):
        layers.extend(["retry_count", "backoff_schedule"])
    if has_dead_letter_intent(text):
        layers.append("dead_letter")
    if has_alert_outbox_intent(text):
        layers.extend(["alert_outbox", "correlation_id"])
    elif has_word(text.lower(), r"\bcorrelation[_ -]?id\b"):
        layers.append("correlation_id")
    if has_feature_flag_intent(text):
        layers.extend(["feature_flag", "flag_evaluation", "evaluation_id", "config_version"])
    if has_rollout_intent(text):
        layers.extend(["cohort_targeting", "variant"])
    if has_flag_default_off_intent(text):
        layers.extend(["default_off", "forbidden request absence"])
    if has_direct_api_denial_intent(text):
        layers.append("direct_api_denial")
    if has_stale_flag_guard_intent(text):
        layers.append("stale_flag_guard")
    if has_authorization_policy_intent(text):
        layers.extend(["authorization_policy", "policy_decision", "api_response"])
    if has_policy_matrix_intent(text):
        layers.append("policy_matrix")
    if has_policy_matched_rule_intent(text):
        layers.append("matched_rule")
    if has_deny_precedence_intent(text):
        layers.append("deny_precedence")
    if has_role_inheritance_intent(text):
        layers.append("role_inheritance")
    if has_resource_scope_intent(text):
        layers.append("resource_scope")
    if has_policy_obligation_intent(text):
        layers.append("obligation")
    if has_policy_cache_guard_intent(text):
        layers.extend(["policy_cache_key", "stale_policy_guard"])
    if has_financial_ledger_intent(text):
        layers.extend(["financial_ledger", "ledger_entry", "api_response"])
    if has_double_entry_intent(text):
        layers.extend(["double_entry", "ledger_balance"])
    if has_immutable_ledger_intent(text):
        layers.append("immutable_ledger")
    if has_reversal_ledger_intent(text):
        layers.append("reversal_entry")
    if has_ledger_balance_intent(text):
        layers.append("ledger_balance")
    if has_minor_unit_amount_intent(text):
        layers.extend(["minor_unit_amount", "no_float_drift"])
    if has_over_refund_denial_intent(text):
        layers.extend(["over_refund_denial", "forbidden request absence", "no_persistence_side_effect"])
    if has_settlement_reconciliation_intent(text):
        layers.extend(["settlement_event", "payout_reconciliation"])
    if has_quota_metering_intent(text):
        layers.extend(["request body", "quota_metering", "usage_counter", "api_response"])
    if has_quota_window_intent(text):
        layers.append("quota_window")
    if has_quota_remaining_intent(text):
        layers.append("quota_remaining")
    if has_atomic_usage_increment_intent(text):
        layers.extend(["atomic_increment", "counter_version"])
    if has_quota_exceeded_denial_intent(text):
        layers.extend(["quota_exceeded_denial", "forbidden request absence", "no_persistence_side_effect"])
    if has_no_negative_quota_intent(text):
        layers.append("no_negative_remaining")
    if has_billing_usage_event_intent(text):
        layers.append("billing_usage_event")
    if has_quota_reset_boundary_intent(text):
        layers.append("reset_boundary")
    if has_transaction_integrity_intent(text):
        layers.extend(["request body", "transaction_integrity", "transaction_id", "atomic_commit", "api_response"])
    if has_payment_authorization_intent(text):
        layers.append("payment_authorization")
    if has_inventory_reservation_intent(text):
        layers.append("inventory_reservation")
    if has_transaction_outbox_intent(text):
        layers.append("outbox_event")
    if has_outbox_dispatch_intent(text):
        layers.extend(["outbox_dispatch", "post_commit_publish", "publish_exactly_once"])
    if has_saga_compensation_intent(text):
        layers.extend(["saga_compensation", "compensation_event", "forbidden request absence", "no_persistence_side_effect"])
    if has_inventory_release_intent(text):
        layers.append("inventory_release")
    if has_authorization_void_intent(text):
        layers.append("authorization_void")
    if has_transaction_integrity_intent(text) and has_word(text.lower(), r"\border\b", r"\bstatus\b", r"\bstate\b", r"\bpending_payment\b", r"\bpayment_failed\b", r"\bpayment_authorized\b"):
        layers.append("order_state")
    if has_trace_correlation_intent(text):
        layers.extend(["trace_id", "correlation_id"])
    if has_subscription_billing_intent(text):
        layers.extend(["request body", "subscription_billing", "subscription_id", "current_plan", "target_plan", "subscription_version", "api_response"])
    if has_subscription_scheduled_change_intent(text):
        layers.extend(["billing_cycle", "billing_anchor", "scheduled_change"])
    if has_subscription_proration_intent(text):
        layers.extend(["proration_behavior", "proration_line_item", "unused_credit", "prorated_charge"])
    if has_subscription_invoice_preview_intent(text):
        layers.append("invoice_preview")
    if has_subscription_tax_intent(text):
        layers.extend(["tax_jurisdiction", "tax_rate", "tax_amount", "invoice_total", "calculation_version"])
    if has_subscription_scheduled_capture_intent(text):
        layers.extend(["payment_intent", "scheduled_capture"])
    if has_subscription_authorization_denial_intent(text):
        layers.append("authorization_denial")
    if has_agent_tool_intent(text):
        layers.extend(["request body", "agent_tool", "agent_session_id", "tool_call_event", "tool_call_id", "tool_name", "api_response", "stream", "terminal_status", "runtime"])
    if has_agent_tool_approval_intent(text):
        layers.extend(["approval_gate", "approval_id", "tool_result_event", "tool_result_id"])
    if has_agent_tool_cancellation_intent(text):
        layers.extend(["cancellation_event", "tool_execution_absence", "no_persistence_side_effect"])
    if has_agent_tool_redaction_intent(text):
        layers.extend(["tool_args_redaction", "args_hash", "forbidden text absence"])
    if has_agent_tool_authorization_denial_intent(text):
        layers.extend(["authorization_denial", "forbidden text absence", "tool_execution_absence", "no_persistence_side_effect"])
    if has_agent_tool_handoff_intent(text):
        layers.extend(["handoff_required", "handoff_id", "persistence"])
    if has_cache_consistency_intent(text):
        layers.extend(["request body", "response_headers", "cache_consistency", "api_response"])
    if has_etag_intent(text):
        layers.append("etag")
    if has_cache_control_intent(text):
        layers.append("cache_control")
    if has_if_none_match_intent(text):
        layers.append("if_none_match")
    if has_not_modified_denial_intent(text):
        layers.append("not_modified_denial")
    if has_cache_invalidation_event_intent(text):
        layers.append("cache_invalidation")
    if has_cache_key_intent(text):
        layers.append("cache_key")
    if has_surrogate_key_purge_intent(text):
        layers.append("surrogate_key_purge")
    if has_stale_revalidation_intent(text):
        layers.append("stale_revalidation")
    if has_stale_response_guard_intent(text):
        layers.append("stale_response_guard")
    if has_origin_fetch_intent(text):
        layers.append("origin_fetch")
    if has_cache_status_intent(text):
        layers.append("cache_status")
    if has_version_token_intent(text):
        layers.append("version_token")
    if has_ui_stale_absence_intent(text):
        layers.append("ui_stale_absence")
    if has_cache_consistency_intent(text) and has_word(text.lower(), r"\btrace[_ -]?id\b"):
        layers.append("trace_id")


def _collect_interaction_and_transport_evidence(text: str, layers: list[str]) -> None:
    if has_keyboard_navigation_intent(text):
        layers.append("keyboard_navigation")
    if has_focus_management_intent(text):
        layers.append("focus_management")
    if has_focus_trap_intent(text):
        layers.append("focus_trap")
    if has_aria_semantics_intent(text):
        layers.extend(["aria_semantics", "accessible_name"])
    if has_escape_close_intent(text) and not has_destructive_confirmation_intent(text):
        layers.extend(["keyboard_navigation", "focus_restoration"])
    if has_success_toast_intent(text):
        layers.append("success_toast")
    if explicit_visible_text_targets(text):
        layers.append("ui_text")
    if explicit_forbidden_visible_text_targets(text):
        layers.extend(["ui_text_absence", "forbidden text absence"])
    if has_realtime_intent(text):
        layers.extend(["realtime", "broadcast_event"])
    if has_multi_client_intent(text):
        layers.append("multi_client")
    if has_ordering_intent(text) and not has_webhook_security_intent(text) and not has_search_relevance_intent(text) and not has_scheduled_job_intent(text):
        layers.append("sequence_order")
    if has_reconnect_replay_intent(text) and not has_scheduled_job_intent(text):
        layers.extend(["reconnect_replay", "terminal_status"])
    if has_concurrency_intent(text) and not has_search_relevance_intent(text):
        layers.append("concurrent_requests")
    if has_conflict_response_intent(text) and not has_search_relevance_intent(text):
        layers.append("conflict_response")
    if has_atomicity_intent(text) and not has_search_relevance_intent(text):
        layers.append("atomicity")
    if has_locking_intent(text) and not has_search_relevance_intent(text):
        layers.append("locking")
    if has_no_negative_inventory_intent(text):
        layers.append("no_negative_inventory")
    if has_upload_intent(text):
        layers.extend(["file_fixture", "upload_request"])
        if has_word(text.lower(), r"\bfile\b", r"\bfixture\b", r"\battachments?\b", r"\.(?:pdf|csv|txt|json|xlsx|exe)\b"):
            layers.append("multipart_request")
    if has_word(text.lower(), r"\bmultipart/form-data\b", r"\bmultipart\b"):
        layers.append("multipart_request")
    if has_word(text.lower(), r"\battachment[_ -]?id\b"):
        layers.append("attachment_id")
    if has_file_security_intent(text):
        layers.extend(["malware_scan", "scan_status"])
    if has_scan_status_intent(text):
        layers.extend(["scan_status", "api_poll", "terminal_status"])
    if has_quarantine_intent(text):
        layers.extend(["quarantine", "scan_engine", "scan_version"])
    if has_storage_key_redaction_intent(text):
        layers.append("storage_key_redaction")
    if has_file_preview_intent(text):
        layers.extend(["preview_rendering", "signed_url"])
    if has_signed_url_intent(text):
        layers.append("signed_url")
    if has_nosniff_intent(text):
        layers.append("nosniff")
    if has_request_marker_intent(text):
        layers.append("request_marker")
    if has_progress_intent(text):
        layers.append("progress_indicator")
    if has_file_validation_intent(text):
        layers.append("file_validation")
        if has_word(text.lower(), r"\bfile\s+size\b", r"\blarger\s+than\s+\d+\s*(?:mb|gb)\b", r"\bsize\s+limit\b"):
            layers.append("file_size_validation")
    if has_download_intent(text):
        layers.extend(["download_file", "file_hash"])
    if has_response_header_intent(text):
        layers.append("response_headers")
        lower = text.lower()
        if "content-type" in lower:
            layers.append("content_type")
        if "content-disposition" in lower or "filename" in lower:
            layers.append("filename")
        if "content-disposition" in lower:
            layers.append("content_disposition")
        if has_nosniff_intent(text):
            layers.append("nosniff")
    if has_csv_content_intent(text):
        layers.extend(["csv_schema", "row_count"])
    if has_pii_redaction_intent(text):
        layers.extend(["pii_redaction", "forbidden text absence"])
    if has_webhook_security_intent(text):
        layers.extend(["request body", "request_headers", "webhook_security", "signature_validation", "api_response"])
    if has_hmac_signature_intent(text):
        layers.append("hmac_signature")
    if has_raw_body_integrity_intent(text):
        layers.append("raw_body_integrity")
    if has_timestamp_tolerance_intent(text):
        layers.append("timestamp_tolerance")
    if has_replay_window_intent(text):
        layers.append("replay_window")
    if has_signature_version_intent(text):
        layers.append("signature_version")
    if has_webhook_secret_leak_guard_intent(text):
        layers.append("forbidden text absence")
    if has_request_header_intent(text):
        layers.append("request_headers")
    if has_signature_validation_intent(text):
        layers.append("signature_validation")
    if has_csrf_intent(text):
        layers.extend(["csrf_token", "csrf_header"])
    if has_csrf_denial_intent(text):
        layers.append("csrf_denial")
    if has_session_security_intent(text):
        layers.append("session_cookie")
    if has_session_rotation_intent(text):
        layers.append("session_rotation")
    if has_logout_invalidation_intent(text):
        layers.append("logout_invalidation")
    if has_cookie_security_intent(text):
        layers.extend(["session_cookie", "cookie_flags", "response_headers"])
    if has_no_session_created_intent(text):
        layers.append("no_session_created")
    if has_account_enumeration_guard_intent(text):
        layers.extend(["generic_error_copy", "account_enumeration_guard"])
    if has_secret_leak_guard_intent(text):
        layers.append("forbidden text absence")


def _collect_operation_and_localization_evidence(text: str, layers: list[str]) -> None:
    if has_bulk_action_intent(text):
        layers.extend(["selection_state", "selected_count"])
    if has_selected_scope_intent(text):
        layers.extend(["selected_scope", "unselected_unchanged"])
    if has_destructive_confirmation_intent(text):
        layers.extend(["confirmation_modal", "destructive_action_guard"])
        if has_negative_request_intent(text) or has_escape_close_intent(text):
            layers.append("forbidden request absence")
    if has_operation_id_intent(text):
        layers.append("operation_id")
    if has_soft_delete_intent(text):
        layers.extend(["soft_delete", "deleted_at", "deleted_by"])
    if has_undo_intent(text):
        layers.extend(["undo_action", "undo_restoration", "operation_id"])
    if has_idempotency_intent(text):
        layers.extend(["idempotency_key", "duplicate_absence"])
    if has_resource_creation_intent(text):
        layers.append("request body")
    if has_same_runtime_object_intent(text):
        layers.extend(["extracted runtime id", "same runtime id"])
    if has_cleanup_intent(text):
        layers.extend(["cleanup", "cleanup_api"])
    if has_cleanup_verification_intent(text):
        layers.append("cleanup_verification")
    if has_always_run_cleanup_intent(text):
        layers.append("always_run_teardown")
    if has_cleanup_deletion_absence_intent(text):
        layers.append("deletion_absence")
    if has_cleanup_cascade_intent(text):
        layers.append("cascade_cleanup")
    if has_cleanup_outbox_absence_intent(text):
        layers.append("outbox_absence")
    if has_decision_table_logic_intent(text):
        layers.extend(["logic", "decision_table", "rule_matrix"])
    if has_rule_precedence_intent(text):
        layers.append("rule_precedence")
    if has_logic_boundary_case_intent(text):
        layers.append("boundary_cases")
    if has_logic_negative_case_intent(text):
        layers.append("negative_cases")
    if has_fixture_io_intent(text):
        layers.extend(["fixture_inputs", "expected_outputs", "stdout_json"])
    if has_scheduled_job_intent(text):
        layers.append("scheduled_job")
    if has_schedule_expression_intent(text):
        layers.extend(["schedule_expression", "next_run_at"])
    if has_scheduler_run_intent(text):
        layers.extend(["scheduler_run", "job_id", "terminal_status"])
    if has_run_key_intent(text):
        layers.append("run_key")
    if has_due_window_intent(text):
        layers.append("due_window")
    if has_catch_up_intent(text):
        layers.append("catch_up")
    if has_scheduler_lock_intent(text):
        layers.extend(["scheduler_lock", "duplicate_absence"])
    if has_scheduled_dry_run_intent(text):
        layers.extend(["dry_run", "no_persistence_side_effect"])
    if has_invoice_rows_intent(text):
        layers.append("invoice_rows")
    if has_localization_intent(text):
        layers.append("localization")
    if has_locale_switch_intent(text):
        layers.append("locale_switch")
    if has_translation_catalog_intent(text):
        layers.extend(["translation_catalog", "catalog_version"])
    if has_translation_fallback_guard_intent(text):
        layers.extend(["translation_key_absence", "fallback_absence"])
    if has_plural_rules_intent(text):
        layers.append("plural_rules")
    if has_rtl_layout_intent(text):
        layers.extend(["rtl_layout", "dir_attribute"])
    if has_lang_attribute_intent(text):
        layers.append("lang_attribute")
    if has_locale_format_intent(text):
        layers.extend(["currency_format", "date_time_format"])
    if has_stale_locale_guard_intent(text):
        layers.append("stale_locale_guard")
    if has_audit_log_intent(text):
        layers.append("audit_log")
    if has_notification_intent(text):
        layers.extend(["notification", "outbox"])
    if has_notification_policy_intent(text):
        layers.append("notification_policy")
    if has_notification_preference_intent(text):
        layers.extend(["notification_preferences", "preference_version"])
    if has_notification_consent_intent(text):
        layers.extend(["consent_state", "consent_source"])
    if has_notification_suppression_intent(text):
        layers.append("suppression_reason")
    if has_unsubscribe_token_intent(text):
        layers.append("unsubscribe_token")
    if has_notification_quiet_hours_intent(text):
        layers.extend(["quiet_hours", "send_after"])
    if has_notification_urgent_override_intent(text):
        layers.append("urgent_override")
    if has_notification_digest_intent(text):
        layers.extend(["digest_key", "digest_dedupe", "event_count"])
    if has_no_real_email_intent(text):
        layers.append("no_real_email")
    if has_no_write_or_duplicate_absence_intent(text):
        layers.append("duplicate_absence")
    if has_time_boundary_intent(text) and not has_audit_integrity_intent(text):
        layers.append("date_range_boundary")
    if has_timezone_intent(text):
        layers.append("timezone")
    if has_inclusive_start_intent(text):
        layers.append("inclusive_start")
    if has_exclusive_end_intent(text):
        layers.append("exclusive_end")
    if has_dst_boundary_intent(text):
        layers.append("dst_boundary")
    if has_money_precision_intent(text):
        layers.extend(["money_precision", "calculation_parity", "request body"])
    if has_rounding_rule_intent(text):
        layers.append("rounding_rule")
    if has_discount_calculation_intent(text):
        layers.append("discount_calculation")
    if has_tax_calculation_intent(text):
        layers.append("tax_calculation")
    if has_currency_conversion_intent(text):
        layers.extend(["currency_conversion", "rate_id"])


def _collect_query_and_revocation_evidence(text: str, layers: list[str]) -> None:
    if has_tenant_isolation_intent(text):
        layers.extend(["tenant_boundary", "data_isolation"])
        if has_word(text.lower(), r"\bworkspace\b"):
            layers.append("workspace_boundary")
    if has_cross_tenant_denial_intent(text):
        layers.append("cross_tenant_denial")
    if has_forbidden_text_absence_intent(text):
        layers.append("forbidden text absence")
    if has_no_persistence_side_effect_intent(text):
        layers.append("no_persistence_side_effect")
    if has_query_param_intent(text):
        layers.append("query_params")
    if has_search_relevance_intent(text):
        layers.extend(["request body", "search_relevance", "search_id", "api_response"])
    if has_search_ranking_intent(text):
        layers.extend(["result_order", "result_position", "relevance_score", "ranking_model"])
    if has_search_query_rewrite_intent(text):
        layers.extend(["query_rewrite", "canonical_query", "typo_tolerance", "synonym_expansion"])
    if has_search_facet_intent(text):
        layers.extend(["facet_counts", "total_count"])
    if has_search_sponsored_intent(text):
        layers.append("sponsored_disclosure")
    if has_search_stale_result_guard_intent(text):
        layers.append("stale_result_guard")
    if has_sort_intent(text):
        layers.append("sorting")
    if has_pagination_intent(text):
        layers.append("pagination")
    if has_empty_state_intent(text):
        layers.append("empty_state")
    if has_error_state_intent(text):
        layers.append("error_state")
    if has_stale_data_guard_intent(text):
        layers.append("stale_data_guard")
    if has_validation_error_ux_intent(text):
        layers.extend(["validation_error", "api_response"])
    if has_field_error_intent(text):
        layers.append("field_error")
    if has_input_value_preserved_intent(text):
        layers.append("input_value_preserved")
    if has_error_clear_on_edit_intent(text):
        layers.append("error_clear_on_edit")
    if has_browser_scroll_state_intent(text):
        layers.extend(["browser_state", "scroll_position", "reload"])
    if has_business_revocation_intent(text):
        layers.extend(["business_revocation", "state_transition", "persistence"])
    if has_revocation_budget_intent(text):
        layers.append("budget_balance")
    if has_revocation_link_status_intent(text):
        layers.append("link_status")


_EVIDENCE_LAYER_COLLECTORS: tuple[Callable[[str, list[str]], None], ...] = (
    _collect_data_and_integrity_evidence,
    _collect_identity_evidence,
    _collect_workflow_and_policy_evidence,
    _collect_interaction_and_transport_evidence,
    _collect_operation_and_localization_evidence,
    _collect_query_and_revocation_evidence,
)

def requirement_specific_evidence_layers(text: str) -> list[str]:
    """按领域收集证据层，并统一执行上下文过滤。"""
    layers: list[str] = []
    for collect_layers in _EVIDENCE_LAYER_COLLECTORS:
        collect_layers(text, layers)
    return filter_contextual_evidence_layers(text, layers)

def quoted_targets(text: str) -> list[str]:
    targets: list[str] = []
    for pattern in (
        r"[\"'“‘]([^\"'”’]{1,40})[\"'”’]\s*(?:button|按钮)",
        r"(?:button|按钮)\s*(?:labeled|named|called|labelled|名称为|名为|叫)?\s*[\"'“‘]([^\"'”’]{1,40})[\"'”’]",
        r"(?:click|press|tap|点击)\s*[\"'“‘]([^\"'”’]{1,40})[\"'”’]",
    ):
        for match in re.finditer(pattern, text, re.IGNORECASE):
            targets.append(match.group(1))
    return targets

def clean_visible_text_target(value: str) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip(" `*_[]()（）:：")
    text = text.strip()
    if not text or len(text) > 120:
        return ""
    if PATH_RE.fullmatch(text) or METHOD_PATH_RE.search(text):
        return ""
    return text

def forbidden_visible_text_trigger_re() -> re.Pattern[str]:
    return re.compile(
        r"(?:"
        r"\b(?:must|should|shall|can|could|does|do|did|will|would)\s+not\s+(?:show|display|render|include|contain|appear|leak)\b"
        r"|"
        r"\b(?:must|should|shall)\s+not\s+be\s+(?:shown|displayed|rendered|visible)\b"
        r"|"
        r"\bnot\s+(?:shown|displayed|rendered|visible)\b"
        r"|"
        r"\bwithout\s+(?:showing|displaying|rendering|including|appearing|leaking)\b"
        r"|"
        r"(?:不能|不得|不要|不应)(?:显示|展示|出现|包含|泄露)"
        r")",
        re.IGNORECASE,
    )

def positive_visible_text_trigger_re() -> re.Pattern[str]:
    return re.compile(
        r"(?:"
        r"\b(?:must|should|shall|will)\s+(?:show|display|render|include|contain)\b"
        r"|"
        r"\b(?:shows?|displays?|renders?|sees?|visible|contains?)\b"
        r"|"
        r"\b(?:toast|message|copy)\s+(?:says?|shows?|displays?)\b"
        r"|"
        r"(?:显示|展示|看到|提示|文案)"
        r")",
        re.IGNORECASE,
    )

def explicit_forbidden_visible_text_targets(text: str) -> list[str]:
    value = str(text or "")
    targets: list[str] = []
    forbidden_re = forbidden_visible_text_trigger_re()
    positive_re = positive_visible_text_trigger_re()
    quoted_re = re.compile(r"[\"'“‘]([^\"'”’]{1,120})[\"'”’]")
    suffix_forbidden_re = re.compile(
        r"^\s*(?:"
        r"(?:must|should|shall|can|could|does|do|did|will|would)\s+not\s+(?:show|display|render|include|contain|appear|leak)"
        r"|(?:must|should|shall)\s+not\s+be\s+(?:shown|displayed|rendered|visible)"
        r"|(?:不能|不得|不要|不应)(?:显示|展示|出现|包含|泄露)"
        r")\b",
        re.IGNORECASE,
    )
    for match in quoted_re.finditer(value):
        cleaned = clean_visible_text_target(match.group(1))
        if not cleaned:
            continue
        prefix = value[max(0, match.start() - 180):match.start()]
        suffix = value[match.end():match.end() + 120]
        forbidden_matches = list(forbidden_re.finditer(prefix))
        positive_matches = list(positive_re.finditer(prefix))
        last_forbidden = forbidden_matches[-1] if forbidden_matches else None
        positive_after_forbidden = bool(
            last_forbidden
            and any(positive.start() >= last_forbidden.end() for positive in positive_matches)
        )
        prefix_marks_forbidden = bool(last_forbidden and not positive_after_forbidden)
        suffix_marks_forbidden = bool(suffix_forbidden_re.search(suffix))
        if (prefix_marks_forbidden or suffix_marks_forbidden) and cleaned not in targets:
            targets.append(cleaned)
    return targets

def explicit_visible_text_targets(text: str) -> list[str]:
    value = str(text or "")
    forbidden_targets = set(explicit_forbidden_visible_text_targets(value))
    targets: list[str] = []
    patterns = [
        r"(?:shows?|displays?|renders?|sees?|visible|contains?|must\s+show|must\s+display|"
        r"toast(?:\s+(?:says?|shows?|displays?))?|message(?:\s+(?:says?|shows?|displays?))?|"
        r"copy(?:\s+(?:says?|shows?|displays?))?)"
        r"[^\"'“‘]{0,100}[\"'“‘]([^\"'”’]{1,120})[\"'”’]",
        r"[\"'“‘]([^\"'”’]{1,120})[\"'”’]\s*(?:success\s+)?(?:toast|message|copy|text|label)\b",
        r"(?:显示|展示|看到|提示|文案)[^\"'“‘]{0,80}[\"'“‘]([^\"'”’]{1,120})[\"'”’]",
        r"[\"'“‘]([^\"'”’]{1,120})[\"'”’]\s*(?:成功提示|提示|文案)",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, value, re.IGNORECASE):
            cleaned = clean_visible_text_target(match.group(1))
            if cleaned and cleaned not in forbidden_targets and cleaned not in targets:
                targets.append(cleaned)
    return targets

def append_visible_text_assertion_steps(
    steps: list[dict[str, Any]],
    *,
    test_id: str,
    req_id: str,
    texts: list[str],
    id_prefix: str,
) -> None:
    for index, visible_text in enumerate(texts, 1):
        steps.append({
            "action": "expectText",
            "id": f"{id_prefix}-text-{index}",
            "testIds": [test_id],
            "requirementIds": [req_id],
            "text": visible_text,
            "evidenceType": "ui_text",
            "proves": f"The page shows the required visible text `{visible_text}` for {req_id}.",
        })

def append_forbidden_visible_text_assertion_steps(
    steps: list[dict[str, Any]],
    *,
    test_id: str,
    req_id: str,
    texts: list[str],
    id_prefix: str,
) -> None:
    for index, forbidden_text in enumerate(texts, 1):
        steps.append({
            "action": "expectHidden",
            "id": f"{id_prefix}-hidden-text-{index}",
            "testIds": [test_id],
            "requirementIds": [req_id],
            "text": forbidden_text,
            "evidenceType": "ui_text_absence",
            "proves": f"The page does not show forbidden visible text `{forbidden_text}` for {req_id}.",
        })

def clean_button_name(value: str) -> str:
    text = re.sub(r"\s+", " ", value).strip(" `*_[]()（）:：-.,;，。；")
    text = re.sub(r"^.*\band\s+the\s+", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^(?:the|a|an)\s+", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+(?:button|btn)$", "", text, flags=re.IGNORECASE)
    text = text.strip(" `*_[]()（）:：-.,;，。；")
    tokens = set(re.findall(r"[a-z]+", text.lower()))
    if tokens.intersection({"user", "can", "should", "must", "open", "click", "press", "tap"}):
        return ""
    if text.lower() in {"the", "a", "an", "this", "that", "target", "button", "btn", "primary", "secondary", "action", "primary action", "main action"}:
        return ""
    return text if 1 <= len(text) <= 40 else ""

def infer_button_name(text: str) -> str | None:
    searchable = PATH_RE.sub(" ", text)
    searchable = re.sub(r"\s+", " ", searchable).strip()

    for target in quoted_targets(searchable):
        cleaned = clean_button_name(target)
        if cleaned:
            return cleaned

    patterns = [
        r"\bclicks?\s+(?:the\s+)?([A-Za-z][A-Za-z0-9 _.-]{0,30})\s+button\b",
        r"\bclicks?\s+(?:the\s+)?([A-Za-z][A-Za-z0-9 _.-]{0,30})(?:\s*,|\s+and|\s+then|\s*$)",
        r"\bpress(?:es)?\s+(?:the\s+)?([A-Za-z][A-Za-z0-9 _.-]{0,30})\s+button\b",
        r"\btaps?\s+(?:the\s+)?([A-Za-z][A-Za-z0-9 _.-]{0,30})\s+button\b",
        r"\b([A-Za-z][A-Za-z0-9 _.-]{0,30})\s+button\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, searchable, re.IGNORECASE)
        if match:
            cleaned = clean_button_name(match.group(1))
            if cleaned:
                return cleaned

    chinese_patterns = [
        r"点击\s*([^\s，。；,.!?！？、]{1,16})\s*按钮",
        r"按下\s*([^\s，。；,.!?！？、]{1,16})\s*按钮",
        r"([^\s，。；,.!?！？、]{1,16})\s*按钮",
    ]
    for pattern in chinese_patterns:
        match = re.search(pattern, searchable)
        if match:
            cleaned = clean_button_name(match.group(1))
            if cleaned:
                return cleaned

    common_labels = [
        ("save", "Save"),
        ("submit", "Submit"),
        ("upload", "Upload"),
        ("send", "Send"),
        ("search", "Search"),
        ("sign in", "Sign in"),
        ("login", "Login"),
        ("log in", "Log in"),
        ("confirm", "Confirm"),
        ("continue", "Continue"),
        ("cancel", "Cancel"),
        ("close", "Close"),
        ("delete", "Delete"),
        ("create", "Create"),
        ("保存", "保存"),
        ("提交", "提交"),
        ("上传", "上传"),
        ("发送", "发送"),
        ("搜索", "搜索"),
        ("登录", "登录"),
        ("确认", "确认"),
        ("继续", "继续"),
        ("取消", "取消"),
        ("关闭", "关闭"),
        ("删除", "删除"),
        ("新建", "新建"),
    ]
    lower = searchable.lower()
    for needle, label in common_labels:
        if needle in lower or needle in searchable:
            return label
    return None

def path_is_stream(path: str) -> bool:
    lower = path.lower().strip("/")
    segments = [segment for segment in re.split(r"[/?#]+", lower) if segment]
    if "audit" in segments and "events" in segments:
        return False
    return any(segment in STREAM_PATH_SEGMENTS for segment in segments)

def path_is_graphql_endpoint(path: str) -> bool:
    lower = str(path or "").lower()
    route = re.split(r"[?#]", lower, maxsplit=1)[0]
    segments = [segment for segment in route.strip("/").split("/") if segment]
    return "graphql" in segments

def path_is_api(path: str) -> bool:
    return path.startswith("/api") or "/api/" in path or path_is_graphql_endpoint(path)

def path_has_api_context(text: str, path: str) -> bool:
    value = str(path or "").strip()
    if not value:
        return False
    lower = text.lower()
    candidates = [value.lower()]
    route_only = re.split(r"[?#]", value, maxsplit=1)[0].lower()
    if route_only and route_only not in candidates:
        candidates.append(route_only)
    for candidate in candidates:
        for match in re.finditer(re.escape(candidate), lower):
            if match.start() > 0 and lower[match.start() - 1] not in " \t\r\n`'\"([{<;:":
                continue
            if match.end() < len(lower) and lower[match.end()] not in " \t\r\n`'\".,;:)]}>!?&":
                continue
            before_window = lower[max(0, match.start() - 90): match.start()]
            after_window = lower[match.end(): min(len(lower), match.end() + 30)]
            if has_word(
                before_window,
                r"\bapi\b",
                r"\bendpoint\b",
                r"\bhttp\b",
                r"\brequest\b",
                r"\bwebhook\b",
            ) or has_chinese(before_window, "接口", "请求"):
                return True
            if has_word(after_window, r"\bendpoint\b"):
                return True
    return False

def path_is_api_for_text(text: str, path: str) -> bool:
    return path_is_api(path) or str(path or "") in method_endpoint_paths(text) or path_has_api_context(text, path)

def has_chinese_api_response_context_intent(text: str) -> bool:
    without_responsive = text.replace("响应式", "")
    return bool(
        re.search(r"响应(?!式)(?:体|数据|字段|内容|头|码|状态|中|里|包含|不得|不能|必须|应该|需要)?", without_responsive)
        or has_chinese(
            without_responsive,
            "返回数据",
            "返回结果",
            "返回 JSON",
            "返回JSON",
            "状态码",
            "接口返回",
            "接口响应",
        )
    )

def has_api_response_context_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_response_header_intent(text)
        or has_forbidden_text_absence_intent(text)
        or has_word(
            lower,
            r"\bhttp\s+\d{3}\b",
            r"\bstatus\s*=?\s*\d{3}\b",
            r"\bcontent[- ]type\b",
            r"\bapplication/json\b",
            r"\bjson\b",
            r"\bresponse\s+(?:body|data|json|field|payload)\b",
            r"\breturns?\s+(?:http\s+)?\d{3}\b",
            r"\breturns?\s+(?:json|application/json|data|field|body|payload)\b",
        )
        or has_chinese_api_response_context_intent(text)
    )

def ui_path(paths: list[str], text: str = "") -> str | None:
    for path in paths:
        if path_is_code_file(path):
            continue
        if path_is_api_for_text(text, path) or path_is_stream(path):
            continue
        if "{" in path or "}" in path:
            continue
        return path
    return None

def api_path(paths: list[str], text: str = "") -> str | None:
    for path in paths:
        if path_is_code_file(path):
            continue
        if path_is_stream(path):
            continue
        if path_is_api_for_text(text, path) and "{" not in path and "}" not in path:
            return path
    return None

def api_target(method_path: tuple[str, str] | None, paths: list[str], text: str = "") -> tuple[str, str]:
    if method_path:
        return method_path
    path = api_path(paths, text) or ""
    return "", path
