"""为 Playwright QA runner 提供单一默认工具注册表。"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .spec import (
    CleanupSemantics,
    RiskClass,
    ToolRegistry,
    ToolSpec,
)


def _object_schema(
    properties: Mapping[str, dict[str, Any]],
    *,
    required: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": dict(properties),
        "required": list(required),
        "additionalProperties": False,
    }


def _string(
    *,
    enum: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string"}
    if enum is not None:
        schema["enum"] = list(enum)
    return schema


def _integer() -> dict[str, Any]:
    return {"type": "integer"}


def _boolean() -> dict[str, Any]:
    return {"type": "boolean"}


def _string_array() -> dict[str, Any]:
    return {
        "type": "array",
        "items": {"type": "string"},
    }


def _cookie_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "name": _string(),
            "value": _string(),
            "url": _string(),
            "domain": _string(),
            "path": _string(),
            "expires": {"type": "number"},
            "httpOnly": _boolean(),
            "secure": _boolean(),
            "sameSite": _string(
                enum=("Strict", "Lax", "None"),
            ),
        },
        required=("name", "value"),
    )


def _common_output_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "status": _string(
                enum=("passed", "failed", "skipped"),
            ),
            "summary": _string(),
            "evidence_paths": _string_array(),
        },
        required=("status",),
    )


def _with_timeout(
    properties: Mapping[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    return {
        **properties,
        "timeoutMs": _integer(),
    }


def _spec(
    action: str,
    *,
    properties: Mapping[str, dict[str, Any]],
    required: tuple[str, ...],
    capabilities: tuple[str, ...],
    risk_class: RiskClass,
    required_authorizations: tuple[str, ...] = (
        "isolated_test_environment",
    ),
    read: tuple[str, ...] = (),
    write: tuple[str, ...] = (),
    side_effects: tuple[str, ...] = (),
    reversible: bool = True,
    idempotent: bool = True,
    default_timeout_seconds: float = 10,
    max_timeout_seconds: float = 60,
    output_limit_bytes: int = 262_144,
    evidence_types: tuple[str, ...] = ("runner_record",),
    cleanup_semantics: CleanupSemantics = CleanupSemantics.NONE,
) -> ToolSpec:
    return ToolSpec(
        action=action,
        version="runner-action@1",
        input_schema=_object_schema(
            _with_timeout(properties),
            required=required,
        ),
        output_schema=_common_output_schema(),
        capabilities=(
            "runner.playwright",
            *capabilities,
        ),
        risk_class=risk_class,
        required_authorizations=required_authorizations,
        read=read,
        write=write,
        side_effects=side_effects,
        reversible=reversible,
        idempotent=idempotent,
        default_timeout_seconds=default_timeout_seconds,
        max_timeout_seconds=max_timeout_seconds,
        output_limit_bytes=output_limit_bytes,
        evidence_types=evidence_types,
        executor_version="playwright_probe.mjs@1",
        cleanup_semantics=cleanup_semantics,
    )


def _default_specs() -> tuple[ToolSpec, ...]:
    locator = {"selector": _string()}
    ignore_patterns = {"ignorePatterns": _string_array()}
    request_target = {
        "method": _string(),
        "path": _string(),
        "url": _string(),
        "urlContains": _string(),
        "responseUrlContains": _string(),
    }
    api_fields = {
        "method": _string(),
        "path": _string(),
        "url": _string(),
        "expectStatus": _integer(),
        "captureBody": _boolean(),
    }

    return (
        _spec(
            "goto",
            properties={
                "path": _string(),
                "url": _string(),
                "waitUntil": _string(
                    enum=(
                        "load",
                        "domcontentloaded",
                        "networkidle",
                        "commit",
                    ),
                ),
            },
            required=("path",),
            capabilities=("browser.navigation",),
            risk_class=RiskClass.LOW,
            read=("http_response",),
            side_effects=("browser_navigation",),
            evidence_types=("browser_navigation",),
            max_timeout_seconds=120,
        ),
        _spec(
            "setLocalStorage",
            properties={
                "path": _string(),
                "origin": _string(),
            },
            required=("path",),
            capabilities=("browser.storage",),
            risk_class=RiskClass.MEDIUM,
            required_authorizations=(
                "browser_state_write",
                "isolated_test_environment",
            ),
            read=("browser_origin",),
            write=("browser_local_storage",),
            side_effects=("browser_state_change",),
            reversible=False,
            idempotent=False,
            evidence_types=("auth_setup",),
            cleanup_semantics=CleanupSemantics.REQUIRED,
        ),
        _spec(
            "addCookies",
            properties={
                "cookies": {
                    "type": "array",
                    "items": _cookie_schema(),
                },
            },
            required=("cookies",),
            capabilities=("browser.cookies",),
            risk_class=RiskClass.MEDIUM,
            required_authorizations=(
                "browser_state_write",
                "isolated_test_environment",
            ),
            write=("browser_cookies",),
            side_effects=("browser_state_change",),
            reversible=False,
            idempotent=False,
            evidence_types=("auth_setup",),
            cleanup_semantics=CleanupSemantics.REQUIRED,
        ),
        _spec(
            "clickText",
            properties={
                "text": _string(),
                "exact": _boolean(),
            },
            required=("text",),
            capabilities=("browser.interaction",),
            risk_class=RiskClass.MEDIUM,
            required_authorizations=(
                "browser_interaction",
                "isolated_test_environment",
            ),
            read=("dom",),
            write=("browser_page_state",),
            side_effects=("ui_click",),
            reversible=False,
            idempotent=False,
            evidence_types=("ui_interaction",),
        ),
        _spec(
            "clickRole",
            properties={
                "role": _string(),
                "name": _string(),
                "exact": _boolean(),
            },
            required=("role", "name"),
            capabilities=("browser.interaction",),
            risk_class=RiskClass.MEDIUM,
            required_authorizations=(
                "browser_interaction",
                "isolated_test_environment",
            ),
            read=("dom",),
            write=("browser_page_state",),
            side_effects=("ui_click",),
            reversible=False,
            idempotent=False,
            evidence_types=("ui_interaction",),
        ),
        _spec(
            "click",
            properties={
                **locator,
                "force": _boolean(),
            },
            required=("selector",),
            capabilities=("browser.interaction",),
            risk_class=RiskClass.MEDIUM,
            required_authorizations=(
                "browser_interaction",
                "isolated_test_environment",
            ),
            read=("dom",),
            write=("browser_page_state",),
            side_effects=("ui_click",),
            reversible=False,
            idempotent=False,
            evidence_types=("ui_interaction",),
        ),
        _spec(
            "clickAndWaitForResponse",
            properties={
                **locator,
                **request_target,
                "force": _boolean(),
                "responseTimeoutMs": _integer(),
                "clickTimeoutMs": _integer(),
                "expectStatus": _integer(),
            },
            required=("selector", "responseUrlContains"),
            capabilities=(
                "browser.interaction",
                "network.observe",
            ),
            risk_class=RiskClass.MEDIUM,
            required_authorizations=(
                "browser_interaction",
                "isolated_test_environment",
            ),
            read=("dom", "http_response"),
            write=("browser_page_state",),
            side_effects=("ui_click", "network_request"),
            reversible=False,
            idempotent=False,
            evidence_types=("ui_to_api",),
            max_timeout_seconds=120,
        ),
        _spec(
            "fillLabel",
            properties={
                "label": _string(),
                "value": _string(),
                "exact": _boolean(),
            },
            required=("label", "value"),
            capabilities=("browser.interaction",),
            risk_class=RiskClass.MEDIUM,
            required_authorizations=(
                "browser_interaction",
                "isolated_test_environment",
            ),
            read=("dom",),
            write=("browser_form_state",),
            side_effects=("ui_input",),
            reversible=True,
            idempotent=True,
            evidence_types=("ui_interaction",),
        ),
        _spec(
            "fillPlaceholder",
            properties={
                "placeholder": _string(),
                "value": _string(),
                "exact": _boolean(),
            },
            required=("placeholder", "value"),
            capabilities=("browser.interaction",),
            risk_class=RiskClass.MEDIUM,
            required_authorizations=(
                "browser_interaction",
                "isolated_test_environment",
            ),
            read=("dom",),
            write=("browser_form_state",),
            side_effects=("ui_input",),
            evidence_types=("ui_interaction",),
        ),
        _spec(
            "fill",
            properties={
                **locator,
                "value": _string(),
            },
            required=("selector", "value"),
            capabilities=("browser.interaction",),
            risk_class=RiskClass.MEDIUM,
            required_authorizations=(
                "browser_interaction",
                "isolated_test_environment",
            ),
            read=("dom",),
            write=("browser_form_state",),
            side_effects=("ui_input",),
            evidence_types=("ui_interaction",),
        ),
        _spec(
            "press",
            properties={"key": _string()},
            required=("key",),
            capabilities=("browser.interaction",),
            risk_class=RiskClass.MEDIUM,
            required_authorizations=(
                "browser_interaction",
                "isolated_test_environment",
            ),
            write=("browser_page_state",),
            side_effects=("keyboard_input",),
            reversible=False,
            idempotent=False,
            evidence_types=("ui_interaction",),
        ),
        _spec(
            "wait",
            properties={"ms": _integer()},
            required=("ms",),
            capabilities=("runner.control",),
            risk_class=RiskClass.LOW,
            evidence_types=("control",),
        ),
        _spec(
            "waitForLoadState",
            properties={
                "state": _string(
                    enum=(
                        "load",
                        "domcontentloaded",
                        "networkidle",
                    ),
                ),
            },
            required=("state",),
            capabilities=("browser.navigation",),
            risk_class=RiskClass.LOW,
            read=("browser_page_state",),
            evidence_types=("control",),
            max_timeout_seconds=120,
        ),
        _spec(
            "waitForResponse",
            properties={
                **request_target,
                "expectStatus": _integer(),
            },
            required=("responseUrlContains",),
            capabilities=("network.observe",),
            risk_class=RiskClass.LOW,
            read=("http_response",),
            side_effects=("network_observation",),
            evidence_types=("network",),
            max_timeout_seconds=120,
        ),
        _spec(
            "expectText",
            properties={
                "text": _string(),
                "exact": _boolean(),
            },
            required=("text",),
            capabilities=("browser.assertion",),
            risk_class=RiskClass.LOW,
            read=("dom",),
            evidence_types=("ui_assertion",),
        ),
        _spec(
            "expectAnyText",
            properties={
                "texts": _string_array(),
                "exact": _boolean(),
            },
            required=("texts",),
            capabilities=("browser.assertion",),
            risk_class=RiskClass.LOW,
            read=("dom",),
            evidence_types=("ui_assertion",),
        ),
        _spec(
            "expectVisible",
            properties=locator,
            required=("selector",),
            capabilities=("browser.assertion",),
            risk_class=RiskClass.LOW,
            read=("dom",),
            evidence_types=("ui_assertion",),
        ),
        _spec(
            "expectClickable",
            properties=locator,
            required=("selector",),
            capabilities=("browser.assertion",),
            risk_class=RiskClass.LOW,
            read=("dom", "browser_hit_test"),
            evidence_types=("ui_assertion",),
        ),
        _spec(
            "expectHidden",
            properties=locator,
            required=("selector",),
            capabilities=("browser.assertion",),
            risk_class=RiskClass.LOW,
            read=("dom",),
            evidence_types=("ui_assertion",),
        ),
        _spec(
            "expectLocatorCount",
            properties={
                **locator,
                "expectCount": _integer(),
                "expectAtLeast": _integer(),
                "expectAtMost": _integer(),
            },
            required=("selector",),
            capabilities=("browser.assertion",),
            risk_class=RiskClass.LOW,
            read=("dom",),
            evidence_types=("ui_assertion",),
        ),
        _spec(
            "expectUrlContains",
            properties={"text": _string()},
            required=("text",),
            capabilities=("browser.assertion",),
            risk_class=RiskClass.LOW,
            read=("browser_url",),
            evidence_types=("ui_assertion",),
        ),
        _spec(
            "expectNoConsoleErrors",
            properties=ignore_patterns,
            required=(),
            capabilities=("browser.runtime_assertion",),
            risk_class=RiskClass.LOW,
            read=("browser_console",),
            evidence_types=("runtime",),
        ),
        _spec(
            "expectNoRequest",
            properties={
                **request_target,
                "waitMs": _integer(),
            },
            required=("urlContains",),
            capabilities=("network.assertion",),
            risk_class=RiskClass.LOW,
            read=("network_requests",),
            evidence_types=("network",),
        ),
        _spec(
            "expectNoRequestFailures",
            properties=ignore_patterns,
            required=(),
            capabilities=("network.assertion",),
            risk_class=RiskClass.LOW,
            read=("network_failures",),
            evidence_types=("runtime",),
        ),
        _spec(
            "expectNoFailedResponses",
            properties=ignore_patterns,
            required=(),
            capabilities=("network.assertion",),
            risk_class=RiskClass.LOW,
            read=("http_responses",),
            evidence_types=("runtime",),
        ),
        _spec(
            "dismissIfPresent",
            properties={
                **locator,
                "force": _boolean(),
                "afterMs": _integer(),
                "once": _boolean(),
            },
            required=("selector",),
            capabilities=("browser.interaction",),
            risk_class=RiskClass.MEDIUM,
            required_authorizations=(
                "browser_interaction",
                "isolated_test_environment",
            ),
            read=("dom",),
            write=("browser_page_state",),
            side_effects=("ui_click",),
            reversible=False,
            idempotent=True,
            evidence_types=("ui_interaction",),
        ),
        _spec(
            "screenshot",
            properties={
                "name": _string(),
                "selector": _string(),
                "fullPage": _boolean(),
            },
            required=("name",),
            capabilities=("browser.capture",),
            risk_class=RiskClass.LOW,
            read=("rendered_page",),
            write=("run_scratch",),
            side_effects=("evidence_file_write",),
            evidence_types=("screenshot",),
            output_limit_bytes=5_242_880,
        ),
        _spec(
            "api",
            properties=api_fields,
            required=("path",),
            capabilities=("network.request",),
            risk_class=RiskClass.HIGH,
            required_authorizations=(
                "isolated_test_environment",
                "network_request",
            ),
            read=("http_response",),
            write=("remote_test_state",),
            side_effects=("network_request",),
            reversible=False,
            idempotent=False,
            evidence_types=("api_response",),
            max_timeout_seconds=120,
        ),
        _spec(
            "pollApi",
            properties={
                **api_fields,
                "pollIntervalMs": _integer(),
                "pollTimeoutMs": _integer(),
                "maxAttempts": _integer(),
            },
            required=("path",),
            capabilities=(
                "network.request",
                "runner.polling",
            ),
            risk_class=RiskClass.HIGH,
            required_authorizations=(
                "isolated_test_environment",
                "network_request",
            ),
            read=("http_response",),
            write=("remote_test_state",),
            side_effects=("repeated_network_request",),
            reversible=False,
            idempotent=False,
            evidence_types=("api_response",),
            max_timeout_seconds=180,
        ),
        _spec(
            "cleanupApi",
            properties={
                **api_fields,
                "alwaysRun": _boolean(),
            },
            required=("path", "expectStatus"),
            capabilities=(
                "network.request",
                "test.cleanup",
            ),
            risk_class=RiskClass.HIGH,
            required_authorizations=(
                "cleanup_execution",
                "isolated_test_environment",
                "network_request",
            ),
            read=("http_response",),
            write=("remote_test_state",),
            side_effects=("test_data_cleanup",),
            reversible=False,
            idempotent=True,
            evidence_types=("cleanup",),
            max_timeout_seconds=120,
            cleanup_semantics=CleanupSemantics.REQUIRED,
        ),
        _spec(
            "websocket",
            properties={
                "path": _string(),
                "url": _string(),
                "expectMessageTextContains": _string(),
                "waitMs": _integer(),
                "captureMessages": _boolean(),
            },
            required=("path",),
            capabilities=("network.websocket",),
            risk_class=RiskClass.MEDIUM,
            required_authorizations=(
                "isolated_test_environment",
                "network_request",
            ),
            read=("websocket_messages",),
            write=("remote_test_state",),
            side_effects=("websocket_connection",),
            reversible=True,
            idempotent=False,
            evidence_types=("websocket",),
            max_timeout_seconds=180,
            cleanup_semantics=CleanupSemantics.REQUIRED,
        ),
        _spec(
            "sse",
            properties={
                "path": _string(),
                "url": _string(),
                "expectMessageTextContains": _string(),
                "waitMs": _integer(),
                "captureMessages": _boolean(),
            },
            required=("path",),
            capabilities=("network.sse",),
            risk_class=RiskClass.MEDIUM,
            required_authorizations=(
                "isolated_test_environment",
                "network_request",
            ),
            read=("sse_messages",),
            side_effects=("sse_connection",),
            evidence_types=("sse",),
            max_timeout_seconds=180,
            cleanup_semantics=CleanupSemantics.REQUIRED,
        ),
        _spec(
            "command",
            properties={
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "cwd": _string(),
                "expectExitCode": _integer(),
                "expectStdoutContains": _string(),
                "expectStderrContains": _string(),
                "captureStdout": _boolean(),
                "captureStderr": _boolean(),
                "maxStdoutChars": _integer(),
                "maxStderrChars": _integer(),
            },
            required=("command",),
            capabilities=("process.command",),
            risk_class=RiskClass.HIGH,
            required_authorizations=(
                "command_execution",
                "isolated_test_environment",
            ),
            read=("declared_command_inputs",),
            write=("run_scratch",),
            side_effects=("local_process",),
            reversible=False,
            idempotent=False,
            evidence_types=("command",),
            default_timeout_seconds=30,
            max_timeout_seconds=300,
            output_limit_bytes=1_048_576,
            cleanup_semantics=CleanupSemantics.REQUIRED,
        ),
    )


DEFAULT_TOOL_SPECS = _default_specs()
DEFAULT_TOOL_ACTIONS = frozenset(
    spec.action
    for spec in DEFAULT_TOOL_SPECS
)
DEFAULT_EVIDENCE_ACTIONS = frozenset(
    {
        "goto",
        "setLocalStorage",
        "addCookies",
        "clickText",
        "clickRole",
        "click",
        "clickAndWaitForResponse",
        "fillLabel",
        "fillPlaceholder",
        "fill",
        "press",
        "waitForResponse",
        "expectText",
        "expectAnyText",
        "expectVisible",
        "expectClickable",
        "expectHidden",
        "expectLocatorCount",
        "expectUrlContains",
        "expectNoConsoleErrors",
        "expectNoRequest",
        "expectNoRequestFailures",
        "expectNoFailedResponses",
        "screenshot",
        "api",
        "pollApi",
        "cleanupApi",
        "websocket",
        "sse",
        "command",
        "dismissIfPresent",
    },
)


def build_default_tool_registry() -> ToolRegistry:
    """返回包含 runner 全部已知 action 的新注册表。"""

    return ToolRegistry(DEFAULT_TOOL_SPECS)
