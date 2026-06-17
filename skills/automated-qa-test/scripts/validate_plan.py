#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


EVIDENCE_ACTIONS = {
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
}
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
    "ui",
    "interaction",
    "api",
    "stream",
    "persistence",
    "permission",
    "runtime",
    "responsive",
    "cleanup",
]


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
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")


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
    if has_any_strategy_term(text, ("user visible", "visible", "screenshot", "page", "screen", "view", "render", "rendered", "ui", "navigation")):
        dims.add("ui")
    if has_any_strategy_term(text, ("click", "button", "tap", "press", "interaction", "actionability", "clickable", "hit test", "form", "modal", "toast")):
        dims.add("interaction")
    if has_any_strategy_term(text, ("api", "http", "endpoint", "response", "request", "json", "poll", "same object")):
        dims.add("api")
    if has_any_strategy_term(text, ("stream", "streaming", "websocket", "sse", "answer_done", "answer_chunk", "terminal event")):
        dims.add("stream")
    if has_any_strategy_term(text, ("persist", "persisted", "persistence", "database", "db", "postgres", "session", "turn", "log", "stdout")):
        dims.add("persistence")
    if has_any_strategy_term(text, ("permission", "auth", "login", "role", "token", "credential", "authorized", "unauthorized", "authenticated", "authentication", "authorization")):
        dims.add("permission")
    if has_any_strategy_term(text, ("runtime", "console", "network", "error", "failed response", "request failure", "500", "exception")):
        dims.add("runtime")
    if has_any_strategy_term(text, ("responsive", "mobile", "desktop", "viewport", "breakpoint")):
        dims.add("responsive")
    if has_any_strategy_term(text, ("cleanup", "clean up", "teardown", "delete", "created test data")):
        dims.add("cleanup")
    if has_any_strategy_term(text, ("logic", "rule", "validation", "branch", "state transition", "ordering", "retry", "idempotency")):
        dims.add("logic")
    return dims


def has_strong_api_strategy_signal(text: str) -> bool:
    if has_any_strategy_term(text, ("api", "endpoint", "same object", "poll", "api path", "http api")):
        return True
    return bool(re.search(r"(^|[\s\"'`(])/(?:api|v\d+)/", text, re.IGNORECASE))


def strategy_dimensions_for_test(test: dict[str, Any]) -> set[str]:
    declared_type = str(test.get("type") or "").strip().lower()
    text = normalized_strategy_text(
        test.get("type"),
        test.get("expected"),
        test.get("steps"),
        test.get("required_evidence"),
        test.get("notes"),
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
    evidence_type = normalized_strategy_text(step.get("evidenceType") or step.get("evidence_type"), step.get("proves"))
    dims = strategy_dimensions_from_text(evidence_type)
    if action in {"goto", "expectText", "expectAnyText", "expectVisible", "expectHidden", "expectLocatorCount", "expectUrlContains", "screenshot", "dismissIfPresent"}:
        dims.add("ui")
    if action in {"clickText", "clickRole", "click", "clickAndWaitForResponse", "expectClickable", "fillLabel", "fillPlaceholder", "fill", "press"}:
        dims.add("interaction")
    if action in {"api", "pollApi", "waitForResponse", "clickAndWaitForResponse"}:
        dims.add("api")
    if action in {"websocket", "sse"}:
        dims.add("stream")
    if action == "command":
        dims.add("persistence")
    if action in {"expectNoConsoleErrors", "expectNoRequestFailures", "expectNoFailedResponses"}:
        dims.add("runtime")
    if action == "cleanupApi":
        dims.update({"api", "cleanup"})
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a QA probe plan against a requirement matrix before execution.")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--summary", help="Optional path to write plan-audit-summary.json")
    parser.add_argument("--allow-unsafe-command", action="store_true", help="Warn instead of fail for command steps that look destructive.")
    args = parser.parse_args()

    plan_path = Path(args.plan).expanduser().resolve()
    matrix_path = Path(args.matrix).expanduser().resolve()
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
            "plan": str(plan_path),
            "matrix": str(matrix_path),
            "requirement_count": 0,
            "test_count": 0,
            "scenario_count": 0,
            "step_count": 0,
            "mapped_executable_test_count": 0,
            "mapped_executable_requirement_count": 0,
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
            cmd_text = command_text(step.get("command") or step.get("cmd"))
            if isinstance(step.get("command") or step.get("cmd"), str):
                warnings.append(f"{location} uses shell string command; prefer array form for reproducibility.")
            if DESTRUCTIVE_COMMAND_RE.search(cmd_text):
                message = f"{location} command looks destructive: {cmd_text}"
                if args.allow_unsafe_command:
                    warnings.append(message)
                else:
                    errors.append(message)

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

    summary = {
        "plan": str(plan_path),
        "matrix": str(matrix_path),
        "requirement_count": len(requirements),
        "test_count": len(tests),
        "scenario_count": len(as_list(plan.get("scenarios"))),
        "step_count": len(steps),
        "mapped_executable_test_count": len(executable_test_ids),
        "mapped_executable_requirement_count": len(executable_requirement_ids),
        "storage_state_check_count": storage_state_check_count,
        "passed": not errors,
        "errors": errors,
        "warnings": warnings,
        "strategy_coverage": build_strategy_coverage(tests, test_step_dims),
    }

    write_summary(args.summary, summary)

    if errors:
        print(json.dumps(summary, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
