#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import shlex
from datetime import datetime
from pathlib import Path
from typing import Any


SECRET_PATTERNS = [
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
    re.compile(r"((?:access[_-]?token|auth[_-]?token|session[_-]?token|api[_-]?key|secret)\s*[:=]\s*)[^\s\"',}]{8,}", re.IGNORECASE),
]
PATH_RE = re.compile(r"(?<![A-Za-z0-9_.-])(/[A-Za-z0-9_~{}:.-]+(?:/[A-Za-z0-9_~{}:.-]+)*)")
METHOD_PATH_RE = re.compile(r"\b(GET|HEAD|POST|PUT|PATCH|DELETE)\s+(/[A-Za-z0-9_~{}:.-]+(?:/[A-Za-z0-9_~{}:.-]+)*)", re.IGNORECASE)
STREAM_PATH_SEGMENTS = {"ws", "websocket", "sse", "stream", "events"}
SEMANTIC_ARTIFACTS_NOT_EVIDENCE = "Planning/oracle/metrics handoff only; not current-run proof."


def try_read_text(path: Path) -> tuple[str | None, str | None]:
    if not path.exists():
        return None, "missing"
    if path.is_dir():
        return None, "path_is_directory"
    try:
        return path.read_text(encoding="utf-8"), None
    except OSError as exc:
        return None, f"read_error: {exc}"


def file_sha256(path: Path) -> str | None:
    if not path.exists() or path.is_dir():
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def source_binding(path: Path, role: str) -> dict[str, Any]:
    return {
        "role": role,
        "path": str(path),
        "exists": path.exists() and not path.is_dir(),
        "sha256": file_sha256(path),
        "size_bytes": path.stat().st_size if path.exists() and not path.is_dir() else None,
    }


def attach_semantic_integrity(
    artifact: dict[str, Any],
    *,
    role: str,
    bindings: dict[str, dict[str, Any]],
) -> None:
    artifact["artifact_role"] = role
    artifact["not_evidence"] = True
    artifact["integrity_note"] = SEMANTIC_ARTIFACTS_NOT_EVIDENCE
    artifact["source_bindings"] = bindings


def write_semantic_artifacts(run_dir: Path, artifacts: dict[str, Any]) -> None:
    requirement_path = run_dir / "requirement.md"
    matrix_path = run_dir / "test-matrix.json"
    plan_path = run_dir / "test-plan.json"
    base_bindings = {
        "requirement": source_binding(requirement_path, "requirement_source"),
        "matrix": source_binding(matrix_path, "test_matrix"),
        "plan": source_binding(plan_path, "test_plan"),
    }

    business_model = artifacts["business_model"]
    attach_semantic_integrity(business_model, role="business_planning_context", bindings=dict(base_bindings))
    (run_dir / "business-model.json").write_text(json.dumps(business_model, indent=2, ensure_ascii=False), encoding="utf-8")

    oracle_model = artifacts["oracle_model"]
    oracle_bindings = dict(base_bindings)
    oracle_bindings["business_model"] = source_binding(run_dir / "business-model.json", "business_planning_context")
    attach_semantic_integrity(oracle_model, role="oracle_contract_context", bindings=oracle_bindings)
    (run_dir / "oracle-model.json").write_text(json.dumps(oracle_model, indent=2, ensure_ascii=False), encoding="utf-8")

    qa_metrics = artifacts["qa_metrics"]
    metrics_bindings = dict(oracle_bindings)
    metrics_bindings["oracle_model"] = source_binding(run_dir / "oracle-model.json", "oracle_contract_context")
    attach_semantic_integrity(qa_metrics, role="qa_planning_metrics", bindings=metrics_bindings)
    (run_dir / "qa-metrics.json").write_text(json.dumps(qa_metrics, indent=2, ensure_ascii=False), encoding="utf-8")

    closeout_candidates = artifacts["closeout_candidates"]
    closeout_bindings = dict(metrics_bindings)
    closeout_bindings["qa_metrics"] = source_binding(run_dir / "qa-metrics.json", "qa_planning_metrics")
    attach_semantic_integrity(closeout_candidates, role="human_confirmed_closeout_candidates", bindings=closeout_bindings)
    (run_dir / "closeout-candidates.json").write_text(json.dumps(closeout_candidates, indent=2, ensure_ascii=False), encoding="utf-8")


def load_text(path: str | None, inline: str | None) -> tuple[str, list[dict[str, str]]]:
    parts: list[str] = []
    input_errors: list[dict[str, str]] = []
    if path:
        source_path = Path(path).expanduser()
        text, read_error = try_read_text(source_path)
        if read_error:
            input_errors.append({"name": "requirement", "path": str(source_path), "error": read_error})
        elif text is not None:
            parts.append(text)
    if inline:
        parts.append(inline)
    return "\n\n".join(part.strip() for part in parts if part and part.strip()), input_errors


def redact(text: str) -> str:
    value = text
    for pattern in SECRET_PATTERNS:
        value = pattern.sub(lambda match: match.group(1) + "[REDACTED]" if match.groups() else "[REDACTED]", value)
    return value


def clean_line(line: str) -> str:
    line = line.strip()
    line = re.sub(r"^#{1,6}\s+", "", line)
    line = re.sub(r"^[-*+]\s+", "", line)
    line = re.sub(r"^\d+[\.)]\s+", "", line)
    line = re.sub(r"^- \[[ xX]\]\s+", "", line)
    return redact(line.strip())


def split_requirement_points(text: str) -> list[dict[str, Any]]:
    raw_lines = [line for line in text.splitlines() if line.strip()]
    candidates: list[tuple[str, str]] = []
    for index, raw in enumerate(raw_lines, 1):
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue
        if re.match(r"^(#{1,6}\s+|[-*+]\s+|\d+[\.)]\s+|- \[[ xX]\]\s+)", stripped):
            cleaned = clean_line(stripped)
            if cleaned:
                candidates.append((f"line {index}", cleaned))
    if not candidates:
        pieces = re.split(r"(?<=[。！？.!?])\s+|\n{2,}", text.strip())
        for index, piece in enumerate(pieces, 1):
            cleaned = clean_line(piece)
            if cleaned:
                candidates.append((f"paragraph {index}", cleaned))
    if not candidates and text.strip():
        candidates.append(("requirement", clean_line(text)))

    seen: set[str] = set()
    points: list[dict[str, Any]] = []
    for source, cleaned in candidates:
        normalized = re.sub(r"\s+", " ", cleaned)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        points.append({"source": source, "text": normalized})
        if len(points) >= 24:
            break
    if not points:
        points.append({
            "source": "missing requirement",
            "text": "Requirement source was not provided; testing is blocked until the expected behavior is supplied.",
        })
    return points


def extract_paths(text: str) -> list[str]:
    return [match.group(1).rstrip(".,;，。；") for match in PATH_RE.finditer(text)]


def extract_method_path(text: str) -> tuple[str, str] | None:
    match = METHOD_PATH_RE.search(text)
    if not match:
        return None
    return match.group(1).upper(), match.group(2).rstrip(".,;，。；")


def extract_method_paths(text: str) -> list[tuple[str, str]]:
    return [
        (match.group(1).upper(), match.group(2).rstrip(".,;，。；"))
        for match in METHOD_PATH_RE.finditer(text)
    ]


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


def terminal_status_value(text: str) -> str | None:
    lower = text.lower()
    if re.search(r"\b(completed|complete|done)\b", lower) or has_chinese(text, "完成", "已完成"):
        return "completed"
    if re.search(r"\b(ready)\b", lower) or has_chinese(text, "就绪"):
        return "ready"
    if re.search(r"\b(succeeded|successful|success)\b", lower) or has_chinese(text, "成功"):
        return "succeeded"
    return None


def has_async_status_intent(text: str) -> bool:
    lower = text.lower()
    return (
        has_word(lower, r"\bpoll(?:ing)?\b", r"\beventually\b", r"\buntil\b", r"\bstatus\b", r"\bjob\b", r"\btask\b", r"\bcomplete(?:d)?\b", r"\bdone\b")
        or has_chinese(text, "轮询", "异步", "状态", "完成", "任务", "作业")
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


def has_word(text: str, *patterns: str) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def has_chinese(text: str, *terms: str) -> bool:
    return any(term in text for term in terms)


def has_click_intent(text: str) -> bool:
    lower = text.lower()
    lower_without_paths = PATH_RE.sub(" ", lower)
    return (
        has_word(
            lower_without_paths,
            r"\bclick(?:able|ed|ing)?\b",
            r"\bpress(?:ed|ing)?\b",
            r"\btap(?:ped|ping)?\b",
            r"\bbutton\b",
            r"\bsubmit\b",
            r"\bsave\b",
            r"\bsend\b",
        )
        or has_chinese(text, "点击", "可点", "按钮", "提交", "保存", "发送", "确认")
    )


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


def clean_button_name(value: str) -> str:
    text = re.sub(r"\s+", " ", value).strip(" `*_[]()（）:：-")
    text = re.sub(r"^(?:the|a|an)\s+", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+(?:button|btn)$", "", text, flags=re.IGNORECASE)
    text = text.strip(" `*_[]()（）:：-")
    tokens = set(re.findall(r"[a-z]+", text.lower()))
    if tokens.intersection({"user", "can", "should", "must", "open", "click", "press", "tap"}):
        return ""
    if text.lower() in {"the", "a", "an", "this", "that", "target", "primary", "secondary", "action", "primary action", "main action"}:
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
        r"\bclick\s+(?:the\s+)?([A-Za-z][A-Za-z0-9 _.-]{0,30})\s+button\b",
        r"\bpress\s+(?:the\s+)?([A-Za-z][A-Za-z0-9 _.-]{0,30})\s+button\b",
        r"\btap\s+(?:the\s+)?([A-Za-z][A-Za-z0-9 _.-]{0,30})\s+button\b",
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
        ("send", "Send"),
        ("search", "Search"),
        ("login", "Login"),
        ("log in", "Log in"),
        ("confirm", "Confirm"),
        ("cancel", "Cancel"),
        ("close", "Close"),
        ("delete", "Delete"),
        ("create", "Create"),
        ("保存", "保存"),
        ("提交", "提交"),
        ("发送", "发送"),
        ("搜索", "搜索"),
        ("登录", "登录"),
        ("确认", "确认"),
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
    return any(segment in STREAM_PATH_SEGMENTS for segment in segments)


def path_is_api(path: str) -> bool:
    return path.startswith("/api") or "/api/" in path


def classify(text: str, paths: list[str]) -> set[str]:
    lower = text.lower()
    lower_without_paths = PATH_RE.sub(" ", lower)
    tags: set[str] = set()
    stream_paths = [path for path in paths if path_is_stream(path)]
    api_like_paths = [path for path in paths if path_is_api(path) and not path_is_stream(path)]
    ui_like_paths = [path for path in paths if not path_is_api(path) and not path_is_stream(path)]
    stream_mentioned = bool(stream_paths) or has_word(lower, r"\bwebsocket\b", r"\bsse\b", r"\bstream\b", r"\bws\b", r"\banswer_done\b", r"\banswer_chunk\b") or has_chinese(lower, "流式")
    if api_like_paths or (not stream_mentioned and has_word(lower_without_paths, r"\bapi\b", r"\bendpoint\b", r"\bhttp\b")) or has_chinese(lower_without_paths, "接口"):
        tags.add("api")
    if stream_mentioned:
        tags.add("stream")
    if has_word(lower_without_paths, r"\bdb\b", r"\bdatabase\b", r"\bpostgres\b", r"\bsql\b", r"\bpersist(?:ed|ence)?\b", r"\bsessions?\b", r"\bturns?\b", r"\bsession[_ -]?id\b", r"\bturn[_ -]?id\b") or has_chinese(lower_without_paths, "数据库", "持久", "保存"):
        tags.add("persistence")
    if has_word(lower_without_paths, r"\blogin\b", r"\bauth(?:enticated|orized|orization)?\b", r"\btoken\b", r"\bpermission\b", r"\brole\b") or has_chinese(lower_without_paths, "登录", "权限", "鉴权"):
        tags.add("permission")
    if ui_like_paths or has_word(lower_without_paths, r"\bclick\b", r"\bbutton\b", r"\bvisible\b", r"\bmodal\b", r"\boverlay\b", r"\btoast\b", r"\bpage\b", r"\bscreen\b", r"\bview\b", r"\bshow\b", r"\bdisplay\b", r"\brender\b", r"\bform\b", r"\binput\b", r"\bdisabled\b", r"\bloading\b", r"\bui\b") or has_chinese(lower_without_paths, "页面", "按钮", "点击", "显示", "弹窗", "交互"):
        tags.add("ui")
    if has_word(lower_without_paths, r"\bconsole\b", r"\bnetwork\b", r"\berror\b", r"\bruntime\b", r"\b500\b") or has_chinese(lower_without_paths, "报错", "错误"):
        tags.add("runtime")
    if not tags:
        tags.add("logic")
    return tags


def ui_path(paths: list[str]) -> str | None:
    for path in paths:
        if path_is_api(path) or path_is_stream(path):
            continue
        if "{" in path or "}" in path:
            continue
        return path
    return None


def api_path(paths: list[str]) -> str | None:
    for path in paths:
        if path_is_stream(path):
            continue
        if path_is_api(path) and "{" not in path and "}" not in path:
            return path
    return None


def api_target(method_path: tuple[str, str] | None, paths: list[str]) -> tuple[str, str]:
    if method_path:
        return method_path
    path = api_path(paths) or ""
    return "", path


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
    patterns = [
        r"\b(?:an?\s+)?(authenticated\s+[A-Za-z][A-Za-z0-9 _-]{1,50}?)(?:\s+can|\s+should|\s+must|\s+opens?|\s+clicks?)\b",
        r"\b(?:an?\s+)?([A-Za-z][A-Za-z0-9 _-]{1,40}?\s+(?:operator|admin|manager|reviewer|approver|user|guest|merchant|customer|member))(?:\s+can|\s+should|\s+must|\s+cannot|\s+must not|\s+opens?|\s+clicks?)\b",
        r"\b(guest users?|anonymous users?|authenticated users?)\b",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            actor = re.sub(r"\s+", " ", match.group(1)).strip().lower()
            actor = re.sub(r"^(?:an?|the)\s+", "", actor)
            if actor and actor not in actors:
                actors.append(actor)
    for term in ("管理员", "运营", "商家", "游客", "用户", "审核员"):
        if term in text and term not in actors:
            actors.append(term)
    if not actors and re.search(r"\buser\b", text, re.IGNORECASE):
        actors.append("user")
    return actors


def extract_entities_from_text(text: str, paths: list[str]) -> list[str]:
    ignored = {
        "api", "v1", "v2", "id", "ws", "sse", "stream", "events",
        "approve", "create", "update", "delete", "submit", "save",
        "send", "search", "login", "logout", "refresh",
        "a", "an", "and", "or", "the", "from", "to", "with",
        "pending", "approved", "completed", "ready", "succeeded",
        "status", "state",
    }
    entities: list[str] = []
    for path in paths:
        for segment in re.split(r"[/{}?&#=.-]+", path):
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
    chinese_match = re.search(r"从\s*([^，。；\s]+)\s*(?:变为|到|至)\s*([^，。；\s]+)", text)
    if chinese_match:
        transitions.append({
            "requirement_id": req_id,
            "from": chinese_match.group(1),
            "to": chinese_match.group(2),
            "source": text,
        })
    return transitions


def extract_workflow_label(text: str, paths: list[str], tests: list[dict[str, Any]]) -> str:
    lower = text.lower()
    action_words = [
        "approve", "create", "update", "delete", "submit", "save", "send",
        "search", "login", "refresh", "persist", "complete", "upload",
    ]
    action = next((word for word in action_words if re.search(rf"\b{word}\b", lower)), "")
    if not action:
        for term in ("审批", "批准", "创建", "更新", "删除", "提交", "保存", "发送", "搜索", "刷新", "持久化", "完成", "上传"):
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


def evidence_layers_for_test_type(test_type: str) -> list[str]:
    mapping = {
        "ui": ["ui"],
        "logic": ["ui", "logic"],
        "interaction": ["ui_interaction"],
        "ui_to_api": ["ui_interaction", "api_response"],
        "api": ["api_response"],
        "api_followup": ["api_response"],
        "api_poll": ["api_response", "terminal_status"],
        "websocket": ["stream"],
        "sse": ["stream"],
        "persistence": ["persistence"],
        "permission": ["permission"],
        "runtime": ["runtime"],
        "cleanup": ["cleanup"],
        "input": ["input_artifact"],
    }
    return mapping.get(str(test_type), [str(test_type or "evidence")])


def weak_signals_for_layers(layers: list[str]) -> list[str]:
    weak: list[str] = []
    if "ui" in layers or "ui_interaction" in layers:
        weak.append("Visible text or screenshots without actionability/API/state evidence.")
    if "api_response" in layers:
        weak.append("HTTP status alone without response body, same-object id, or checked JSON evidence.")
    if "stream" in layers:
        weak.append("Prompt/request marker only, zero stream messages, or missing terminal event evidence.")
    if "persistence" in layers or "terminal_status" in layers:
        weak.append("Seed data, fallback text, or handwritten terminal-state notes without returned/persisted status evidence.")
    if "permission" in layers:
        weak.append("Single-role success without denied-role evidence when authorization is part of the requirement.")
    if "runtime" in layers:
        weak.append("Ignoring console/network failures without count-aware runtime disposition evidence.")
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
        paths = extract_paths(text)
        for actor in extract_actors_from_text(text):
            add_indexed_item(actor_index, actor, req_id, text)
        for entity in extract_entities_from_text(text, paths):
            add_indexed_item(entity_index, entity, req_id, text)
        for path in paths:
            if path_is_api(path) or path_is_stream(path):
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
            "source_requirement_ids": [req_id],
            "entry_points": [path for path in paths if path in entry_points],
            "api_paths": [path for path in paths if path in api_paths],
            "evidence_layers": sorted({layer for test in req_tests for layer in evidence_layers_for_test_type(str(test.get("type") or ""))}),
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
        layers = sorted({layer for test in req_tests for layer in evidence_layers_for_test_type(str(test.get("type") or ""))})
        oracle_requirements.append({
            "requirement_id": req_id,
            "requirement_text": req.get("text", ""),
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


def build_qa_metrics(requirements: list[dict[str, Any]], tests: list[dict[str, Any]], steps: list[dict[str, Any]], gaps: list[str], business_model: dict[str, Any], oracle_model: dict[str, Any]) -> dict[str, Any]:
    layer_counts = oracle_model.get("summary", {}).get("evidence_layer_counts", {})
    blocked_tests = [test for test in tests if test.get("status") == "Blocked"]
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


def scaffold(requirement: str, base_url: str, artifact_dir: Path, entry_path: str | None = None, persistence_command: str | None = None, allow_live_stream: bool = False, allow_mutating_api: bool = False) -> dict[str, Any]:
    points = split_requirement_points(requirement)
    requirements: list[dict[str, Any]] = []
    tests: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    gaps: list[str] = []
    test_index = 1
    default_entry_path = entry_path

    for req_index, point in enumerate(points, 1):
        req_id = f"R{req_index}"
        text = point["text"]
        paths = extract_paths(text)
        method_paths = extract_method_paths(text)
        method_path = method_paths[0] if method_paths else extract_method_path(text)
        response_method, response_path = api_target(method_path, paths)
        followup_method_path = next(
            (
                (method, path)
                for method, path in method_paths
                if method in {"GET", "HEAD"} and path_placeholders(path)
            ),
            None,
        )
        tags = classify(text, paths)
        req_tests: list[dict[str, Any]] = []
        click_intent = has_click_intent(text)
        button_name = infer_button_name(text) if click_intent else None
        page_path = ui_path(paths) or default_entry_path
        click_response_generated = False

        if "ui" in tags or "logic" in tags:
            path = page_path
            status = "Untested" if path else "Blocked"
            test = make_test(
                req_id,
                test_index,
                "ui" if "ui" in tags else "logic",
                point,
                status,
                f"User-visible behavior matches requirement: {text}",
                [f"Open `{path}` and capture visible state."] if path else ["Identify the user-facing entry path before execution."],
                ["screenshot", "UI assertion", "console/network summary"] + (["separate clickability evidence"] if click_intent else []),
            )
            req_tests.append(test)
            tests.append(test)
            if path:
                steps.extend([
                    {
                        "action": "goto",
                        "id": f"{test['id']}-open",
                        "testIds": [test["id"]],
                        "requirementIds": [req_id],
                        "path": path,
                        "evidenceType": "navigation",
                        "proves": f"The generated entry path `{path}` opens for {req_id}.",
                    },
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

            if click_intent:
                interaction_status = "Untested" if path and button_name else "Blocked"
                interaction_steps = (
                    [f"Verify the `{button_name}` button receives pointer events before any click."]
                    if path and button_name
                    else ["Identify a stable button label, role/name, selector, or test id before clickability can be proven."]
                )
                interaction_test = make_test(
                    req_id,
                    test_index,
                    "interaction",
                    point,
                    interaction_status,
                    f"Click target is actionable and not blocked by overlays for requirement: {text}",
                    interaction_steps,
                    ["ui_interaction", "center-point hit-test", "actionability check", "blocker evidence on failure"],
                )
                req_tests.append(interaction_test)
                tests.append(interaction_test)
                if path and button_name:
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
                    if not button_name:
                        gaps.append(f"{req_id}: clickability probe needs a stable button label, role/name, selector, or test id.")
                test_index += 1

                if response_path:
                    mutating_response = response_method in {"POST", "PUT", "PATCH", "DELETE"}
                    click_response_executable = bool(path and button_name and "{" not in response_path and "}" not in response_path and (not mutating_response or allow_mutating_api))
                    extra_click_response_tests = 0
                    if path and button_name and mutating_response and not allow_mutating_api:
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
                            "expectStatus": 200,
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
                                    "expectStatus": 200,
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
                    test_index += 1

        if "api" in tags:
            method, path = (response_method or "GET"), response_path
            safe_method = method in {"GET", "HEAD"}
            executable = bool(path) and "{" not in path and safe_method
            status = "Untested" if executable else "Blocked"
            reason = "Call the API endpoint and assert a successful status." if executable else "Identify a safe read-only endpoint or provide reversible test data."
            if click_response_generated:
                if not executable and method and method not in {"GET", "HEAD"} and not allow_mutating_api:
                    gaps.append(f"{req_id}: direct API probe for mutating `{method} {path}` skipped; use click-to-response with safe test data when authorized.")
            else:
                test = make_test(
                    req_id,
                    test_index,
                    "api",
                    point,
                    status,
                    f"{method} {path or '<endpoint>'} satisfies requirement: {text}",
                    [reason],
                    ["HTTP status", "response body", "checked JSON when schema is known"],
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
                        "expectStatus": 200,
                        "captureBody": True,
                        "evidenceType": "api_response",
                        "proves": f"`{method} {path}` returns a successful response for {req_id}.",
                    })
                else:
                    if method and method not in {"GET", "HEAD"} and not allow_mutating_api:
                        gaps.append(f"{req_id}: mutating API `{method} {path}` needs safe test data or explicit authorization.")
                    else:
                        gaps.append(f"{req_id}: API endpoint is missing or contains runtime placeholders.")
                test_index += 1

        if "stream" in tags:
            path = api_path(paths) or next((item for item in paths if "ws" in item.lower()), "")
            executable = bool(path) and allow_live_stream and "{" not in path
            status = "Untested" if executable else "Blocked"
            test = make_test(
                req_id,
                test_index,
                "websocket",
                point,
                status,
                f"The stream emits a terminal success event for: {text}",
                ["Open stream and require a terminal success event such as answer_done."] if executable else ["Provide stream endpoint, auth, and safe payload before execution."],
                ["captured stream messages", "terminal event", "runtime errors"],
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
                ["command stdout/stderr", "persisted terminal state", "event/log trail"],
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

        if "permission" in tags:
            test = make_test(
                req_id,
                test_index,
                "permission",
                point,
                "Blocked",
                f"Permission behavior satisfies requirement: {text}",
                ["Provide roles/accounts or auth state before execution."],
                ["authorized status", "unauthorized status", "UI/API denial evidence"],
            )
            req_tests.append(test)
            tests.append(test)
            gaps.append(f"{req_id}: permission test needs role/account fixtures.")
            test_index += 1

        if "runtime" in tags and not any(test["type"] == "ui" and test["status"] == "Untested" for test in req_tests):
            test = make_test(
                req_id,
                test_index,
                "runtime",
                point,
                "Blocked",
                f"Runtime errors are absent or explicitly dispositioned for: {text}",
                ["Attach runtime checks to an executable UI/API/stream probe."],
                ["console errors", "request failures", "failed responses", "logs"],
            )
            req_tests.append(test)
            tests.append(test)
            gaps.append(f"{req_id}: runtime checks need an executable parent probe.")
            test_index += 1

        requirements.append({
            "id": req_id,
            "source": f"requirement.md {point['source']}",
            "text": text,
            "risk": ", ".join(sorted(tags)),
            "test_ids": [test["id"] for test in req_tests],
            "status": status_for_tests(req_tests),
            **({"notes": "Generated requirement has no executable probe yet; see coverage gaps."} if status_for_tests(req_tests) == "Blocked" else {}),
        })

    plan = {
        "schemaVersion": 2,
        "baseUrl": base_url,
        "artifactDir": str(artifact_dir),
        "metadata": {
            "businessModel": "business-model.json",
            "oracleModel": "oracle-model.json",
            "qaMetrics": "qa-metrics.json",
            "closeoutCandidates": "closeout-candidates.json",
        },
        "viewport": {"width": 1440, "height": 980},
        "headless": True,
        "captureWebSockets": True,
        "scenarios": [
            {
                "id": "scaffolded-requirement-probes",
                "title": "Scaffolded requirement probes",
                "continueOnFailure": True,
                "steps": steps,
            }
        ],
    }
    matrix = {
        "schemaVersion": 2,
        "requirements": requirements,
        "tests": tests,
    }
    business_model = build_business_model(requirement, requirements, tests, gaps)
    oracle_model = build_oracle_model(requirements, tests)
    qa_metrics = build_qa_metrics(requirements, tests, steps, gaps, business_model, oracle_model)
    closeout_candidates = build_closeout_candidates(business_model, oracle_model, gaps)
    charter = render_charter(requirement, requirements, tests, gaps, business_model, oracle_model)
    summary = {
        "schema_version": 1,
        "requirement_count": len(requirements),
        "test_count": len(tests),
        "planned_step_count": len(steps),
        "clickability_probe_count": len([step for step in steps if step.get("action") == "expectClickable"]),
        "blocked_clickability_test_count": len([test for test in tests if test.get("type") == "interaction" and test.get("status") == "Blocked"]),
        "click_response_probe_count": len([step for step in steps if step.get("action") == "clickAndWaitForResponse"]),
        "blocked_click_response_test_count": len([test for test in tests if test.get("type") == "ui_to_api" and test.get("status") == "Blocked"]),
        "followup_api_probe_count": len([step for step in steps if step.get("action") in {"api", "pollApi"} and step.get("pathTemplate")]),
        "poll_api_probe_count": len([step for step in steps if step.get("action") == "pollApi"]),
        "cleanup_api_probe_count": len([step for step in steps if step.get("action") == "cleanupApi"]),
        "blocked_followup_api_test_count": len([test for test in tests if test.get("type") == "api_followup" and test.get("status") == "Blocked"]),
        "blocked_cleanup_test_count": len([test for test in tests if test.get("type") == "cleanup" and test.get("status") == "Blocked"]),
        "blocked_test_count": len([test for test in tests if test.get("status") == "Blocked"]),
        "business_model": {
            "actor_count": len(business_model.get("actors", [])),
            "entity_count": len(business_model.get("entities", [])),
            "workflow_count": len(business_model.get("workflows", [])),
            "business_rule_count": len(business_model.get("business_rules", [])),
        },
        "oracle_model": oracle_model.get("summary", {}),
        "qa_metrics": "qa-metrics.json",
        "closeout_candidates": "closeout-candidates.json",
        "coverage_gaps": gaps,
        "input_artifact_errors": [],
    }
    return {
        "charter": charter,
        "matrix": matrix,
        "plan": plan,
        "summary": summary,
        "business_model": business_model,
        "oracle_model": oracle_model,
        "qa_metrics": qa_metrics,
        "closeout_candidates": closeout_candidates,
    }


def input_error_artifacts(base_url: str, artifact_dir: Path, input_errors: list[dict[str, str]]) -> dict[str, Any]:
    requirement = "Requirement source input is unreadable; QA planning is blocked until the input artifact is fixed."
    requirement_item = {
        "id": "R-input-1",
        "source": "requirement input",
        "text": requirement,
        "risk": "input_artifacts",
        "test_ids": ["T-input-1"],
        "status": "Blocked",
        "notes": "Generated because requirement input could not be read.",
    }
    test_item = {
        "id": "T-input-1",
        "requirement_ids": ["R-input-1"],
        "type": "input",
        "expected": "Requirement source file can be read before QA planning starts.",
        "status": "Blocked",
        "steps": ["Fix unreadable requirement input artifacts before generating probes."],
        "required_evidence": ["readable requirement source"],
        "notes": "No product probes were synthesized from unreadable requirement input.",
    }
    gaps = [f"{item['name']} input is unreadable: {item['error']} ({item['path']})" for item in input_errors]
    matrix = {
        "schemaVersion": 2,
        "requirements": [requirement_item],
        "tests": [test_item],
    }
    plan = {
        "schemaVersion": 2,
        "baseUrl": base_url,
        "artifactDir": str(artifact_dir),
        "metadata": {
            "businessModel": "business-model.json",
            "oracleModel": "oracle-model.json",
            "qaMetrics": "qa-metrics.json",
            "closeoutCandidates": "closeout-candidates.json",
        },
        "viewport": {"width": 1440, "height": 980},
        "headless": True,
        "captureWebSockets": True,
        "scenarios": [
            {
                "id": "scaffolded-requirement-probes",
                "title": "Scaffolded requirement probes",
                "continueOnFailure": True,
                "steps": [],
            }
        ],
    }
    summary = {
        "schema_version": 1,
        "status": "blocked",
        "requirement_count": 1,
        "test_count": 1,
        "planned_step_count": 0,
        "clickability_probe_count": 0,
        "blocked_clickability_test_count": 0,
        "click_response_probe_count": 0,
        "blocked_click_response_test_count": 0,
        "followup_api_probe_count": 0,
        "poll_api_probe_count": 0,
        "cleanup_api_probe_count": 0,
        "blocked_followup_api_test_count": 0,
        "blocked_cleanup_test_count": 0,
        "blocked_test_count": 1,
        "coverage_gaps": gaps,
        "input_artifact_errors": input_errors,
    }
    business_model = build_business_model(requirement, [requirement_item], [test_item], gaps)
    oracle_model = build_oracle_model([requirement_item], [test_item])
    qa_metrics = build_qa_metrics([requirement_item], [test_item], [], gaps, business_model, oracle_model)
    closeout_candidates = build_closeout_candidates(business_model, oracle_model, gaps)
    summary["business_model"] = {
        "actor_count": len(business_model.get("actors", [])),
        "entity_count": len(business_model.get("entities", [])),
        "workflow_count": len(business_model.get("workflows", [])),
        "business_rule_count": len(business_model.get("business_rules", [])),
    }
    summary["oracle_model"] = oracle_model.get("summary", {})
    summary["qa_metrics"] = "qa-metrics.json"
    summary["closeout_candidates"] = "closeout-candidates.json"
    return {
        "charter": render_charter(requirement, [requirement_item], [test_item], gaps, business_model, oracle_model),
        "matrix": matrix,
        "plan": plan,
        "summary": summary,
        "business_model": business_model,
        "oracle_model": oracle_model,
        "qa_metrics": qa_metrics,
        "closeout_candidates": closeout_candidates,
    }


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Scaffold a QA charter, matrix, and probe plan from requirement text.")
    parser.add_argument("--requirement-file")
    parser.add_argument("--requirement-text")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument("--entry-path", help="Optional user-facing entry path to use when requirements mention UI but no route.")
    parser.add_argument("--persistence-command", help="Project-approved read-only persistence/log helper command.")
    parser.add_argument("--allow-live-stream", action="store_true", help="Allow scaffolded WebSocket probes when a stream endpoint is present.")
    parser.add_argument("--allow-mutating-api", action="store_true", help="Allow mutating API methods in generated probes. Use only with safe test data.")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "screenshots").mkdir(exist_ok=True)
    (run_dir / "evidence").mkdir(exist_ok=True)
    requirement, input_errors = load_text(args.requirement_file, args.requirement_text)
    if not requirement and (run_dir / "requirement.md").exists():
        existing_requirement, existing_error = try_read_text(run_dir / "requirement.md")
        if existing_error:
            input_errors.append({"name": "requirement", "path": str(run_dir / "requirement.md"), "error": existing_error})
        else:
            requirement = existing_requirement or ""
    (run_dir / "requirement.md").write_text(requirement or "Requirement source was not provided.\n", encoding="utf-8")

    if input_errors:
        artifacts = input_error_artifacts(args.base_url, run_dir, input_errors)
    else:
        artifacts = scaffold(
            requirement=requirement,
            base_url=args.base_url,
            artifact_dir=run_dir,
            entry_path=args.entry_path,
            persistence_command=args.persistence_command,
            allow_live_stream=args.allow_live_stream,
            allow_mutating_api=args.allow_mutating_api,
        )
    (run_dir / "test-charter.md").write_text(artifacts["charter"], encoding="utf-8")
    (run_dir / "test-matrix.json").write_text(json.dumps(artifacts["matrix"], indent=2, ensure_ascii=False), encoding="utf-8")
    (run_dir / "test-plan.json").write_text(json.dumps(artifacts["plan"], indent=2, ensure_ascii=False), encoding="utf-8")
    (run_dir / "scaffold-summary.json").write_text(json.dumps(artifacts["summary"], indent=2, ensure_ascii=False), encoding="utf-8")
    write_semantic_artifacts(run_dir, artifacts)
    print(run_dir)
    return 1 if input_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
