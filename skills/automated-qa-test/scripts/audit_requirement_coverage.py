#!/usr/bin/env python3
import argparse
import json
import re
import shlex
from pathlib import Path
from typing import Any

from qa_common import atomic_write_json

LIST_MARKER_RE = re.compile(r"^(#{1,6}\s+|[-*+]\s+|\d+[\.)]\s+|- \[[ xX]\]\s+)")
LEADING_MARKER_RE = re.compile(r"^(#{1,6}\s+|[-*+]\s+|\d+[\.)]\s+|- \[[ xX]\]\s+)")
TOKEN_RE = re.compile(r"[A-Za-z0-9_:/.-]+|[\u4e00-\u9fff]")
IDENTIFIER_TOKEN_RE = re.compile(r"[A-Za-z0-9_:/.-]*\d[A-Za-z0-9_:/.-]*")
PATH_PATTERN = r"/[A-Za-z0-9_~{}:.-]+(?:/[A-Za-z0-9_~{}:.-]+)*(?:\?[A-Za-z0-9_~{}:./=&%+,\[\]-]+)?"
METHOD_PATH_RE = re.compile(rf"\b(GET|HEAD|POST|PUT|PATCH|DELETE)\s+({PATH_PATTERN})", re.IGNORECASE)
HTTP_STATUS_REASON_WORDS = r"(?:ok|created|accepted|no\s+content|unauthorized|forbidden|not\s+found|conflict|rate\s+limited)"
HTTP_STATUS_IN_TEXT_RE = re.compile(
    rf"\b(?:(?:returns?|return|responds?\s+with|status(?:\s+code)?|http)\s*(?:either\s*)?(?:HTTP\s*)?[1-5][0-9]{{2}}|"
    rf"[1-5][0-9]{{2}}\s+{HTTP_STATUS_REASON_WORDS})\b",
    re.IGNORECASE,
)
STATUS_CONTINUATION_START_RE = re.compile(
    r"^(?:it|this\s+request|that\s+request|the\s+request|request|the\s+response|response|the\s+endpoint|endpoint)\b",
    re.IGNORECASE,
)
IGNORE_LINE_RE = re.compile(r"^(背景|说明|备注|note|notes|context|background|scope|目标|目的)[:：]?$", re.IGNORECASE)
CHINESE_BEHAVIOR_RE = re.compile(
    r"(接口|请求|响应|返回|状态码|字段|包含|保存|创建|更新|删除|持久化|数据库|入库|落库|写入|读取|展示|显示|toast|提示|跳转|渲染|校验|验证|允许|拒绝|阻止|记录|生成|发送|通知)"
)
CHINESE_CLAUSE_START_RE = re.compile(
    r"(?:并且|然后|同时|并|且|还|也)?(?:接口|请求|响应|返回|状态码|字段|包含|保存|创建|更新|删除|持久化|数据库|入库|落库|写入|读取|展示|显示|toast|提示|跳转|渲染|校验|验证|允许|拒绝|阻止|记录|生成|发送|通知|POST|GET|PUT|PATCH|DELETE|/[A-Za-z0-9_./:-]+)"
)
ENGLISH_CLAUSE_START_RE = re.compile(
    r"(?:api|post|get|put|patch|delete|response|body|json|header|headers|field|fields|includes?|contains?|persist|persists|database|db|toast|shows?|see|visible|returns?|creates?|updates?|deletes?|writes?|records?|blocks?|denies?|allows?|cannot|forbidden|unauthorized|403|401|redirects?|renders?|validates?|/[A-Za-z0-9_./:{}-]+)",
    re.IGNORECASE,
)
VALIDATION_LABEL_RE = re.compile(
    r"^(?:validation|validate|verification|tests?|testing|checks?|check|qa|api\s+check|quality\s+gates?)\s*[:：-]\s*",
    re.IGNORECASE,
)
COMMAND_STARTERS = {
    "python", "python3", "node", "npm", "pnpm", "yarn", "pytest",
    "go", "cargo", "make", "bash", "sh", "ruby", "bundle", "php", "cat", "dd",
    "npx", "bun", "deno", "uv", "poetry", "pipenv", "tox", "nox",
    "vitest", "jest", "playwright", "turbo", "nx", "mvn", "gradle", "gradlew",
    "ruff", "mypy", "tsc", "eslint", "biome", "rails", "rake", "artisan",
    "sequelize", "typeorm", "knex", "aws", "gcloud", "az", "helm", "kubectl",
    "oc", "terraform", "tofu", "rm", "git", "gh", "docker", "docker-compose",
    "vercel", "supabase", "firebase", "fly", "heroku", "netlify", "printenv",
    "env", "vault", "op", "source", ".", "grep", "egrep", "fgrep", "sed",
    "awk", "head", "tail", "less", "more", "rg", "base64", "cp", "curl",
    "find", "openssl", "rsync", "scp", "tar", "zip", "apt", "apt-get", "apk", "brew",
    "composer", "dnf", "pacman", "pip", "pip3", "yum", "zypper",
}
ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.+$")
SHELL_WRAPPED_COMMAND_RE = re.compile(
    r"\b(?:bash|fish|sh|zsh)\s+(?:-[A-Za-z]*c|--command)\s+(?P<quote>['\"])(?P<script>.*?)(?P=quote)",
    re.IGNORECASE,
)
PROSE_COMMAND_STOP_WORDS = {
    "after", "and", "before", "because", "if", "then", "unless", "until", "when", "while",
    "并", "并且", "然后", "之后", "以前", "之前",
}


def try_read_text(path: Path) -> tuple[str | None, str | None]:
    if not path.exists():
        return None, "missing"
    if path.is_dir():
        return None, "path_is_directory"
    try:
        return path.read_text(encoding="utf-8"), None
    except OSError as exc:
        return None, f"read_error: {exc}"


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


def write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write_json(path, value)


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def clean_line(value: str) -> str:
    text = value.strip()
    text = LEADING_MARKER_RE.sub("", text).strip()
    text = re.sub(r"\s+", " ", text)
    return text


def clause_has_method_path(text: str) -> bool:
    return bool(METHOD_PATH_RE.search(str(text or "")))


def status_continuation_clause(text: str) -> bool:
    value = re.sub(r"\s+", " ", clean_line(str(text or ""))).strip()
    if not value or clause_has_method_path(value):
        return False
    return bool(STATUS_CONTINUATION_START_RE.search(value) and HTTP_STATUS_IN_TEXT_RE.search(value))


def merge_status_continuation_clauses(parts: list[str]) -> list[str]:
    merged: list[str] = []
    for part in parts:
        if merged and clause_has_method_path(merged[-1]) and status_continuation_clause(part):
            merged[-1] = f"{merged[-1]}; {part}"
        else:
            merged.append(part)
    return merged


def normalize(value: str) -> str:
    text = clean_line(value).lower()
    text = re.sub(r"[`*_#>\[\](),，。；;！!？?\"'“”‘’]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def normalize_command(value: str) -> str:
    text = clean_line(str(value or ""))
    text = VALIDATION_LABEL_RE.sub("", text).strip()
    text = re.sub(r"^(?:verified|validated|tested|checked)(?:\s+(?:with|via|by|using|through))\s+", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^(?:run|执行|运行)\s+", "", text, flags=re.IGNORECASE)
    text = text.strip().strip("`")
    text = re.sub(r"[`\"'“”‘’]", "", text)
    text = strip_sentence_terminal_punctuation(text)
    return re.sub(r"\s+", " ", text).strip().lower()


def command_starter_name(value: str) -> str:
    return "." if str(value) == "." else Path(value).name.lower()


def command_parts_look_executable(parts: list[str]) -> bool:
    index = 0
    while index < len(parts) and ENV_ASSIGNMENT_RE.match(parts[index]):
        index += 1
    if index >= len(parts):
        return False
    if len(parts) - index >= 4 and parts[index] == "cd" and parts[index + 2] == "&&":
        index += 3
        while index < len(parts) and ENV_ASSIGNMENT_RE.match(parts[index]):
            index += 1
        if index >= len(parts):
            return False
    return command_starter_name(parts[index]) in COMMAND_STARTERS


def strip_sentence_terminal_punctuation(value: str) -> str:
    text = str(value or "").strip()
    while text.endswith(("。", "；", "，", ";", ",")):
        text = text[:-1].rstrip()
    if text.endswith(".") and not text.endswith(" ."):
        text = text[:-1].rstrip()
    return text


def split_prose_command_segments(value: str) -> list[str]:
    text = str(value or "").strip()
    if not text:
        return []
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            index += 1
            continue
        if char in {",", ";"}:
            segment = strip_sentence_terminal_punctuation("".join(current))
            if not segment:
                return []
            segments.append(segment)
            current = []
            index += 1
            continue
        if text[index:index + 5].lower() == " and ":
            segment = strip_sentence_terminal_punctuation("".join(current))
            if not segment:
                return []
            segments.append(segment)
            current = []
            index += 5
            continue
        current.append(char)
        index += 1
    segment = strip_sentence_terminal_punctuation("".join(current))
    if not segment:
        return []
    segments.append(segment)
    return segments if len(segments) > 1 else []


def split_shell_operator_segments(candidate: str) -> list[str]:
    try:
        parts = shlex.split(candidate)
    except ValueError:
        return []
    if not parts:
        return []
    if "&&" not in parts:
        return []
    segments: list[list[str]] = []
    current: list[str] = []
    for part in parts:
        if part == "&&":
            if not current:
                return []
            segments.append(current)
            current = []
        else:
            current.append(part)
    if not current:
        return []
    segments.append(current)
    if len(segments) < 2:
        return []
    return [shlex.join(segment) for segment in segments]


def split_command_candidate_text(value: str) -> set[str]:
    candidate = normalize_command(value)
    if not candidate:
        return set()

    prose_segments = split_prose_command_segments(candidate)
    if prose_segments:
        commands: set[str] = set()
        for segment in prose_segments:
            nested = split_shell_operator_segments(segment)
            if nested:
                for nested_segment in nested:
                    try:
                        nested_parts = shlex.split(nested_segment)
                    except ValueError:
                        return {candidate}
                    if not command_parts_look_executable(nested_parts):
                        return {candidate}
                    commands.add(normalize_command(nested_segment))
                continue
            try:
                segment_parts = shlex.split(segment)
            except ValueError:
                return {candidate}
            if not command_parts_look_executable(segment_parts):
                return {candidate}
            commands.add(normalize_command(segment))
        return {command for command in commands if command}

    nested = split_shell_operator_segments(candidate)
    if nested:
        commands = set()
        for segment in nested:
            try:
                segment_parts = shlex.split(segment)
            except ValueError:
                return {candidate}
            if not command_parts_look_executable(segment_parts):
                return {candidate}
            commands.add(normalize_command(segment))
        return {command for command in commands if command}

    try:
        parts = shlex.split(candidate)
    except ValueError:
        return {candidate}
    if not parts:
        return set()
    return {candidate}


def prose_command_context_start(parts: list[str], start_index: int) -> int:
    candidate_start = start_index
    while candidate_start > 0 and ENV_ASSIGNMENT_RE.match(parts[candidate_start - 1]):
        candidate_start -= 1
    if (
        candidate_start >= 3
        and parts[candidate_start - 3] == "cd"
        and parts[candidate_start - 1] == "&&"
        and re.match(r"^[A-Za-z0-9_./-]+$", parts[candidate_start - 2])
    ):
        candidate_start -= 3
        while candidate_start > 0 and ENV_ASSIGNMENT_RE.match(parts[candidate_start - 1]):
            candidate_start -= 1
    return candidate_start


def bare_command_candidates_from_prose(value: str) -> set[str]:
    candidates: set[str] = set()
    for piece in re.split(r"`[^`\n]{3,220}`", str(value or "")):
        normalized = normalize_command(piece)
        if not normalized:
            continue
        try:
            parts = shlex.split(normalized)
        except ValueError:
            continue
        start_index = 0
        while start_index < len(parts):
            part = parts[start_index]
            if command_starter_name(part) not in COMMAND_STARTERS:
                start_index += 1
                continue
            end_index = len(parts)
            for index in range(start_index + 1, len(parts)):
                if parts[index].lower().strip(".,;:") in PROSE_COMMAND_STOP_WORDS:
                    end_index = index
                    break
            context_start = prose_command_context_start(parts, start_index)
            command_parts = parts[context_start:end_index]
            if command_parts_look_executable(command_parts):
                candidates.add(normalize_command(shlex.join(command_parts)))
                start_index = end_index
                continue
            start_index += 1
    return {candidate for candidate in candidates if candidate}


def shell_wrapped_command_candidates(value: str) -> set[str]:
    candidates: set[str] = set()
    for match in SHELL_WRAPPED_COMMAND_RE.finditer(str(value or "")):
        candidates.add(normalize_command(match.group(0)))
    return {candidate for candidate in candidates if candidate}


def command_candidates(value: str) -> set[str]:
    text = clean_line(str(value or ""))
    shell_wrapped_candidates = shell_wrapped_command_candidates(text)
    if shell_wrapped_candidates:
        return shell_wrapped_candidates
    candidates = {
        normalize_command(match.group(1))
        for match in re.finditer(r"`([^`\n]{3,220})`", text)
    }
    candidates.update(bare_command_candidates_from_prose(text))
    if candidates:
        return {candidate for candidate in candidates if candidate}
    lowered = text.lower()
    if re.search(r"\b(?:run|执行|运行)\b", lowered) or re.search(r"\b(?:command|cmd|quality gate|validation|test|check)\b", lowered):
        candidates.update(split_command_candidate_text(text))
    return {candidate for candidate in candidates if candidate}


def tokens(value: str) -> set[str]:
    return {item.lower() for item in TOKEN_RE.findall(normalize(value)) if item.strip()}


def identifier_tokens(value: str) -> set[str]:
    return {item.lower().strip(".,;:") for item in IDENTIFIER_TOKEN_RE.findall(normalize(value)) if item.strip(".,;:")}


def source_matches(unit_source: str, req_source: str) -> bool:
    if not unit_source or not req_source:
        return False
    if unit_source == req_source:
        return True
    return bool(re.search(rf"(?<!\w){re.escape(unit_source)}(?!\w)", req_source))


def identifiers_compatible(unit_text: str, req_text: str) -> bool:
    unit_ids = identifier_tokens(unit_text)
    req_ids = identifier_tokens(req_text)
    return not unit_ids or not req_ids or bool(unit_ids.intersection(req_ids))


def split_sentences(text: str) -> list[str]:
    pieces = re.split(r"(?<=[。！？.!?])\s+|\n{2,}", text.strip())
    return [clean_line(piece) for piece in pieces if clean_line(piece)]


def looks_like_behavior_clause(text: str) -> bool:
    normalized = normalize(text)
    token_count = len(tokens(normalized))
    if token_count < 3:
        return False
    return bool(
        re.search(
            r"\b(api|post|get|put|patch|delete|response|body|json|header|headers|field|fields|includes?|contains?|persist|persists|database|db|toast|shows?|see|visible|returns?|creates?|updates?|deletes?|writes?|records?|blocks?|denies?|allows?|cannot|forbidden|unauthorized|403|401|redirects?|renders?|validates?)\b",
            normalized,
        )
        or re.search(r"/[A-Za-z0-9_./:-]+", text)
        or CHINESE_BEHAVIOR_RE.search(text)
    )


def split_weak_behavior_clauses(text: str) -> list[str]:
    if command_candidates(text):
        return [text]
    english_clause_start = ENGLISH_CLAUSE_START_RE.pattern
    chinese_clause_start = CHINESE_CLAUSE_START_RE.pattern
    raw_parts = [
        clean_line(part)
        for part in re.split(
            rf"\s*(?:,\s+(?=(?:and|then)\b)|,\s*|，\s*(?={chinese_clause_start})|\s+(?:and|then)\s+(?={english_clause_start})|(?:并且|然后|同时|并|且|还|也)\s*(?={chinese_clause_start}))\s*",
            text,
            flags=re.IGNORECASE,
        )
        if clean_line(part)
    ]
    if len(raw_parts) < 2:
        return [text]
    clauses = [re.sub(r"^(?:and|then|并且|然后|同时|并|且|还|也)\s*", "", part, flags=re.IGNORECASE).strip() for part in raw_parts]
    if all(looks_like_behavior_clause(clause) for clause in clauses):
        return clauses
    return [text]


def split_behavior_clauses(text: str) -> list[str]:
    if command_candidates(text):
        return [text]
    raw_strong_parts = [clean_line(part) for part in re.split(r"\s*[;；]\s*", text) if clean_line(part)]
    strong_parts = merge_status_continuation_clauses(raw_strong_parts) if len(raw_strong_parts) > 1 else raw_strong_parts
    if len(strong_parts) > 1:
        clauses: list[str] = []
        for part in strong_parts:
            clauses.extend(split_weak_behavior_clauses(part))
        if clauses and all(looks_like_behavior_clause(clause) for clause in clauses):
            return clauses
        return strong_parts
    if len(raw_strong_parts) > 1 and len(strong_parts) == 1:
        return split_weak_behavior_clauses(strong_parts[0])
    return split_weak_behavior_clauses(text)


def collect_source_units(requirement_text: str) -> list[dict[str, Any]]:
    raw_lines = requirement_text.splitlines()
    explicit: list[dict[str, Any]] = []
    for line_no, raw in enumerate(raw_lines, 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        cleaned = clean_line(stripped)
        if not cleaned or IGNORE_LINE_RE.match(cleaned):
            continue
        if LIST_MARKER_RE.match(stripped):
            clauses = split_behavior_clauses(cleaned)
            if len(clauses) == 1:
                explicit.append({"id": f"S{len(explicit) + 1}", "source": f"line {line_no}", "text": cleaned})
            else:
                for clause_index, clause in enumerate(clauses, 1):
                    explicit.append({"id": f"S{len(explicit) + 1}", "source": f"line {line_no} clause {clause_index}", "text": clause})
    if explicit:
        return explicit

    units: list[dict[str, Any]] = []
    for idx, piece in enumerate(split_sentences(requirement_text), 1):
        if IGNORE_LINE_RE.match(piece):
            continue
        clauses = split_behavior_clauses(piece)
        if len(clauses) == 1:
            units.append({"id": f"S{len(units) + 1}", "source": f"paragraph {idx}", "text": piece})
        else:
            for clause_index, clause in enumerate(clauses, 1):
                units.append({"id": f"S{len(units) + 1}", "source": f"paragraph {idx} clause {clause_index}", "text": clause})
    if not units and requirement_text.strip():
        units.append({"id": "S1", "source": "requirement", "text": clean_line(requirement_text)})
    return units


def limit_source_units(units: list[dict[str, Any]], max_units: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    total_count = len(units)
    if max_units > 0 and total_count > max_units:
        return units[:max_units], {
            "source_unit_total_count": total_count,
            "source_unit_omitted_count": total_count - max_units,
            "source_units_truncated": True,
            "max_units": max_units,
        }
    return units, {
        "source_unit_total_count": total_count,
        "source_unit_omitted_count": 0,
        "source_units_truncated": False,
        "max_units": max_units,
    }


def source_units(requirement_text: str, max_units: int) -> list[dict[str, Any]]:
    units, _ = limit_source_units(collect_source_units(requirement_text), max_units)
    return units


def matrix_requirements(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in as_list(matrix.get("requirements")):
        if not isinstance(item, dict):
            continue
        out.append(item)
    return out


def coverage_match(unit: dict[str, Any], requirement: dict[str, Any], min_overlap: float) -> dict[str, Any] | None:
    unit_text = normalize(unit.get("text", ""))
    req_text = normalize(str(requirement.get("text") or ""))
    req_source = normalize(str(requirement.get("source") or ""))
    unit_source = normalize(str(unit.get("source") or ""))
    unit_commands = command_candidates(str(unit.get("text") or ""))
    req_commands = command_candidates(str(requirement.get("text") or ""))
    if unit_commands:
        if req_commands:
            matched_commands = unit_commands.intersection(req_commands)
            if matched_commands:
                return {
                    "method": "command_exact",
                    "score": round(len(matched_commands) / max(len(unit_commands), 1), 3),
                    "matched_commands": sorted(matched_commands),
                }
        return None
    if source_matches(unit_source, req_source):
        return {"method": "source", "score": 1.0}
    if req_commands:
        return None
    if unit_text and req_text and (unit_text in req_text or req_text in unit_text):
        return {"method": "text_contains", "score": 1.0}
    if not identifiers_compatible(unit_text, req_text + " " + req_source):
        return None
    unit_tokens = tokens(unit_text)
    req_tokens = tokens(req_text + " " + req_source)
    if not unit_tokens or not req_tokens:
        return None
    overlap = len(unit_tokens.intersection(req_tokens)) / max(len(unit_tokens), 1)
    if overlap >= min_overlap:
        return {"method": "token_overlap", "score": round(overlap, 3)}
    return None


def audit(requirement_text: str, matrix: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    units, source_unit_meta = limit_source_units(collect_source_units(requirement_text), args.max_units)
    requirements = matrix_requirements(matrix)
    coverage: list[dict[str, Any]] = []
    uncovered: list[dict[str, Any]] = []
    for unit in units:
        matches: list[dict[str, Any]] = []
        unit_commands = command_candidates(str(unit.get("text") or ""))
        matched_commands: set[str] = set()
        for req in requirements:
            match = coverage_match(unit, req, args.min_overlap)
            if match:
                for command in as_list(match.get("matched_commands")):
                    if isinstance(command, str) and command:
                        matched_commands.add(command)
                matches.append({
                    "requirement_id": req.get("id"),
                    "requirement_status": req.get("status"),
                    "method": match["method"],
                    "score": match["score"],
                    **({"matched_commands": match.get("matched_commands")} if match.get("matched_commands") else {}),
                })
        missing_commands = sorted(unit_commands - matched_commands) if unit_commands else []
        covered = bool(matches) and not missing_commands
        item = {
            **unit,
            "covered": covered,
            "matches": matches,
            **(
                {
                    "required_commands": sorted(unit_commands),
                    "matched_commands": sorted(matched_commands),
                    "missing_commands": missing_commands,
                }
                if unit_commands
                else {}
            ),
        }
        coverage.append(item)
        if not covered:
            uncovered.append(item)

    errors = []
    for item in uncovered:
        missing_commands = as_list(item.get("missing_commands"))
        if missing_commands:
            errors.append(
                f"{item['id']} ({item['source']}) is missing command mappings: {', '.join(str(command) for command in missing_commands)}"
            )
        else:
            errors.append(f"{item['id']} ({item['source']}) is not mapped to any matrix requirement: {item['text']}")
    if not requirements:
        errors.append("test-matrix.json has no requirements to cover the requirement source.")
    omitted_count = int(source_unit_meta.get("source_unit_omitted_count") or 0)
    if omitted_count:
        errors.append(
            f"Requirement source audit omitted {omitted_count} source unit(s) because --max-units={args.max_units}; "
            "increase --max-units or split the requirement before claiming source coverage."
        )

    coverage_complete = not errors
    execution_allowed = coverage_complete or args.allow_unmapped_source
    return {
        "schema_version": 1,
        "requirement_unit_count": len(units),
        "source_unit_audited_count": len(units),
        **source_unit_meta,
        "matrix_requirement_count": len(requirements),
        "covered_count": len([item for item in coverage if item.get("covered")]),
        "uncovered_count": len(uncovered) + omitted_count,
        "coverage_complete": coverage_complete,
        "allow_unmapped_source": bool(args.allow_unmapped_source),
        "execution_allowed": execution_allowed,
        "passed": coverage_complete,
        "coverage": coverage,
        "errors": errors,
        "warnings": errors if args.allow_unmapped_source else [],
        "input_artifact_errors": [],
    }


def input_error_summary(
    requirement_path: Path,
    matrix_path: Path,
    requirement_text: str | None,
    matrix: dict[str, Any] | None,
    input_errors: list[dict[str, str]],
    args: argparse.Namespace,
) -> dict[str, Any]:
    if requirement_text is not None:
        units, source_unit_meta = limit_source_units(collect_source_units(requirement_text), args.max_units)
    else:
        units, source_unit_meta = [], {
            "source_unit_total_count": 0,
            "source_unit_omitted_count": 0,
            "source_units_truncated": False,
            "max_units": args.max_units,
        }
    requirements = matrix_requirements(matrix or {})
    coverage = [{**unit, "covered": False, "matches": []} for unit in units]
    errors = [
        f"{item['name']} artifact is unreadable: {item['error']} ({item['path']})"
        for item in input_errors
    ]
    omitted_count = int(source_unit_meta.get("source_unit_omitted_count") or 0)
    if omitted_count:
        errors.append(
            f"Requirement source audit omitted {omitted_count} source unit(s) because --max-units={args.max_units}; "
            "increase --max-units or split the requirement before claiming source coverage."
        )
    return {
        "schema_version": 1,
        "requirement": str(requirement_path),
        "matrix": str(matrix_path),
        "requirement_unit_count": len(units),
        "source_unit_audited_count": len(units),
        **source_unit_meta,
        "matrix_requirement_count": len(requirements),
        "covered_count": 0,
        "uncovered_count": len(units) + omitted_count,
        "coverage_complete": False,
        "allow_unmapped_source": bool(args.allow_unmapped_source),
        "execution_allowed": False,
        "passed": False,
        "coverage": coverage,
        "errors": errors,
        "warnings": [],
        "input_artifact_errors": input_errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit whether requirement.md source behavior points are represented in test-matrix.json.")
    parser.add_argument("--requirement", required=True)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--out")
    parser.add_argument("--min-overlap", type=float, default=0.72)
    parser.add_argument("--max-units", type=int, default=0, help="Maximum source units to audit; 0 means unlimited. Truncation blocks pass claims.")
    parser.add_argument("--allow-unmapped-source", action="store_true", help="Write warnings instead of failing for uncovered requirement source units.")
    args = parser.parse_args()

    requirement_path = Path(args.requirement).expanduser().resolve()
    matrix_path = Path(args.matrix).expanduser().resolve()
    requirement_text, requirement_error = try_read_text(requirement_path)
    matrix, matrix_error = try_load_json(matrix_path)
    input_errors: list[dict[str, str]] = []
    if requirement_error:
        input_errors.append({"name": "requirement", "path": str(requirement_path), "error": requirement_error})
    if matrix_error:
        input_errors.append({"name": "matrix", "path": str(matrix_path), "error": matrix_error})

    if input_errors:
        summary = input_error_summary(requirement_path, matrix_path, requirement_text, matrix, input_errors, args)
    else:
        assert requirement_text is not None
        assert matrix is not None
        summary = audit(requirement_text, matrix, args)
        summary["requirement"] = str(requirement_path)
        summary["matrix"] = str(matrix_path)
    if args.out:
        write_json(Path(args.out).expanduser().resolve(), summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary.get("execution_allowed", summary.get("passed")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
