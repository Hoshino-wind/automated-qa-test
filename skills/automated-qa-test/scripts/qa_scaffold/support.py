"""需求解析、命令安全与通用脚手架支持。"""

import re
import shlex
from pathlib import Path
from typing import Any

SECRET_PATTERNS = [
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
    re.compile(r"((?:access[_-]?token|auth[_-]?token|session[_-]?token|api[_-]?key|secret)\s*[:=]\s*)[^\s\"',}]{8,}", re.IGNORECASE),
]

PATH_PATTERN = r"/[A-Za-z0-9_~{}:.-]+(?:/[A-Za-z0-9_~{}:.-]+)*(?:\?[A-Za-z0-9_~{}:./=&%+,\[\]-]+)?"

PATH_RE = re.compile(rf"(?<![A-Za-z0-9_.-])({PATH_PATTERN})")

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

CODE_FILE_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])/?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\."
    r"(?:py|pyi|js|jsx|ts|tsx|go|java|kt|swift|rs|rb|php|sql|css|scss|md|json|ya?ml|toml)\b",
    re.IGNORECASE,
)

VALIDATION_COMMAND_PATTERNS = [
    re.compile(r"(?:run|执行|运行)\s+`([^`\n]{3,180})`", re.IGNORECASE),
    re.compile(
        r"(?:validation|validate|verification|test|check)"
        r"(?:\s+(?:command|cmd|step|steps|script|scripts))?\s*[:：-]\s*`([^`\n]{3,180})`",
        re.IGNORECASE,
    ),
    re.compile(r"(?:verified|validated|tested|checked)(?:\s+(?:with|via|by|using|through))?\s+`([^`\n]{3,180})`", re.IGNORECASE),
    re.compile(r"(?:verified|validated|tested|checked)(?:\s+(?:with|via|by|using|through))\s+([^\n]{3,220})", re.IGNORECASE),
    re.compile(r"(?:验证|校验|测试|检查)(?:命令|脚本)?\s*[:：-]\s*`([^`\n]{3,180})`", re.IGNORECASE),
]

VALIDATION_SECTION_RE = re.compile(
    r"^(?:#{1,6}\s*)?"
    r"(?:(?:how\s+to\s+test|testing\s+notes?|qa|quality\s+assurance|ci|continuous\s+integration|quality\s+gates?)|"
    r"(?:checks?|tests?|validation|verification)\s+(?:performed|run|executed)|"
    r"(?:unit|integration|e2e|end[-\s]?to[-\s]?end|manual|smoke|regression|acceptance|browser|api|frontend|backend|automated)\s+(?:tests?|testing|qa)|"
    r"(?P<label>validation|validate|verification|tests?|testing|checks?|验证|校验|测试|检查)"
    r"(?:(?:\s+(?:commands?|cmds?|steps?|scripts?|plans?|cases?|instructions?|strategy|strategies|notes?|matrix|matrices))|(?:命令|脚本|步骤|计划|用例|说明|策略))?)"
    r"\s*(?:(?::|：|-)\s*(?P<rest>.*)|$)",
    re.IGNORECASE,
)

VALIDATION_INLINE_LABEL_RE = re.compile(
    r"^(?:"
    r"tests?|testing|test\s+plan|qa|quality\s+assurance|ci|checks?|validation|verify|verification|"
    r"unit(?:\s+tests?)?|integration(?:\s+tests?)?|e2e|end[-\s]?to[-\s]?end|"
    r"browser|api(?:\s+(?:checks?|tests?|testing))?|backend|frontend|smoke|regression"
    r")\s*[:：-]\s*(?P<command>.+)$",
    re.IGNORECASE,
)

SHELL_COMMAND_STARTERS = {
    "python", "python3", "node", "npm", "pnpm", "yarn", "pytest",
    "go", "cargo", "make", "bash", "sh", "ruby", "bundle", "php", "dd",
    "npx", "bun", "deno", "uv", "poetry", "pipenv", "tox", "nox",
    "vitest", "jest", "playwright", "turbo", "nx", "mvn", "gradle", "gradlew",
    "ruff", "mypy", "tsc", "eslint", "biome",
}

QUALITY_COMMAND_STARTERS = {"ruff", "eslint", "biome"}

MUTATING_QUALITY_COMMAND_OPTIONS = {"--fix", "--fix-only", "--write", "--apply", "--apply-unsafe"}

MUTATING_QUALITY_COMMAND_CONTEXT_TOKENS = {"ruff", "eslint", "biome", "prettier", "lint", "format", "fmt"}

DEFAULT_MUTATING_QUALITY_TOOLS = {"black", "isort"}

NON_MUTATING_QUALITY_OPTIONS = {"--check", "--diff", "--dry-run", "--check-only"}

DATABASE_MUTATION_TOOLS = {
    "alembic",
    "artisan",
    "django-admin",
    "flask",
    "knex",
    "manage.py",
    "prisma",
    "rails",
    "rake",
    "sequelize",
    "typeorm",
}

DATABASE_MUTATION_ACTION_TERMS = {
    "dbmigrate",
    "dbseed",
    "deploy",
    "downgrade",
    "migrate",
    "migrationrevert",
    "migrationrun",
    "reset",
    "seed",
    "upgrade",
}

INFRASTRUCTURE_MUTATION_TOOLS = {
    "aws", "az", "firebase", "fly", "gcloud", "gh", "git", "helm",
    "heroku", "kubectl", "netlify", "oc", "supabase", "terraform", "tofu",
    "vercel",
}

INFRASTRUCTURE_MUTATION_ACTION_TERMS = {
    "apply",
    "create",
    "delete",
    "deletebranch",
    "deletestack",
    "deploy",
    "destroy",
    "drain",
    "edit",
    "exec",
    "install",
    "merge",
    "modify",
    "patch",
    "put",
    "push",
    "replace",
    "rm",
    "rollback",
    "scale",
    "set",
    "sync",
    "taint",
    "uninstall",
    "update",
    "upgrade",
}

DOCKER_MUTATION_ACTIONS = {"build", "down", "kill", "pull", "push", "restart", "rm", "stop", "up"}

DOCKER_SYSTEM_MUTATION_ACTIONS = {"prune"}

SECRET_ENV_NAME_COMPACT_TERMS = {
    "accesstoken",
    "apikey",
    "authcookie",
    "authorization",
    "connectionstring",
    "credentials",
    "databaseurl",
    "dbpassword",
    "dburl",
    "password",
    "privatekey",
    "secret",
    "sessioncookie",
    "token",
}

SECRET_PATH_EXTENSIONS = {".env", ".key", ".pem", ".p12", ".pfx"}

SECRET_PATH_TERMS = {"credential", "credentials", "password", "private_key", "secret", "secrets", "token"}

AWS_SECRET_READ_SERVICES = {"secretsmanager", "ssm"}

AWS_SECRET_READ_ACTIONS = {"batchgetsecretvalue", "getparameter", "getparameters", "getparametersbypath", "getsecretvalue"}

KUBECTL_SECRET_READ_ACTIONS = {"describe", "edit", "get"}

VAULT_SECRET_READ_ACTIONS = {"kv", "read", "write"}

ONE_PASSWORD_SECRET_READ_ACTIONS = {"item", "read"}

SHELL_SCRIPT_COMMANDS = {"bash", "fish", "sh", "zsh"}

SOURCE_ENV_FILE_COMMANDS = {".", "source"}

SECRET_FILE_READ_COMMANDS = {"awk", "egrep", "fgrep", "grep", "head", "less", "more", "rg", "sed", "tail"}

SED_AWK_FILE_READ_COMMANDS = {"awk", "sed"}

SEARCH_FILE_READ_COMMANDS = {"egrep", "fgrep", "grep", "rg"}

SEARCH_OPTIONS_WITH_VALUE = {
    "-A", "--after-context", "-B", "--before-context", "-C", "--context",
    "-e", "--regexp", "-f", "--file", "-g", "--glob", "-m", "--max-count",
    "-r", "--replace", "-t", "--type", "-T", "--type-not",
    "--colors", "--encoding", "--sort", "--sortr",
}

SECRET_FILE_WRITE_COMMANDS = {"tee", "touch", "truncate"}

SECRET_FILE_METADATA_MUTATION_COMMANDS = {"chgrp", "chmod", "chown", "install", "ln", "mv", "rm", "unlink"}

SECRET_FILE_MUTATION_COMMANDS = SECRET_FILE_WRITE_COMMANDS | SECRET_FILE_METADATA_MUTATION_COMMANDS

TEE_OPTIONS_WITH_VALUE = {"--output-error"}

TOUCH_OPTIONS_WITH_VALUE = {"-d", "--date", "-r", "--reference", "-t", "--time"}

TRUNCATE_OPTIONS_WITH_VALUE = {"-o", "--io-blocks", "-r", "--reference", "-s", "--size"}

SECRET_FILE_METADATA_MUTATION_OPTIONS_WITH_VALUE = {
    "chgrp": {"--reference"},
    "chmod": {"--reference"},
    "chown": {"--from", "--reference"},
    "install": {"-D", "-g", "--group", "-m", "--mode", "-o", "--owner", "-S", "--suffix", "-t", "--target-directory"},
    "ln": {"-S", "--suffix", "-t", "--target-directory"},
    "mv": {"-S", "--suffix", "-t", "--target-directory"},
}

SHELL_OUTPUT_REDIRECTION_TOKENS = {">", ">>", ">|", "&>", "1>", "1>>", "2>", "2>>"}

SHELL_REDIRECTION_OPERATORS = {"<", "<>", ">", ">>", ">|", "&>", "1>", "1>>", "2>", "2>>", "<<<"}

SECRET_FILE_EXFILTRATION_COMMANDS = {
    "base64", "cp", "curl", "dd", "openssl", "rsync", "scp", "tar", "zip",
}

SHELL_PASSTHROUGH_COMMAND_WRAPPERS = {"command", "eval", "nice", "nohup", "sudo", "time"}

SHELL_ENV_ASSIGNMENT_BUILTINS = {"declare", "export", "local", "readonly", "typeset"}

SHELL_POSITIONAL_PARAMETER_NAMES = {str(index) for index in range(1, 10)}

SHELL_READ_OPTIONS_WITH_VALUE = {"-a", "-d", "-n", "-N", "-p", "-t", "-u"}

SHELL_MAPFILE_COMMANDS = {"mapfile", "readarray"}

SHELL_MAPFILE_OPTIONS_WITH_VALUE = {"-C", "-c", "-d", "-n", "-O", "-s", "-u"}

XARGS_OPTIONS_WITH_VALUE = {
    "-a", "--arg-file", "-d", "--delimiter", "-E", "-I", "--replace", "-n",
    "--max-args", "-P", "--max-procs", "-s", "--max-chars",
}

XARGS_SECRET_FILE_READ_COMMANDS = {"cat"} | SECRET_FILE_READ_COMMANDS | SECRET_FILE_EXFILTRATION_COMMANDS

SHELL_STDIN_TEXT_COMMANDS = {"echo", "printf"}

INLINE_INTERPRETER_SCRIPT_OPTIONS = {
    "perl": {"-e"},
    "python": {"-c"},
    "python3": {"-c"},
    "node": {"-e", "--eval"},
    "ruby": {"-e"},
}

INLINE_FILE_READ_TERMS = {
    ".read_text(",
    "createreadstream(",
    "file.open(",
    "file.read(",
    "io.read(",
    "open(",
    "readbytes(",
    "readfile(",
    "readfilesync(",
}

INLINE_FILE_WRITE_TERMS = {
    ".write_text(",
    "createwritestream(",
    "file.write(",
    "io.write(",
    "writefile(",
    "writefilesync(",
}

DEPENDENCY_MUTATION_ACTIONS = {
    "add",
    "ci",
    "install",
    "i",
    "remove",
    "rm",
    "sync",
    "uninstall",
    "update",
    "upgrade",
    "up",
}

PACKAGE_DEPENDENCY_MUTATION_RUNNERS = {"bun", "npm", "pnpm", "yarn"}

PYTHON_DEPENDENCY_MUTATION_TOOLS = {"pip", "pip3"}

PROJECT_DEPENDENCY_MUTATION_TOOLS = {"bundle", "composer", "poetry"}

SYSTEM_DEPENDENCY_MUTATION_TOOLS = {"apt", "apt-get", "apk", "brew", "dnf", "pacman", "yum", "zypper"}

MUTATING_MAKE_TARGET_TERMS = {
    "apply",
    "dbdrop",
    "dbmigrate",
    "dbreset",
    "dbseed",
    "deploy",
    "destroy",
    "drop",
    "install",
    "migrate",
    "migration",
    "migrations",
    "provision",
    "publish",
    "release",
    "reset",
    "seed",
    "uninstall",
    "write",
}

MAKE_OPTIONS_WITH_VALUE = {"-C", "--directory", "-f", "--file", "-I", "--include-dir", "-j", "--jobs", "-l", "--load-average"}

COREPACK_RUNNERS = {"npm", "npx", "pnpm", "yarn"}

PACKAGE_COMMAND_STARTERS = {"corepack", *COREPACK_RUNNERS}

PACKAGE_CROSS_ENV_EXEC_SUBCOMMANDS = {"exec", "dlx", "x"}

PACKAGE_SCRIPT_RUNNERS = {"npm", "pnpm", "yarn", "bun"}

PACKAGE_SCRIPT_RUN_SUBCOMMANDS = {"run", "run-script"}

PACKAGE_EXEC_SUBCOMMANDS = {"exec", "dlx", "x"}

PACKAGE_RUNNER_OPTIONS_WITH_VALUE = {
    "--cache", "--call", "-c", "--cwd", "-C", "--dir", "--filter", "-F",
    "--package", "-p", "--prefix", "--registry", "--userconfig",
    "--workspace", "-w",
}

PYTHON_MODULE_COMMAND_STARTERS = {"python", "python3"}

TOOL_RUNNER_COMMAND_STARTERS = {"uv", "poetry", "pipenv", "tox", "nox"}

ABSOLUTE_COMMAND_ROOT_SEGMENTS = {"bin", "sbin", "usr", "opt", "home", "users", "var", "private", "tmp", "volumes", "applications"}

DOCKER_COMPOSE_RUN_ACTIONS = {"run", "exec"}

DOCKER_COMPOSE_OPTIONS_WITH_VALUE = {
    "--env", "-e", "--env-file", "--file", "-f", "--project-name", "-p",
    "--user", "-u", "--workdir", "-w", "--profile", "--index",
}

ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")

ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

SHELL_VARIABLE_REFERENCE_RE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")

SHELL_ARRAY_VARIABLE_REFERENCE_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\[[^}]+\]\}")

SHELL_POSITIONAL_PARAMETER_REFERENCE_RE = re.compile(r"\$(?:\{([0-9]+)\}|([0-9]+))")

SHELL_SUBSTITUTION_ASSIGNMENT_RE = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)="
    r"(?P<value>\"?[A-Za-z0-9_./@:+-]*(?:\$\([^)]*\)|`[^`]*`)[A-Za-z0-9_./@:+-]*\"?)"
)

SECRET_PATH_LITERAL_RE = re.compile(
    r"(?:[A-Za-z0-9_./\\@+-]*\.env(?:\.[A-Za-z0-9_.-]+)?|"
    r"[A-Za-z0-9_./\\@+-]*(?:credential|credentials|password|private[_-]?key|secret|secrets|token)[A-Za-z0-9_./\\@+-]*|"
    r"[A-Za-z0-9_./\\@+-]+\.(?:key|pem|p12|pfx))",
    re.IGNORECASE,
)

ENV_FILE_WRAPPER_COMMANDS = {"dotenv", "dotenv-cli", "dotenvx"}

SAFE_RELATIVE_CWD_RE = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_./@+-]+$")

SHELL_OPERATOR_TOKENS = {"&&", "||", ";", "|", "&"}

STREAM_PATH_SEGMENTS = {"ws", "websocket", "sse", "stream", "events"}

PROSE_COMMAND_STOP_WORDS = {
    "after", "and", "before", "because", "if", "then", "unless", "until", "when", "while",
    "并", "并且", "然后", "之后", "以前", "之前",
}

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

ENGLISH_REQUIREMENT_CLAUSE_START_RE = re.compile(
    r"(?:api|post|get|put|patch|delete|response|body|json|header|headers|field|fields|includes?|contains?|persist|persists|database|db|toast|shows?|see|visible|returns?|creates?|updates?|deletes?|writes?|records?|blocks?|denies?|allows?|cannot|forbidden|unauthorized|403|401|redirects?|renders?|validates?|/[A-Za-z0-9_./:{}-]+)",
    re.IGNORECASE,
)

CHINESE_REQUIREMENT_CLAUSE_START_RE = re.compile(
    r"(?:并且|然后|同时|并|且|还|也)?(?:接口|请求|响应|返回|状态码|字段|包含|保存|创建|更新|删除|持久化|数据库|入库|落库|写入|读取|展示|显示|toast|提示|跳转|渲染|校验|验证|允许|拒绝|阻止|记录|生成|发送|通知|POST|GET|PUT|PATCH|DELETE|/[A-Za-z0-9_./:{}-]+)"
)

def requirement_clause_tokens(value: str) -> set[str]:
    return {item.lower() for item in re.findall(r"[A-Za-z0-9_:/{}.-]+|[\u4e00-\u9fff]", str(value or "")) if item.strip()}

def looks_like_requirement_behavior_clause(text: str) -> bool:
    normalized = re.sub(r"\s+", " ", str(text or "")).strip().lower()
    if len(requirement_clause_tokens(normalized)) < 3:
        return False
    return bool(
        ENGLISH_REQUIREMENT_CLAUSE_START_RE.search(normalized)
        or CHINESE_REQUIREMENT_CLAUSE_START_RE.search(text)
    )

def split_weak_requirement_behavior_clauses(text: str) -> list[str]:
    value = str(text or "").strip()
    if not value:
        return []
    english_clause_start = ENGLISH_REQUIREMENT_CLAUSE_START_RE.pattern
    chinese_clause_start = CHINESE_REQUIREMENT_CLAUSE_START_RE.pattern
    raw_parts = [
        clean_line(part)
        for part in re.split(
            rf"\s*(?:,\s+(?=(?:and|then)\b)|,\s*|，\s*(?={chinese_clause_start})|\s+(?:and|then)\s+(?={english_clause_start})|(?:并且|然后|同时|并|且|还|也)\s*(?={chinese_clause_start}))\s*",
            value,
            flags=re.IGNORECASE,
        )
        if clean_line(part)
    ]
    if len(raw_parts) < 2:
        return [value]
    clauses = [
        re.sub(r"^(?:and|then|并且|然后|同时|并|且|还|也)\s*", "", part, flags=re.IGNORECASE).strip()
        for part in raw_parts
    ]
    if all(looks_like_requirement_behavior_clause(clause) for clause in clauses):
        return clauses
    return [value]

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

def split_requirement_behavior_clauses(text: str) -> list[str]:
    value = str(text or "").strip()
    if not value:
        return []
    raw_strong_parts = [clean_line(part) for part in re.split(r"\s*[;；]\s*", value) if clean_line(part)]
    strong_parts = merge_status_continuation_clauses(raw_strong_parts) if len(raw_strong_parts) > 1 else raw_strong_parts
    if len(strong_parts) > 1:
        clauses: list[str] = []
        for part in strong_parts:
            clauses.extend(split_weak_requirement_behavior_clauses(part))
        if clauses and all(looks_like_requirement_behavior_clause(clause) for clause in clauses):
            return clauses
        return strong_parts
    if len(raw_strong_parts) > 1 and len(strong_parts) == 1:
        return split_weak_requirement_behavior_clauses(strong_parts[0])
    return split_weak_requirement_behavior_clauses(value)

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
                clauses = split_requirement_behavior_clauses(cleaned)
                if len(clauses) == 1:
                    candidates.append((f"line {index}", cleaned))
                else:
                    for clause_index, clause in enumerate(clauses, 1):
                        candidates.append((f"line {index} clause {clause_index}", clause))
    if not candidates:
        pieces = re.split(r"(?<=[。！？.!?])\s+|\n{2,}", text.strip())
        for index, piece in enumerate(pieces, 1):
            cleaned = clean_line(piece)
            if cleaned:
                clauses = split_requirement_behavior_clauses(cleaned)
                if len(clauses) == 1:
                    candidates.append((f"paragraph {index}", cleaned))
                else:
                    for clause_index, clause in enumerate(clauses, 1):
                        candidates.append((f"paragraph {index} clause {clause_index}", clause))
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
    if not points:
        points.append({
            "source": "missing requirement",
            "text": "Requirement source was not provided; testing is blocked until the expected behavior is supplied.",
        })
    return points

def extract_paths(text: str) -> list[str]:
    return [match.group(1).rstrip(".,;，。；") for match in PATH_RE.finditer(text)]

def extract_code_file_paths(text: str) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for match in CODE_FILE_RE.finditer(text):
        path = match.group(0).strip("`'\".,;，。；")
        key = path.lstrip("/")
        if path and key not in seen:
            paths.append(path)
            seen.add(key)
    return paths

def path_is_code_file(path: str) -> bool:
    value = str(path or "")
    if re.match(r"^/api(?:/|$)", value, re.IGNORECASE):
        return False
    return bool(CODE_FILE_RE.search(value))

def split_leading_env_assignments(command: str) -> tuple[dict[str, str], list[str]]:
    try:
        parts = shlex.split(command)
    except ValueError:
        return {}, []
    return split_leading_env_assignments_from_parts(parts)

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

def split_leading_env_assignments_from_parts(parts: list[str]) -> tuple[dict[str, str], list[str]]:
    env: dict[str, str] = {}
    index = 0
    while index < len(parts) and ENV_ASSIGNMENT_RE.match(parts[index]):
        key, value = parts[index].split("=", 1)
        env[key] = value
        index += 1
    if index < len(parts) - 1 and Path(parts[index]).name.lower() == "env" and ENV_ASSIGNMENT_RE.match(parts[index + 1]):
        index += 1
        while index < len(parts) and ENV_ASSIGNMENT_RE.match(parts[index]):
            key, value = parts[index].split("=", 1)
            env[key] = value
            index += 1
        if index < len(parts) - 1 and parts[index] == "--":
            index += 1
    cross_env_start = package_runner_cross_env_index(parts, index)
    if cross_env_start is not None and cross_env_start < len(parts) - 1:
        cross_env_index = cross_env_start + 1
        cross_env: dict[str, str] = {}
        while cross_env_index < len(parts) and ENV_ASSIGNMENT_RE.match(parts[cross_env_index]):
            key, value = parts[cross_env_index].split("=", 1)
            cross_env[key] = value
            cross_env_index += 1
        if cross_env and cross_env_index < len(parts):
            if cross_env_index < len(parts) - 1 and parts[cross_env_index] == "--":
                cross_env_index += 1
            if cross_env_index < len(parts):
                env.update(cross_env)
                index = cross_env_index
    return env, parts[index:]

def env_assignments_reference_secret_file(env: dict[str, str]) -> bool:
    return any(path_names_secret(value) for value in env.values())

def leading_env_assignments_reference_secret_file(parts: list[str]) -> bool:
    env, remaining = split_leading_env_assignments_from_parts(parts)
    return bool(remaining and env_assignments_reference_secret_file(env))

def shell_variable_reference_names(value: str) -> set[str]:
    names: set[str] = set()
    for match in SHELL_ARRAY_VARIABLE_REFERENCE_RE.finditer(str(value or "")):
        names.add(match.group(1))
    for match in SHELL_VARIABLE_REFERENCE_RE.finditer(str(value or "")):
        name = match.group(1) or match.group(2)
        if name:
            names.add(name)
    for match in SHELL_POSITIONAL_PARAMETER_REFERENCE_RE.finditer(str(value or "")):
        name = match.group(1) or match.group(2)
        if name:
            names.add(name)
    return names

def env_assignment_value_is_secret(value: str, secret_env_names: set[str] | None = None) -> bool:
    if text_mentions_secret_path_literal(value):
        return True
    if not secret_env_names:
        return False
    return bool(shell_variable_reference_names(value) & secret_env_names)

def secret_env_assignment_names_from_env(env: dict[str, str], secret_env_names: set[str] | None = None) -> set[str]:
    return {
        name
        for name, value in env.items()
        if env_assignment_value_is_secret(value, secret_env_names)
    }

def token_references_secret_env_name(value: str, secret_env_names: set[str]) -> bool:
    return bool(secret_env_names and (shell_variable_reference_names(value) & secret_env_names))

def text_mentions_secret_path_literal(value: str) -> bool:
    text = str(value or "")
    if path_names_secret(text):
        return True
    for match in SECRET_PATH_LITERAL_RE.finditer(text):
        token = match.group(0)
        if path_names_secret(token) or (token.startswith("-") and path_names_secret(token[1:])):
            return True
    return False

def inline_interpreter_script_argument(tokens: list[str]) -> tuple[str, int] | None:
    if not tokens:
        return None
    starter = Path(tokens[0]).name.lower()
    options = INLINE_INTERPRETER_SCRIPT_OPTIONS.get(starter)
    if not options:
        return None
    index = 1
    while index < len(tokens):
        token = str(tokens[index])
        if token == "--":
            return None
        if token in options:
            if index + 1 < len(tokens):
                return str(tokens[index + 1]), index + 1
            return None
        if starter == "node" and token.startswith("--eval="):
            return token.split("=", 1)[1], index
        if starter == "perl" and token.startswith("-e") and token != "-e":
            return token[2:], index
        if starter == "perl" and token.startswith("-") and token != "-" and "e" in token[1:]:
            suffix = token[1:].split("e", 1)[1]
            if suffix:
                return suffix, index
            if index + 1 < len(tokens):
                return str(tokens[index + 1]), index + 1
            return None
        index += 1
    return None

def inline_script_has_file_read(script: str) -> bool:
    compact = re.sub(r"\s+", "", str(script or "").lower())
    return any(term in compact for term in INLINE_FILE_READ_TERMS)

def inline_script_has_file_write(script: str) -> bool:
    compact = re.sub(r"\s+", "", str(script or "").lower())
    return any(term in compact for term in INLINE_FILE_WRITE_TERMS)

def perl_option_flags(tokens: list[str]) -> str:
    flags: list[str] = []
    for token in tokens[1:]:
        if token == "--":
            break
        if token in SHELL_OPERATOR_TOKENS or token in SHELL_REDIRECTION_OPERATORS:
            break
        if not token.startswith("-") or token == "-":
            continue
        if token.startswith("-e"):
            continue
        flags.append(token.lstrip("-"))
    return "".join(flags)

def perl_uses_implicit_file_loop(tokens: list[str]) -> bool:
    flags = perl_option_flags(tokens)
    return "n" in flags or "p" in flags

def perl_uses_inplace_edit(tokens: list[str]) -> bool:
    return "i" in perl_option_flags(tokens)

def inline_tail_targets_secret_path(tokens: list[str], script_index: int, secret_env_names: set[str] | None = None) -> bool:
    for token in tokens[script_index + 1:]:
        if token in SHELL_OPERATOR_TOKENS or token in SHELL_REDIRECTION_OPERATORS:
            break
        if text_mentions_secret_path_literal(token):
            return True
        if secret_env_names and token_references_secret_env_name(token, secret_env_names):
            return True
    return False

def inline_interpreter_window_is_exposure(window: list[str], secret_env_names: set[str] | None = None) -> bool:
    tokens = [str(part) for part in window]
    parsed = inline_interpreter_script_argument(tokens)
    if not parsed:
        return False
    script, script_index = parsed
    starter = Path(tokens[0]).name.lower() if tokens else ""
    if starter == "perl" and perl_uses_implicit_file_loop(tokens):
        return inline_tail_targets_secret_path(tokens, script_index, secret_env_names)
    if not inline_script_has_file_read(script):
        return False
    if text_mentions_secret_path_literal(script):
        return True
    if not secret_env_names:
        return False
    if token_references_secret_env_name(script, secret_env_names):
        return True
    return any(token_references_secret_env_name(token, secret_env_names) for token in window[script_index + 1:])

def inline_interpreter_window_is_secret_file_mutation(window: list[str], secret_env_names: set[str] | None = None) -> bool:
    tokens = [str(part) for part in window]
    parsed = inline_interpreter_script_argument(tokens)
    if not parsed:
        return False
    script, script_index = parsed
    starter = Path(tokens[0]).name.lower() if tokens else ""
    if inline_script_has_file_write(script):
        if text_mentions_secret_path_literal(script):
            return True
        if secret_env_names and token_references_secret_env_name(script, secret_env_names):
            return True
        return inline_tail_targets_secret_path(tokens, script_index, secret_env_names)
    if starter == "perl" and perl_uses_inplace_edit(tokens):
        return inline_tail_targets_secret_path(tokens, script_index, secret_env_names)
    return False

def shell_script_has_heredoc_inline_interpreter_secret_read(script: str) -> bool:
    text = str(script or "")
    pattern = re.compile(
        r"(?:^|[;&|]\s*)"
        r"(?P<cmd>python3?|node|ruby)\b[^\n]*?<<-?\s*['\"]?(?P<tag>[A-Za-z_][A-Za-z0-9_]*)['\"]?"
        r"\n(?P<body>.*?)(?:\n(?P=tag)\b|$)",
        re.DOTALL,
    )
    for match in pattern.finditer(text):
        body = match.group("body")
        if inline_script_has_file_read(body) and text_mentions_secret_path_literal(body):
            return True
    return False

def env_wrapper_nested_command_index(command_parts: list[str], env_index: int = 0) -> int | None:
    if env_index >= len(command_parts) or Path(command_parts[env_index]).name.lower() != "env":
        return None
    index = env_index + 1
    while index < len(command_parts):
        part = str(command_parts[index])
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
            if index + 1 >= len(command_parts) or not ENV_NAME_RE.match(str(command_parts[index + 1])):
                return None
            index += 2
            continue
        if part.startswith("--unset="):
            if not ENV_NAME_RE.match(part.split("=", 1)[1]):
                return None
            index += 1
            continue
        break
    if index >= len(command_parts):
        return None
    return index

def env_command_is_allowed(command_parts: list[str]) -> bool:
    nested_index = env_wrapper_nested_command_index(command_parts)
    if nested_index is None:
        return False
    return command_parts_are_allowed(command_parts[nested_index:])

def command_parts_are_allowed(command_parts: list[str]) -> bool:
    if not command_parts:
        return False
    if any(part in SHELL_OPERATOR_TOKENS for part in command_parts):
        return False
    if len(command_parts) == 1 and single_token_absolute_route(command_parts[0]):
        return False
    if has_mutating_make_target(command_parts):
        return False
    if has_mutating_package_script(command_parts):
        return False
    if has_dependency_mutation_command(command_parts):
        return False
    if has_mutating_database_command(command_parts):
        return False
    if has_mutating_infrastructure_command(command_parts):
        return False
    if has_secret_file_write_command(command_parts):
        return False
    if has_secret_exposure_command(command_parts):
        return False
    if has_shell_wrapped_blocked_validation_command(command_parts):
        return False
    if has_default_mutating_quality_command(command_parts):
        return False
    if has_mutating_quality_option(command_parts) and has_mutating_quality_context(command_parts):
        return False
    if has_env_file_command_wrapper(command_parts):
        return False
    if len(command_parts) == 1 and path_is_code_file(command_parts[0]):
        return False
    starter = Path(command_parts[0]).name.lower()
    if starter == "env":
        return env_command_is_allowed(command_parts)
    if starter == "corepack":
        return corepack_command_is_allowed(command_parts)
    if starter in {"docker", "docker-compose"}:
        return docker_compose_command_is_allowed(command_parts)
    command_path = bool(re.match(r"^(?:\.{1,2}/|[A-Za-z0-9_.-]+/)[A-Za-z0-9_./-]+$", command_parts[0]))
    return starter in SHELL_COMMAND_STARTERS or command_path

def has_env_file_command_wrapper(command_parts: list[str]) -> bool:
    if not command_parts:
        return False
    starter = Path(command_parts[0]).name.lower()
    if starter in ENV_FILE_WRAPPER_COMMANDS:
        return True
    if starter == "direnv" and len(command_parts) >= 2 and command_parts[1] == "exec":
        return True
    if starter == "corepack" and len(command_parts) >= 2 and Path(command_parts[1]).name.lower() in COREPACK_RUNNERS:
        return has_env_file_command_wrapper(command_parts[1:])
    if starter in {"npx", "npm", "pnpm", "yarn"}:
        index = skip_package_runner_options(command_parts, 1)
        if index < len(command_parts) and command_parts[index] in {"exec", "dlx", "x"}:
            index = skip_package_runner_options(command_parts, index + 1)
        return index < len(command_parts) and Path(command_parts[index]).name.lower() in ENV_FILE_WRAPPER_COMMANDS
    return False

def has_mutating_quality_option(command_parts: list[str]) -> bool:
    return any(str(part).split("=", 1)[0] in MUTATING_QUALITY_COMMAND_OPTIONS for part in command_parts[1:])

def single_token_absolute_route(command_part: str) -> bool:
    value = str(command_part or "").strip()
    if not value.startswith("/") or "://" in value:
        return False
    route = re.split(r"[?#]", value, maxsplit=1)[0].strip("/")
    if not route:
        return False
    segments = [segment for segment in route.split("/") if segment]
    if not segments:
        return False
    if segments[0].lower() in ABSOLUTE_COMMAND_ROOT_SEGMENTS:
        return False
    return True

def has_non_mutating_quality_option(command_parts: list[str]) -> bool:
    return any(str(part).split("=", 1)[0] in NON_MUTATING_QUALITY_OPTIONS for part in command_parts[1:])

def make_target_terms(target: str) -> set[str]:
    value = Path(str(target)).name.lower()
    if not value or value.startswith("-") or "=" in value:
        return set()
    pieces = [piece for piece in re.split(r"[^a-z0-9]+", value) if piece]
    return {value.replace("-", "").replace("_", "").replace(":", ""), *pieces}

def has_mutating_make_target(command_parts: list[str]) -> bool:
    tokens = [str(part) for part in command_parts]
    candidate_windows: list[list[str]] = []
    for index, token in enumerate(tokens):
        if Path(token).name.lower() == "make":
            candidate_windows.append(tokens[index:])
    if not candidate_windows:
        return False

    for window in candidate_windows:
        index = 1
        while index < len(window):
            part = window[index]
            option = part.split("=", 1)[0]
            if part == "--":
                index += 1
                continue
            if part.startswith("-"):
                index += 1
                if "=" not in part and option in MAKE_OPTIONS_WITH_VALUE and index < len(window):
                    index += 1
                continue
            if "=" in part:
                index += 1
                continue
            if make_target_terms(part) & MUTATING_MAKE_TARGET_TERMS:
                return True
            index += 1
    return False

def package_script_targets(command_parts: list[str]) -> list[str]:
    tokens = [str(part) for part in command_parts]
    targets: list[str] = []
    for index, token in enumerate(tokens):
        runner = Path(token).name.lower()
        if runner not in PACKAGE_SCRIPT_RUNNERS:
            continue
        cursor = skip_package_runner_options(tokens, index + 1)
        if cursor >= len(tokens):
            continue
        action = Path(tokens[cursor]).name.lower()
        if action in PACKAGE_EXEC_SUBCOMMANDS:
            continue
        if runner == "yarn" and action == "workspace":
            workspace_cursor = skip_package_runner_options(tokens, cursor + 1)
            script_cursor = skip_package_runner_options(tokens, workspace_cursor + 1)
            if script_cursor >= len(tokens):
                continue
            workspace_action = Path(tokens[script_cursor]).name.lower()
            if workspace_action in PACKAGE_EXEC_SUBCOMMANDS:
                continue
            if workspace_action in PACKAGE_SCRIPT_RUN_SUBCOMMANDS:
                script_cursor = skip_package_runner_options(tokens, script_cursor + 1)
                if script_cursor < len(tokens) and tokens[script_cursor] != "--":
                    targets.append(tokens[script_cursor])
                continue
            targets.append(tokens[script_cursor])
            continue
        if action in PACKAGE_SCRIPT_RUN_SUBCOMMANDS:
            cursor = skip_package_runner_options(tokens, cursor + 1)
            if cursor < len(tokens) and tokens[cursor] != "--":
                targets.append(tokens[cursor])
            continue
        targets.append(tokens[cursor])
    return targets

def has_mutating_package_script(command_parts: list[str]) -> bool:
    for target in package_script_targets(command_parts):
        if make_target_terms(target) & MUTATING_MAKE_TARGET_TERMS:
            return True
    return False

def dependency_mutation_candidate_windows(command_parts: list[str]) -> list[list[str]]:
    tokens = [str(part) for part in command_parts]
    windows: list[list[str]] = [tokens]
    if not tokens:
        return windows
    starter = Path(tokens[0]).name.lower()
    if starter == "env":
        nested_index = env_wrapper_nested_command_index(tokens)
        if nested_index is not None and nested_index < len(tokens):
            windows.extend(dependency_mutation_candidate_windows(tokens[nested_index:]))
    if starter == "corepack" and len(tokens) >= 2 and Path(tokens[1]).name.lower() in COREPACK_RUNNERS:
        windows.extend(dependency_mutation_candidate_windows(tokens[1:]))
    if starter in PYTHON_MODULE_COMMAND_STARTERS and len(tokens) >= 3 and tokens[1] == "-m":
        windows.append(tokens[2:])
    if starter in {"npm", "pnpm", "yarn", "bun"}:
        cursor = skip_package_runner_options(tokens, 1)
        if cursor < len(tokens) and Path(tokens[cursor]).name.lower() in PACKAGE_EXEC_SUBCOMMANDS:
            cursor = skip_package_runner_options(tokens, cursor + 1)
            if cursor < len(tokens):
                windows.extend(dependency_mutation_candidate_windows(tokens[cursor:]))
    if starter in TOOL_RUNNER_COMMAND_STARTERS:
        run_index = tokens.index("run") + 1 if "run" in tokens else 1
        if run_index < len(tokens):
            windows.append(tokens[run_index:])
    return windows

def first_non_option_action(tokens: list[str], start_index: int = 1) -> str | None:
    index = start_index
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return Path(token).name.lower()
    return None

def dependency_mutation_window_is_mutating(window: list[str]) -> bool:
    tokens = [str(part) for part in window if str(part)]
    if not tokens:
        return False
    starter = Path(tokens[0]).name.lower()
    if starter in PACKAGE_DEPENDENCY_MUTATION_RUNNERS:
        cursor = skip_package_runner_options(tokens, 1)
        if cursor >= len(tokens):
            return False
        action = Path(tokens[cursor]).name.lower()
        return action in DEPENDENCY_MUTATION_ACTIONS
    if starter in PYTHON_DEPENDENCY_MUTATION_TOOLS:
        action = first_non_option_action(tokens)
        return action in DEPENDENCY_MUTATION_ACTIONS
    if starter == "uv" and len(tokens) >= 3 and Path(tokens[1]).name.lower() == "pip":
        action = first_non_option_action(tokens, 2)
        return action in DEPENDENCY_MUTATION_ACTIONS
    if starter in PROJECT_DEPENDENCY_MUTATION_TOOLS:
        action = first_non_option_action(tokens)
        return action in DEPENDENCY_MUTATION_ACTIONS
    if starter in SYSTEM_DEPENDENCY_MUTATION_TOOLS:
        action = first_non_option_action(tokens)
        return action in DEPENDENCY_MUTATION_ACTIONS
    return False

def has_dependency_mutation_command(command_parts: list[str]) -> bool:
    return any(
        dependency_mutation_window_is_mutating(window)
        for window in dependency_mutation_candidate_windows(command_parts)
    )

def database_mutation_candidate_windows(command_parts: list[str]) -> list[list[str]]:
    tokens = [str(part) for part in command_parts]
    windows: list[list[str]] = [tokens]
    if len(tokens) >= 2 and Path(tokens[0]).name.lower() == "corepack" and Path(tokens[1]).name.lower() in COREPACK_RUNNERS:
        windows.extend(database_mutation_candidate_windows(tokens[1:]))

    for index, token in enumerate(tokens):
        runner = Path(token).name.lower()
        if runner in {"npm", "pnpm", "yarn", "bun"}:
            cursor = skip_package_runner_options(tokens, index + 1)
            if cursor < len(tokens) and Path(tokens[cursor]).name.lower() in PACKAGE_EXEC_SUBCOMMANDS:
                cursor = skip_package_runner_options(tokens, cursor + 1)
                if cursor < len(tokens):
                    windows.append(tokens[cursor:])
            continue
        if runner == "npx":
            cursor = skip_package_runner_options(tokens, index + 1)
            if cursor < len(tokens):
                windows.append(tokens[cursor:])

    if tokens:
        starter = Path(tokens[0]).name.lower()
        if starter in PYTHON_MODULE_COMMAND_STARTERS:
            if len(tokens) >= 3 and tokens[1] == "-m":
                windows.append(tokens[2:])
            if len(tokens) >= 2 and Path(tokens[1]).name.lower() == "manage.py":
                windows.append(tokens[1:])
        if starter in TOOL_RUNNER_COMMAND_STARTERS:
            run_index = tokens.index("run") + 1 if "run" in tokens else 1
            if run_index < len(tokens):
                windows.append(tokens[run_index:])
    return windows

def database_mutation_window_is_mutating(window: list[str]) -> bool:
    normalized = [Path(str(part)).name.lower() for part in window if str(part)]
    if not normalized:
        return False
    tool_index = next((index for index, token in enumerate(normalized) if token in DATABASE_MUTATION_TOOLS), None)
    if tool_index is None:
        return False
    action_terms: set[str] = set()
    for token in normalized[tool_index + 1:]:
        action_terms.update(make_target_terms(token))
    return bool(action_terms & DATABASE_MUTATION_ACTION_TERMS)

def has_mutating_database_command(command_parts: list[str]) -> bool:
    return any(
        database_mutation_window_is_mutating(window)
        for window in database_mutation_candidate_windows(command_parts)
    )

def has_mutating_infrastructure_command(command_parts: list[str]) -> bool:
    tokens = [str(part) for part in command_parts]
    if not tokens:
        return False
    starter = Path(tokens[0]).name.lower()
    if starter == "rm":
        return len(tokens) > 1
    if starter in {"docker", "docker-compose"}:
        if starter == "docker" and len(tokens) >= 3 and tokens[1] == "compose":
            return Path(tokens[2]).name.lower() in DOCKER_MUTATION_ACTIONS
        if starter == "docker-compose" and len(tokens) >= 2:
            return Path(tokens[1]).name.lower() in DOCKER_MUTATION_ACTIONS
        if starter == "docker" and len(tokens) >= 3 and tokens[1] == "system":
            return Path(tokens[2]).name.lower() in DOCKER_SYSTEM_MUTATION_ACTIONS
        return False
    if starter in {"env", "corepack"}:
        nested_index = env_wrapper_nested_command_index(tokens) if starter == "env" else 1
        if nested_index is not None and nested_index < len(tokens):
            return has_mutating_infrastructure_command(tokens[nested_index:])
    windows: list[list[str]] = [tokens]
    if starter in {"npm", "pnpm", "yarn", "bun"}:
        cursor = skip_package_runner_options(tokens, 1)
        if cursor < len(tokens) and Path(tokens[cursor]).name.lower() in PACKAGE_EXEC_SUBCOMMANDS:
            cursor = skip_package_runner_options(tokens, cursor + 1)
            if cursor < len(tokens):
                windows.append(tokens[cursor:])
    if starter == "npx":
        cursor = skip_package_runner_options(tokens, 1)
        if cursor < len(tokens):
            windows.append(tokens[cursor:])
    if starter in TOOL_RUNNER_COMMAND_STARTERS:
        run_index = tokens.index("run") + 1 if "run" in tokens else 1
        if run_index < len(tokens):
            windows.append(tokens[run_index:])

    for window in windows:
        normalized = [Path(str(part)).name.lower() for part in window if str(part)]
        tool_index = next((index for index, token in enumerate(normalized) if token in INFRASTRUCTURE_MUTATION_TOOLS), None)
        if tool_index is None:
            continue
        action_terms: set[str] = set()
        for token in normalized[tool_index + 1:]:
            action_terms.update(make_target_terms(token))
        if action_terms & INFRASTRUCTURE_MUTATION_ACTION_TERMS:
            return True
    return False

def compact_secret_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())

def token_names_secret(value: str) -> bool:
    compact = compact_secret_name(value)
    if not compact:
        return False
    if compact in SECRET_ENV_NAME_COMPACT_TERMS:
        return True
    return any(term in compact for term in ("password", "privatekey", "credential", "secret", "token"))

def path_names_secret(value: str) -> bool:
    text = str(value or "").strip()
    if not text or text.startswith("-"):
        return False
    lowered = text.lower()
    path = Path(lowered)
    name = path.name
    if name in {".env", ".envrc"} or name.startswith(".env."):
        return True
    if any(lowered.endswith(extension) for extension in SECRET_PATH_EXTENSIONS):
        return True
    segments = [segment for segment in re.split(r"[/\\._-]+", lowered) if segment]
    return bool(set(segments) & SECRET_PATH_TERMS)

def env_secret_assignment_names(tokens: list[str]) -> bool:
    for token in tokens:
        if token == "--":
            continue
        if token in {"-u", "--unset"}:
            continue
        if token.startswith("--unset="):
            continue
        if ENV_ASSIGNMENT_RE.match(token) and token_names_secret(token.split("=", 1)[0]):
            return True
    return False

def aws_secret_read_window_is_exposure(window: list[str]) -> bool:
    normalized = [Path(str(part)).name.lower() for part in window if str(part)]
    if not normalized or normalized[0] != "aws" or len(normalized) < 3:
        return False
    service = normalized[1]
    if service not in AWS_SECRET_READ_SERVICES:
        return False
    action_terms: set[str] = set()
    for token in normalized[2:]:
        action_terms.update(make_target_terms(token))
    if not (action_terms & AWS_SECRET_READ_ACTIONS):
        return False
    if service == "secretsmanager":
        return True
    return "--with-decryption" in window or any(path_names_secret(token) or token_names_secret(token) for token in window[3:])

def kubectl_secret_read_window_is_exposure(window: list[str]) -> bool:
    normalized = [Path(str(part)).name.lower() for part in window if str(part)]
    if not normalized or normalized[0] not in {"kubectl", "oc"} or len(normalized) < 3:
        return False
    action = normalized[1]
    if action not in KUBECTL_SECRET_READ_ACTIONS:
        return False
    return any(make_target_terms(token) & {"secret", "secrets"} for token in normalized[2:])

def gh_secret_window_is_exposure(window: list[str]) -> bool:
    normalized = [Path(str(part)).name.lower() for part in window if str(part)]
    return len(normalized) >= 3 and normalized[0] == "gh" and normalized[1] == "secret"

def vault_secret_window_is_exposure(window: list[str]) -> bool:
    normalized = [Path(str(part)).name.lower() for part in window if str(part)]
    if not normalized or normalized[0] != "vault" or len(normalized) < 2:
        return False
    action = normalized[1]
    if action == "kv":
        return len(normalized) >= 3 and normalized[2] in {"get", "put", "patch", "delete", "undelete", "destroy"}
    return action in VAULT_SECRET_READ_ACTIONS

def one_password_window_is_exposure(window: list[str]) -> bool:
    normalized = [Path(str(part)).name.lower() for part in window if str(part)]
    if not normalized or normalized[0] != "op" or len(normalized) < 2:
        return False
    if normalized[1] == "read":
        return True
    return len(normalized) >= 3 and normalized[1] == "item" and normalized[2] in {"get", "edit", "delete"}

def shell_script_argument(tokens: list[str]) -> str | None:
    for index, token in enumerate(tokens[1:], start=1):
        if not token.startswith("-"):
            continue
        option = token.split("=", 1)[0]
        if "c" not in option:
            continue
        if "=" in token:
            return token.split("=", 1)[1]
        if index + 1 < len(tokens):
            return tokens[index + 1]
        return None
    return None

def split_shell_script_parts(script: str) -> list[str]:
    lexer = shlex.shlex(str(script or ""), posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)

SHELL_PAREN_SUBSTITUTION_OPENERS = ("$(", "<(", ">(")

def shell_parenthesized_substitution_script(text: str, index: int) -> tuple[str, int] | None:
    depth = 1
    cursor = index + 2
    inner_quote: str | None = None
    inner_escaped = False
    while cursor < len(text):
        inner_char = text[cursor]
        if inner_escaped:
            inner_escaped = False
            cursor += 1
            continue
        if inner_char == "\\":
            inner_escaped = True
            cursor += 1
            continue
        if inner_quote == "'":
            if inner_char == "'":
                inner_quote = None
            cursor += 1
            continue
        if inner_quote == '"':
            if inner_char == '"':
                inner_quote = None
                cursor += 1
                continue
        elif inner_char in {"'", '"'}:
            inner_quote = inner_char
            cursor += 1
            continue
        if any(text.startswith(opener, cursor) for opener in SHELL_PAREN_SUBSTITUTION_OPENERS):
            depth += 1
            cursor += 2
            continue
        if inner_char == ")":
            depth -= 1
            if depth == 0:
                return text[index + 2:cursor], cursor + 1
        cursor += 1
    return None

def shell_command_substitution_scripts(script: str) -> list[str]:
    text = str(script or "")
    scripts: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\":
            escaped = True
            index += 1
            continue
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if quote == '"':
            if char == '"':
                quote = None
                index += 1
                continue
        elif char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if any(text.startswith(opener, index) for opener in SHELL_PAREN_SUBSTITUTION_OPENERS):
            parsed = shell_parenthesized_substitution_script(text, index)
            if parsed:
                inner_script, next_index = parsed
                scripts.append(inner_script)
                index = next_index
            else:
                index += 2
            continue
        if char == "`":
            cursor = index + 1
            inner_escaped = False
            while cursor < len(text):
                inner_char = text[cursor]
                if inner_escaped:
                    inner_escaped = False
                    cursor += 1
                    continue
                if inner_char == "\\":
                    inner_escaped = True
                    cursor += 1
                    continue
                if inner_char == "`":
                    scripts.append(text[index + 1:cursor])
                    index = cursor + 1
                    break
                cursor += 1
            else:
                index += 1
            continue
        index += 1
    return scripts

def shell_command_segments_from_script(script: str, substitution_depth: int = 2) -> list[list[str]]:
    try:
        parts = split_shell_script_parts(str(script))
    except ValueError:
        return []
    segments: list[list[str]] = []
    current: list[str] = []
    for part in [*parts, "&&"]:
        if part in SHELL_OPERATOR_TOKENS:
            _, segment_parts = split_leading_env_assignments_from_parts(current)
            if segment_parts:
                segments.append(segment_parts)
            current = []
        else:
            current.append(part)
    if substitution_depth > 0:
        for substitution_script in shell_command_substitution_scripts(script):
            segments.extend(shell_command_segments_from_script(substitution_script, substitution_depth=substitution_depth - 1))
    return segments

def shell_tokens_after_leading_env_assignments(tokens: list[str]) -> list[str]:
    _, remaining = split_leading_env_assignments_from_parts([str(token) for token in tokens])
    return remaining or [str(token) for token in tokens]

def shell_token_segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for token in [*tokens, "&&"]:
        if token in SHELL_OPERATOR_TOKENS:
            _, segment_parts = split_leading_env_assignments_from_parts(current)
            if segment_parts:
                segments.append(segment_parts)
            current = []
        else:
            current.append(str(token))
    return segments

def shell_read_variable_names(tokens: list[str]) -> set[str] | None:
    command_tokens = shell_tokens_after_leading_env_assignments(tokens)
    if not command_tokens or Path(command_tokens[0]).name.lower() != "read":
        return None
    names: list[str] = []
    index = 1
    while index < len(command_tokens):
        token = command_tokens[index]
        if token in SHELL_OPERATOR_TOKENS or token in {"<<<", "<", ">"}:
            break
        if token == "--":
            index += 1
            continue
        if token.startswith("-") and token != "-":
            index += 2 if token in SHELL_READ_OPTIONS_WITH_VALUE else 1
            continue
        if ENV_NAME_RE.match(token):
            names.append(token)
        index += 1
    return set(names or ["REPLY"])

def shell_mapfile_variable_names(tokens: list[str]) -> set[str] | None:
    command_tokens = shell_tokens_after_leading_env_assignments(tokens)
    if not command_tokens or Path(command_tokens[0]).name.lower() not in SHELL_MAPFILE_COMMANDS:
        return None
    name = "MAPFILE"
    index = 1
    while index < len(command_tokens):
        token = command_tokens[index]
        if token in SHELL_OPERATOR_TOKENS or token in {"<<<", "<", ">"}:
            break
        if token == "--":
            index += 1
            continue
        if token.startswith("-") and token != "-":
            index += 2 if token in SHELL_MAPFILE_OPTIONS_WITH_VALUE else 1
            continue
        if ENV_NAME_RE.match(token):
            name = token
        index += 1
    return {name}

def shell_read_here_string_state_changes(tokens: list[str], secret_env_names: set[str]) -> tuple[set[str], set[str]] | None:
    command_tokens = shell_tokens_after_leading_env_assignments(tokens)
    if not command_tokens or Path(command_tokens[0]).name.lower() != "read" or "<<<" not in command_tokens:
        return None
    here_index = command_tokens.index("<<<")
    if here_index + 1 >= len(command_tokens):
        return None

    assigned_names = shell_read_variable_names(command_tokens[:here_index]) or {"REPLY"}
    if env_assignment_value_is_secret(command_tokens[here_index + 1], secret_env_names):
        return assigned_names, set()
    return set(), assigned_names

def shell_mapfile_here_string_state_changes(tokens: list[str], secret_env_names: set[str]) -> tuple[set[str], set[str]] | None:
    command_tokens = shell_tokens_after_leading_env_assignments(tokens)
    if not command_tokens or Path(command_tokens[0]).name.lower() not in SHELL_MAPFILE_COMMANDS or "<<<" not in command_tokens:
        return None
    here_index = command_tokens.index("<<<")
    if here_index + 1 >= len(command_tokens):
        return None
    assigned_names = shell_mapfile_variable_names(command_tokens[:here_index]) or {"MAPFILE"}
    if env_assignment_value_is_secret(command_tokens[here_index + 1], secret_env_names):
        return assigned_names, set()
    return set(), assigned_names

def shell_read_input_redirection_state_changes(tokens: list[str], secret_env_names: set[str]) -> tuple[set[str], set[str]] | None:
    command_tokens = shell_tokens_after_leading_env_assignments(tokens)
    if not command_tokens or Path(command_tokens[0]).name.lower() != "read" or "<" not in command_tokens:
        return None
    redirect_index = command_tokens.index("<")
    if redirect_index + 1 >= len(command_tokens):
        return None
    assigned_names = shell_read_variable_names(command_tokens[:redirect_index]) or {"REPLY"}
    redirection_value = " ".join(command_tokens[redirect_index + 1:])
    if env_assignment_value_is_secret(redirection_value, secret_env_names):
        return assigned_names, set()
    return set(), assigned_names

def shell_mapfile_input_redirection_state_changes(tokens: list[str], secret_env_names: set[str]) -> tuple[set[str], set[str]] | None:
    command_tokens = shell_tokens_after_leading_env_assignments(tokens)
    if not command_tokens or Path(command_tokens[0]).name.lower() not in SHELL_MAPFILE_COMMANDS or "<" not in command_tokens:
        return None
    redirect_index = command_tokens.index("<")
    if redirect_index + 1 >= len(command_tokens):
        return None
    assigned_names = shell_mapfile_variable_names(command_tokens[:redirect_index]) or {"MAPFILE"}
    redirection_value = " ".join(command_tokens[redirect_index + 1:])
    if env_assignment_value_is_secret(redirection_value, secret_env_names):
        return assigned_names, set()
    return set(), assigned_names

def shell_set_positional_state_changes(tokens: list[str], secret_env_names: set[str]) -> tuple[set[str], set[str]] | None:
    if not tokens or Path(tokens[0]).name.lower() != "set" or "--" not in tokens:
        return None
    args = tokens[tokens.index("--") + 1:]
    assigned_secret_names: set[str] = set()
    cleared_names: set[str] = set(SHELL_POSITIONAL_PARAMETER_NAMES)
    for index, value in enumerate(args[:len(SHELL_POSITIONAL_PARAMETER_NAMES)], start=1):
        name = str(index)
        if env_assignment_value_is_secret(value, secret_env_names):
            assigned_secret_names.add(name)
            cleared_names.discard(name)
    return assigned_secret_names, cleared_names

def shell_env_state_changes_from_segment(parts: list[str], secret_env_names: set[str]) -> tuple[set[str], set[str]]:
    tokens = [str(part) for part in parts]
    if not tokens:
        return set(), set()

    assigned_secret_names: set[str] = set()
    cleared_names: set[str] = set()
    if ENV_ASSIGNMENT_RE.match(tokens[0]):
        env, remaining = split_leading_env_assignments_from_parts(tokens)
        if not remaining:
            assigned_secret_names = secret_env_assignment_names_from_env(env, secret_env_names)
            cleared_names = set(env) - assigned_secret_names
            return assigned_secret_names, cleared_names

    starter = Path(tokens[0]).name.lower()
    if starter == "unset":
        for token in tokens[1:]:
            if token == "--" or token.startswith("-"):
                continue
            if ENV_NAME_RE.match(token):
                cleared_names.add(token)
        return set(), cleared_names

    read_state_changes = shell_read_here_string_state_changes(tokens, secret_env_names)
    if read_state_changes is not None:
        return read_state_changes

    read_redirect_state_changes = shell_read_input_redirection_state_changes(tokens, secret_env_names)
    if read_redirect_state_changes is not None:
        return read_redirect_state_changes

    mapfile_state_changes = shell_mapfile_here_string_state_changes(tokens, secret_env_names)
    if mapfile_state_changes is not None:
        return mapfile_state_changes

    mapfile_redirect_state_changes = shell_mapfile_input_redirection_state_changes(tokens, secret_env_names)
    if mapfile_redirect_state_changes is not None:
        return mapfile_redirect_state_changes

    positional_state_changes = shell_set_positional_state_changes(tokens, secret_env_names)
    if positional_state_changes is not None:
        return positional_state_changes

    if starter not in SHELL_ENV_ASSIGNMENT_BUILTINS:
        return set(), set()

    parsing_options = True
    for token in tokens[1:]:
        if parsing_options and token == "--":
            parsing_options = False
            continue
        if parsing_options and token.startswith("-"):
            continue
        if not ENV_ASSIGNMENT_RE.match(token):
            continue
        name, value = token.split("=", 1)
        if env_assignment_value_is_secret(value, secret_env_names):
            assigned_secret_names.add(name)
        else:
            cleared_names.add(name)
    return assigned_secret_names, cleared_names

def secret_env_reference_window_is_exposure(window: list[str], secret_env_names: set[str]) -> bool:
    tokens = [str(part) for part in window]
    if len(tokens) < 2 or not secret_env_names:
        return False
    starter = "." if tokens[0] == "." else Path(tokens[0]).name.lower()
    if inline_interpreter_window_is_exposure(tokens, secret_env_names):
        return True
    if starter == "xargs":
        return xargs_here_string_secret_path_window_is_exposure(tokens, secret_env_names)
    if starter in SOURCE_ENV_FILE_COMMANDS or starter == "cat":
        return any(token_references_secret_env_name(token, secret_env_names) for token in tokens[1:])
    if starter in SED_AWK_FILE_READ_COMMANDS:
        return sed_awk_file_read_window_is_exposure(tokens, secret_env_names)
    if starter in SECRET_FILE_READ_COMMANDS or starter in SECRET_FILE_EXFILTRATION_COMMANDS:
        return any(token_references_secret_env_name(token, secret_env_names) for token in tokens[1:])
    return False

def shell_segment_references_secret_env_state(parts: list[str], secret_env_names: set[str]) -> bool:
    if not parts or not secret_env_names:
        return False
    _, segment_parts = split_leading_env_assignments_from_parts([str(part) for part in parts])
    command_parts = segment_parts or [str(part) for part in parts]
    return any(
        secret_env_reference_window_is_exposure(window, secret_env_names)
        for window in secret_exposure_candidate_windows(command_parts)
    )

def xargs_reader_command_index(tokens: list[str]) -> int | None:
    if not tokens or Path(tokens[0]).name.lower() != "xargs":
        return None
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in SHELL_OPERATOR_TOKENS or token == "<<<":
            return None
        if token == "--":
            index += 1
            break
        if token.startswith("-") and token != "-":
            index += 2 if token in XARGS_OPTIONS_WITH_VALUE else 1
            continue
        break
    if index < len(tokens) and Path(tokens[index]).name.lower() in XARGS_SECRET_FILE_READ_COMMANDS:
        return index
    return None

def xargs_secret_file_mutation_command_index(tokens: list[str]) -> int | None:
    if not tokens or Path(tokens[0]).name.lower() != "xargs":
        return None
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in SHELL_OPERATOR_TOKENS or token == "<<<":
            return None
        if token == "--":
            index += 1
            break
        if token.startswith("-") and token != "-":
            index += 2 if token in XARGS_OPTIONS_WITH_VALUE else 1
            continue
        break
    if index < len(tokens) and Path(tokens[index]).name.lower() in SECRET_FILE_MUTATION_COMMANDS:
        return index
    return None

def xargs_here_string_secret_path_window_is_exposure(
    window: list[str],
    secret_env_names: set[str] | None = None,
) -> bool:
    tokens = [str(part) for part in window]
    if xargs_reader_command_index(tokens) is None or "<<<" not in tokens:
        return False
    here_index = tokens.index("<<<")
    if here_index + 1 >= len(tokens):
        return False
    value = tokens[here_index + 1]
    if text_mentions_secret_path_literal(value):
        return True
    return bool(secret_env_names and token_references_secret_env_name(value, secret_env_names))

def xargs_here_string_secret_path_window_is_mutation(window: list[str]) -> bool:
    tokens = [str(part) for part in window]
    if xargs_secret_file_mutation_command_index(tokens) is None or "<<<" not in tokens:
        return False
    here_index = tokens.index("<<<")
    return here_index + 1 < len(tokens) and text_mentions_secret_path_literal(tokens[here_index + 1])

def shell_stdin_text_segment_mentions_secret_path(segment: list[str]) -> bool:
    if not segment or Path(segment[0]).name.lower() not in SHELL_STDIN_TEXT_COMMANDS:
        return False
    return any(text_mentions_secret_path_literal(token) for token in segment[1:])

def shell_script_has_secret_xargs_pipe(script: str) -> bool:
    try:
        parts = split_shell_script_parts(str(script))
    except ValueError:
        return False
    segments: list[list[str]] = []
    operators: list[str] = []
    current: list[str] = []
    for part in parts:
        if part in SHELL_OPERATOR_TOKENS:
            segments.append(current)
            operators.append(part)
            current = []
        else:
            current.append(part)
    segments.append(current)
    for index, operator in enumerate(operators):
        if operator != "|" or index + 1 >= len(segments):
            continue
        if shell_stdin_text_segment_mentions_secret_path(segments[index]) and xargs_reader_command_index(segments[index + 1]) is not None:
            return True
    return False

def shell_script_has_secret_xargs_mutation_pipe(script: str) -> bool:
    try:
        parts = split_shell_script_parts(str(script))
    except ValueError:
        return False
    segments: list[list[str]] = []
    operators: list[str] = []
    current: list[str] = []
    for part in parts:
        if part in SHELL_OPERATOR_TOKENS:
            segments.append(current)
            operators.append(part)
            current = []
        else:
            current.append(part)
    segments.append(current)
    for index, operator in enumerate(operators):
        if operator != "|" or index + 1 >= len(segments):
            continue
        if shell_stdin_text_segment_mentions_secret_path(segments[index]) and xargs_secret_file_mutation_command_index(segments[index + 1]) is not None:
            return True
    return False

def shell_script_has_secret_substitution_env_assignment(script: str) -> bool:
    text = str(script or "")
    for match in SHELL_SUBSTITUTION_ASSIGNMENT_RE.finditer(text):
        name = match.group("name")
        value = match.group("value").strip('"')
        if not text_mentions_secret_path_literal(value):
            continue
        later_script = text[match.end():]
        later_segments = shell_command_segments_from_script(later_script, substitution_depth=0)
        if any(shell_segment_references_secret_env_state(segment, {name}) for segment in later_segments):
            return True
    return False

def shell_first_token_index(tokens: list[str], token: str, start: int) -> int | None:
    try:
        return tokens.index(token, start)
    except ValueError:
        return None

def shell_script_has_secret_for_loop(parts: list[str]) -> bool:
    tokens = [str(part) for part in parts]
    index = 0
    while index < len(tokens):
        if tokens[index] != "for" or index + 3 >= len(tokens) or not ENV_NAME_RE.match(tokens[index + 1]):
            index += 1
            continue
        name = tokens[index + 1]
        in_index = shell_first_token_index(tokens, "in", index + 2)
        if in_index is None:
            index += 1
            continue
        value_end = shell_first_token_index(tokens, ";", in_index + 1)
        inline_do_index = shell_first_token_index(tokens, "do", in_index + 1)
        if inline_do_index is not None and (value_end is None or inline_do_index < value_end):
            value_end = inline_do_index
            do_index = inline_do_index
        else:
            if value_end is None:
                index += 1
                continue
            do_index = value_end + 1 if value_end + 1 < len(tokens) and tokens[value_end + 1] == "do" else None
        if do_index is None:
            index += 1
            continue
        done_index = shell_first_token_index(tokens, "done", do_index + 1)
        if done_index is None:
            index += 1
            continue
        values = tokens[in_index + 1:value_end]
        if any(env_assignment_value_is_secret(value) for value in values):
            body_segments = shell_token_segments(tokens[do_index + 1:done_index])
            if any(shell_segment_references_secret_env_state(segment, {name}) for segment in body_segments):
                return True
        index = done_index + 1
    return False

def shell_script_has_secret_while_read_loop(parts: list[str]) -> bool:
    tokens = [str(part) for part in parts]
    index = 0
    while index < len(tokens):
        if tokens[index] != "while":
            index += 1
            continue
        do_index = shell_first_token_index(tokens, "do", index + 1)
        if do_index is None:
            index += 1
            continue
        done_index = shell_first_token_index(tokens, "done", do_index + 1)
        if done_index is None:
            index += 1
            continue
        input_mentions_secret = False
        here_index = shell_first_token_index(tokens, "<<<", done_index + 1)
        if here_index is not None and here_index + 1 < len(tokens):
            input_mentions_secret = env_assignment_value_is_secret(tokens[here_index + 1])
        if not input_mentions_secret:
            redirect_index = shell_first_token_index(tokens, "<", done_index + 1)
            if redirect_index is not None and redirect_index + 1 < len(tokens):
                redirection_tokens: list[str] = []
                cursor = redirect_index + 1
                while cursor < len(tokens) and tokens[cursor] not in SHELL_OPERATOR_TOKENS:
                    redirection_tokens.append(tokens[cursor])
                    cursor += 1
                input_mentions_secret = env_assignment_value_is_secret(" ".join(redirection_tokens))
        if not input_mentions_secret and index > 0 and tokens[index - 1] == "|":
            previous_operator = max(
                [pos for pos, token in enumerate(tokens[:index - 1]) if token in SHELL_OPERATOR_TOKENS],
                default=-1,
            )
            input_mentions_secret = shell_stdin_text_segment_mentions_secret_path(tokens[previous_operator + 1:index - 1])
        if not input_mentions_secret:
            index = done_index + 1
            continue
        names: set[str] = set()
        for condition_segment in shell_token_segments(tokens[index + 1:do_index]):
            read_names = shell_read_variable_names(condition_segment)
            if read_names:
                names.update(read_names)
        if names:
            body_segments = shell_token_segments(tokens[do_index + 1:done_index])
            if any(shell_segment_references_secret_env_state(segment, names) for segment in body_segments):
                return True
        index = done_index + 1
    return False

def shell_script_has_secret_control_flow(script: str) -> bool:
    try:
        parts = split_shell_script_parts(str(script))
    except ValueError:
        return False
    return shell_script_has_secret_for_loop(parts) or shell_script_has_secret_while_read_loop(parts)

def shell_script_has_secret_env_assignment(script: str) -> bool:
    if shell_script_has_secret_substitution_env_assignment(script):
        return True
    if shell_script_has_secret_control_flow(script):
        return True
    try:
        parts = split_shell_script_parts(str(script))
    except ValueError:
        return False
    current: list[str] = []
    secret_env_names: set[str] = set()
    for part in [*parts, "&&"]:
        if part in SHELL_OPERATOR_TOKENS:
            if leading_env_assignments_reference_secret_file(current):
                return True
            if shell_segment_references_secret_env_state(current, secret_env_names):
                return True
            assigned_secret_names, cleared_names = shell_env_state_changes_from_segment(current, secret_env_names)
            secret_env_names.difference_update(cleared_names)
            if part not in {"|", "&"}:
                secret_env_names.update(assigned_secret_names)
            current = []
        else:
            current.append(part)
    return False

def shell_script_command_segments(tokens: list[str]) -> list[list[str]]:
    script = shell_script_argument(tokens)
    if not script:
        return []
    return shell_command_segments_from_script(str(script))

def shell_wrapped_blocked_candidate_windows(command_parts: list[str]) -> list[list[str]]:
    tokens = [str(part) for part in command_parts]
    windows: list[list[str]] = [tokens]
    if not tokens:
        return windows
    starter = Path(tokens[0]).name.lower()
    if starter == "env":
        nested_index = env_wrapper_nested_command_index(tokens)
        if nested_index is not None and nested_index < len(tokens):
            windows.extend(shell_wrapped_blocked_candidate_windows(tokens[nested_index:]))
    if starter == "corepack" and len(tokens) >= 2 and Path(tokens[1]).name.lower() in COREPACK_RUNNERS:
        windows.extend(shell_wrapped_blocked_candidate_windows(tokens[1:]))
    if starter in {"npm", "pnpm", "yarn", "bun"}:
        cursor = skip_package_runner_options(tokens, 1)
        if cursor < len(tokens) and Path(tokens[cursor]).name.lower() in PACKAGE_EXEC_SUBCOMMANDS:
            cursor = skip_package_runner_options(tokens, cursor + 1)
            if cursor < len(tokens):
                windows.extend(shell_wrapped_blocked_candidate_windows(tokens[cursor:]))
    if starter == "npx":
        cursor = skip_package_runner_options(tokens, 1)
        if cursor < len(tokens):
            windows.extend(shell_wrapped_blocked_candidate_windows(tokens[cursor:]))
    if starter in TOOL_RUNNER_COMMAND_STARTERS:
        run_index = tokens.index("run") + 1 if "run" in tokens else 1
        if run_index < len(tokens):
            windows.extend(shell_wrapped_blocked_candidate_windows(tokens[run_index:]))
    return windows

def has_shell_wrapped_blocked_validation_command(command_parts: list[str], shell_depth: int = 2) -> bool:
    if shell_depth <= 0 or not command_parts:
        return False
    for window in shell_wrapped_blocked_candidate_windows(command_parts):
        starter = Path(str(window[0])).name.lower() if window else ""
        if starter not in SHELL_SCRIPT_COMMANDS:
            continue
        if any(
            blocked_validation_command_parts(segment_parts, shell_depth=shell_depth - 1)
            for segment_parts in shell_script_command_segments(window)
        ):
            return True
    return False

def shell_script_has_secret_exposure(script: str) -> bool:
    if shell_script_has_heredoc_inline_interpreter_secret_read(script):
        return True
    if shell_script_has_secret_env_assignment(script):
        return True
    if shell_script_has_secret_xargs_pipe(script):
        return True
    segments = shell_command_segments_from_script(str(script or ""))
    if not segments:
        text = str(script or "").lower()
        return ".env" in text or any(term in text for term in ("database_url", "password", "secret", "token"))
    return any(has_secret_exposure_command(segment) for segment in segments)

def source_env_file_window_is_exposure(window: list[str]) -> bool:
    if len(window) < 2:
        return False
    return any(path_names_secret(token) for token in window[1:])

def token_targets_secret_file(value: str, secret_env_names: set[str] | None = None) -> bool:
    if path_names_secret(value):
        return True
    return bool(secret_env_names and token_references_secret_env_name(value, secret_env_names))

def secret_file_read_window_is_exposure(window: list[str]) -> bool:
    if len(window) < 2:
        return False
    return any(path_names_secret(token) for token in window[1:])

def shell_redirection_reads_secret_file(tokens: list[str]) -> bool:
    for index, token in enumerate(tokens):
        if token in {"<", "<>"} and index + 1 < len(tokens) and path_names_secret(tokens[index + 1]):
            return True
        if token.startswith("<") and token not in {"<", "<<", "<<<"} and path_names_secret(token.lstrip("<")):
            return True
    return False

def shell_output_redirection_target(token: str) -> str | None:
    value = str(token or "").strip()
    if not value:
        return None
    match = re.match(r"^(?:[0-9])?(?:>>?|>\||&>)(?P<target>.+)$", value)
    if not match:
        return None
    return match.group("target")

def shell_redirection_writes_secret_file(tokens: list[str]) -> bool:
    for index, token in enumerate(tokens):
        if token in SHELL_OUTPUT_REDIRECTION_TOKENS:
            if index + 1 < len(tokens) and path_names_secret(tokens[index + 1]):
                return True
            continue
        target = shell_output_redirection_target(token)
        if target and path_names_secret(target):
            return True
    return False

def sed_file_read_window_is_exposure(window: list[str], secret_env_names: set[str] | None = None) -> bool:
    tokens = [str(part) for part in window]
    if len(tokens) < 2:
        return False
    if shell_redirection_reads_secret_file(tokens):
        return True

    script_seen = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in SHELL_OPERATOR_TOKENS or token in SHELL_REDIRECTION_OPERATORS:
            break
        if token == "--":
            index += 1
            continue
        if token in {"-f", "--file"}:
            if index + 1 < len(tokens) and token_targets_secret_file(tokens[index + 1], secret_env_names):
                return True
            script_seen = True
            index += 2
            continue
        if token.startswith("--file="):
            if token_targets_secret_file(token.split("=", 1)[1], secret_env_names):
                return True
            script_seen = True
            index += 1
            continue
        if token in {"-e", "--expression"}:
            script_seen = True
            index += 2
            continue
        if token.startswith("--expression="):
            script_seen = True
            index += 1
            continue
        if token.startswith("-") and token != "-":
            short_options = token[1:]
            if short_options.endswith("f") and index + 1 < len(tokens):
                if token_targets_secret_file(tokens[index + 1], secret_env_names):
                    return True
                script_seen = True
                index += 2
                continue
            if short_options.endswith("e") and index + 1 < len(tokens):
                script_seen = True
                index += 2
                continue
            index += 1
            continue
        if not script_seen:
            script_seen = True
            index += 1
            continue
        if token_targets_secret_file(token, secret_env_names):
            return True
        index += 1
    return False

def awk_file_read_window_is_exposure(window: list[str], secret_env_names: set[str] | None = None) -> bool:
    tokens = [str(part) for part in window]
    if len(tokens) < 2:
        return False
    if shell_redirection_reads_secret_file(tokens):
        return True

    program_seen = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in SHELL_OPERATOR_TOKENS or token in SHELL_REDIRECTION_OPERATORS:
            break
        if token == "--":
            index += 1
            continue
        if token in {"-f", "--file"}:
            if index + 1 < len(tokens) and token_targets_secret_file(tokens[index + 1], secret_env_names):
                return True
            program_seen = True
            index += 2
            continue
        if token.startswith("--file="):
            if token_targets_secret_file(token.split("=", 1)[1], secret_env_names):
                return True
            program_seen = True
            index += 1
            continue
        if token in {"-v", "--assign", "-F", "--field-separator"}:
            index += 2
            continue
        if token.startswith("--assign=") or token.startswith("--field-separator=") or token.startswith("-F"):
            index += 1
            continue
        if token.startswith("-") and token != "-":
            index += 1
            continue
        if not program_seen:
            program_seen = True
            index += 1
            continue
        if token_targets_secret_file(token, secret_env_names):
            return True
        index += 1
    return False

def sed_awk_file_read_window_is_exposure(window: list[str], secret_env_names: set[str] | None = None) -> bool:
    if not window:
        return False
    starter = Path(str(window[0])).name.lower()
    if starter == "sed":
        return sed_file_read_window_is_exposure(window, secret_env_names)
    if starter == "awk":
        return awk_file_read_window_is_exposure(window, secret_env_names)
    return False

def search_file_read_window_is_exposure(window: list[str]) -> bool:
    tokens = [str(part) for part in window]
    if len(tokens) < 2:
        return False
    if shell_redirection_reads_secret_file(tokens):
        return True

    pattern_seen = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in SHELL_OPERATOR_TOKENS or token in {"<", ">", ">>", "<<<"}:
            break
        if token == "--":
            index += 1
            continue
        if token in {"-f", "--file"}:
            if index + 1 < len(tokens) and path_names_secret(tokens[index + 1]):
                return True
            index += 2
            continue
        if token.startswith("--file="):
            if path_names_secret(token.split("=", 1)[1]):
                return True
            index += 1
            continue
        if token.startswith("-") and token != "-":
            index += 2 if token in SEARCH_OPTIONS_WITH_VALUE else 1
            continue
        if not pattern_seen:
            pattern_seen = True
            index += 1
            continue
        if path_names_secret(token):
            return True
        index += 1
    return False

def token_references_secret_file(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if path_names_secret(text):
        return True
    if text.startswith("@") and path_names_secret(text[1:]):
        return True
    if "=" in text:
        suffix = text.split("=", 1)[1]
        return path_names_secret(suffix) or (suffix.startswith("@") and path_names_secret(suffix[1:]))
    return False

def secret_file_exfiltration_window_is_exposure(window: list[str]) -> bool:
    if len(window) < 2:
        return False
    return any(token_references_secret_file(token) for token in window[1:])

def write_command_option_has_value(starter: str, token: str) -> bool:
    option = token.split("=", 1)[0]
    if starter == "tee":
        return option in TEE_OPTIONS_WITH_VALUE
    if starter == "touch":
        return option in TOUCH_OPTIONS_WITH_VALUE
    if starter == "truncate":
        return option in TRUNCATE_OPTIONS_WITH_VALUE
    return False

def secret_file_mutation_option_has_value(starter: str, token: str) -> bool:
    if write_command_option_has_value(starter, token):
        return True
    option = token.split("=", 1)[0]
    return option in SECRET_FILE_METADATA_MUTATION_OPTIONS_WITH_VALUE.get(starter, set())

def secret_file_write_window_is_mutation(window: list[str]) -> bool:
    tokens = [str(part) for part in window]
    if not tokens:
        return False
    if shell_redirection_writes_secret_file(tokens):
        return True

    starter = Path(tokens[0]).name.lower()
    if starter == "find":
        return find_secret_file_mutation_window_is_mutation(tokens)
    if starter == "xargs":
        return xargs_here_string_secret_path_window_is_mutation(tokens)
    if inline_interpreter_window_is_secret_file_mutation(tokens):
        return True
    if starter not in SECRET_FILE_MUTATION_COMMANDS:
        return False

    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in SHELL_OPERATOR_TOKENS or token in SHELL_REDIRECTION_OPERATORS:
            break
        if token == "--":
            index += 1
            continue
        if token.startswith("-") and token != "-":
            if "=" in token:
                option_value = token.split("=", 1)[1]
                if path_names_secret(option_value):
                    return True
                index += 1
                continue
            if secret_file_mutation_option_has_value(starter, token):
                if index + 1 < len(tokens) and path_names_secret(tokens[index + 1]):
                    return True
                index += 2
                continue
            index += 1
            continue
        if path_names_secret(token):
            return True
        index += 1
    return False

def find_secret_file_mutation_window_is_mutation(window: list[str]) -> bool:
    tokens = [str(part) for part in window]
    if len(tokens) < 3 or Path(tokens[0]).name.lower() != "find":
        return False
    secret_predicate = any(text_mentions_secret_path_literal(token) for token in tokens[1:])
    if not secret_predicate:
        return False
    if "-delete" in tokens:
        return True
    exec_index = next((index for index, token in enumerate(tokens) if token in {"-exec", "-execdir"}), None)
    if exec_index is None or exec_index + 1 >= len(tokens):
        return False
    exec_tokens: list[str] = []
    for token in tokens[exec_index + 1:]:
        if token in {";", "+"}:
            break
        exec_tokens.append(token)
    if not exec_tokens:
        return False
    return Path(exec_tokens[0]).name.lower() in SECRET_FILE_MUTATION_COMMANDS

def shell_script_has_secret_file_write(script: str) -> bool:
    if shell_script_has_secret_xargs_mutation_pipe(script):
        return True
    segments = shell_command_segments_from_script(str(script or ""))
    if not segments:
        try:
            tokens = split_shell_script_parts(str(script or ""))
        except ValueError:
            return False
        return secret_file_write_window_is_mutation(tokens)
    return any(has_secret_file_write_command(segment) for segment in segments)

def has_secret_file_write_window(window: list[str]) -> bool:
    tokens = [str(part) for part in window]
    if not tokens:
        return False
    starter = Path(tokens[0]).name.lower()
    if starter in SHELL_SCRIPT_COMMANDS:
        script = shell_script_argument(tokens)
        return bool(script and shell_script_has_secret_file_write(script))
    return secret_file_write_window_is_mutation(tokens)

def has_secret_file_write_command(command_parts: list[str]) -> bool:
    return any(
        has_secret_file_write_window(window)
        for window in secret_exposure_candidate_windows(command_parts)
    )

def find_exec_secret_file_window_is_exposure(window: list[str]) -> bool:
    tokens = [str(part) for part in window]
    if len(tokens) < 5 or Path(tokens[0]).name.lower() != "find":
        return False
    exec_index = next((index for index, token in enumerate(tokens) if token in {"-exec", "-execdir"}), None)
    if exec_index is None or exec_index + 1 >= len(tokens):
        return False
    predicate_tokens = tokens[1:exec_index]
    if not any(text_mentions_secret_path_literal(token) for token in predicate_tokens):
        return False
    exec_tokens: list[str] = []
    for token in tokens[exec_index + 1:]:
        if token in {";", "+"}:
            break
        exec_tokens.append(token)
    if not exec_tokens:
        return False
    starter = "." if exec_tokens[0] == "." else Path(exec_tokens[0]).name.lower()
    return (
        starter in SOURCE_ENV_FILE_COMMANDS
        or starter == "cat"
        or starter in SECRET_FILE_READ_COMMANDS
        or starter in SECRET_FILE_EXFILTRATION_COMMANDS
    )

def secret_exposure_candidate_windows(command_parts: list[str]) -> list[list[str]]:
    tokens = [str(part) for part in command_parts]
    windows: list[list[str]] = [tokens]
    if not tokens:
        return windows
    starter = Path(tokens[0]).name.lower()
    if starter in SHELL_PASSTHROUGH_COMMAND_WRAPPERS and len(tokens) >= 2:
        windows.extend(secret_exposure_candidate_windows(tokens[1:]))
    if starter == "env":
        nested_index = env_wrapper_nested_command_index(tokens)
        if nested_index is not None and nested_index < len(tokens):
            windows.extend(secret_exposure_candidate_windows(tokens[nested_index:]))
    if starter == "corepack" and len(tokens) >= 2 and Path(tokens[1]).name.lower() in COREPACK_RUNNERS:
        windows.extend(secret_exposure_candidate_windows(tokens[1:]))
    if starter in {"npm", "pnpm", "yarn", "bun"}:
        cursor = skip_package_runner_options(tokens, 1)
        if cursor < len(tokens) and Path(tokens[cursor]).name.lower() in PACKAGE_EXEC_SUBCOMMANDS:
            cursor = skip_package_runner_options(tokens, cursor + 1)
            if cursor < len(tokens):
                windows.extend(secret_exposure_candidate_windows(tokens[cursor:]))
    if starter == "npx":
        cursor = skip_package_runner_options(tokens, 1)
        if cursor < len(tokens):
            windows.extend(secret_exposure_candidate_windows(tokens[cursor:]))
    if starter in TOOL_RUNNER_COMMAND_STARTERS:
        run_index = tokens.index("run") + 1 if "run" in tokens else 1
        if run_index < len(tokens):
            windows.extend(secret_exposure_candidate_windows(tokens[run_index:]))
    return windows

def has_secret_exposure_window(window: list[str]) -> bool:
    tokens = [str(part) for part in window]
    if not tokens:
        return False
    starter = "." if tokens[0] == "." else Path(tokens[0]).name.lower()
    if starter in SOURCE_ENV_FILE_COMMANDS:
        return source_env_file_window_is_exposure(tokens)
    if starter in SHELL_SCRIPT_COMMANDS:
        script = shell_script_argument(tokens)
        return bool(script and shell_script_has_secret_exposure(script))
    if starter == "cat":
        return any(path_names_secret(token) for token in tokens[1:])
    if starter in SEARCH_FILE_READ_COMMANDS:
        return search_file_read_window_is_exposure(tokens)
    if starter in SED_AWK_FILE_READ_COMMANDS:
        return sed_awk_file_read_window_is_exposure(tokens)
    if starter in SECRET_FILE_READ_COMMANDS:
        return secret_file_read_window_is_exposure(tokens)
    if starter in SECRET_FILE_EXFILTRATION_COMMANDS:
        return secret_file_exfiltration_window_is_exposure(tokens)
    if starter == "find":
        return find_exec_secret_file_window_is_exposure(tokens)
    if starter == "xargs":
        return xargs_here_string_secret_path_window_is_exposure(tokens)
    if inline_interpreter_window_is_exposure(tokens):
        return True
    if starter == "printenv":
        return len(tokens) == 1 or any(token_names_secret(token) for token in tokens[1:])
    if starter == "env":
        nested_index = env_wrapper_nested_command_index(tokens)
        direct_args = tokens[1:] if nested_index is None else tokens[1:nested_index]
        return nested_index is None or env_secret_assignment_names(direct_args)
    if starter == "aws":
        return aws_secret_read_window_is_exposure(tokens)
    if starter in {"kubectl", "oc"}:
        return kubectl_secret_read_window_is_exposure(tokens)
    if starter == "gh":
        return gh_secret_window_is_exposure(tokens)
    if starter == "vault":
        return vault_secret_window_is_exposure(tokens)
    if starter == "op":
        return one_password_window_is_exposure(tokens)
    if starter == "gcloud":
        normalized = [Path(str(part)).name.lower() for part in tokens]
        return "secrets" in normalized and any(token in {"access", "versions"} for token in normalized)
    if starter == "az":
        normalized = [Path(str(part)).name.lower() for part in tokens]
        return "keyvault" in normalized and "secret" in normalized
    return False

def has_secret_exposure_command(command_parts: list[str]) -> bool:
    if leading_env_assignments_reference_secret_file(command_parts):
        return True
    return any(
        has_secret_exposure_window(window)
        for window in secret_exposure_candidate_windows(command_parts)
    )

def command_secret_boundary_violation(command_parts: list[str]) -> str | None:
    """返回不可被普通 unsafe 开关放行的命令秘密边界原因码。"""
    if has_secret_exposure_command(command_parts):
        return "secret_read_or_exfiltration"
    if has_secret_file_write_command(command_parts):
        return "secret_file_mutation"
    return None

def has_default_mutating_quality_command(command_parts: list[str]) -> bool:
    if has_non_mutating_quality_option(command_parts):
        return False
    tokens = [Path(str(part)).name.lower() for part in command_parts]
    if not tokens:
        return False
    candidate_windows: list[list[str]] = [tokens]
    if tokens[0] in PYTHON_MODULE_COMMAND_STARTERS and "-m" in tokens:
        module_index = tokens.index("-m") + 1
        candidate_windows.append(tokens[module_index:])
    if tokens[0] in TOOL_RUNNER_COMMAND_STARTERS:
        run_index = tokens.index("run") + 1 if "run" in tokens else 1
        candidate_windows.append(tokens[run_index:])
    for window in candidate_windows:
        if not window:
            continue
        if window[0] == "ruff" and "format" in window[1:]:
            return True
        if any(token in DEFAULT_MUTATING_QUALITY_TOOLS for token in window):
            return True
    return False

def has_mutating_quality_context(command_parts: list[str]) -> bool:
    tokens = [Path(str(part)).name.lower() for part in command_parts]
    if not tokens:
        return False
    if tokens[0] in QUALITY_COMMAND_STARTERS:
        return True
    if tokens[0] in PACKAGE_COMMAND_STARTERS:
        return any(token in MUTATING_QUALITY_COMMAND_CONTEXT_TOKENS for token in tokens[1:])
    if tokens[0] in PYTHON_MODULE_COMMAND_STARTERS and "-m" in tokens:
        module_index = tokens.index("-m") + 1
        return any(token in MUTATING_QUALITY_COMMAND_CONTEXT_TOKENS for token in tokens[module_index:])
    if tokens[0] in TOOL_RUNNER_COMMAND_STARTERS:
        return any(token in MUTATING_QUALITY_COMMAND_CONTEXT_TOKENS for token in tokens[1:])
    return False

def corepack_command_is_allowed(command_parts: list[str]) -> bool:
    if len(command_parts) < 3:
        return False
    runner = Path(command_parts[1]).name.lower()
    if runner not in COREPACK_RUNNERS:
        return False
    return command_parts_are_allowed(command_parts[1:])

def docker_compose_command_is_allowed(command_parts: list[str]) -> bool:
    if not command_parts:
        return False
    starter = Path(command_parts[0]).name.lower()
    if starter == "docker":
        if len(command_parts) < 5 or command_parts[1] != "compose":
            return False
        action_index = 2
    elif starter == "docker-compose":
        if len(command_parts) < 4:
            return False
        action_index = 1
    else:
        return False
    action = command_parts[action_index]
    if action not in DOCKER_COMPOSE_RUN_ACTIONS:
        return False
    index = action_index + 1
    while index < len(command_parts) and command_parts[index].startswith("-"):
        option = command_parts[index]
        index += 1
        if option in DOCKER_COMPOSE_OPTIONS_WITH_VALUE:
            index += 1
    if index >= len(command_parts):
        return False
    service = command_parts[index]
    if service.startswith("-") or service in SHELL_OPERATOR_TOKENS:
        return False
    nested_command = command_parts[index + 1:]
    return command_parts_are_allowed(nested_command)

def split_cd_prefixed_command(command: str) -> tuple[str | None, dict[str, str], list[str]]:
    try:
        raw_parts = shlex.split(command)
    except ValueError:
        return None, {}, []
    leading_env, parts = split_leading_env_assignments_from_parts(raw_parts)
    if len(parts) < 4 or parts[0] != "cd" or parts[2] != "&&":
        return None, leading_env, parts
    cwd = parts[1]
    if not SAFE_RELATIVE_CWD_RE.match(cwd):
        return None, leading_env, []
    trailing_env, command_parts = split_leading_env_assignments_from_parts(parts[3:])
    merged_env = {**leading_env, **trailing_env}
    if not command_parts_are_allowed(command_parts):
        return None, merged_env, []
    return cwd, merged_env, command_parts

def format_env_assignments(env: dict[str, str]) -> list[str]:
    return [f"{key}={value}" for key, value in env.items()]

def split_safe_and_chained_commands(command: str) -> list[str]:
    try:
        raw_parts = shlex.split(command)
    except ValueError:
        return []
    if not raw_parts or "&&" not in raw_parts:
        return []
    if any(part in {"||", ";", "|", "&"} for part in raw_parts):
        return []

    segments: list[list[str]] = []
    current: list[str] = []
    for part in raw_parts:
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

    leading_env, first_parts = split_leading_env_assignments_from_parts(segments[0])
    if len(first_parts) == 2 and first_parts[0] == "cd" and SAFE_RELATIVE_CWD_RE.match(first_parts[1]):
        cwd = first_parts[1]
        commands: list[str] = []
        for segment in segments[1:]:
            segment_env, segment_parts = split_leading_env_assignments_from_parts(segment)
            if not command_parts_are_allowed(segment_parts):
                return []
            commands.append(shlex.join([*format_env_assignments({**leading_env, **segment_env}), "cd", cwd, "&&", *segment_parts]))
        return commands

    commands = []
    for segment in segments:
        _, segment_parts = split_leading_env_assignments_from_parts(segment)
        if not command_parts_are_allowed(segment_parts):
            return []
        commands.append(shlex.join(segment))
    return commands

def strip_sentence_terminal_punctuation(value: str) -> str:
    text = str(value or "").strip()
    while text.endswith(("。", "；", "，", ";", ",")):
        text = text[:-1].rstrip()
    if text.endswith(".") and not text.endswith(" ."):
        text = text[:-1].rstrip()
    return text

def split_prose_command_segments(command: str) -> list[str]:
    value = str(command or "").strip()
    if not value:
        return []
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(value):
        char = value[index]
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
        if value[index:index + 5].lower() == " and ":
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

def split_safe_prose_separated_commands(command: str) -> list[str]:
    segments = split_prose_command_segments(command)
    if len(segments) < 2:
        return []
    commands: list[str] = []
    for segment in segments:
        expanded = split_safe_and_chained_commands(segment)
        if expanded:
            commands.extend(expanded)
        elif looks_like_shell_command(segment):
            commands.append(segment)
        else:
            return []
    return commands

def build_command_step_fields(command: str) -> tuple[dict[str, str], list[str]]:
    cwd, command_env, command_parts = split_cd_prefixed_command(command)
    if cwd:
        shell_command = f"cd {shlex.quote(cwd)} && {shlex.join(command_parts)}"
        return command_env, ["sh", "-lc", shell_command]
    command_env, command_parts = split_leading_env_assignments(command)
    return command_env, command_parts

def validation_command_signature(command: str) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...]]:
    command_env, command_parts = build_command_step_fields(command)
    return tuple(sorted(command_env.items())), tuple(command_parts)

def looks_like_shell_command(command: str) -> bool:
    command = re.sub(r"\s+", " ", str(command or "")).strip()
    if not command or command.lstrip().startswith(("{", "[")):
        return False
    cwd, _, command_parts = split_cd_prefixed_command(command)
    if cwd:
        return True
    _, command_parts = split_leading_env_assignments(command)
    return command_parts_are_allowed(command_parts)

def expand_validation_candidate_commands(command: str) -> list[str]:
    candidates = [strip_sentence_terminal_punctuation(command)]
    label_match = re.match(r"^[A-Za-z][A-Za-z0-9_. /-]{0,40}\s*[:：]\s*(.+)$", str(command or "").strip())
    if label_match:
        candidates.append(strip_sentence_terminal_punctuation(label_match.group(1)))
    for candidate in candidates:
        expanded = split_safe_prose_separated_commands(candidate)
        if expanded:
            return expanded
        expanded = split_safe_and_chained_commands(candidate)
        if expanded:
            return expanded
        if looks_like_shell_command(candidate):
            return [candidate]
    return []

def candidate_command_parts(command: str) -> list[str]:
    try:
        raw_parts = shlex.split(str(command or ""))
    except ValueError:
        return []
    _, parts = split_leading_env_assignments_from_parts(raw_parts)
    return parts

def blocked_validation_command_parts(command_parts: list[str], shell_depth: int = 2) -> bool:
    if not command_parts:
        return False
    if has_env_file_command_wrapper(command_parts):
        return True
    if has_mutating_make_target(command_parts):
        return True
    if has_mutating_package_script(command_parts):
        return True
    if has_dependency_mutation_command(command_parts):
        return True
    if has_mutating_database_command(command_parts):
        return True
    if has_mutating_infrastructure_command(command_parts):
        return True
    if has_secret_file_write_command(command_parts):
        return True
    if has_secret_exposure_command(command_parts):
        return True
    if has_shell_wrapped_blocked_validation_command(command_parts, shell_depth=shell_depth):
        return True
    if has_default_mutating_quality_command(command_parts):
        return True
    return has_mutating_quality_option(command_parts) and has_mutating_quality_context(command_parts)

def is_blocked_validation_command_candidate(command: str) -> bool:
    value = normalize_candidate_command(command)
    if not value:
        return False
    candidates = [value]
    label_match = re.match(r"^[A-Za-z][A-Za-z0-9_. /-]{0,40}\s*[:：]\s*(.+)$", value)
    if label_match:
        candidates.append(label_match.group(1).strip())
    for candidate in candidates:
        try:
            raw_parts = shlex.split(candidate)
        except ValueError:
            continue
        if not raw_parts:
            continue
        if any(part in SHELL_OPERATOR_TOKENS for part in raw_parts):
            if shell_script_has_secret_exposure(candidate) or shell_script_has_secret_file_write(candidate):
                return True
            current: list[str] = []
            for part in [*raw_parts, "&&"]:
                if part in SHELL_OPERATOR_TOKENS:
                    _, segment_parts = split_leading_env_assignments_from_parts(current)
                    if blocked_validation_command_parts(segment_parts):
                        return True
                    current = []
                else:
                    current.append(part)
            continue
        _, parts = split_leading_env_assignments_from_parts(raw_parts)
        if blocked_validation_command_parts(parts):
            return True
    return False

def normalize_candidate_command(line: str) -> str:
    value = re.sub(r"\s+", " ", str(line or "")).strip()
    value = re.sub(r"^- \[[ xX]\]\s+", "", value)
    value = re.sub(r"^[-*+]\s+", "", value)
    value = re.sub(r"^\d+[\.)]\s+", "", value)
    value = re.sub(r"^(?:(?:✅|✔️|✔|☑️|☑|🧪|🔍|🚦|▶️|▶)\s*)+", "", value)
    value = re.sub(r"^(?:run|执行|运行)\s+", "", value, flags=re.IGNORECASE)
    value = value.strip("` \t")
    while value.endswith(("。", "；", "，", ";", ",")):
        value = value[:-1].rstrip()
    if value.endswith(".") and not value.endswith(" ."):
        value = value[:-1].rstrip()
    value = value.strip("` \t")
    value = re.sub(r"^(?:\$|%|>)\s+", "", value)
    return redact(value.strip())

def add_candidate(candidates: list[str], candidate: str) -> None:
    normalized = normalize_candidate_command(candidate)
    if normalized and normalized not in candidates:
        candidates.append(normalized)

def add_backtick_aware_validation_candidate(candidates: list[str], candidate: str) -> None:
    normalized = normalize_candidate_command(candidate)
    if not normalized:
        return
    if "`" in normalized and (looks_like_shell_command(normalized) or is_blocked_validation_command_candidate(normalized)):
        add_candidate(candidates, normalized)
        return
    if "`" in normalized:
        for backticked_candidate in backticked_command_candidates(normalized):
            add_candidate(candidates, backticked_candidate)
        return
    add_candidate(candidates, normalized)

def backticked_command_candidates(text: str) -> list[str]:
    return [match.group(1) for match in re.finditer(r"`([^`\n]{3,220})`", str(text or ""))]

def prose_command_context_start(parts: list[str], start_index: int) -> int:
    candidate_start = start_index
    while candidate_start > 0 and ENV_ASSIGNMENT_RE.match(parts[candidate_start - 1]):
        candidate_start -= 1
    if (
        candidate_start >= 3
        and parts[candidate_start - 3] == "cd"
        and parts[candidate_start - 1] == "&&"
        and SAFE_RELATIVE_CWD_RE.match(parts[candidate_start - 2])
    ):
        candidate_start -= 3
        while candidate_start > 0 and ENV_ASSIGNMENT_RE.match(parts[candidate_start - 1]):
            candidate_start -= 1
    return candidate_start

def bare_command_candidates_from_prose(text: str) -> list[str]:
    candidates: list[str] = []
    for piece in re.split(r"`[^`\n]{3,220}`", str(text or "")):
        normalized = normalize_candidate_command(piece)
        if not normalized:
            continue
        try:
            parts = shlex.split(normalized)
        except ValueError:
            continue
        start_index = 0
        while start_index < len(parts):
            part = parts[start_index]
            starter = Path(part).name.lower()
            if starter not in SHELL_COMMAND_STARTERS and starter not in {"corepack", "env", "docker", "docker-compose"}:
                start_index += 1
                continue
            end_index = len(parts)
            for index in range(start_index + 1, len(parts)):
                if parts[index].lower().strip(".,;:") in PROSE_COMMAND_STOP_WORDS:
                    end_index = index
                    break
            context_start = prose_command_context_start(parts, start_index)
            command_parts = parts[context_start:end_index]
            candidate = shlex.join(command_parts)
            if looks_like_shell_command(candidate):
                if candidate not in candidates:
                    candidates.append(candidate)
                start_index = end_index
                continue
            start_index += 1
    return candidates

def validation_line_has_command_context(line: str) -> bool:
    return bool(
        re.search(
            r"\b(?:validation|validate|verification|tests?|testing|checks?|check|qa|how\s+to\s+test|run|verified|validated|tested|checked)\b",
            line,
            re.IGNORECASE,
        )
    )

def mixed_backtick_bare_validation_commands(text: str) -> list[str]:
    commands: list[str] = []
    for raw_line in str(text or "").splitlines():
        line = clean_validation_label_line(raw_line)
        if not line or not validation_line_has_command_context(line):
            continue
        for candidate in bare_command_candidates_from_prose(line):
            for command in expand_validation_candidate_commands(candidate):
                if command not in commands:
                    commands.append(command)
    return commands

def clean_validation_label_line(line: str) -> str:
    value = str(line or "").strip()
    value = re.sub(r"^- \[[ xX]\]\s+", "", value)
    value = re.sub(r"^[-*+]\s+", "", value)
    value = re.sub(r"^\d+[\.)]\s+", "", value)
    value = re.sub(r"^(?:(?:✅|✔️|✔|☑️|☑|🧪|🔍|🚦|▶️|▶)\s*)+", "", value)
    value = re.sub(r"^(?:\$|%|>)\s+", "", value)
    return value

def extract_inline_validation_label_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for raw_line in text.splitlines():
        line = clean_validation_label_line(raw_line)
        if not line or line.startswith(("#", "|")):
            continue
        match = VALIDATION_INLINE_LABEL_RE.match(line)
        if match:
            command_text = match.group("command")
            add_backtick_aware_validation_candidate(candidates, command_text)
    return candidates

def extract_validation_section_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    in_validation_section = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        heading = re.match(r"^#{1,6}\s+(.+)$", line)
        section_match = VALIDATION_SECTION_RE.match(line)
        if heading:
            in_validation_section = bool(section_match)
            if not in_validation_section:
                continue
        if section_match:
            in_validation_section = True
            rest = section_match.group("rest") or ""
            if rest.strip():
                add_backtick_aware_validation_candidate(candidates, rest)
            continue
        if not in_validation_section:
            continue
        if line.startswith("```"):
            continue
        if "`" in line:
            add_backtick_aware_validation_candidate(candidates, line)
            continue
        table_cells = markdown_table_cells(line)
        if table_cells:
            for cell in table_cells:
                add_candidate(candidates, cell)
            continue
        add_candidate(candidates, line)
    return candidates

def extract_validation_command_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for pattern in VALIDATION_COMMAND_PATTERNS:
        for match in pattern.finditer(text):
            add_candidate(candidates, match.group(1))
    for candidate in extract_inline_validation_label_candidates(text):
        add_candidate(candidates, candidate)
    for candidate in extract_validation_section_candidates(text):
        add_candidate(candidates, candidate)
    return candidates

def extract_point_validation_command_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for match in re.finditer(r"`([^`\n]{3,220})`", text):
        candidate = normalize_candidate_command(match.group(1))
        if looks_like_shell_command(candidate) or is_blocked_validation_command_candidate(candidate):
            add_candidate(candidates, candidate)
    if not candidates:
        candidate = normalize_candidate_command(text)
        if looks_like_shell_command(candidate) or is_blocked_validation_command_candidate(candidate):
            add_candidate(candidates, candidate)
    return candidates

def extract_blocked_validation_commands(text: str) -> list[str]:
    blocked: list[str] = []
    safe_commands = set(extract_validation_commands(text))
    for candidate in extract_validation_command_candidates(text):
        expanded = expand_validation_candidate_commands(candidate)
        if expanded and all(command in safe_commands for command in expanded):
            continue
        if is_blocked_validation_command_candidate(candidate) and candidate not in blocked:
            blocked.append(candidate)
    return blocked

def markdown_table_cells(line: str) -> list[str]:
    value = str(line or "").strip()
    if "|" not in value:
        return []
    if not (value.startswith("|") and value.endswith("|")):
        return []
    cells = [cell.strip() for cell in value.strip("|").split("|")]
    cells = [cell for cell in cells if cell]
    if len(cells) < 2:
        return []
    if all(re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in cells):
        return []
    return cells

def extract_validation_section_commands(text: str) -> list[str]:
    commands: list[str] = []
    in_validation_section = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        heading = re.match(r"^#{1,6}\s+(.+)$", line)
        section_match = VALIDATION_SECTION_RE.match(line)
        if heading:
            in_validation_section = bool(section_match)
            if not in_validation_section:
                continue
        if section_match:
            in_validation_section = True
            raw_rest = section_match.group("rest") or ""
            if "`" in raw_rest:
                for candidate in backticked_command_candidates(raw_rest):
                    command = normalize_candidate_command(candidate)
                    for expanded_command in expand_validation_candidate_commands(command):
                        if expanded_command not in commands:
                            commands.append(expanded_command)
                continue
            rest = normalize_candidate_command(raw_rest)
            if rest:
                for command in expand_validation_candidate_commands(rest):
                    if command not in commands:
                        commands.append(command)
            continue
        if not in_validation_section:
            continue
        if line.startswith("```"):
            continue
        if "`" in line:
            for match in re.finditer(r"`([^`\n]{3,220})`", line):
                candidate = normalize_candidate_command(match.group(1))
                for command in expand_validation_candidate_commands(candidate):
                    if command not in commands:
                        commands.append(command)
            continue
        table_cells = markdown_table_cells(line)
        if table_cells:
            for cell in table_cells:
                candidate = normalize_candidate_command(cell)
                for command in expand_validation_candidate_commands(candidate):
                    if command not in commands:
                        commands.append(command)
            continue
        candidate = normalize_candidate_command(line)
        for command in expand_validation_candidate_commands(candidate):
            if command not in commands:
                commands.append(command)
    return commands

def extract_inline_validation_label_commands(text: str) -> list[str]:
    commands: list[str] = []
    for raw_line in text.splitlines():
        line = clean_validation_label_line(raw_line)
        if not line or line.startswith(("#", "|")):
            continue
        match = VALIDATION_INLINE_LABEL_RE.match(line)
        if not match:
            continue
        command_text = match.group("command")
        raw_candidates = backticked_command_candidates(command_text) if "`" in command_text else [command_text]
        for raw_candidate in raw_candidates:
            candidate = normalize_candidate_command(raw_candidate)
            for command in expand_validation_candidate_commands(candidate):
                if command not in commands:
                    commands.append(command)
    return commands

def extract_validation_commands(text: str) -> list[str]:
    commands: list[str] = []
    seen_signatures: set[tuple[tuple[tuple[str, str], ...], tuple[str, ...]]] = set()
    def add_command(command: str) -> None:
        signature = validation_command_signature(command)
        if signature in seen_signatures:
            return
        seen_signatures.add(signature)
        commands.append(command)
    for pattern in VALIDATION_COMMAND_PATTERNS:
        for match in pattern.finditer(text):
            command = normalize_candidate_command(match.group(1))
            for expanded_command in expand_validation_candidate_commands(command):
                add_command(expanded_command)
    for command in mixed_backtick_bare_validation_commands(text):
        add_command(command)
    for command in extract_inline_validation_label_commands(text):
        add_command(command)
    for command in extract_validation_section_commands(text):
        add_command(command)
    return commands[:6]

def extract_shell_commands(text: str) -> list[str]:
    commands: list[str] = []
    for match in re.finditer(r"`([^`\n]{3,220})`", text):
        command = normalize_candidate_command(match.group(1))
        for expanded_command in expand_validation_candidate_commands(command):
            if expanded_command not in commands:
                commands.append(expanded_command)
    return commands[:6]

def is_code_pr_requirement(text: str) -> bool:
    lower = text.lower()
    code_paths = extract_code_file_paths(text)
    negated_review_context = bool(
        re.search(r"\bnot\s+(?:a\s+)?(?:pr|pull request|merge request|code)\s+review\b", lower)
        or re.search(r"\bnot\s+(?:a\s+)?(?:pull request|merge request)\b", lower)
        or "不是 pr" in lower
        or "不是代码评审" in text
        or "不是代码审查" in text
    )
    pr_signals = (
        "pull request" in lower
        or "merge request" in lower
        or re.search(r"\bpr\s*#?\d+\b", lower)
        or "changed files" in lower
        or "files changed" in lower
        or "pr body" in lower
        or "pr description" in lower
        or "code review" in lower
        or "diff" in lower
        or re.search(r"\bcommit\s+[0-9a-f]{7,40}\b", lower)
        or "代码评审" in text
        or "代码审查" in text
        or "合并请求" in text
        or "拉取请求" in text
    )
    return bool(pr_signals and not negated_review_context and len(code_paths) >= 1)

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
