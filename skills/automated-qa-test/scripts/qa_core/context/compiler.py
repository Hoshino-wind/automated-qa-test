"""把运行输入和仓库能力编译为确定性 ContextSnapshot。"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from qa_core.contracts.artifacts import ARTIFACT_FILENAMES
from qa_core.contracts.evidence import boundary_field_confirmed
from qa_core.human_runtime import (
    HumanRuntimeError,
    KnowledgeRuntimeConfig,
    compile_knowledge_snapshot,
    empty_knowledge_snapshot,
)
from qa_core.tools import ToolRegistry, build_default_tool_registry

_SCHEMA_VERSION = 1
_MAX_INPUT_BYTES = 4 * 1024 * 1024
_MAX_REPOSITORY_FILES = 2_000
_MAX_REPOSITORY_FILE_BYTES = 8 * 1024 * 1024
_MAX_REPOSITORY_TOTAL_BYTES = 64 * 1024 * 1024
_REPOSITORY_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".css",
        ".dart",
        ".go",
        ".h",
        ".hpp",
        ".html",
        ".java",
        ".js",
        ".jsx",
        ".json",
        ".kt",
        ".kts",
        ".m",
        ".md",
        ".mjs",
        ".mm",
        ".php",
        ".py",
        ".rb",
        ".rs",
        ".sh",
        ".swift",
        ".toml",
        ".ts",
        ".tsx",
        ".vue",
        ".yaml",
        ".yml",
    }
)
_IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".idea",
        ".mypy_cache",
        ".next",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "target",
        "vendor",
    }
)
_SENSITIVE_FILENAMES = frozenset(
    {
        ".env",
        ".env.local",
        ".npmrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        "id_ed25519",
        "id_rsa",
    }
)
_LANGUAGES = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".dart": "dart",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".m": "objective-c",
    ".mm": "objective-cpp",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".sh": "shell",
    ".swift": "swift",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".vue": "vue",
}
_DEPENDENCY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


class ContextCompileError(RuntimeError):
    """上下文路径或内容越过安全、大小或结构边界。"""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "error": "context_compile_error",
            "code": self.code,
            "message": str(self),
        }


@dataclass(frozen=True, slots=True)
class ContextSnapshot:
    """供 Planner/Critic 使用、但不能进入 Verdict 证据门的上下文。"""

    sources: tuple[dict[str, Any], ...]
    semantic_summary: dict[str, Any]
    knowledge: dict[str, Any]
    repository: dict[str, Any]
    capability_graph: dict[str, Any]
    blockers: tuple[dict[str, str], ...]

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self._unsigned_dict())

    @property
    def ready(self) -> bool:
        return not self.blockers

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "context_sha256": self.canonical_sha256,
        }

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "kind": "agent_context_snapshot",
            "not_evidence": True,
            "sources": [dict(item) for item in self.sources],
            "semantic_summary": self.semantic_summary,
            "knowledge": self.knowledge,
            "repository": self.repository,
            "capability_graph": self.capability_graph,
            "blockers": [dict(item) for item in self.blockers],
            "ready": self.ready,
        }


def compile_context_snapshot(
    run_dir: Path,
    *,
    project_root: Path | None = None,
    registry: ToolRegistry | None = None,
    require_requirement: bool = True,
    require_environment_boundary: bool = True,
    max_repository_files: int = _MAX_REPOSITORY_FILES,
    max_repository_bytes: int = _MAX_REPOSITORY_TOTAL_BYTES,
    knowledge_config: KnowledgeRuntimeConfig | None = None,
) -> ContextSnapshot:
    """编译稳定上下文；缺失事实形成 blocker，不会被推断补齐。"""

    resolved_run_dir = _directory(run_dir, code="run_dir_invalid")
    selected_registry = registry or build_default_tool_registry()
    if not isinstance(selected_registry, ToolRegistry):
        raise ContextCompileError(
            "tool_registry_invalid",
            "registry must be a ToolRegistry",
        )
    if not isinstance(require_requirement, bool):
        raise ContextCompileError(
            "require_requirement_invalid",
            "require_requirement must be a boolean",
        )
    if (
        isinstance(max_repository_files, bool)
        or not isinstance(max_repository_files, int)
        or max_repository_files <= 0
        or max_repository_files > _MAX_REPOSITORY_FILES
    ):
        raise ContextCompileError(
            "repository_limit_invalid",
            (
                "max_repository_files must be a positive integer no greater "
                f"than {_MAX_REPOSITORY_FILES}"
            ),
        )
    if (
        isinstance(max_repository_bytes, bool)
        or not isinstance(max_repository_bytes, int)
        or max_repository_bytes <= 0
        or max_repository_bytes > _MAX_REPOSITORY_TOTAL_BYTES
    ):
        raise ContextCompileError(
            "repository_limit_invalid",
            (
                "max_repository_bytes must be a positive integer no greater "
                f"than {_MAX_REPOSITORY_TOTAL_BYTES}"
            ),
        )

    blockers: list[dict[str, str]] = []
    sources: list[dict[str, Any]] = []
    values: dict[str, Any] = {}
    for name, required, kind in (
        ("requirement", require_requirement, "text"),
        ("plan", True, "json"),
        ("matrix", True, "json"),
        ("adapter_context", False, "json"),
    ):
        path = resolved_run_dir / ARTIFACT_FILENAMES[name]
        source, value, source_blockers = _compile_source(
            resolved_run_dir,
            name=name,
            path=path,
            required=required,
            kind=kind,
        )
        sources.append(source)
        values[name] = value
        blockers.extend(source_blockers)

    plan_summary, used_actions = _summarize_plan(values.get("plan"))
    matrix_summary = _summarize_matrix(values.get("matrix"))
    requirement_summary = _summarize_requirement(
        values.get("requirement"),
    )
    adapter_summary = _summarize_adapter(
        values.get("adapter_context"),
    )
    if require_environment_boundary and not adapter_summary[
        "environment_boundary_confirmed"
    ]:
        blockers.append(
            _blocker(
                "environment_boundary_unconfirmed",
                "Adapter context does not confirm runtime and data boundaries",
            )
        )

    graph, graph_blockers = _build_capability_graph(
        selected_registry,
        used_actions=used_actions,
        adapter_summary=adapter_summary,
    )
    blockers.extend(graph_blockers)
    repository = (
        _compile_repository(
            _directory(project_root, code="project_root_invalid"),
            max_files=max_repository_files,
            max_total_bytes=max_repository_bytes,
            excluded_roots=(resolved_run_dir,),
        )
        if project_root is not None
        else {
            "requested": False,
            "complete": False,
            "root": None,
            "root_sha256": None,
            "files": [],
            "languages": {},
            "dependencies": [],
            "snapshot_sha256": None,
        }
    )
    if repository.get("requested") and not repository.get("complete"):
        blockers.append(
            _blocker(
                "repository_snapshot_incomplete",
                str(
                    repository.get("error")
                    or "repository snapshot is incomplete"
                ),
            )
        )
    try:
        knowledge = compile_knowledge_snapshot(knowledge_config)
    except HumanRuntimeError as error:
        knowledge = {
            **empty_knowledge_snapshot(),
            "requested": knowledge_config is not None,
            "complete": False,
            "error": error.to_dict(),
        }
        unsigned_knowledge = dict(knowledge)
        unsigned_knowledge.pop("knowledge_snapshot_sha256", None)
        knowledge["knowledge_snapshot_sha256"] = _canonical_sha256(
            unsigned_knowledge
        )
        blockers.append(
            _blocker(
                error.code,
                f"Knowledge context failed closed: {error}",
            )
        )

    return ContextSnapshot(
        sources=tuple(sources),
        semantic_summary={
            "requirement": requirement_summary,
            "plan": plan_summary,
            "matrix": matrix_summary,
            "adapter": adapter_summary,
        },
        knowledge=knowledge,
        repository=repository,
        capability_graph=graph,
        blockers=tuple(_deduplicate_blockers(blockers)),
    )


def _compile_source(
    run_dir: Path,
    *,
    name: str,
    path: Path,
    required: bool,
    kind: str,
) -> tuple[dict[str, Any], Any, list[dict[str, str]]]:
    relative = path.relative_to(run_dir).as_posix()
    if not os.path.lexists(path):
        source = {
            "name": name,
            "path": relative,
            "kind": kind,
            "required": required,
            "status": "missing",
            "sha256": _canonical_sha256(
                {"name": name, "status": "missing"},
            ),
            "size": 0,
        }
        blockers = (
            [_blocker(f"{name}_missing", f"Required input is missing: {relative}")]
            if required
            else []
        )
        return source, None, blockers
    try:
        payload = _read_regular(path, max_bytes=_MAX_INPUT_BYTES)
    except ContextCompileError as error:
        return (
            {
                "name": name,
                "path": relative,
                "kind": kind,
                "required": required,
                "status": "invalid",
                "sha256": None,
                "size": 0,
            },
            None,
            [_blocker(error.code, str(error))],
        )
    digest = hashlib.sha256(payload).hexdigest()
    try:
        text = payload.decode("utf-8")
        value = json.loads(text) if kind == "json" else text
        if kind == "json" and not isinstance(value, dict):
            raise ValueError("JSON root must be an object")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return (
            {
                "name": name,
                "path": relative,
                "kind": kind,
                "required": required,
                "status": "invalid",
                "sha256": digest,
                "size": len(payload),
            },
            None,
            [
                _blocker(
                    f"{name}_invalid",
                    f"Input cannot be normalized: {relative}: {error}",
                )
            ],
        )
    return (
        {
            "name": name,
            "path": relative,
            "kind": kind,
            "required": required,
            "status": "current",
            "sha256": digest,
            "size": len(payload),
        },
        value,
        [],
    )


def _summarize_requirement(value: Any) -> dict[str, Any]:
    if not isinstance(value, str):
        return {"title": None, "headings": [], "line_count": 0}
    lines = value.splitlines()
    headings = [
        line.lstrip("#").strip()
        for line in lines
        if line.strip().startswith("#") and line.lstrip("#").strip()
    ][:100]
    title = headings[0] if headings else next(
        (line.strip() for line in lines if line.strip()),
        None,
    )
    return {
        "title": title[:500] if isinstance(title, str) else None,
        "headings": headings,
        "line_count": len(lines),
    }


def _summarize_plan(value: Any) -> tuple[dict[str, Any], tuple[str, ...]]:
    scenarios = value.get("scenarios") if isinstance(value, dict) else None
    if not isinstance(scenarios, list):
        return (
            {"schema_version": None, "scenario_count": 0, "step_count": 0},
            (),
        )
    actions: list[str] = []
    step_count = 0
    for scenario in scenarios:
        steps = scenario.get("steps") if isinstance(scenario, dict) else None
        if not isinstance(steps, list):
            continue
        step_count += len(steps)
        for step in steps:
            action = step.get("action") if isinstance(step, dict) else None
            if isinstance(action, str) and action.strip():
                actions.append(action.strip())
    unique_actions = tuple(sorted(set(actions)))
    return (
        {
            "schema_version": value.get("schemaVersion"),
            "scenario_count": len(scenarios),
            "step_count": step_count,
            "actions": list(unique_actions),
        },
        unique_actions,
    )


def _summarize_matrix(value: Any) -> dict[str, Any]:
    tests = value.get("tests") if isinstance(value, dict) else None
    if not isinstance(tests, list):
        tests = value.get("rows") if isinstance(value, dict) else None
    if not isinstance(tests, list):
        tests = []
    statuses: dict[str, int] = {}
    for test in tests:
        status_value = test.get("status") if isinstance(test, dict) else None
        status = (
            status_value.strip().lower()
            if isinstance(status_value, str) and status_value.strip()
            else "unspecified"
        )
        statuses[status] = statuses.get(status, 0) + 1
    return {
        "schema_version": (
            value.get("schemaVersion") if isinstance(value, dict) else None
        ),
        "test_count": len(tests),
        "status_counts": dict(sorted(statuses.items())),
    }


def _summarize_adapter(value: Any) -> dict[str, Any]:
    adapter = value if isinstance(value, dict) else {}
    boundary = adapter.get("environment_boundary")
    boundary = boundary if isinstance(boundary, dict) else {}
    runtime_mode = boundary.get("runtime_mode")
    data_status = boundary.get("data_boundary_status")
    services = adapter.get("services")
    service_names: list[str] = []
    if isinstance(services, dict):
        service_names.extend(str(name) for name in services)
    elif isinstance(services, list):
        for item in services:
            if isinstance(item, str):
                service_names.append(item)
            elif isinstance(item, dict):
                name = item.get("name") or item.get("id")
                if isinstance(name, str):
                    service_names.append(name)
    capabilities = adapter.get("capabilities")
    normalized_capabilities = (
        sorted(
            {
                item.strip()
                for item in capabilities
                if isinstance(item, str) and item.strip()
            }
        )
        if isinstance(capabilities, list)
        else []
    )
    return {
        "adapter": adapter.get("adapter"),
        "runtime_mode": runtime_mode,
        "data_boundary_status": data_status,
        "services": sorted(set(service_names)),
        "capabilities": normalized_capabilities,
        "environment_boundary_confirmed": (
            boundary_field_confirmed(runtime_mode)
            and boundary_field_confirmed(data_status)
        ),
    }


def _build_capability_graph(
    registry: ToolRegistry,
    *,
    used_actions: Iterable[str],
    adapter_summary: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str]] = set()
    blockers: list[dict[str, str]] = []
    used = set(used_actions)
    for action in registry.actions:
        spec = registry.get(action)
        action_id = f"tool:{action}"
        nodes[action_id] = {
            "id": action_id,
            "kind": "tool_action",
            "name": action,
            "risk_class": spec.risk_class.value,
            "used_by_plan": action in used,
            "tool_spec_sha256": spec.canonical_sha256,
        }
        for capability in spec.capabilities:
            capability_id = f"capability:{capability}"
            nodes.setdefault(
                capability_id,
                {
                    "id": capability_id,
                    "kind": "capability",
                    "name": capability,
                },
            )
            edges.add((action_id, "provides", capability_id))
    for action in sorted(used - set(registry.actions)):
        unknown_id = f"unknown_tool:{action}"
        nodes[unknown_id] = {
            "id": unknown_id,
            "kind": "unknown_tool_action",
            "name": action,
            "used_by_plan": True,
        }
        blockers.append(
            _blocker(
                "unknown_plan_action",
                f"Plan references an unregistered action: {action}",
            )
        )
    for service in adapter_summary.get("services", []):
        service_id = f"service:{service}"
        nodes[service_id] = {
            "id": service_id,
            "kind": "service",
            "name": service,
        }
    for capability in adapter_summary.get("capabilities", []):
        capability_id = f"adapter_capability:{capability}"
        nodes[capability_id] = {
            "id": capability_id,
            "kind": "adapter_capability",
            "name": capability,
        }
    return (
        {
            "tool_registry_sha256": registry.canonical_sha256,
            "nodes": [nodes[key] for key in sorted(nodes)],
            "edges": [
                {"from": source, "relation": relation, "to": target}
                for source, relation, target in sorted(edges)
            ],
        },
        blockers,
    )


def _compile_repository(
    root: Path,
    *,
    max_files: int,
    excluded_roots: tuple[Path, ...],
    max_total_bytes: int = _MAX_REPOSITORY_TOTAL_BYTES,
) -> dict[str, Any]:
    if (
        isinstance(max_files, bool)
        or not isinstance(max_files, int)
        or max_files <= 0
        or max_files > _MAX_REPOSITORY_FILES
        or isinstance(max_total_bytes, bool)
        or not isinstance(max_total_bytes, int)
        or max_total_bytes <= 0
        or max_total_bytes > _MAX_REPOSITORY_TOTAL_BYTES
    ):
        raise ContextCompileError(
            "repository_limit_invalid",
            "repository scan limits exceed their hard safety caps",
        )
    files: list[dict[str, Any]] = []
    languages: dict[str, int] = {}
    dependencies: set[str] = set()
    total_bytes = 0
    error: str | None = None
    excluded = tuple(
        path
        for path in excluded_roots
        if path == root or root in path.parents
    )
    if root in excluded:
        return {
            "requested": True,
            "complete": False,
            "root": ".",
            "root_sha256": hashlib.sha256(
                str(root).encode("utf-8")
            ).hexdigest(),
            "files": [],
            "languages": {},
            "dependencies": [],
            "snapshot_sha256": None,
            "error": "project_root must not be the dynamic run directory",
        }
    for directory, child_dirs, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        current_dir = Path(directory).resolve()
        if any(
            current_dir == path or path in current_dir.parents
            for path in excluded
        ):
            child_dirs[:] = []
            continue
        child_dirs[:] = sorted(
            name
            for name in child_dirs
            if name not in _IGNORED_DIRECTORIES
            and not (Path(directory) / name).is_symlink()
            and not any(
                (Path(directory) / name).resolve() == path
                or path in (Path(directory) / name).resolve().parents
                for path in excluded
            )
        )
        for filename in sorted(filenames):
            path = Path(directory) / filename
            if (
                filename in _SENSITIVE_FILENAMES
                or filename.startswith(".env.")
                or path.suffix.lower() not in _REPOSITORY_SUFFIXES
                or path.is_symlink()
            ):
                continue
            if len(files) >= max_files:
                error = f"repository contains more than {max_files} eligible files"
                break
            remaining_total_bytes = max_total_bytes - total_bytes
            if remaining_total_bytes <= 0:
                error = (
                    "repository exceeds total read budget of "
                    f"{max_total_bytes} bytes"
                )
                break
            try:
                payload = _read_regular(
                    path,
                    max_bytes=min(
                        _MAX_REPOSITORY_FILE_BYTES,
                        remaining_total_bytes,
                    ),
                )
            except ContextCompileError as compile_error:
                if (
                    compile_error.code == "context_source_too_large"
                    and remaining_total_bytes
                    < _MAX_REPOSITORY_FILE_BYTES
                ):
                    error = (
                        "repository exceeds total read budget of "
                        f"{max_total_bytes} bytes"
                    )
                else:
                    error = str(compile_error)
                break
            total_bytes += len(payload)
            relative = path.relative_to(root).as_posix()
            language = _LANGUAGES.get(path.suffix.lower())
            files.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                    "language": language,
                }
            )
            if language:
                languages[language] = languages.get(language, 0) + 1
            dependencies.update(_manifest_dependencies(relative, payload))
        if error is not None:
            break
    files.sort(key=lambda item: item["path"])
    snapshot_payload = {
        "files": files,
        "languages": dict(sorted(languages.items())),
        "dependencies": sorted(dependencies),
    }
    return {
        "requested": True,
        "complete": error is None,
        "root": ".",
        "root_sha256": hashlib.sha256(
            str(root).encode("utf-8")
        ).hexdigest(),
        **snapshot_payload,
        "snapshot_sha256": _canonical_sha256(snapshot_payload),
        **({"error": error} if error is not None else {}),
    }


def _manifest_dependencies(relative: str, payload: bytes) -> set[str]:
    filename = Path(relative).name
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return set()
    if filename == "package.json":
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            return set()
        names: set[str] = set()
        for field in ("dependencies", "devDependencies"):
            section = value.get(field) if isinstance(value, dict) else None
            if isinstance(section, dict):
                names.update(str(name) for name in section)
        return names
    if filename == "pyproject.toml":
        try:
            value = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return set()
        project = value.get("project") if isinstance(value, dict) else None
        raw = project.get("dependencies") if isinstance(project, dict) else None
        if not isinstance(raw, list):
            return set()
        return {
            name
            for item in raw
            if isinstance(item, str) and item.strip()
            for name in [_dependency_name(item)]
            if name is not None
        }
    if filename == "requirements.txt":
        return {
            name
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith(("#", "module ", "go "))
            for name in [_dependency_name(line)]
            if name is not None
        }
    if filename == "go.mod":
        return {
            parts[0]
            for line in text.splitlines()
            if (
                (parts := line.strip().split())
                and len(parts) >= 2
                and parts[0] not in {"module", "go", "require", "replace", "exclude"}
            )
        }
    return set()


def _dependency_name(value: str) -> str | None:
    matched = _DEPENDENCY_NAME.match(value.strip())
    return matched.group(0) if matched else None


def _read_regular(path: Path, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ContextCompileError(
            "context_source_unreadable",
            f"Cannot safely open context source {path}: {error}",
        ) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ContextCompileError(
                "context_source_not_regular",
                f"Context source is not a regular file: {path}",
            )
        if before.st_size > max_bytes:
            raise ContextCompileError(
                "context_source_too_large",
                f"Context source exceeds {max_bytes} bytes: {path}",
            )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise ContextCompileError(
                    "context_source_too_large",
                    f"Context source exceeds {max_bytes} bytes: {path}",
                )
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ContextCompileError(
                "context_source_changed",
                f"Context source changed while being read: {path}",
            )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _directory(path: Path, *, code: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_dir():
        raise ContextCompileError(code, f"Directory does not exist: {resolved}")
    return resolved


def _blocker(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _deduplicate_blockers(
    blockers: Iterable[dict[str, str]],
) -> list[dict[str, str]]:
    observed: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for blocker in blockers:
        key = (blocker["code"], blocker["message"])
        if key not in observed:
            observed.add(key)
            unique.append(blocker)
    return sorted(unique, key=lambda item: (item["code"], item["message"]))


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
