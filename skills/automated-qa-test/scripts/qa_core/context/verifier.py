"""只读验证 ContextSnapshot 与当前输入、工具注册表是否闭合。"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from qa_core.contracts.artifacts import ARTIFACT_FILENAMES
from qa_core.human_runtime import (
    HumanRuntimeError,
    KnowledgeRuntimeConfig,
    compile_knowledge_snapshot,
)
from qa_core.tools import ToolRegistry, build_default_tool_registry

from . import compiler as _compiler

_SHA256 = re.compile(r"[0-9a-f]{64}")
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "not_evidence",
        "sources",
        "semantic_summary",
        "knowledge",
        "repository",
        "capability_graph",
        "blockers",
        "ready",
        "context_sha256",
    }
)
_SOURCE_FIELDS = frozenset(
    {
        "name",
        "path",
        "kind",
        "required",
        "status",
        "sha256",
        "size",
    }
)
_SOURCE_SPECS = (
    ("requirement", "text", None),
    ("plan", "json", True),
    ("matrix", "json", True),
    ("adapter_context", "json", False),
)
_MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ContextVerificationResult:
    """验证成功时才暴露经过验证的普通 JSON 字典。"""

    valid: bool
    errors: tuple[dict[str, str], ...]
    context_sha256: str | None
    snapshot: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "valid": self.valid,
            "context_sha256": self.context_sha256,
            "errors": [dict(error) for error in self.errors],
        }


class _DuplicateKey(ValueError):
    pass


def verify_context_snapshot(
    run_dir: Path,
    snapshot_path: Path,
    registry: ToolRegistry | None = None,
    *,
    project_root: Path | None = None,
    require_repository_current: bool = True,
    knowledge_config: KnowledgeRuntimeConfig | None = None,
    require_knowledge_current: bool = True,
) -> ContextVerificationResult:
    """验证磁盘快照；不写文件，也不把 ContextSnapshot 当作证据。"""

    errors: list[dict[str, str]] = []
    resolved_run_dir = run_dir.expanduser().resolve()
    if not resolved_run_dir.is_dir():
        _error(
            errors,
            "run_dir_invalid",
            f"run directory does not exist: {resolved_run_dir}",
        )
        return _result(errors)

    selected_registry = registry or build_default_tool_registry()
    if not isinstance(selected_registry, ToolRegistry):
        _error(
            errors,
            "tool_registry_invalid",
            "registry must be a ToolRegistry",
        )
        return _result(errors)

    try:
        raw = _read_stable_regular(
            snapshot_path.expanduser(),
            max_bytes=_MAX_SNAPSHOT_BYTES,
            require_single_link=True,
        )
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except FileNotFoundError:
        _error(errors, "context_snapshot_missing", "context snapshot is missing")
        return _result(errors)
    except UnicodeDecodeError:
        _error(
            errors,
            "context_snapshot_not_utf8",
            "context snapshot must be UTF-8",
        )
        return _result(errors)
    except _DuplicateKey as exc:
        _error(errors, "context_snapshot_duplicate_key", exc)
        return _result(errors)
    except json.JSONDecodeError as exc:
        _error(errors, "context_snapshot_json_invalid", exc)
        return _result(errors)
    except (OSError, ValueError) as exc:
        _error(errors, "context_snapshot_unreadable", exc)
        return _result(errors)

    if type(payload) is not dict:
        _error(
            errors,
            "context_snapshot_root_invalid",
            "context snapshot root must be an object",
        )
        return _result(errors)

    _validate_top_level(payload, errors)
    if errors:
        return _result(errors)

    unsigned = dict(payload)
    observed_context_hash = unsigned.pop("context_sha256")
    computed_context_hash = _compiler._canonical_sha256(unsigned)
    if observed_context_hash != computed_context_hash:
        _error(
            errors,
            "context_sha256_mismatch",
            "context_sha256 does not match the canonical snapshot payload",
        )

    values = _validate_sources(
        resolved_run_dir,
        payload["sources"],
        errors,
    )
    _validate_semantic_summary(payload["semantic_summary"], values, errors)
    _validate_knowledge(
        payload["knowledge"],
        knowledge_config,
        errors,
        require_current=require_knowledge_current,
    )
    _validate_repository(
        payload["repository"],
        errors,
        run_dir=resolved_run_dir,
        project_root=project_root,
        require_current=require_repository_current,
    )
    _validate_capability_graph(
        payload["capability_graph"],
        values,
        selected_registry,
        errors,
    )

    return _result(
        errors,
        context_sha256=computed_context_hash,
        snapshot=payload,
    )


def _validate_top_level(
    payload: dict[str, Any],
    errors: list[dict[str, str]],
) -> None:
    _exact_fields(payload, _TOP_LEVEL_FIELDS, "$", errors)
    if errors:
        return
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        _error(
            errors,
            "context_schema_version_invalid",
            "schema_version must equal integer 1",
        )
    if payload["kind"] != "agent_context_snapshot":
        _error(
            errors,
            "context_kind_invalid",
            "kind must equal 'agent_context_snapshot'",
        )
    if payload["not_evidence"] is not True:
        _error(
            errors,
            "context_evidence_boundary_invalid",
            "not_evidence must be true",
        )
    if type(payload["ready"]) is not bool or payload["ready"] is not True:
        _error(
            errors,
            "context_not_ready",
            "ready must be true",
        )
    if type(payload["blockers"]) is not list:
        _error(
            errors,
            "context_blockers_schema_invalid",
            "blockers must be an array",
        )
    elif payload["blockers"]:
        for index, blocker in enumerate(payload["blockers"]):
            if type(blocker) is not dict:
                _error(
                    errors,
                    "context_blockers_schema_invalid",
                    f"blockers[{index}] must be an object",
                )
                continue
            _exact_fields(
                blocker,
                frozenset({"code", "message"}),
                f"$.blockers[{index}]",
                errors,
            )
            for field in ("code", "message"):
                if field in blocker and not _non_empty_text(blocker[field]):
                    _error(
                        errors,
                        "context_blockers_schema_invalid",
                        f"blockers[{index}].{field} must be non-empty text",
                    )
        _error(
            errors,
            "context_has_blockers",
            "a verified context must have no blockers",
        )
    for field in (
        "sources",
        "semantic_summary",
        "knowledge",
        "repository",
        "capability_graph",
    ):
        expected_type = list if field == "sources" else dict
        if type(payload[field]) is not expected_type:
            _error(
                errors,
                "context_schema_type_invalid",
                f"{field} must be a {expected_type.__name__}",
            )
    if not _is_sha256(payload["context_sha256"]):
        _error(
            errors,
            "context_sha256_invalid",
            "context_sha256 must be a lowercase SHA-256",
        )


def _validate_knowledge(
    raw_knowledge: Any,
    config: KnowledgeRuntimeConfig | None,
    errors: list[dict[str, str]],
    *,
    require_current: bool,
) -> None:
    """Re-run the exact-scope store query to prove snapshot currentness."""

    if type(raw_knowledge) is not dict:
        _error(
            errors,
            "context_knowledge_schema_invalid",
            "knowledge must be an object",
        )
        return
    unsigned = dict(raw_knowledge)
    recorded = unsigned.pop("knowledge_snapshot_sha256", None)
    if (
        raw_knowledge.get("not_evidence") is not True
        or raw_knowledge.get("complete") is not True
        or recorded != _compiler._canonical_sha256(unsigned)
    ):
        _error(
            errors,
            "context_knowledge_integrity_invalid",
            "knowledge snapshot boundary or canonical hash is invalid",
        )
        return
    if not require_current:
        return
    try:
        expected = compile_knowledge_snapshot(config)
    except HumanRuntimeError as error:
        _error(
            errors,
            error.code,
            f"current knowledge replay failed closed: {error}",
        )
        return
    if not _canonical_equal(raw_knowledge, expected):
        _error(
            errors,
            "context_knowledge_not_current",
            (
                "knowledge snapshot does not match the current store, "
                "checkpoint, trust allowlist, scope, or time-filtered query"
            ),
        )


def _validate_sources(
    run_dir: Path,
    raw_sources: Any,
    errors: list[dict[str, str]],
) -> dict[str, Any]:
    values: dict[str, Any] = {}
    if type(raw_sources) is not list:
        return values
    if len(raw_sources) != len(_SOURCE_SPECS):
        _error(
            errors,
            "context_sources_invalid",
            "sources must contain exactly the four canonical inputs",
        )
        return values

    for index, (name, kind, fixed_required) in enumerate(_SOURCE_SPECS):
        raw_source = raw_sources[index]
        path_label = f"$.sources[{index}]"
        if type(raw_source) is not dict:
            _error(
                errors,
                "context_source_schema_invalid",
                f"{path_label} must be an object",
            )
            continue
        _exact_fields(raw_source, _SOURCE_FIELDS, path_label, errors)
        if set(raw_source) != _SOURCE_FIELDS:
            continue
        required = raw_source["required"]
        if type(required) is not bool:
            _error(
                errors,
                "context_source_schema_invalid",
                f"{path_label}.required must be a boolean",
            )
            continue
        if fixed_required is not None and required is not fixed_required:
            _error(
                errors,
                "context_source_policy_invalid",
                f"{name}.required does not match the compiler contract",
            )

        expected_path = ARTIFACT_FILENAMES[name]
        for field, expected in (
            ("name", name),
            ("path", expected_path),
            ("kind", kind),
        ):
            if raw_source[field] != expected:
                _error(
                    errors,
                    "context_source_identity_invalid",
                    f"{path_label}.{field} must equal {expected!r}",
                )
        if raw_source["status"] not in {"current", "missing"}:
            _error(
                errors,
                "context_source_status_invalid",
                f"{name}.status must be 'current' or 'missing'",
            )
        if not _is_sha256(raw_source["sha256"]):
            _error(
                errors,
                "context_source_hash_invalid",
                f"{name}.sha256 must be a lowercase SHA-256",
            )
        if not _non_negative_integer(raw_source["size"]):
            _error(
                errors,
                "context_source_size_invalid",
                f"{name}.size must be a non-negative integer",
            )

        current_path = run_dir / expected_path
        try:
            if not os.path.lexists(current_path):
                value = None
                expected_source = {
                    "name": name,
                    "path": expected_path,
                    "kind": kind,
                    "required": required,
                    "status": "missing",
                    "sha256": _compiler._canonical_sha256(
                        {"name": name, "status": "missing"},
                    ),
                    "size": 0,
                }
            else:
                current_bytes = _read_stable_regular(
                    current_path,
                    max_bytes=_compiler._MAX_INPUT_BYTES,
                    require_single_link=False,
                )
                value = _decode_source(current_bytes, kind=kind)
                expected_source = {
                    "name": name,
                    "path": expected_path,
                    "kind": kind,
                    "required": required,
                    "status": "current",
                    "sha256": hashlib.sha256(current_bytes).hexdigest(),
                    "size": len(current_bytes),
                }
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            _error(
                errors,
                "context_current_input_invalid",
                f"{name} cannot be read as the declared source: {exc}",
            )
            continue

        values[name] = value
        if raw_source != expected_source:
            _error(
                errors,
                "context_source_not_current",
                f"{name} source metadata does not match the current input",
            )
        if required and value is None:
            _error(
                errors,
                "context_required_input_missing",
                f"required input is missing: {expected_path}",
            )
    return values


def _validate_semantic_summary(
    raw_summary: Any,
    values: Mapping[str, Any],
    errors: list[dict[str, str]],
) -> None:
    if type(raw_summary) is not dict:
        return
    _exact_fields(
        raw_summary,
        frozenset({"requirement", "plan", "matrix", "adapter"}),
        "$.semantic_summary",
        errors,
    )
    if set(raw_summary) != {"requirement", "plan", "matrix", "adapter"}:
        return
    expected_plan, _ = _compiler._summarize_plan(values.get("plan"))
    expected = {
        "requirement": _compiler._summarize_requirement(
            values.get("requirement")
        ),
        "plan": expected_plan,
        "matrix": _compiler._summarize_matrix(values.get("matrix")),
        "adapter": _compiler._summarize_adapter(
            values.get("adapter_context")
        ),
    }
    if not _canonical_equal(raw_summary, expected):
        _error(
            errors,
            "context_semantic_summary_mismatch",
            "semantic_summary does not match the current canonical inputs",
        )
        return
    _validate_summary_shapes(raw_summary, errors)


def _validate_summary_shapes(
    summary: dict[str, Any],
    errors: list[dict[str, str]],
) -> None:
    shapes = {
        "requirement": frozenset({"title", "headings", "line_count"}),
        "plan": frozenset(
            {"schema_version", "scenario_count", "step_count", "actions"}
        ),
        "matrix": frozenset(
            {"schema_version", "test_count", "status_counts"}
        ),
        "adapter": frozenset(
            {
                "adapter",
                "runtime_mode",
                "data_boundary_status",
                "environment_boundary_confirmed",
                "services",
                "capabilities",
            }
        ),
    }
    for name, fields in shapes.items():
        value = summary[name]
        if type(value) is not dict:
            _error(
                errors,
                "context_semantic_schema_invalid",
                f"semantic_summary.{name} must be an object",
            )
            continue
        _exact_fields(value, fields, f"$.semantic_summary.{name}", errors)

    requirement = summary["requirement"]
    if type(requirement) is dict:
        if requirement.get("title") is not None and type(
            requirement.get("title")
        ) is not str:
            _error(
                errors,
                "context_semantic_schema_invalid",
                "requirement.title must be text or null",
            )
        if not _string_array(requirement.get("headings")):
            _error(
                errors,
                "context_semantic_schema_invalid",
                "requirement.headings must be a string array",
            )
        if not _non_negative_integer(requirement.get("line_count")):
            _error(
                errors,
                "context_semantic_schema_invalid",
                "requirement.line_count must be a non-negative integer",
            )

    plan = summary["plan"]
    if type(plan) is dict:
        for field in ("scenario_count", "step_count"):
            if not _non_negative_integer(plan.get(field)):
                _error(
                    errors,
                    "context_semantic_schema_invalid",
                    f"plan.{field} must be a non-negative integer",
                )
        if not _sorted_unique_strings(plan.get("actions")):
            _error(
                errors,
                "context_semantic_schema_invalid",
                "plan.actions must be a sorted unique string array",
            )

    matrix = summary["matrix"]
    if type(matrix) is dict:
        if not _non_negative_integer(matrix.get("test_count")):
            _error(
                errors,
                "context_semantic_schema_invalid",
                "matrix.test_count must be a non-negative integer",
            )
        statuses = matrix.get("status_counts")
        if type(statuses) is not dict or any(
            not _non_empty_text(key) or not _non_negative_integer(value)
            for key, value in (
                statuses.items() if type(statuses) is dict else ()
            )
        ):
            _error(
                errors,
                "context_semantic_schema_invalid",
                "matrix.status_counts must map text to non-negative integers",
            )

    adapter = summary["adapter"]
    if type(adapter) is dict:
        if type(adapter.get("environment_boundary_confirmed")) is not bool:
            _error(
                errors,
                "context_semantic_schema_invalid",
                "adapter.environment_boundary_confirmed must be a boolean",
            )
        for field in ("services", "capabilities"):
            if not _sorted_unique_strings(adapter.get(field)):
                _error(
                    errors,
                    "context_semantic_schema_invalid",
                    f"adapter.{field} must be a sorted unique string array",
                )


def _validate_repository(
    repository: Any,
    errors: list[dict[str, str]],
    *,
    run_dir: Path,
    project_root: Path | None,
    require_current: bool,
) -> None:
    if type(repository) is not dict:
        return
    common_fields = {
        "requested",
        "complete",
        "root",
        "root_sha256",
        "files",
        "languages",
        "dependencies",
        "snapshot_sha256",
    }
    requested = repository.get("requested")
    complete = repository.get("complete")
    if type(requested) is not bool or type(complete) is not bool:
        _error(
            errors,
            "context_repository_schema_invalid",
            "repository requested and complete must be booleans",
        )
        return
    expected_fields = frozenset(
        common_fields | ({"error"} if requested and not complete else set())
    )
    _exact_fields(repository, expected_fields, "$.repository", errors)
    if set(repository) != expected_fields:
        return
    if not requested:
        expected = {
            "requested": False,
            "complete": False,
            "root": None,
            "root_sha256": None,
            "files": [],
            "languages": {},
            "dependencies": [],
            "snapshot_sha256": None,
        }
        if repository != expected:
            _error(
                errors,
                "context_repository_schema_invalid",
                "an unrequested repository must use the canonical empty snapshot",
            )
        return
    if not complete:
        _error(
            errors,
            "context_repository_incomplete",
            "a verified context cannot contain an incomplete repository snapshot",
        )
        return
    if repository["root"] != ".":
        _error(
            errors,
            "context_repository_root_invalid",
            "repository.root must equal '.'",
        )
    if not _is_sha256(repository["root_sha256"]):
        _error(
            errors,
            "context_repository_root_invalid",
            "repository.root_sha256 must be a lowercase SHA-256",
        )
    files = repository["files"]
    if type(files) is not list or len(files) > _compiler._MAX_REPOSITORY_FILES:
        _error(
            errors,
            "context_repository_files_invalid",
            "repository.files must be a bounded array",
        )
        return
    observed_paths: list[str] = []
    observed_languages: dict[str, int] = {}
    observed_total_bytes = 0
    for index, item in enumerate(files):
        if type(item) is not dict:
            _error(
                errors,
                "context_repository_file_invalid",
                f"repository.files[{index}] must be an object",
            )
            continue
        _exact_fields(
            item,
            frozenset({"path", "sha256", "size", "language"}),
            f"$.repository.files[{index}]",
            errors,
        )
        if set(item) != {"path", "sha256", "size", "language"}:
            continue
        path = item["path"]
        if not _safe_relative_path(path):
            _error(
                errors,
                "context_repository_path_invalid",
                f"repository.files[{index}].path is not a safe relative path",
            )
        else:
            observed_paths.append(path)
            parsed_path = PurePosixPath(path)
            filename = parsed_path.name
            if (
                filename in _compiler._SENSITIVE_FILENAMES
                or filename.startswith(".env.")
            ):
                _error(
                    errors,
                    "context_repository_sensitive_path",
                    f"repository snapshot contains a sensitive path: {path}",
                )
            if any(
                part in _compiler._IGNORED_DIRECTORIES
                for part in parsed_path.parts[:-1]
            ):
                _error(
                    errors,
                    "context_repository_ignored_path",
                    f"repository snapshot contains an ignored path: {path}",
                )
            if parsed_path.suffix.lower() not in _compiler._REPOSITORY_SUFFIXES:
                _error(
                    errors,
                    "context_repository_suffix_invalid",
                    f"repository snapshot contains an ineligible file: {path}",
                )
        if not _is_sha256(item["sha256"]):
            _error(
                errors,
                "context_repository_file_invalid",
                f"repository.files[{index}].sha256 is invalid",
            )
        size = item["size"]
        if (
            not _non_negative_integer(size)
            or size > _compiler._MAX_REPOSITORY_FILE_BYTES
        ):
            _error(
                errors,
                "context_repository_file_invalid",
                f"repository.files[{index}].size is invalid",
            )
        else:
            observed_total_bytes += size
        language = item["language"]
        if language is not None and not _non_empty_text(language):
            _error(
                errors,
                "context_repository_file_invalid",
                f"repository.files[{index}].language must be text or null",
            )
        elif isinstance(language, str):
            observed_languages[language] = (
                observed_languages.get(language, 0) + 1
            )
        if _safe_relative_path(path):
            expected_language = _compiler._LANGUAGES.get(
                PurePosixPath(path).suffix.lower()
            )
            if language != expected_language:
                _error(
                    errors,
                    "context_repository_language_invalid",
                    f"repository.files[{index}].language does not match its suffix",
                )
    if observed_total_bytes > _compiler._MAX_REPOSITORY_TOTAL_BYTES:
        _error(
            errors,
            "context_repository_total_bytes_exceeded",
            (
                "repository.files declares more than "
                f"{_compiler._MAX_REPOSITORY_TOTAL_BYTES} total bytes"
            ),
        )
    if observed_paths != sorted(set(observed_paths)):
        _error(
            errors,
            "context_repository_order_invalid",
            "repository file paths must be sorted and unique",
        )
    languages = repository["languages"]
    if type(languages) is not dict or languages != dict(
        sorted(observed_languages.items())
    ):
        _error(
            errors,
            "context_repository_languages_invalid",
            "repository.languages does not match repository.files",
        )
    dependencies = repository["dependencies"]
    if not _sorted_unique_strings(dependencies):
        _error(
            errors,
            "context_repository_dependencies_invalid",
            "repository.dependencies must be sorted and unique",
        )
    snapshot_payload = {
        "files": files,
        "languages": languages,
        "dependencies": dependencies,
    }
    if (
        not _is_sha256(repository["snapshot_sha256"])
        or repository["snapshot_sha256"]
        != _compiler._canonical_sha256(snapshot_payload)
    ):
        _error(
            errors,
            "context_repository_hash_mismatch",
            "repository.snapshot_sha256 does not match its canonical payload",
        )
    if not require_current:
        return
    if project_root is None:
        _error(
            errors,
            "context_project_root_required",
            "a requested repository snapshot requires the same project_root "
            "for currentness verification",
        )
        return
    try:
        resolved_project_root = _compiler._directory(
            project_root,
            code="project_root_invalid",
        )
        current = _compiler._compile_repository(
            resolved_project_root,
            max_files=_compiler._MAX_REPOSITORY_FILES,
            excluded_roots=(run_dir,),
        )
    except _compiler.ContextCompileError as exc:
        _error(
            errors,
            "context_project_root_invalid",
            str(exc),
        )
        return
    if not _canonical_equal(repository, current):
        _error(
            errors,
            "context_repository_not_current",
            "repository snapshot does not match the current project_root",
        )


def _validate_capability_graph(
    raw_graph: Any,
    values: Mapping[str, Any],
    registry: ToolRegistry,
    errors: list[dict[str, str]],
) -> None:
    if type(raw_graph) is not dict:
        return
    _exact_fields(
        raw_graph,
        frozenset({"tool_registry_sha256", "nodes", "edges"}),
        "$.capability_graph",
        errors,
    )
    if set(raw_graph) != {"tool_registry_sha256", "nodes", "edges"}:
        return
    if raw_graph["tool_registry_sha256"] != registry.canonical_sha256:
        _error(
            errors,
            "context_tool_registry_hash_mismatch",
            "capability graph does not reference the current tool registry",
        )
    _, used_actions = _compiler._summarize_plan(values.get("plan"))
    adapter = _compiler._summarize_adapter(values.get("adapter_context"))
    expected_graph, graph_blockers = _compiler._build_capability_graph(
        registry,
        used_actions=used_actions,
        adapter_summary=adapter,
    )
    if graph_blockers:
        _error(
            errors,
            "context_capability_blocked",
            "; ".join(item["message"] for item in graph_blockers),
        )
    if not _canonical_equal(raw_graph, expected_graph):
        _error(
            errors,
            "context_capability_graph_mismatch",
            "capability graph does not match current inputs and registry",
        )


def _read_stable_regular(
    path: Path,
    *,
    max_bytes: int,
    require_single_link: bool,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"not a regular file: {path}")
        if require_single_link and before.st_nlink != 1:
            raise ValueError(f"hard-linked snapshot is not allowed: {path}")
        if before.st_size > max_bytes:
            raise ValueError(f"file exceeds {max_bytes} bytes: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, max_bytes + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"file exceeds {max_bytes} bytes: {path}")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_nlink,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_nlink,
        )
        if identity_before != identity_after:
            raise ValueError(f"file changed while being read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _decode_source(payload: bytes, *, kind: str) -> Any:
    text = payload.decode("utf-8")
    if kind == "text":
        return text
    value = json.loads(
        text,
        object_pairs_hook=_object_without_duplicates,
        parse_constant=_reject_json_constant,
    )
    if type(value) is not dict:
        raise ValueError("JSON source root must be an object")
    return value


def _object_without_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _exact_fields(
    value: dict[str, Any],
    expected: frozenset[str],
    path: str,
    errors: list[dict[str, str]],
) -> None:
    observed = set(value)
    if observed != expected:
        missing = sorted(expected - observed)
        unknown = sorted(observed - expected)
        _error(
            errors,
            "context_schema_fields_invalid",
            f"{path} fields are not closed; missing={missing}, unknown={unknown}",
        )


def _canonical_equal(left: Any, right: Any) -> bool:
    try:
        return _compiler._canonical_sha256(left) == _compiler._canonical_sha256(
            right
        )
    except (TypeError, ValueError):
        return False


def _safe_relative_path(value: Any) -> bool:
    if not _non_empty_text(value):
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and value == path.as_posix()
        and "." not in path.parts
        and ".." not in path.parts
    )


def _is_sha256(value: Any) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _non_empty_text(value: Any) -> bool:
    return type(value) is str and bool(value.strip())


def _non_negative_integer(value: Any) -> bool:
    return type(value) is int and value >= 0


def _string_array(value: Any) -> bool:
    return type(value) is list and all(type(item) is str for item in value)


def _sorted_unique_strings(value: Any) -> bool:
    return (
        _string_array(value)
        and all(bool(item.strip()) for item in value)
        and value == sorted(set(value))
    )


def _error(
    errors: list[dict[str, str]],
    code: str,
    message: BaseException | str,
) -> None:
    item = {"code": code, "message": str(message)}
    if item not in errors:
        errors.append(item)


def _result(
    errors: list[dict[str, str]],
    *,
    context_sha256: str | None = None,
    snapshot: dict[str, Any] | None = None,
) -> ContextVerificationResult:
    valid = not errors
    return ContextVerificationResult(
        valid=valid,
        errors=tuple(errors),
        context_sha256=context_sha256 if valid else None,
        snapshot=dict(snapshot) if valid and snapshot is not None else None,
    )
