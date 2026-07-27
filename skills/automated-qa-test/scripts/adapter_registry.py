#!/usr/bin/env python3
"""严格加载、校验并发现版本化项目 Adapter。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from qa_common import atomic_write_json, safe_output_path

ADAPTER_DIR = (
    Path(__file__).resolve().parent.parent / "references" / "adapters"
)
ADAPTER_SCHEMA_VERSION = 1
_MAX_DEFINITION_BYTES = 1024 * 1024
_MAX_DEFINITIONS = 128
_MAX_ITEMS = 256
_MAX_TEXT = 16_384
_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_SHELL_META = re.compile(r"[;&|`<>]")
_ROOT_FIELDS = {
    "schema_version",
    "id",
    "display_name",
    "markers",
    "services",
    "data_boundaries",
    "evidence_layers",
    "preflight",
    "probe_template",
}
_SERVICE_FIELDS = {
    "id",
    "role",
    "path",
    "default_url",
    "start_command",
}
_EVIDENCE_FIELDS = {
    "id",
    "strong_signal",
    "weak_signal_to_avoid",
}
_PREFLIGHT_FIELDS = {
    "env_candidates",
    "base_url_contains",
    "plan_text_contains",
}
_PROBE_TEMPLATE_FIELDS = {
    "kind",
    "required_services",
    "base_url_service_rules",
    "ws_path",
    "session_detail_path",
    "terminal_type",
}
_FORBIDDEN_KEY_PARTS = (
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
)


class AdapterContractError(ValueError):
    """Adapter definition or registry violates the public contract."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str = "$",
    ) -> None:
        self.code = code
        self.path = path
        super().__init__(message)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "error": "adapter_contract_error",
            "code": self.code,
            "path": self.path,
            "message": str(self),
        }


def load_adapter_definition(path: Path) -> dict[str, Any]:
    """Read one bounded regular JSON file and validate its semantics."""

    resolved, raw = _read_regular(path)
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise AdapterContractError(
            "adapter_json_invalid",
            f"invalid adapter JSON: {error}",
            path=str(resolved),
        ) from error
    validated = validate_adapter_definition(value)
    return {
        **validated,
        "definition_path": str(resolved),
        "definition_sha256": hashlib.sha256(raw).hexdigest(),
    }


def validate_adapter_definition(value: object) -> dict[str, Any]:
    """Validate the versioned adapter schema and referential integrity."""

    root = _object("$", value)
    _exact_fields("$", root, required=_ROOT_FIELDS - {"probe_template"})
    if root["schema_version"] != ADAPTER_SCHEMA_VERSION:
        raise AdapterContractError(
            "adapter_schema_unsupported",
            "schema_version must equal 1",
            path="$.schema_version",
        )
    _reject_secret_keys(root)
    adapter_id = _identifier("$.id", root["id"])
    display_name = _text("$.display_name", root["display_name"])
    markers = _relative_path_array("$.markers", root["markers"])
    if not markers:
        raise AdapterContractError(
            "adapter_markers_empty",
            "markers must contain at least one repository-relative file",
            path="$.markers",
        )
    services_value = _array("$.services", root["services"])
    services: list[dict[str, Any]] = []
    service_ids: set[str] = set()
    for index, raw_service in enumerate(services_value):
        item_path = f"$.services[{index}]"
        service = _object(item_path, raw_service)
        _exact_fields(item_path, service, required=_SERVICE_FIELDS)
        service_id = _identifier(f"{item_path}.id", service["id"])
        if service_id in service_ids:
            raise AdapterContractError(
                "adapter_service_duplicate",
                f"duplicate service id: {service_id}",
                path=f"{item_path}.id",
            )
        service_ids.add(service_id)
        command = _text(
            f"{item_path}.start_command",
            service["start_command"],
        )
        try:
            command_parts = shlex.split(command)
        except ValueError as error:
            raise AdapterContractError(
                "adapter_start_command_invalid",
                str(error),
                path=f"{item_path}.start_command",
            ) from error
        if (
            not command_parts
            or any(_SHELL_META.search(part) for part in command_parts)
        ):
            raise AdapterContractError(
                "adapter_start_command_unsafe",
                "start_command must parse to argv without shell metacharacters",
                path=f"{item_path}.start_command",
            )
        services.append(
            {
                "id": service_id,
                "role": _text(f"{item_path}.role", service["role"]),
                "path": _relative_path(
                    f"{item_path}.path",
                    service["path"],
                ),
                "default_url": _service_url(
                    f"{item_path}.default_url",
                    service["default_url"],
                ),
                "start_command": command,
            }
        )
    boundaries = _text_array(
        "$.data_boundaries",
        root["data_boundaries"],
        allow_empty=False,
    )
    evidence_value = _array(
        "$.evidence_layers",
        root["evidence_layers"],
    )
    evidence_layers: list[dict[str, str]] = []
    evidence_ids: set[str] = set()
    for index, raw_layer in enumerate(evidence_value):
        item_path = f"$.evidence_layers[{index}]"
        layer = _object(item_path, raw_layer)
        _exact_fields(item_path, layer, required=_EVIDENCE_FIELDS)
        layer_id = _identifier(f"{item_path}.id", layer["id"])
        if layer_id in evidence_ids:
            raise AdapterContractError(
                "adapter_evidence_layer_duplicate",
                f"duplicate evidence layer id: {layer_id}",
                path=f"{item_path}.id",
            )
        evidence_ids.add(layer_id)
        evidence_layers.append(
            {
                "id": layer_id,
                "strong_signal": _text(
                    f"{item_path}.strong_signal",
                    layer["strong_signal"],
                ),
                "weak_signal_to_avoid": _text(
                    f"{item_path}.weak_signal_to_avoid",
                    layer["weak_signal_to_avoid"],
                ),
            }
        )
    preflight = _validate_preflight(root["preflight"], service_ids)
    normalized: dict[str, Any] = {
        "schema_version": ADAPTER_SCHEMA_VERSION,
        "id": adapter_id,
        "display_name": display_name,
        "markers": markers,
        "services": services,
        "data_boundaries": boundaries,
        "evidence_layers": evidence_layers,
        "preflight": preflight,
    }
    if "probe_template" in root:
        normalized["probe_template"] = _validate_probe_template(
            root["probe_template"],
            service_ids,
        )
    return normalized


def adapter_definitions(
    directory: Path | None = None,
) -> list[dict[str, Any]]:
    """Load the complete registry; one invalid file invalidates the registry."""

    selected = (directory or ADAPTER_DIR).expanduser()
    if not selected.exists():
        return []
    if not selected.is_dir() or selected.is_symlink():
        raise AdapterContractError(
            "adapter_registry_not_directory",
            f"adapter registry must be a real directory: {selected}",
            path=str(selected),
        )
    paths = sorted(selected.glob("*.json"))
    if len(paths) > _MAX_DEFINITIONS:
        raise AdapterContractError(
            "adapter_registry_too_large",
            f"adapter registry exceeds {_MAX_DEFINITIONS} definitions",
            path=str(selected),
        )
    definitions = [load_adapter_definition(path) for path in paths]
    ids = [item["id"] for item in definitions]
    if len(ids) != len(set(ids)):
        raise AdapterContractError(
            "adapter_id_duplicate",
            "adapter ids must be unique across the registry",
            path=str(selected),
        )
    return definitions


def get_adapter_definition(
    adapter_id: str | None,
) -> dict[str, Any] | None:
    if adapter_id is None:
        return None
    matches = [
        item for item in adapter_definitions()
        if item["id"] == adapter_id
    ]
    return matches[0] if matches else None


def detect_adapter_id(project_root: Path) -> str:
    """Detect exactly one adapter from non-escaping regular-file markers."""

    root = project_root.expanduser().resolve()
    if not root.is_dir():
        # 项目根目录输入错误由上下文编译器处理。检测必须保持无副作用并返回
        # 保守的通用路由，使调用者仍能发布结构化阻断交接。
        return "generic"
    matches: list[str] = []
    for definition in adapter_definitions():
        if all(_marker_matches(root, marker) for marker in definition["markers"]):
            matches.append(str(definition["id"]))
    if len(matches) > 1:
        raise AdapterContractError(
            "adapter_detection_ambiguous",
            "multiple adapters match the same project root: "
            + ", ".join(matches),
            path=str(root),
        )
    return matches[0] if matches else "generic"


def validate_adapter_onboarding(
    definition_path: Path,
    *,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """Produce a deterministic onboarding/conformance report."""

    definition = load_adapter_definition(definition_path)
    marker_checks: list[dict[str, object]] = []
    project_matches: bool | None = None
    resolved_project_root: str | None = None
    if project_root is not None:
        root = project_root.expanduser().resolve(strict=True)
        resolved_project_root = str(root)
        marker_checks = [
            {
                "path": marker,
                "matched": _marker_matches(root, marker),
            }
            for marker in definition["markers"]
        ]
        project_matches = all(
            item["matched"] is True for item in marker_checks
        )
    blockers: list[dict[str, Any]] = []
    if project_matches is False:
        unmatched_markers = [
            str(item["path"])
            for item in marker_checks
            if item["matched"] is not True
        ]
        blockers.append(
            {
                "code": "adapter_markers_not_matched",
                "message": (
                    "adapter definition markers do not match the supplied "
                    "project root"
                ),
                "project_root": resolved_project_root,
                "unmatched_markers": unmatched_markers,
            },
        )
    payload = {
        "schema_version": 1,
        "kind": "qa_adapter_onboarding",
        "not_evidence": True,
        "not_authorization": True,
        "ready": not blockers,
        "adapter_id": definition["id"],
        "definition_path": definition["definition_path"],
        "definition_sha256": definition["definition_sha256"],
        "project_root": resolved_project_root,
        "project_matches": project_matches,
        "marker_checks": marker_checks,
        "blockers": blockers,
        "service_ids": [
            item["id"] for item in definition["services"]
        ],
        "evidence_layer_ids": [
            item["id"] for item in definition["evidence_layers"]
        ],
        "checks": {
            "strict_schema": True,
            "relative_paths_only": True,
            "service_references_closed": True,
            "shell_execution_forbidden": True,
            "secret_fields_forbidden": True,
        },
    }
    return {
        **payload,
        "report_sha256": _canonical_sha256(payload),
    }


def _validate_preflight(
    value: object,
    service_ids: set[str],
) -> dict[str, Any]:
    preflight = _object("$.preflight", value)
    _exact_fields("$.preflight", preflight, required=_PREFLIGHT_FIELDS)
    env = _object("$.preflight.env_candidates", preflight["env_candidates"])
    normalized_env: dict[str, list[str]] = {}
    for service_id, candidates in env.items():
        _known_service(
            "$.preflight.env_candidates",
            service_id,
            service_ids,
        )
        normalized_env[service_id] = _relative_path_array(
            f"$.preflight.env_candidates.{service_id}",
            candidates,
        )
    return {
        "env_candidates": normalized_env,
        "base_url_contains": _service_reference_map(
            "$.preflight.base_url_contains",
            preflight["base_url_contains"],
            service_ids,
        ),
        "plan_text_contains": _service_reference_map(
            "$.preflight.plan_text_contains",
            preflight["plan_text_contains"],
            service_ids,
        ),
    }


def _validate_probe_template(
    value: object,
    service_ids: set[str],
) -> dict[str, Any]:
    template = _object("$.probe_template", value)
    _exact_fields(
        "$.probe_template",
        template,
        required=_PROBE_TEMPLATE_FIELDS,
    )
    required_services = _service_ids(
        "$.probe_template.required_services",
        template["required_services"],
        service_ids,
    )
    for field in ("ws_path", "session_detail_path"):
        path_value = _text(
            f"$.probe_template.{field}",
            template[field],
        )
        if not path_value.startswith("/") or "\\" in path_value:
            raise AdapterContractError(
                "adapter_probe_path_invalid",
                f"{field} must be an absolute URL path",
                path=f"$.probe_template.{field}",
            )
    return {
        "kind": _identifier(
            "$.probe_template.kind",
            template["kind"],
        ),
        "required_services": required_services,
        "base_url_service_rules": _service_reference_map(
            "$.probe_template.base_url_service_rules",
            template["base_url_service_rules"],
            service_ids,
        ),
        "ws_path": template["ws_path"],
        "session_detail_path": template["session_detail_path"],
        "terminal_type": _identifier(
            "$.probe_template.terminal_type",
            template["terminal_type"],
        ),
    }


def _service_reference_map(
    path: str,
    value: object,
    service_ids: set[str],
) -> dict[str, list[str]]:
    mapping = _object(path, value)
    result: dict[str, list[str]] = {}
    for marker, raw_ids in mapping.items():
        normalized_marker = _text(f"{path}.<key>", marker)
        result[normalized_marker] = _service_ids(
            f"{path}.{normalized_marker}",
            raw_ids,
            service_ids,
        )
    return result


def _service_ids(
    path: str,
    value: object,
    service_ids: set[str],
) -> list[str]:
    values = _text_array(path, value, allow_empty=False)
    for service_id in values:
        _known_service(path, service_id, service_ids)
    return values


def _known_service(
    path: str,
    service_id: str,
    service_ids: set[str],
) -> None:
    if service_id not in service_ids:
        raise AdapterContractError(
            "adapter_service_reference_unknown",
            f"unknown service id: {service_id}",
            path=path,
        )


def _marker_matches(root: Path, marker: str) -> bool:
    candidate = root / marker
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return False
    return resolved.is_file()


def _read_regular(path: Path) -> tuple[Path, bytes]:
    candidate = path.expanduser()
    parent = candidate.parent.resolve(strict=True)
    resolved = parent / candidate.name
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(resolved, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise AdapterContractError(
                "adapter_input_not_regular",
                f"adapter definition is not a regular file: {resolved}",
                path=str(resolved),
            )
        if before.st_nlink != 1:
            raise AdapterContractError(
                "adapter_input_hardlinked",
                f"hard-linked adapter definition is rejected: {resolved}",
                path=str(resolved),
            )
        if before.st_size > _MAX_DEFINITION_BYTES:
            raise AdapterContractError(
                "adapter_input_too_large",
                f"adapter definition exceeds {_MAX_DEFINITION_BYTES} bytes",
                path=str(resolved),
            )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, _MAX_DEFINITION_BYTES + 1 - size),
            )
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _MAX_DEFINITION_BYTES:
                raise AdapterContractError(
                    "adapter_input_too_large",
                    "adapter definition exceeds its byte limit",
                    path=str(resolved),
                )
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise AdapterContractError(
                "adapter_input_changed",
                "adapter definition changed while reading",
                path=str(resolved),
            )
        return resolved, b"".join(chunks)
    finally:
        os.close(descriptor)


def _relative_path_array(path: str, value: object) -> list[str]:
    values = _text_array(path, value, allow_empty=True)
    return [
        _relative_path(f"{path}[{index}]", item)
        for index, item in enumerate(values)
    ]


def _relative_path(path: str, value: object) -> str:
    text = _text(path, value)
    pure = PurePosixPath(text)
    if (
        pure.is_absolute()
        or text.startswith("~")
        or "\\" in text
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise AdapterContractError(
            "adapter_path_invalid",
            "path must be normalized, relative, and non-traversing",
            path=path,
        )
    return text


def _service_url(path: str, value: object) -> str:
    text = _text(path, value)
    parsed = urlsplit(text)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AdapterContractError(
            "adapter_service_url_invalid",
            "default_url must be credential-free HTTP(S) origin/path",
            path=path,
        )
    return text


def _reject_secret_keys(value: object, *, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = key.lower()
            if any(part in lowered for part in _FORBIDDEN_KEY_PARTS):
                raise AdapterContractError(
                    "adapter_secret_field_forbidden",
                    f"secret-bearing field name is forbidden: {key}",
                    path=f"{path}.{key}",
                )
            _reject_secret_keys(nested, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_secret_keys(nested, path=f"{path}[{index}]")


def _object(path: str, value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterContractError(
            "adapter_type_invalid",
            "value must be an object",
            path=path,
        )
    return dict(value)


def _array(path: str, value: object) -> list[Any]:
    if not isinstance(value, list) or len(value) > _MAX_ITEMS:
        raise AdapterContractError(
            "adapter_array_invalid",
            f"value must be an array with at most {_MAX_ITEMS} items",
            path=path,
        )
    return list(value)


def _text(path: str, value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > _MAX_TEXT
    ):
        raise AdapterContractError(
            "adapter_text_invalid",
            f"value must be trimmed text up to {_MAX_TEXT} characters",
            path=path,
        )
    return value


def _identifier(path: str, value: object) -> str:
    text = _text(path, value)
    if not _ID.fullmatch(text):
        raise AdapterContractError(
            "adapter_identifier_invalid",
            "identifier must match [a-z][a-z0-9_-]{0,63}",
            path=path,
        )
    return text


def _text_array(
    path: str,
    value: object,
    *,
    allow_empty: bool,
) -> list[str]:
    raw = _array(path, value)
    values = [
        _text(f"{path}[{index}]", item)
        for index, item in enumerate(raw)
    ]
    if not allow_empty and not values:
        raise AdapterContractError(
            "adapter_array_empty",
            "array must not be empty",
            path=path,
        )
    if len(values) != len(set(values)):
        raise AdapterContractError(
            "adapter_array_duplicate",
            "array values must be unique",
            path=path,
        )
    return values


def _exact_fields(
    path: str,
    value: Mapping[str, Any],
    *,
    required: set[str],
) -> None:
    allowed = set(_ROOT_FIELDS) if path == "$" else set(required)
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - allowed)
    if missing or unknown:
        raise AdapterContractError(
            "adapter_fields_invalid",
            f"fields invalid; missing={missing}, unknown={unknown}",
            path=path,
        )


def _object_without_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a project Adapter onboarding contract.",
    )
    parser.add_argument("--definition", required=True)
    parser.add_argument("--project-root")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    definition_path = Path(args.definition)
    project_root = Path(args.project_root) if args.project_root else None
    output_path: Path | None = None
    try:
        output_path = safe_output_path(
            Path(args.out),
            protected_paths=[definition_path],
            protected_roots=(
                [project_root] if project_root is not None else []
            ),
        )
        report = validate_adapter_onboarding(
            definition_path,
            project_root=project_root,
        )
    except (
        AdapterContractError,
        OSError,
        ValueError,
    ) as error:
        payload = (
            error.to_dict()
            if isinstance(error, AdapterContractError)
            else {
                "schema_version": 1,
                "error": "adapter_onboarding_error",
                "message": str(error),
            }
        )
        if output_path is not None:
            try:
                atomic_write_json(output_path, payload)
                print(output_path)
            except (OSError, ValueError):
                print(
                    json.dumps(payload, ensure_ascii=False),
                    file=sys.stderr,
                )
        else:
            print(json.dumps(payload, ensure_ascii=False), file=sys.stderr)
        return 2
    atomic_write_json(output_path, report)
    print(output_path)
    return 0 if report["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
