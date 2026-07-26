"""定义工具规格、模型调用意图与失败关闭的注册表。"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

TOOL_MANIFEST_SCHEMA_VERSION = 1
_ACTION_PATTERN = re.compile(
    r"[a-z][A-Za-z0-9]*(?:[._-][A-Za-z0-9]+)*",
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_JSON_TYPES = frozenset(
    {
        "object",
        "array",
        "string",
        "integer",
        "number",
        "boolean",
        "null",
    },
)
_SCHEMA_KEYS = frozenset(
    {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "enum",
        "title",
        "description",
    },
)
_MODEL_INVOCATION_FIELDS = frozenset({"action", "arguments"})


class RiskClass(StrEnum):
    """工具动作的静态风险等级。"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CleanupSemantics(StrEnum):
    """工具结束后资源清理的强度。"""

    NONE = "none"
    BEST_EFFORT = "best_effort"
    REQUIRED = "required"


class ToolContractError(ValueError):
    """工具规格、注册或调用违反契约。"""

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

    def to_dict(self) -> dict[str, str | int]:
        """返回可交付给上层 handoff 的结构化错误。"""

        return {
            "schema_version": 1,
            "error": "tool_contract_error",
            "code": self.code,
            "path": self.path,
            "message": str(self),
        }


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """一个不可变、可哈希并可在执行前验证的工具规格。"""

    action: str
    version: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    capabilities: tuple[str, ...]
    risk_class: RiskClass | str
    required_authorizations: tuple[str, ...]
    read: tuple[str, ...]
    write: tuple[str, ...]
    side_effects: tuple[str, ...]
    reversible: bool
    idempotent: bool
    default_timeout_seconds: float
    max_timeout_seconds: float
    output_limit_bytes: int
    evidence_types: tuple[str, ...]
    executor_version: str
    cleanup_semantics: CleanupSemantics | str

    def __post_init__(self) -> None:
        action = _action(self.action)
        version = _non_empty_text("version", self.version)
        executor_version = _non_empty_text(
            "executor_version",
            self.executor_version,
        )
        input_schema = _strict_object_schema(
            self.input_schema,
            path="$.input_schema",
        )
        output_schema = _strict_object_schema(
            self.output_schema,
            path="$.output_schema",
        )
        capabilities = _string_set("capabilities", self.capabilities)
        required_authorizations = _string_set(
            "required_authorizations",
            self.required_authorizations,
        )
        read = _string_set("read", self.read)
        write = _string_set("write", self.write)
        side_effects = _string_set("side_effects", self.side_effects)
        evidence_types = _string_set(
            "evidence_types",
            self.evidence_types,
        )
        risk_class = _enum_value(
            "risk_class",
            self.risk_class,
            RiskClass,
        )
        cleanup_semantics = _enum_value(
            "cleanup_semantics",
            self.cleanup_semantics,
            CleanupSemantics,
        )
        reversible = _boolean("reversible", self.reversible)
        idempotent = _boolean("idempotent", self.idempotent)
        default_timeout = _positive_number(
            "default_timeout_seconds",
            self.default_timeout_seconds,
        )
        max_timeout = _positive_number(
            "max_timeout_seconds",
            self.max_timeout_seconds,
        )
        if default_timeout > max_timeout:
            raise ToolContractError(
                "timeout_order_invalid",
                "default_timeout_seconds 不得大于 max_timeout_seconds",
                path="$.default_timeout_seconds",
            )
        output_limit = _positive_integer(
            "output_limit_bytes",
            self.output_limit_bytes,
        )

        object.__setattr__(self, "action", action)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "executor_version", executor_version)
        object.__setattr__(self, "input_schema", _freeze(input_schema))
        object.__setattr__(self, "output_schema", _freeze(output_schema))
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(
            self,
            "required_authorizations",
            required_authorizations,
        )
        object.__setattr__(self, "read", read)
        object.__setattr__(self, "write", write)
        object.__setattr__(self, "side_effects", side_effects)
        object.__setattr__(self, "evidence_types", evidence_types)
        object.__setattr__(self, "risk_class", risk_class)
        object.__setattr__(self, "cleanup_semantics", cleanup_semantics)
        object.__setattr__(self, "reversible", reversible)
        object.__setattr__(self, "idempotent", idempotent)
        object.__setattr__(
            self,
            "default_timeout_seconds",
            default_timeout,
        )
        object.__setattr__(
            self,
            "max_timeout_seconds",
            max_timeout,
        )
        object.__setattr__(self, "output_limit_bytes", output_limit)

    @property
    def canonical_sha256(self) -> str:
        """返回只由规格内容决定的规范 SHA-256。"""

        return _canonical_sha256(
            {
                "schema_version": TOOL_MANIFEST_SCHEMA_VERSION,
                "tool": self.to_dict(),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        """返回稳定、可 JSON 序列化的规格。"""

        return {
            "action": self.action,
            "version": self.version,
            "input_schema": _thaw(self.input_schema),
            "output_schema": _thaw(self.output_schema),
            "capabilities": list(self.capabilities),
            "risk_class": self.risk_class.value,
            "required_authorizations": list(
                self.required_authorizations,
            ),
            "read": list(self.read),
            "write": list(self.write),
            "side_effects": list(self.side_effects),
            "reversible": self.reversible,
            "idempotent": self.idempotent,
            "default_timeout_seconds": self.default_timeout_seconds,
            "max_timeout_seconds": self.max_timeout_seconds,
            "output_limit_bytes": self.output_limit_bytes,
            "evidence_types": list(self.evidence_types),
            "executor_version": self.executor_version,
            "cleanup_semantics": self.cleanup_semantics.value,
        }


@dataclass(frozen=True, slots=True)
class ToolInvocation:
    """模型或规则提出的工具调用意图；该对象不是执行授权。"""

    action: str
    version: str
    arguments: Mapping[str, Any]
    spec_sha256: str

    def __post_init__(self) -> None:
        action = _action(self.action)
        version = _non_empty_text("version", self.version)
        spec_sha256 = _sha256_text(
            "spec_sha256",
            self.spec_sha256,
        )
        arguments = _plain_json(
            self.arguments,
            path="$.arguments",
        )
        if not isinstance(arguments, dict):
            raise ToolContractError(
                "arguments_not_object",
                "arguments 必须是 JSON object",
                path="$.arguments",
            )
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "spec_sha256", spec_sha256)
        object.__setattr__(self, "arguments", _freeze(arguments))

    def to_dict(self) -> dict[str, Any]:
        """返回不含授权字段的调用意图。"""

        return {
            "action": self.action,
            "version": self.version,
            "arguments": _thaw(self.arguments),
            "spec_sha256": self.spec_sha256,
        }


class ToolRegistry:
    """注册工具规格并在执行前实施契约门禁。"""

    def __init__(self, specs: Iterable[ToolSpec] = ()) -> None:
        self._specs: dict[str, ToolSpec] = {}
        for spec in specs:
            self.register(spec)

    @property
    def actions(self) -> tuple[str, ...]:
        """返回按字典序排列的 action。"""

        return tuple(sorted(self._specs))

    @property
    def canonical_sha256(self) -> str:
        """返回与注册顺序无关的 registry SHA-256。"""

        return _canonical_sha256(self.to_manifest())

    def register(self, spec: ToolSpec) -> None:
        """注册一个新规格；重复 action 默认拒绝。"""

        if not isinstance(spec, ToolSpec):
            raise ToolContractError(
                "spec_type_invalid",
                "registry 只能注册 ToolSpec",
                path="$.tool",
            )
        if spec.action in self._specs:
            raise ToolContractError(
                "duplicate_action",
                f"action 已注册：{spec.action}",
                path=f"$.tools.{spec.action}",
            )
        self._specs[spec.action] = spec

    def get(self, action: str) -> ToolSpec:
        """读取已注册规格；未知 action 默认拒绝。"""

        normalized = _action(action)
        try:
            return self._specs[normalized]
        except KeyError as exc:
            raise ToolContractError(
                "unknown_action",
                f"未知 action：{normalized}",
                path="$.action",
            ) from exc

    def to_manifest(self) -> dict[str, Any]:
        """返回 action 已排序的规范 registry manifest。"""

        return {
            "schema_version": TOOL_MANIFEST_SCHEMA_VERSION,
            "tools": [
                self._specs[action].to_dict()
                for action in sorted(self._specs)
            ],
        }

    def invocation_from_model(
        self,
        model_input: Mapping[str, Any],
    ) -> ToolInvocation:
        """把模型输入转为调用意图，不创建或暗示执行授权。"""

        payload = _plain_json(
            model_input,
            path="$.model_input",
        )
        if not isinstance(payload, dict):
            raise ToolContractError(
                "model_input_not_object",
                "模型工具输入必须是 JSON object",
                path="$.model_input",
            )
        fields = set(payload)
        missing = sorted(_MODEL_INVOCATION_FIELDS - fields)
        if missing:
            raise ToolContractError(
                "model_fields_missing",
                f"模型工具输入缺少字段：{', '.join(missing)}",
                path="$.model_input",
            )
        unknown = sorted(fields - _MODEL_INVOCATION_FIELDS)
        if unknown:
            raise ToolContractError(
                "model_fields_unknown",
                f"模型工具输入包含未知字段：{', '.join(unknown)}",
                path="$.model_input",
            )
        spec = self.get(payload["action"])
        invocation = ToolInvocation(
            action=spec.action,
            version=spec.version,
            arguments=payload["arguments"],
            spec_sha256=spec.canonical_sha256,
        )
        self.validate_invocation(invocation)
        return invocation

    def validate_invocation(
        self,
        invocation: ToolInvocation,
    ) -> ToolSpec:
        """执行前验证调用并返回匹配规格；返回值不是执行授权。"""

        if not isinstance(invocation, ToolInvocation):
            raise ToolContractError(
                "invocation_type_invalid",
                "执行前输入必须是 ToolInvocation",
                path="$.invocation",
            )
        spec = self.get(invocation.action)
        if invocation.version != spec.version:
            raise ToolContractError(
                "tool_version_drift",
                (
                    f"调用版本 {invocation.version} "
                    f"与当前版本 {spec.version} 不一致"
                ),
                path="$.invocation.version",
            )
        if not hmac.compare_digest(
            invocation.spec_sha256,
            spec.canonical_sha256,
        ):
            raise ToolContractError(
                "tool_spec_drift",
                "调用绑定的 ToolSpec 已发生变化",
                path="$.invocation.spec_sha256",
            )
        _validate_instance(
            invocation.arguments,
            spec.input_schema,
            path="$.arguments",
        )
        return spec

    def validate_output(
        self,
        invocation: ToolInvocation,
        output: Mapping[str, Any],
    ) -> None:
        """按调用绑定的同一规格验证工具输出。"""

        spec = self.validate_invocation(invocation)
        normalized = _plain_json(output, path="$.output")
        _validate_instance(
            normalized,
            spec.output_schema,
            path="$.output",
        )


def _strict_object_schema(
    value: Mapping[str, Any],
    *,
    path: str,
) -> dict[str, Any]:
    schema = _plain_json(value, path=path)
    if not isinstance(schema, dict):
        raise ToolContractError(
            "schema_not_object",
            "工具 schema 必须是 JSON object",
            path=path,
        )
    _validate_schema_node(schema, path=path, root=True)
    return schema


def _validate_schema_node(
    schema: Mapping[str, Any],
    *,
    path: str,
    root: bool = False,
) -> None:
    unknown_keywords = sorted(set(schema) - _SCHEMA_KEYS)
    if unknown_keywords:
        raise ToolContractError(
            "schema_keyword_unknown",
            f"schema 包含未实现关键字：{', '.join(unknown_keywords)}",
            path=path,
        )
    declared_type = schema.get("type")
    if not isinstance(declared_type, str) or declared_type not in _JSON_TYPES:
        raise ToolContractError(
            "schema_type_invalid",
            "schema.type 必须是受支持的单一 JSON 类型",
            path=f"{path}.type",
        )
    if root and declared_type != "object":
        raise ToolContractError(
            "schema_root_not_object",
            "工具输入和输出 schema 的根类型必须是 object",
            path=path,
        )

    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, list) or not enum:
            raise ToolContractError(
                "schema_enum_invalid",
                "schema.enum 必须是非空 JSON array",
                path=f"{path}.enum",
            )
        seen: set[str] = set()
        for index, item in enumerate(enum):
            if not _matches_type(item, declared_type):
                raise ToolContractError(
                    "schema_enum_type_mismatch",
                    "schema.enum 值与声明类型不一致",
                    path=f"{path}.enum[{index}]",
                )
            encoded = _canonical_json(item)
            if encoded in seen:
                raise ToolContractError(
                    "schema_enum_duplicate",
                    "schema.enum 不得包含重复值",
                    path=f"{path}.enum[{index}]",
                )
            seen.add(encoded)

    if declared_type == "object":
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            raise ToolContractError(
                "schema_properties_invalid",
                "object schema 必须显式声明 properties",
                path=f"{path}.properties",
            )
        if schema.get("additionalProperties") is not False:
            raise ToolContractError(
                "schema_not_closed",
                "object schema 必须设置 additionalProperties=false",
                path=path,
            )
        required = schema.get("required", [])
        if not isinstance(required, list) or any(
            not isinstance(item, str) or not item
            for item in required
        ):
            raise ToolContractError(
                "schema_required_invalid",
                "schema.required 必须是非空字段名组成的 array",
                path=f"{path}.required",
            )
        if len(required) != len(set(required)):
            raise ToolContractError(
                "schema_required_duplicate",
                "schema.required 不得包含重复字段",
                path=f"{path}.required",
            )
        unknown_required = sorted(set(required) - set(properties))
        if unknown_required:
            raise ToolContractError(
                "schema_required_unknown",
                (
                    "schema.required 引用了未知属性："
                    f"{', '.join(unknown_required)}"
                ),
                path=f"{path}.required",
            )
        if "items" in schema:
            raise ToolContractError(
                "schema_keyword_incompatible",
                "object schema 不得声明 items",
                path=f"{path}.items",
            )
        for name, child in properties.items():
            if not isinstance(child, dict):
                raise ToolContractError(
                    "schema_property_invalid",
                    "property schema 必须是 JSON object",
                    path=f"{path}.properties.{name}",
                )
            _validate_schema_node(
                child,
                path=f"{path}.properties.{name}",
            )
        return

    object_only = {
        "properties",
        "required",
        "additionalProperties",
    }.intersection(schema)
    if object_only:
        raise ToolContractError(
            "schema_keyword_incompatible",
            (
                f"{declared_type} schema 不得声明："
                f"{', '.join(sorted(object_only))}"
            ),
            path=path,
        )

    if declared_type == "array":
        items = schema.get("items")
        if not isinstance(items, dict):
            raise ToolContractError(
                "schema_items_invalid",
                "array schema 必须显式声明 items schema",
                path=f"{path}.items",
            )
        _validate_schema_node(items, path=f"{path}.items")
    elif "items" in schema:
        raise ToolContractError(
            "schema_keyword_incompatible",
            f"{declared_type} schema 不得声明 items",
            path=f"{path}.items",
        )


def _validate_instance(
    value: Any,
    schema: Mapping[str, Any],
    *,
    path: str,
) -> None:
    declared_type = schema["type"]
    if not _matches_type(value, declared_type):
        raise ToolContractError(
            "type_mismatch",
            f"{path} 必须是 {declared_type}",
            path=path,
        )
    if "enum" in schema and not any(
        _json_equal(value, candidate)
        for candidate in schema["enum"]
    ):
        raise ToolContractError(
            "enum_mismatch",
            f"{path} 不在允许的 enum 中",
            path=path,
        )

    if declared_type == "object":
        properties = schema["properties"]
        required = schema.get("required", ())
        missing = sorted(set(required) - set(value))
        if missing:
            raise ToolContractError(
                "required_missing",
                f"{path} 缺少必填字段：{', '.join(missing)}",
                path=path,
            )
        unknown = sorted(set(value) - set(properties))
        if unknown:
            name = unknown[0]
            raise ToolContractError(
                "additional_property",
                f"{path} 包含未知字段：{', '.join(unknown)}",
                path=f"{path}.{name}",
            )
        for name, child_value in value.items():
            _validate_instance(
                child_value,
                properties[name],
                path=f"{path}.{name}",
            )
    elif declared_type == "array":
        for index, item in enumerate(value):
            _validate_instance(
                item,
                schema["items"],
                path=f"{path}[{index}]",
            )


def _matches_type(value: Any, declared_type: str) -> bool:
    if declared_type == "object":
        return isinstance(value, Mapping)
    if declared_type == "array":
        return isinstance(value, (list, tuple))
    if declared_type == "string":
        return isinstance(value, str)
    if declared_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if declared_type == "number":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and (not isinstance(value, float) or math.isfinite(value))
        )
    if declared_type == "boolean":
        return isinstance(value, bool)
    if declared_type == "null":
        return value is None
    return False


def _plain_json(value: Any, *, path: str) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ToolContractError(
                    "json_key_invalid",
                    "JSON object 的 key 必须是字符串",
                    path=path,
                )
            result[key] = _plain_json(
                item,
                path=f"{path}.{key}",
            )
        return result
    if isinstance(value, (list, tuple)):
        return [
            _plain_json(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise ToolContractError(
        "json_value_invalid",
        "值必须能无损表示为标准 JSON",
        path=path,
    )


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType(
            {
                key: _freeze(item)
                for key, item in value.items()
            },
        )
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _thaw(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _string_set(name: str, value: Iterable[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise ToolContractError(
            "string_list_invalid",
            f"{name} 必须是字符串集合",
            path=f"$.{name}",
        )
    normalized: set[str] = set()
    for item in value:
        normalized.add(_non_empty_text(name, item))
    return tuple(sorted(normalized))


def _enum_value(
    name: str,
    value: StrEnum | str,
    enum_type: type[StrEnum],
) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(item.value for item in enum_type)
        raise ToolContractError(
            f"{name}_invalid",
            f"{name} 必须是以下值之一：{allowed}",
            path=f"$.{name}",
        ) from exc


def _boolean(name: str, value: bool) -> bool:
    if type(value) is not bool:
        raise ToolContractError(
            "boolean_invalid",
            f"{name} 必须是 boolean",
            path=f"$.{name}",
        )
    return value


def _positive_number(name: str, value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ToolContractError(
            "positive_number_invalid",
            f"{name} 必须是有限正数",
            path=f"$.{name}",
        )
    return float(value)


def _positive_integer(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ToolContractError(
            "positive_integer_invalid",
            f"{name} 必须是正整数",
            path=f"$.{name}",
        )
    return value


def _action(value: str) -> str:
    normalized = _non_empty_text("action", value)
    if _ACTION_PATTERN.fullmatch(normalized) is None:
        raise ToolContractError(
            "action_invalid",
            "action 必须以小写字母开头，且只能包含字母、数字和分隔符 ._-",
            path="$.action",
        )
    return normalized


def _non_empty_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolContractError(
            "text_invalid",
            f"{name} 必须是非空字符串",
            path=f"$.{name}",
        )
    return value.strip()


def _sha256_text(name: str, value: str) -> str:
    normalized = _non_empty_text(name, value).lower()
    if _SHA256_PATTERN.fullmatch(normalized) is None:
        raise ToolContractError(
            "sha256_invalid",
            f"{name} 必须是 64 位十六进制 SHA-256",
            path=f"$.{name}",
        )
    return normalized


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        _canonical_json(value).encode("utf-8"),
    ).hexdigest()


def _json_equal(left: Any, right: Any) -> bool:
    return _canonical_json(_thaw(left)) == _canonical_json(_thaw(right))
