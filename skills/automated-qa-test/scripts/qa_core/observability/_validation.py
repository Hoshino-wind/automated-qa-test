"""可观测性契约共用的严格校验与规范哈希。"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime
from typing import Any, Mapping, TypeVar

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_T = TypeVar("_T")


class ObservabilityError(ValueError):
    """Trace 或 SLO 输入不可信时的结构化错误。"""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, object] | None = None,
    ) -> None:
        self.code = code
        self.details = dict(details or {})
        super().__init__(message)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "error": "observability_contract_error",
            "code": self.code,
            "message": str(self),
            "details": dict(self.details),
        }


def exact_object(
    path: str,
    value: object,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    payload = object_value(path, value)
    allowed = required | (optional or set())
    missing = sorted(required - set(payload))
    unknown = sorted(set(payload) - allowed)
    if missing:
        raise ObservabilityError(
            "schema_fields_missing",
            f"{path} 缺少字段：{', '.join(missing)}",
            details={"path": path, "missing": missing},
        )
    if unknown:
        raise ObservabilityError(
            "schema_unknown_fields",
            f"{path} 包含未知字段：{', '.join(unknown)}",
            details={"path": path, "unknown": unknown},
        )
    return payload


def object_value(path: str, value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ObservabilityError("schema_type_invalid", f"{path} 必须是对象")
    return value


def list_value(path: str, value: object) -> list[Any]:
    if not isinstance(value, list):
        raise ObservabilityError("schema_type_invalid", f"{path} 必须是数组")
    return value


def text(path: str, value: object) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ObservabilityError(
            "schema_text_invalid",
            f"{path} 必须是无首尾空白的非空字符串",
        )
    return value


def nullable_text(path: str, value: object) -> str | None:
    return None if value is None else text(path, value)


def boolean(path: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise ObservabilityError("schema_boolean_invalid", f"{path} 必须是布尔值")
    return value


def integer(path: str, value: object, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ObservabilityError(
            "schema_integer_invalid",
            f"{path} 必须是大于等于 {minimum} 的整数",
        )
    return value


def number(path: str, value: object, *, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ObservabilityError("schema_number_invalid", f"{path} 必须是数值")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < minimum:
        raise ObservabilityError(
            "schema_number_invalid",
            f"{path} 必须是有限且大于等于 {minimum} 的数值",
        )
    return normalized


def optional_number(
    path: str,
    value: object,
    *,
    minimum: float = 0.0,
) -> float | None:
    return None if value is None else number(path, value, minimum=minimum)


def optional_integer(
    path: str,
    value: object,
    *,
    minimum: int = 0,
) -> int | None:
    return None if value is None else integer(path, value, minimum=minimum)


def choice(path: str, value: object, choices: set[str]) -> str:
    normalized = text(path, value)
    if normalized not in choices:
        raise ObservabilityError(
            "schema_choice_invalid",
            f"{path} 必须是：{', '.join(sorted(choices))}",
        )
    return normalized


def sha256(path: str, value: object) -> str:
    normalized = text(path, value)
    if not _SHA256_PATTERN.fullmatch(normalized):
        raise ObservabilityError(
            "schema_sha256_invalid",
            f"{path} 必须是小写 SHA-256",
        )
    return normalized


def timestamp(path: str, value: object) -> tuple[str, datetime]:
    normalized = text(path, value)
    candidate = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise ObservabilityError(
            "schema_timestamp_invalid",
            f"{path} 必须是带时区的 ISO 8601 时间",
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ObservabilityError(
            "schema_timestamp_invalid",
            f"{path} 必须包含时区",
        )
    return normalized, parsed


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
