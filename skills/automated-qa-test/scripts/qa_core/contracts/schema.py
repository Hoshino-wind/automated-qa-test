"""使用仓库内 JSON Schema 执行基础运行时契约校验。"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

SCHEMA_ROOT = Path(__file__).resolve().parents[3] / "references" / "schemas"
SCHEMA_FILENAMES = {
    "plan": "test-plan.schema.json",
    "matrix": "test-matrix.schema.json",
    "results": "results.schema.json",
    "ledger": "evidence-ledger.schema.json",
}


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict[str, Any]:
    filename = SCHEMA_FILENAMES.get(name)
    if not filename:
        raise KeyError(f"Unknown artifact schema: {name}")
    value = json.loads((SCHEMA_ROOT / filename).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Schema root must be an object: {filename}")
    return value


def _type_matches(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, True)


def _validate(value: Any, schema: dict[str, Any], path: str, errors: list[str]) -> None:
    expected_type = schema.get("type")
    if isinstance(expected_type, str) and not _type_matches(value, expected_type):
        errors.append(f"{path} must be {expected_type}; got {type(value).__name__}")
        return
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path} must equal {schema['const']!r}; got {value!r}")
    if isinstance(value, str) and isinstance(schema.get("minLength"), int) and len(value) < schema["minLength"]:
        errors.append(f"{path} must contain at least {schema['minLength']} characters")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}.{key} is required")
        properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        for key, child_schema in properties.items():
            if key in value and isinstance(child_schema, dict):
                _validate(value[key], child_schema, f"{path}.{key}", errors)
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(value):
            _validate(item, schema["items"], f"{path}[{index}]", errors)


def validate_artifact_schema(name: str, value: Any) -> list[str]:
    errors: list[str] = []
    try:
        schema = load_schema(name)
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        return [f"{name} schema is unavailable: {exc}"]
    _validate(value, schema, name, errors)
    return errors
