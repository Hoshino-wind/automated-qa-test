#!/usr/bin/env python3
"""从独立 JSON 配置加载可选项目 Adapter，通用脚本不保存项目路径。"""

import json
from pathlib import Path
from typing import Any

ADAPTER_DIR = Path(__file__).resolve().parent.parent / "references" / "adapters"


def adapter_definitions() -> list[dict[str, Any]]:
    definitions: list[dict[str, Any]] = []
    if not ADAPTER_DIR.is_dir():
        return definitions
    for path in sorted(ADAPTER_DIR.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("schema_version") == 1 and value.get("id"):
            definitions.append({**value, "definition_path": str(path)})
    return definitions


def get_adapter_definition(adapter_id: str | None) -> dict[str, Any] | None:
    return next((item for item in adapter_definitions() if item.get("id") == adapter_id), None)


def detect_adapter_id(project_root: Path) -> str:
    for definition in adapter_definitions():
        markers = [str(item) for item in definition.get("markers", []) if str(item)]
        if markers and all((project_root / marker).exists() for marker in markers):
            return str(definition["id"])
    return "generic"
