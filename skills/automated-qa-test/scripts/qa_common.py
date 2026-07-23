#!/usr/bin/env python3
"""QA 辅助脚本共享的安全文件与契约工具。"""

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

SUPPORTED_SCHEMA_VERSION = 2


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """在目标同目录写临时文件，再原子替换，避免中断留下半截 JSON。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding=encoding) as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, ensure_ascii=False))


def file_sha256(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def schema_version_error(value: Any, *, field: str, artifact: str) -> str | None:
    if value != SUPPORTED_SCHEMA_VERSION:
        return f"{artifact}.{field} must equal supported major version {SUPPORTED_SCHEMA_VERSION}; got {value!r}."
    return None


def manual_evidence_manifest_errors(manifest: dict[str, Any] | None, required_evidence_ids: set[str]) -> list[str]:
    if not isinstance(manifest, dict):
        return ["manual evidence manifest must be a JSON object"]
    errors: list[str] = []
    if manifest.get("schema_version") != 1:
        errors.append("manual evidence manifest schema_version must equal 1")
    if manifest.get("mode") != "manual":
        errors.append("manual evidence manifest mode must equal 'manual'")
    for field in ("operator", "observed_at", "statement"):
        if not isinstance(manifest.get(field), str) or not str(manifest.get(field)).strip():
            errors.append(f"manual evidence manifest {field} must be non-empty text")
    declared = {
        str(item).strip()
        for item in manifest.get("evidence_ids", [])
        if isinstance(item, str) and item.strip()
    } if isinstance(manifest.get("evidence_ids"), list) else set()
    missing = sorted(required_evidence_ids - declared)
    if missing:
        errors.append(f"manual evidence manifest is missing passed evidence ids: {', '.join(missing)}")
    return errors
