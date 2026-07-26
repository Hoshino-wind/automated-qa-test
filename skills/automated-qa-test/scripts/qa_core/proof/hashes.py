"""Proof graph 使用的规范哈希与缺失输入哨兵。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from qa_common import file_sha256


def canonical_json_sha256(value: Any) -> str:
    """对 JSON 值执行排序、无空白且拒绝 NaN 的 SHA-256。"""

    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def input_file_sha256(name: str, path: Path) -> str:
    """文件缺失也产生稳定父哈希，避免后创建输入复活旧证明。"""

    digest = file_sha256(path)
    if digest is not None:
        return digest
    return canonical_json_sha256(
        {
            "name": name,
            "status": "missing",
        }
    )
