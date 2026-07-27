#!/usr/bin/env python3
"""对候选探针执行确定性 Critic 排序，不签发执行授权。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from qa_common import (
    StableFileReadError,
    atomic_write_json,
    read_stable_regular_file,
    safe_output_path,
)
from qa_core.planning import (
    CriticContractError,
    CriticRequest,
    DeterministicProbeCritic,
)

MAX_REQUEST_BYTES = 1_048_576


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "按信息增益、缺陷风险、冲突、成本"
            "与历史进展排序候选探针；"
            "输出不是执行授权。"
        )
    )
    parser.add_argument(
        "--request",
        required=True,
        help="严格 Critic request JSON 文件。",
    )
    parser.add_argument("--out", help="可选的原子写入结果路径。")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.out:
        try:
            args.out = str(
                safe_output_path(
                    Path(args.out),
                    protected_paths=(Path(args.request),),
                )
            )
        except (OSError, ValueError) as exc:
            print(
                json.dumps(
                    {
                        "schema_version": 1,
                        "status": "error",
                        "not_authorization": True,
                        "error": _error_payload(exc),
                    },
                    ensure_ascii=False,
                ),
                file=sys.stderr,
            )
            return 1
    try:
        payload = _read_object(Path(args.request))
        request = CriticRequest.from_dict(payload)
        result = DeterministicProbeCritic().rank(request)
        output = {
            "schema_version": 1,
            "status": "ok",
            **result.to_dict(),
        }
        _emit(output, args.out)
        return 0
    except (
        CriticContractError,
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        output = {
            "schema_version": 1,
            "status": "error",
            "not_authorization": True,
            "error": _error_payload(exc),
        }
        try:
            _emit(output, args.out)
        except (OSError, ValueError):
            pass
        print(
            json.dumps(
                output,
                ensure_ascii=False,
                allow_nan=False,
            ),
            file=sys.stderr,
        )
        return 1


def _read_object(path: Path) -> dict[str, Any]:
    try:
        raw = read_stable_regular_file(
            path,
            max_bytes=MAX_REQUEST_BYTES,
        )
    except FileNotFoundError as exc:
        raise CriticContractError(
            "request_missing",
            f"Critic request 文件不存在：{path}",
            path="$.request",
        ) from exc
    except StableFileReadError as exc:
        code = {
            "symlink_rejected": "request_symlink_rejected",
            "not_regular_file": "request_not_regular_file",
            "hardlink_rejected": "request_hardlink_rejected",
            "too_large": "request_too_large",
            "changed": "request_changed",
        }.get(exc.code, "request_unreadable")
        raise CriticContractError(
            code,
            str(exc),
            path="$.request",
        ) from exc
    value = json.loads(
        raw.decode("utf-8"),
        parse_constant=_reject_nonfinite_json,
        object_pairs_hook=_reject_duplicate_keys,
    )
    if not isinstance(value, dict):
        raise CriticContractError(
            "request_not_object",
            "Critic request 根必须是 JSON object",
        )
    return value


def _reject_nonfinite_json(value: str) -> None:
    raise CriticContractError(
        "json_number_nonfinite",
        f"JSON 不允许非有限数值：{value}",
    )


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise CriticContractError(
                "json_duplicate_key",
                f"JSON object 包含重复字段：{key}",
            )
        payload[key] = value
    return payload


def _emit(payload: dict[str, Any], output: str | None) -> None:
    if output:
        atomic_write_json(Path(output), payload)
        return
    print(
        json.dumps(
            payload,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
    )


def _error_payload(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, CriticContractError):
        return exc.to_dict()
    return {
        "schema_version": 1,
        "error": "agent_critic_cli_error",
        "code": "input_error",
        "path": "$",
        "message": str(exc),
    }


if __name__ == "__main__":
    raise SystemExit(main())
