#!/usr/bin/env python3
"""生成不具备执行权限的安全探针组合与批次建议。"""

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
from qa_core.scheduling import (
    ScheduleRequest,
    SchedulingContractError,
    build_probe_schedule,
)

MAX_REQUEST_BYTES = 1_048_576


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "在共享预算内选择已通过策略的候选动作；"
            "输出只是一份调度建议，不是执行授权。"
        ),
    )
    parser.add_argument(
        "--request",
        required=True,
        help="严格 JSON 调度请求。",
    )
    parser.add_argument("--out")
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
                    _error_payload(exc),
                    ensure_ascii=False,
                    allow_nan=False,
                ),
                file=sys.stderr,
            )
            return 1
    try:
        request = ScheduleRequest.from_dict(
            _read_object(Path(args.request)),
        )
        schedule = build_probe_schedule(request)
        payload = {
            "schema_version": 1,
            "status": "advice_ready",
            "not_authorization": True,
            "admission_allowed": False,
            "schedule": schedule.to_dict(),
        }
        _emit(payload, args.out)
        return 0
    except (
        SchedulingContractError,
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        payload = _error_payload(exc)
        try:
            _emit(payload, args.out)
        except (OSError, ValueError):
            pass
        print(
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
            ),
            file=sys.stderr,
        )
        if (
            isinstance(exc, SchedulingContractError)
            and exc.code == "budget_insufficient"
        ):
            return 2
        return 1


def _read_object(path: Path) -> dict[str, Any]:
    try:
        raw = read_stable_regular_file(
            path,
            max_bytes=MAX_REQUEST_BYTES,
        )
    except FileNotFoundError as exc:
        raise SchedulingContractError(
            "request_missing",
            f"request 文件不存在：{path}",
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
        raise SchedulingContractError(
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
        raise SchedulingContractError(
            "request_not_object",
            "request 文件根必须是 JSON object",
        )
    return value


def _reject_nonfinite_json(value: str) -> None:
    raise SchedulingContractError(
        "json_number_nonfinite",
        f"JSON 不允许非有限数值：{value}",
    )


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise SchedulingContractError(
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
        ),
    )


def _error_payload(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, SchedulingContractError):
        detail = exc.to_dict()
    else:
        detail = {
            "schema_version": 1,
            "error": "agent_schedule_cli_error",
            "code": "input_error",
            "message": str(exc),
        }
    return {
        "schema_version": 1,
        "status": "error",
        "not_authorization": True,
        "error": detail,
    }


if __name__ == "__main__":
    raise SystemExit(main())
