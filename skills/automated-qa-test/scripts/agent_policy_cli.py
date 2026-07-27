#!/usr/bin/env python3
"""验证模型 proposal、签发策略授权或独立验签。"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from qa_common import (
    StableFileReadError,
    atomic_write_json,
    read_stable_regular_file,
    safe_output_path,
)
from qa_core.agent import (
    AgentContractError,
    DeterministicPolicyEngine,
    ExecutionAuthorization,
    PlanProposal,
    PolicyContractError,
)
from qa_core.runtime import RunBudget
from qa_core.tools import (
    RiskClass,
    ToolContractError,
    build_default_tool_registry,
)

DEFAULT_HMAC_KEY_ENV = "QA_POLICY_HMAC_KEY"
DEFAULT_POLICY_VERSION = "qa-default-policy@1"
MAX_POLICY_INPUT_BYTES = 4 * 1024 * 1024


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "在任何工具执行前验证 proposal、策略边界和 HMAC 授权。"
        ),
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    registry = subparsers.add_parser(
        "registry",
        help="输出默认 Tool Registry manifest 与规范哈希。",
    )
    registry.add_argument("--out")

    validate = subparsers.add_parser(
        "validate",
        help="验证 proposal，并在所有策略门通过后签发授权。",
    )
    _add_proposal_binding_args(validate)
    validate.add_argument(
        "--grant",
        action="append",
        default=[],
        help="显式授予的权限；可重复。",
    )
    validate.add_argument(
        "--max-risk",
        choices=[item.value for item in RiskClass],
        default=RiskClass.LOW.value,
    )
    validate.add_argument(
        "--total-timeout",
        type=float,
        default=60.0,
    )
    validate.add_argument(
        "--max-probes",
        type=int,
        default=1,
    )
    validate.add_argument(
        "--max-output-bytes",
        type=int,
        default=1_048_576,
    )
    validate.add_argument(
        "--authorization-ttl",
        type=float,
        default=30.0,
    )
    validate.add_argument(
        "--hmac-key-env",
        default=DEFAULT_HMAC_KEY_ENV,
        help="保存 HMAC key 的环境变量名；key 不接受命令行传值。",
    )
    validate.add_argument("--out")

    verify = subparsers.add_parser(
        "verify",
        help="由执行器边界独立验证已有授权。",
    )
    _add_proposal_binding_args(verify)
    verify.add_argument(
        "--authorization-file",
        required=True,
    )
    verify.add_argument(
        "--hmac-key-env",
        default=DEFAULT_HMAC_KEY_ENV,
    )
    verify.add_argument("--out")
    return parser


def _add_proposal_binding_args(
    parser: argparse.ArgumentParser,
) -> None:
    parser.add_argument("--proposal", required=True)
    parser.add_argument("--probe-id", required=True)
    parser.add_argument(
        "--context-sha256",
        required=True,
    )
    parser.add_argument(
        "--state-sha256",
        required=True,
    )
    parser.add_argument(
        "--model-id",
        required=True,
        help="受信调用边界选择的精确模型/版本标识。",
    )
    parser.add_argument(
        "--evidence-ref",
        action="append",
        required=True,
        help="允许模型引用的已注入证据标识；可重复。",
    )
    parser.add_argument(
        "--policy-version",
        default=DEFAULT_POLICY_VERSION,
    )
    parser.add_argument(
        "--now",
        type=float,
        help="仅用于可重放评测；省略时使用当前 Unix 时间。",
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    requested_output = getattr(args, "out", None)
    args.out = None
    try:
        if requested_output:
            protected = [
                Path(value)
                for name in ("proposal", "authorization_file")
                if (value := getattr(args, name, None))
            ]
            args.out = str(
                safe_output_path(
                    Path(requested_output),
                    protected_paths=tuple(protected),
                )
            )
        if args.command == "registry":
            return _registry_command(args)
        if args.command == "validate":
            return _validate_command(args)
        if args.command == "verify":
            return _verify_command(args)
        raise PolicyContractError(
            "command_unknown",
            f"未知子命令：{args.command}",
        )
    except (
        AgentContractError,
        ToolContractError,
        PolicyContractError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        payload = _error_payload(exc)
        _emit(payload, getattr(args, "out", None))
        print(
            json.dumps(payload, ensure_ascii=False),
            file=sys.stderr,
        )
        return 1


def _registry_command(args: argparse.Namespace) -> int:
    registry = build_default_tool_registry()
    payload = {
        "schema_version": 1,
        "status": "ok",
        "tool_registry_sha256": registry.canonical_sha256,
        "manifest": registry.to_manifest(),
    }
    _emit(payload, args.out)
    return 0


def _validate_command(args: argparse.Namespace) -> int:
    registry = build_default_tool_registry()
    proposal = PlanProposal.from_model_input(
        _read_object(Path(args.proposal), name="proposal"),
        registry=registry,
        expected_model_id=args.model_id,
        allowed_evidence_refs=tuple(args.evidence_ref),
    )
    clock = _clock(args.now)
    budget = RunBudget(
        total_timeout=args.total_timeout,
        max_probes=args.max_probes,
        max_output_bytes=args.max_output_bytes,
        clock=clock,
    )
    engine = DeterministicPolicyEngine(
        registry=registry,
        hmac_key=_hmac_key_from_env(args.hmac_key_env),
        policy_version=args.policy_version,
        max_risk_class=args.max_risk,
        authorization_ttl_seconds=args.authorization_ttl,
        clock=clock,
    )
    decision = engine.decide(
        proposal,
        probe_id=args.probe_id,
        expected_context_sha256=args.context_sha256,
        expected_state_sha256=args.state_sha256,
        budget=budget,
        granted_authorizations=tuple(args.grant),
    )
    payload = {
        "schema_version": 1,
        "status": "allowed" if decision.allowed else "rejected",
        "tool_registry_sha256": registry.canonical_sha256,
        "plan_sha256": proposal.canonical_sha256,
        "probe_id": args.probe_id,
        "decision": decision.to_dict(),
    }
    _emit(payload, args.out)
    return 0 if decision.allowed else 2


def _verify_command(args: argparse.Namespace) -> int:
    registry = build_default_tool_registry()
    proposal = PlanProposal.from_model_input(
        _read_object(Path(args.proposal), name="proposal"),
        registry=registry,
        expected_model_id=args.model_id,
        allowed_evidence_refs=tuple(args.evidence_ref),
    )
    probe = proposal.find_probe(args.probe_id)
    authorization = ExecutionAuthorization.from_dict(
        _read_object(
            Path(args.authorization_file),
            name="authorization",
        ),
    )
    spec = registry.validate_invocation(probe.invocation)
    now = args.now if args.now is not None else time.time()
    verified = authorization.verify(
        hmac_key=_hmac_key_from_env(args.hmac_key_env),
        invocation=probe.invocation,
        context_sha256=args.context_sha256,
        state_sha256=args.state_sha256,
        tool_registry_sha256=registry.canonical_sha256,
        plan_sha256=proposal.canonical_sha256,
        probe_sha256=probe.canonical_sha256,
        policy_version=args.policy_version,
        now=now,
        executor_version=spec.executor_version,
    )
    payload = {
        "schema_version": 1,
        "status": "verified" if verified else "rejected",
        "verified": verified,
        "authorization_id": authorization.authorization_id,
        "tool_registry_sha256": registry.canonical_sha256,
        "plan_sha256": proposal.canonical_sha256,
        "probe_sha256": probe.canonical_sha256,
    }
    _emit(payload, args.out)
    return 0 if verified else 2


def _clock(
    fixed_now: float | None,
) -> Callable[[], float]:
    if fixed_now is None:
        return time.time
    return lambda: fixed_now


def _hmac_key_from_env(name: str) -> bytes:
    if not isinstance(name, str) or not name.strip():
        raise PolicyContractError(
            "hmac_key_env_invalid",
            "hmac_key 环境变量名不能为空",
        )
    value = os.environ.get(name)
    if value is None:
        raise PolicyContractError(
            "hmac_key_missing",
            f"环境变量 {name} 未设置",
        )
    return value.encode("utf-8")


def _read_object(path: Path, *, name: str) -> dict[str, Any]:
    try:
        raw = read_stable_regular_file(
            path,
            max_bytes=MAX_POLICY_INPUT_BYTES,
        )
    except FileNotFoundError as exc:
        raise PolicyContractError(
            f"{name}_missing",
            f"{name} 文件不存在：{path}",
        ) from exc
    except StableFileReadError as exc:
        raise PolicyContractError(
            f"{name}_{exc.code}",
            str(exc),
            path=f"$.{name}",
        ) from exc
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=lambda pairs: _object_without_duplicates(
            pairs,
            name=name,
        ),
        parse_constant=lambda constant: _reject_nonfinite(
            constant,
            name=name,
        ),
    )
    if not isinstance(value, dict):
        raise PolicyContractError(
            f"{name}_not_object",
            f"{name} 文件根必须是 JSON object",
        )
    return value


def _object_without_duplicates(
    pairs: list[tuple[str, Any]],
    *,
    name: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyContractError(
                f"{name}_duplicate_key",
                f"{name} JSON 包含重复字段：{key}",
                path=f"$.{name}.{key}",
            )
        result[key] = value
    return result


def _reject_nonfinite(value: str, *, name: str) -> None:
    raise PolicyContractError(
        f"{name}_nonfinite_number",
        f"{name} JSON 不允许非有限数：{value}",
        path=f"$.{name}",
    )


def _emit(payload: dict[str, Any], output: str | None) -> None:
    if output:
        atomic_write_json(Path(output), payload)
        return
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def _error_payload(exc: Exception) -> dict[str, Any]:
    if hasattr(exc, "to_dict"):
        detail = exc.to_dict()
    else:
        detail = {
            "schema_version": 1,
            "error": "agent_policy_cli_error",
            "code": "input_or_configuration_error",
            "message": str(exc),
        }
    return {
        "schema_version": 1,
        "status": "error",
        "error": detail,
    }


if __name__ == "__main__":
    raise SystemExit(main())
