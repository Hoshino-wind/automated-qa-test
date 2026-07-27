#!/usr/bin/env python3
"""Knowledge Store 与可恢复 HITL 的独立人工控制入口。"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from qa_common import atomic_write_json, safe_output_path
from qa_core.hitl import (
    HITLDecision,
    HITLRequest,
    HITLStore,
    HITLStoreError,
    HumanControlContractError,
    HumanControlJournalError,
    HumanDecision,
    OperatorIdentity,
)
from qa_core.knowledge import (
    KnowledgeCandidate,
    KnowledgeStore,
    KnowledgeStoreError,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "管理人工确认知识与 hash-bound HITL 请求；"
            "本 CLI 不执行被审批的 action。"
        ),
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    knowledge_subject = subparsers.add_parser(
        "knowledge-write-subject",
        help="计算 Knowledge candidate 的审批 subject hash。",
    )
    _add_store(knowledge_subject)
    knowledge_subject.add_argument("--candidate", required=True)
    knowledge_subject.add_argument("--operator", required=True)
    _add_output(knowledge_subject)

    knowledge_write = subparsers.add_parser(
        "knowledge-write",
        help="使用 operator identity 与已绑定收据写入 Knowledge。",
    )
    _add_store(knowledge_write)
    knowledge_write.add_argument("--candidate", required=True)
    knowledge_write.add_argument("--operator", required=True)
    knowledge_write.add_argument("--receipt", required=True)
    _add_output(knowledge_write)

    revoke_subject = subparsers.add_parser(
        "knowledge-revoke-subject",
        help="计算明确 Knowledge version 的撤销审批 subject。",
    )
    _add_store(revoke_subject)
    _add_entry_version(revoke_subject)
    revoke_subject.add_argument("--operator", required=True)
    _add_output(revoke_subject)

    revoke = subparsers.add_parser(
        "knowledge-revoke",
        help="使用已绑定收据撤销明确 Knowledge version。",
    )
    _add_store(revoke)
    _add_entry_version(revoke)
    revoke.add_argument("--operator", required=True)
    revoke.add_argument("--receipt", required=True)
    _add_output(revoke)

    query = subparsers.add_parser(
        "knowledge-query",
        help="过滤过期、撤销、未来和越 scope 条目。",
    )
    _add_store(query)
    query.add_argument(
        "--scope",
        action="append",
        required=True,
        help="当前 scope token；可重复。",
    )
    _add_output(query)

    hitl_create = subparsers.add_parser(
        "hitl-create",
        help="创建或幂等恢复同一个 HITL request。",
    )
    _add_store(hitl_create)
    hitl_create.add_argument("--request", required=True)
    _add_output(hitl_create)

    hitl_subject = subparsers.add_parser(
        "hitl-decision-subject",
        help="校验 currentness 后计算 decision 审批 subject。",
    )
    _add_store(hitl_subject)
    hitl_subject.add_argument("--request-id", required=True)
    hitl_subject.add_argument("--decision-id", required=True)
    hitl_subject.add_argument(
        "--decision",
        required=True,
        choices=[item.value for item in HumanDecision],
    )
    hitl_subject.add_argument("--reason", required=True)
    hitl_subject.add_argument("--decided-at", required=True)
    hitl_subject.add_argument("--operator", required=True)
    _add_bindings(hitl_subject)
    _add_output(hitl_subject)

    hitl_decide = subparsers.add_parser(
        "hitl-decide",
        help="记录已审批、与当前绑定一致的终局 decision。",
    )
    _add_store(hitl_decide)
    hitl_decide.add_argument("--decision-file", required=True)
    _add_bindings(hitl_decide)
    _add_output(hitl_decide)

    hitl_resume = subparsers.add_parser(
        "hitl-resume",
        help="按 run/context/action hash 恢复 HITL request。",
    )
    _add_store(hitl_resume)
    hitl_resume.add_argument("--request-id", required=True)
    _add_bindings(hitl_resume)
    _add_output(hitl_resume)

    hitl_consume = subparsers.add_parser(
        "hitl-consume",
        help="一次性消费与当前绑定一致的 approved decision。",
    )
    _add_store(hitl_consume)
    hitl_consume.add_argument("--request-id", required=True)
    hitl_consume.add_argument("--consumption-id", required=True)
    _add_bindings(hitl_consume)
    _add_output(hitl_consume)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.out:
        protected = tuple(
            Path(value)
            for name in (
                "candidate",
                "operator",
                "receipt",
                "request",
                "decision_file",
                "trust_config",
                "checkpoint",
            )
            if (value := getattr(args, name, None))
        )
        try:
            args.out = str(
                safe_output_path(
                    Path(args.out),
                    protected_paths=protected,
                    protected_roots=(Path(args.store),),
                )
            )
        except ValueError as exc:
            result = {
                "schema_version": 1,
                "status": "error",
                "journal_assurance": {
                    "mode": args.journal_mode,
                    "checkpoint_required": (
                        args.journal_mode == "production"
                    ),
                    "production_ready": False,
                    "covered_count": None,
                    "current_count": None,
                    "tail_count": None,
                },
                "error": _error(exc),
            }
            print(
                json.dumps(result, ensure_ascii=False),
                file=sys.stderr,
            )
            return 1
    try:
        payload = _dispatch(args)
        result = {
            "schema_version": 1,
            "status": "ok",
            "journal_assurance": {
                "mode": args.journal_mode,
                "checkpoint_required": (
                    args.journal_mode == "production"
                ),
                "production_ready": (
                    args.journal_mode == "production"
                ),
                "covered_count": None,
                "current_count": None,
                "tail_count": None,
            },
            **payload,
        }
        _emit(result, args.out)
        return 0
    except (
        HumanControlContractError,
        HumanControlJournalError,
        KnowledgeStoreError,
        HITLStoreError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        result = {
            "schema_version": 1,
            "status": "error",
            "journal_assurance": _error_assurance(args, exc),
            "error": _error(exc),
        }
        _emit(result, getattr(args, "out", None))
        print(
            json.dumps(result, ensure_ascii=False),
            file=sys.stderr,
        )
        return 1


def _dispatch(args: argparse.Namespace) -> dict[str, Any]:
    if args.command.startswith("knowledge-"):
        approval_trust, checkpoint_trust = _read_trust_config(
            args.trust_config,
        )
        store = KnowledgeStore(
            Path(args.store),
            trusted_authority_keys=approval_trust,
            journal_mode=args.journal_mode,
            checkpoint_path=(
                Path(args.checkpoint)
                if args.checkpoint is not None
                else None
            ),
            trusted_checkpoint_keys=checkpoint_trust,
        )
        if args.command == "knowledge-write-subject":
            subject = store.write_subject_sha256(
                KnowledgeCandidate.from_dict(
                    _read_object(args.candidate),
                ),
                operator=OperatorIdentity.from_dict(
                    _read_object(args.operator),
                ),
            )
            return {
                "journal_assurance": store.journal_assurance,
                "subject_sha256": subject,
            }
        if args.command == "knowledge-write":
            entry = store.write(
                _read_object(args.candidate),
                operator=_read_object(args.operator),
                approval_receipt=_read_object(args.receipt),
            )
            return {
                "journal_assurance": store.journal_assurance,
                "entry": entry.to_dict(),
            }
        if args.command == "knowledge-revoke-subject":
            subject = store.revoke_subject_sha256(
                args.entry_id,
                args.version,
                operator=_read_object(args.operator),
            )
            return {
                "journal_assurance": store.journal_assurance,
                "subject_sha256": subject,
            }
        if args.command == "knowledge-revoke":
            entry = store.revoke(
                args.entry_id,
                args.version,
                operator=_read_object(args.operator),
                approval_receipt=_read_object(args.receipt),
            )
            return {
                "journal_assurance": store.journal_assurance,
                "entry": entry.to_dict(),
            }
        if args.command == "knowledge-query":
            entries = store.query(
                scope=args.scope,
            )
            return {
                "journal_assurance": store.journal_assurance,
                "entries": [entry.to_dict() for entry in entries],
            }

    if args.command.startswith("hitl-"):
        approval_trust, checkpoint_trust = _read_trust_config(
            args.trust_config,
        )
        store = HITLStore(
            Path(args.store),
            trusted_authority_keys=approval_trust,
            journal_mode=args.journal_mode,
            checkpoint_path=(
                Path(args.checkpoint)
                if args.checkpoint is not None
                else None
            ),
            trusted_checkpoint_keys=checkpoint_trust,
        )
        if args.command == "hitl-create":
            state = store.create_request(
                HITLRequest.from_dict(
                    _read_object(args.request),
                ),
            )
            return {
                "journal_assurance": store.journal_assurance,
                "hitl": state.to_dict(),
            }
        if args.command == "hitl-decision-subject":
            subject = store.decision_subject_sha256(
                args.request_id,
                decision_id=args.decision_id,
                decision=args.decision,
                reason=args.reason,
                decided_at=args.decided_at,
                operator=_read_object(args.operator),
                **_bindings(args),
            )
            return {
                "journal_assurance": store.journal_assurance,
                "subject_sha256": subject,
            }
        if args.command == "hitl-decide":
            state = store.record_decision(
                HITLDecision.from_dict(
                    _read_object(args.decision_file),
                ),
                **_bindings(args),
            )
            return {
                "journal_assurance": store.journal_assurance,
                "hitl": state.to_dict(),
            }
        if args.command == "hitl-resume":
            state = store.resume(
                args.request_id,
                **_bindings(args),
            )
            return {
                "journal_assurance": store.journal_assurance,
                "hitl": state.to_dict(),
            }
        if args.command == "hitl-consume":
            state = store.consume_approved(
                args.request_id,
                consumption_id=args.consumption_id,
                **_bindings(args),
            )
            return {
                "journal_assurance": store.journal_assurance,
                "hitl": state.to_dict(),
            }

    raise ValueError(f"未知 command：{args.command}")


def _bindings(args: argparse.Namespace) -> dict[str, str]:
    return {
        "expected_run_id": args.expected_run_id,
        "expected_lease_generation": args.expected_lease_generation,
        "expected_context_sha256": args.expected_context_sha256,
        "expected_action_sha256": args.expected_action_sha256,
        "expected_policy_sha256": args.expected_policy_sha256,
        "expected_authorization_sha256": (
            args.expected_authorization_sha256
        ),
    }


def _read_object(path: str) -> dict[str, Any]:
    source = Path(path)
    metadata = source.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"JSON 输入必须是普通文件：{path}")
    if metadata.st_nlink != 1:
        raise ValueError(f"JSON 输入 hard-link count 必须等于 1：{path}")
    if metadata.st_size > 1024 * 1024:
        raise ValueError(f"JSON 输入超过 1048576 bytes：{path}")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino)
            != (metadata.st_dev, metadata.st_ino)
        ):
            raise ValueError(f"JSON 输入在读取前被替换：{path}")
        chunks: list[bytes] = []
        remaining = 1024 * 1024 + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > 1024 * 1024:
            raise ValueError(f"JSON 输入超过 1048576 bytes：{path}")
        current = source.lstat()
        final_opened = os.fstat(descriptor)
        if (
            (current.st_dev, current.st_ino)
            != (metadata.st_dev, metadata.st_ino)
            or final_opened.st_size != len(raw)
        ):
            raise ValueError(f"JSON 输入在读取期间发生变化：{path}")
    finally:
        os.close(descriptor)
    value = _strict_json(raw.decode("utf-8"), path=path)
    if not isinstance(value, dict):
        raise ValueError(f"JSON 文件根必须是 object：{path}")
    return value


def _read_trust_config(
    path: str,
) -> tuple[
    dict[str, dict[str, str]],
    dict[str, dict[str, str]],
]:
    """严格读取 public-key allowlist；任何私钥字段都会被拒绝。"""

    value = _read_object(path)
    required = {"schema_version", "authorities"}
    allowed = {*required, "checkpoint_authorities"}
    if not required.issubset(value) or not set(value).issubset(allowed):
        raise ValueError(
            (
                "trust config 必须包含 schema_version/authorities，"
                "且只可附加 checkpoint_authorities"
            ),
        )
    if value["schema_version"] != 1:
        raise ValueError("trust config schema_version 必须等于 1")

    return (
        _parse_authorities(value["authorities"], field="authorities"),
        _parse_authorities(
            value.get("checkpoint_authorities", []),
            field="checkpoint_authorities",
            allow_empty=True,
        ),
    )


def _parse_authorities(
    authorities: Any,
    *,
    field: str,
    allow_empty: bool = False,
) -> dict[str, dict[str, str]]:
    if not isinstance(authorities, list) or not authorities:
        if allow_empty and authorities == []:
            return {}
        raise ValueError(f"trust config {field} 必须是非空 array")
    result: dict[str, dict[str, str]] = {}
    for index, authority_item in enumerate(authorities):
        if (
            not isinstance(authority_item, dict)
            or set(authority_item) != {"authority", "keys"}
        ):
            raise ValueError(
                f"trust config {field}[{index}] 字段非法",
            )
        authority = authority_item["authority"]
        keys = authority_item["keys"]
        if (
            not isinstance(authority, str)
            or not authority
            or authority in result
        ):
            raise ValueError(
                f"trust config {field}[{index}].authority 非法",
            )
        if not isinstance(keys, list) or not keys:
            raise ValueError(
                f"trust config {field}[{index}].keys 必须非空",
            )
        key_ring: dict[str, str] = {}
        for key_index, key_item in enumerate(keys):
            if (
                not isinstance(key_item, dict)
                or set(key_item)
                != {"key_id", "algorithm", "public_key_pem"}
            ):
                raise ValueError(
                    "trust config key 只允许 "
                    "key_id/algorithm/public_key_pem",
                )
            if key_item["algorithm"] != "Ed25519":
                raise ValueError("trust config algorithm 必须是 Ed25519")
            key_id = key_item["key_id"]
            public_key = key_item["public_key_pem"]
            if (
                not isinstance(key_id, str)
                or not key_id
                or key_id in key_ring
                or not isinstance(public_key, str)
                or "PRIVATE KEY" in public_key
            ):
                raise ValueError(
                    (
                        "trust config key 非法或包含私钥："
                        f"{field}[{index}].keys[{key_index}]"
                    ),
                )
            key_ring[key_id] = public_key
        result[authority] = key_ring
    return result


def _strict_json(raw: str, *, path: str) -> Any:
    def object_pairs(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"JSON 包含重复 key：{path}:{key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise ValueError(f"JSON 不允许非有限数：{path}:{value}")

    try:
        return json.loads(
            raw,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except RecursionError as exc:
        raise ValueError(f"JSON nesting 过深：{path}") from exc


def _emit(payload: dict[str, Any], output: str | None) -> None:
    if output:
        atomic_write_json(Path(output), payload)
        return
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def _error(exc: Exception) -> dict[str, Any]:
    if hasattr(exc, "to_dict"):
        return exc.to_dict()
    return {
        "schema_version": 1,
        "error": "human_control_cli_error",
        "code": "input_or_configuration_error",
        "message": str(exc),
    }


def _error_assurance(
    args: argparse.Namespace,
    exc: Exception,
) -> dict[str, Any]:
    covered_count = getattr(exc, "covered_count", None)
    current_count = getattr(exc, "current_count", None)
    tail_count = getattr(exc, "tail_count", None)
    return {
        "mode": args.journal_mode,
        "checkpoint_required": args.journal_mode == "production",
        "production_ready": False,
        "covered_count": covered_count,
        "current_count": current_count,
        "tail_count": tail_count,
    }


def _add_store(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--store",
        required=True,
        help="独立 Knowledge 或 HITL store directory。",
    )
    parser.add_argument(
        "--trust-config",
        required=True,
        help=(
            "authority→Ed25519 public-key allowlist JSON；"
            "CLI 不接受私钥。"
        ),
    )
    parser.add_argument(
        "--journal-mode",
        choices=("local-test", "production"),
        default="local-test",
        help=(
            "默认 local-test 并在输出中标记非生产；production "
            "必须同时提供受信 --checkpoint。"
        ),
    )
    parser.add_argument(
        "--checkpoint",
        help="外部 checkpoint authority 签名的只读 checkpoint JSON。",
    )


def _add_output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--out")


def _add_entry_version(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--entry-id", required=True)
    parser.add_argument("--version", required=True, type=int)


def _add_bindings(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument(
        "--expected-lease-generation",
        required=True,
        type=int,
    )
    parser.add_argument("--expected-context-sha256", required=True)
    parser.add_argument("--expected-action-sha256", required=True)
    parser.add_argument("--expected-policy-sha256", required=True)
    parser.add_argument("--expected-authorization-sha256", required=True)


if __name__ == "__main__":
    raise SystemExit(main())
