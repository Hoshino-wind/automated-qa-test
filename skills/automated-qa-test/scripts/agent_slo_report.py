#!/usr/bin/env python3
"""从 proof roots 生成生产 SLO 门，或从 trace 生成分析报告。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Sequence

from qa_common import atomic_write_json, safe_output_path
from qa_core.observability import (
    ObservabilityError,
    SloSamplingContract,
    SloThresholds,
    TraceJournal,
    TraceRecord,
    aggregate_run_directories,
    aggregate_slo,
)

_MAX_TRACE_INPUTS = 32
_MAX_TRACE_CORPUS_BYTES = 256 * 1024 * 1024
_MAX_TRACE_RECORDS = 100_000
_MAX_THRESHOLDS_BYTES = 1024 * 1024
_MAX_CANDIDATE_IDENTITY_BYTES = 64 * 1024
_MAX_SAMPLING_CONTRACT_BYTES = 64 * 1024


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "从 proof-verified run roots 生成生产 SLO 门，或从 trace 生成"
            "不可用于生产资格的分析报告。"
        ),
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--trace",
        action="append",
        help=(
            "可重复提供的 trace JSONL；该模式只生成 "
            "synthetic_or_unverified 分析报告。"
        ),
    )
    source.add_argument(
        "--run-dir",
        action="append",
        help=(
            "可重复提供的 QA run directory；生产资格唯一入口，"
            "每个 root 都会现场调用 verify_run_proof，并只接受独立闭合的 "
            "success、failure 或 cancellation_or_timeout outcome。"
        ),
    )
    parser.add_argument("--thresholds", help="可选的完整 SLO 阈值 JSON 对象。")
    parser.add_argument(
        "--candidate-identity",
        help=(
            "run-dir 模式必需；完整 candidate identity JSON，且每个 proof "
            "必须独立绑定同一对象。"
        ),
    )
    parser.add_argument(
        "--sampling-contract",
        help="run-dir 模式必需；预注册的生产或显式 development 样本合同。",
    )
    parser.add_argument("--out", required=True, help="报告 JSON 输出路径。")
    args = parser.parse_args(argv)
    protected = [Path(value) for value in (args.trace or [])]
    if args.thresholds:
        protected.append(Path(args.thresholds))
    if args.candidate_identity:
        protected.append(Path(args.candidate_identity))
    if args.sampling_contract:
        protected.append(Path(args.sampling_contract))
    try:
        output_path = safe_output_path(
            Path(args.out),
            protected_paths=tuple(protected),
            protected_roots=tuple(
                Path(value)
                for value in (args.run_dir or [])
            ),
        )
    except ValueError as error:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "error": "observability_output_boundary_error",
                    "message": str(error),
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 2
    try:
        thresholds = SloThresholds()
        threshold_hashes: dict[str, str] = {}
        parsed_input_paths: list[Path] = []
        if args.thresholds:
            threshold_path, raw_thresholds = _read_bounded_regular_file(
                Path(args.thresholds),
                maximum_bytes=_MAX_THRESHOLDS_BYTES,
                label="thresholds",
            )
            value = json.loads(
                raw_thresholds,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite_constant,
            )
            thresholds = SloThresholds.from_dict(value)
            parsed_input_paths.append(threshold_path)
            threshold_hashes[f"thresholds:{threshold_path}"] = hashlib.sha256(
                raw_thresholds
            ).hexdigest()
        if args.run_dir:
            if not args.candidate_identity or not args.sampling_contract:
                raise ObservabilityError(
                    "slo_production_inputs_missing",
                    (
                        "--run-dir requires --candidate-identity and "
                        "--sampling-contract"
                    ),
                )
            identity_path, identity_value, _ = _read_json_object(
                Path(args.candidate_identity),
                maximum_bytes=_MAX_CANDIDATE_IDENTITY_BYTES,
                label="candidate_identity",
            )
            (
                sampling_path,
                sampling_value,
                _,
            ) = _read_json_object(
                Path(args.sampling_contract),
                maximum_bytes=_MAX_SAMPLING_CONTRACT_BYTES,
                label="sampling_contract",
            )
            parsed_input_paths.extend((identity_path, sampling_path))
            if len(parsed_input_paths) != len(set(parsed_input_paths)):
                raise ObservabilityError(
                    "slo_input_alias_rejected",
                    "threshold、candidate identity 与 sampling contract 不得 alias",
                )
            sampling_contract = SloSamplingContract.from_dict(
                sampling_value
            )
            report = aggregate_run_directories(
                args.run_dir,
                thresholds=thresholds,
                additional_input_hashes=threshold_hashes,
                expected_candidate_identity=identity_value,
                sampling_contract=sampling_contract,
            )
        else:
            records, trace_hashes = _read_trace_corpus(args.trace or [])
            report = aggregate_slo(
                records,
                input_hashes={**trace_hashes, **threshold_hashes},
                thresholds=thresholds,
            )
    except (
        ObservabilityError,
        json.JSONDecodeError,
        OSError,
        UnicodeDecodeError,
    ) as error:
        payload = (
            error.to_dict()
            if isinstance(error, ObservabilityError)
            else {
                "schema_version": 1,
                "error": "observability_input_error",
                "message": str(error),
            }
        )
        atomic_write_json(output_path, payload)
        print(output_path)
        print(str(error), file=sys.stderr)
        return 2
    atomic_write_json(output_path, report)
    print(output_path)
    return 0 if report["qualified"] else 1


def _read_trace_corpus(
    raw_paths: Sequence[str],
) -> tuple[list[TraceRecord], dict[str, str]]:
    if not raw_paths:
        raise ObservabilityError(
            "slo_trace_paths_empty",
            "trace-only 分析至少需要一个 --trace",
        )
    if len(raw_paths) > _MAX_TRACE_INPUTS:
        raise ObservabilityError(
            "slo_trace_path_limit_exceeded",
            "--trace 数量超过上限",
            details={
                "maximum_trace_inputs": _MAX_TRACE_INPUTS,
                "observed_trace_inputs": len(raw_paths),
            },
        )
    journals = [TraceJournal(value) for value in raw_paths]
    trace_paths = [journal.path for journal in journals]
    if len(trace_paths) != len(set(trace_paths)):
        raise ObservabilityError(
            "slo_trace_path_duplicate",
            "--trace 不得重复或通过 alias 指向同一文件",
        )
    records: list[TraceRecord] = []
    input_hashes: dict[str, str] = {}
    total_bytes = 0
    for journal in sorted(journals, key=lambda item: str(item.path)):
        path = journal.path
        if not path.exists():
            raise ObservabilityError(
                "slo_trace_missing",
                f"trace journal 不存在：{path}",
            )
        snapshot = journal.snapshot()
        total_bytes += snapshot.byte_size
        if total_bytes > _MAX_TRACE_CORPUS_BYTES:
            raise ObservabilityError(
                "slo_trace_corpus_too_large",
                "trace-only corpus 超过字节上限",
                details={
                    "maximum_bytes": _MAX_TRACE_CORPUS_BYTES,
                    "observed_bytes": total_bytes,
                },
            )
        records.extend(snapshot.records)
        if len(records) > _MAX_TRACE_RECORDS:
            raise ObservabilityError(
                "slo_trace_record_limit_exceeded",
                "trace-only corpus record 数超过上限",
                details={
                    "maximum_records": _MAX_TRACE_RECORDS,
                    "observed_records": len(records),
                },
            )
        input_hashes[f"trace:{path}"] = snapshot.sha256
    return records, input_hashes


def _read_bounded_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
    label: str,
) -> tuple[Path, bytes]:
    candidate = path.expanduser()
    parent = candidate.parent.resolve(strict=True)
    resolved = parent / candidate.name
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(resolved, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ObservabilityError(
                "slo_input_not_regular",
                f"{label} 必须是普通文件：{resolved}",
            )
        if before.st_nlink != 1:
            raise ObservabilityError(
                "slo_input_hardlink_rejected",
                f"{label} 不得存在硬链接 alias：{resolved}",
            )
        if before.st_size > maximum_bytes:
            raise ObservabilityError(
                "slo_input_too_large",
                f"{label} 超过字节上限",
                details={
                    "maximum_bytes": maximum_bytes,
                    "observed_bytes": before.st_size,
                },
            )
        payload = b""
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(payload))
            if not chunk:
                raise ObservabilityError(
                    "slo_input_truncated",
                    f"{label} 读取时意外截断",
                )
            payload += chunk
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise ObservabilityError(
                "slo_input_changed",
                f"{label} 在读取期间发生变化",
            )
    finally:
        os.close(descriptor)
    return resolved, payload


def _read_json_object(
    path: Path,
    *,
    maximum_bytes: int,
    label: str,
) -> tuple[Path, dict[str, object], str]:
    resolved, raw = _read_bounded_regular_file(
        path,
        maximum_bytes=maximum_bytes,
        label=label,
    )
    value = json.loads(
        raw,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_nonfinite_constant,
    )
    if not isinstance(value, dict):
        raise ObservabilityError(
            "slo_input_object_required",
            f"{label} 必须是 JSON 对象",
        )
    return resolved, value, hashlib.sha256(raw).hexdigest()


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ObservabilityError(
                "slo_threshold_key_duplicate",
                f"thresholds JSON 包含重复键：{key}",
            )
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> object:
    raise ObservabilityError(
        "slo_threshold_nonfinite",
        f"thresholds JSON 不得包含非有限数：{value}",
    )


if __name__ == "__main__":
    raise SystemExit(main())
