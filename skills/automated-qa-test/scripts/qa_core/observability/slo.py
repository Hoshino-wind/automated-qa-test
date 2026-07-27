"""从已验链 trace 生成不可加权抵消的 SLO 发布门。"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from itertools import islice
from pathlib import Path
from typing import Any, Iterable, Mapping

from ._metrics import calculate_metrics
from ._validation import (
    ObservabilityError,
    canonical_sha256,
    exact_object,
    number,
    sha256,
    text,
)
from .contracts import TraceRecord
from .journal import TraceJournal

_GATE_ORDER = (
    "provenance",
    "sampling",
    "integrity",
    "bounded_execution",
    "reliability",
)
_MAX_SLO_RUN_DIRECTORIES = 32
_MAX_SLO_RECORDS = 100_000
_MAX_SLO_TRACE_BYTES = 256 * 1024 * 1024
_MAX_SLO_INPUT_HASHES = 128
_MAX_SLO_INPUT_NAME_LENGTH = 2_048
_TRACE_JOURNAL_FILENAME = "agent-trace.jsonl"
_MAXIMUM_PRODUCTION_THRESHOLDS = {
    "deadline_p99_excess_seconds": 0.0,
    "cancellation_p95_seconds": 2.0,
    "cleanup_p99_seconds": 10.0,
    "cleanup_hard_limit_seconds": 30.0,
    "handoff_p99_seconds": 15.0,
    "recovery_limit_seconds": 60.0,
}
_MINIMUM_PRODUCTION_THRESHOLDS = {
    "handoff_success_rate": 0.999,
    "artifact_integrity_rate": 1.0,
    "recovery_success_rate": 0.99,
    "executable_plan_rate": 0.98,
    "convergence_rate": 0.95,
    "observability_coverage_rate": 1.0,
}
_CANDIDATE_IDENTITY_FIELDS = {
    "agent_bundle_sha256",
    "policy_sha256",
    "tool_registry_sha256",
    "model_id",
    "memory_snapshot_sha256",
}
_PRODUCTION_REQUIRED_CATEGORIES = frozenset(
    {"success", "failure", "cancellation_or_timeout"}
)
_ALL_SAMPLING_CATEGORIES = frozenset(
    {*_PRODUCTION_REQUIRED_CATEGORIES, "recovery"}
)
_MINIMUM_PRODUCTION_RUN_COUNT = 20
_MAXIMUM_PRODUCTION_WINDOW = timedelta(days=30)
_MAXIMUM_PRODUCTION_RUN_AGE = timedelta(days=7)


@dataclass(frozen=True, slots=True)
class SloSamplingContract:
    """预注册的 SLO 样本量、类别和时间窗口合同。"""

    mode: str
    registered_at: str
    window_started_at: str
    window_ended_at: str
    maximum_run_age_seconds: int
    minimum_run_count: int
    required_categories: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.mode not in {"production", "development"}:
            raise ObservabilityError(
                "slo_sampling_mode_invalid",
                "sampling_contract.mode 必须是 production 或 development",
            )
        registered = _sampling_timestamp(
            "sampling_contract.registered_at",
            self.registered_at,
        )
        window_start = _sampling_timestamp(
            "sampling_contract.window_started_at",
            self.window_started_at,
        )
        window_end = _sampling_timestamp(
            "sampling_contract.window_ended_at",
            self.window_ended_at,
        )
        if not registered < window_start < window_end:
            raise ObservabilityError(
                "slo_sampling_time_order_invalid",
                (
                    "sampling timestamps must satisfy registered_at < "
                    "window_started_at < window_ended_at"
                ),
            )
        if (
            not isinstance(self.maximum_run_age_seconds, int)
            or isinstance(self.maximum_run_age_seconds, bool)
            or self.maximum_run_age_seconds <= 0
        ):
            raise ObservabilityError(
                "slo_sampling_maximum_age_invalid",
                "maximum_run_age_seconds 必须是正整数",
            )
        if (
            not isinstance(self.minimum_run_count, int)
            or isinstance(self.minimum_run_count, bool)
            or self.minimum_run_count <= 0
        ):
            raise ObservabilityError(
                "slo_sampling_minimum_run_count_invalid",
                "minimum_run_count 必须是正整数",
            )
        if (
            not isinstance(self.required_categories, tuple)
            or not self.required_categories
            or tuple(sorted(set(self.required_categories)))
            != self.required_categories
            or any(
                not isinstance(item, str)
                or item not in _ALL_SAMPLING_CATEGORIES
                for item in self.required_categories
            )
        ):
            raise ObservabilityError(
                "slo_sampling_categories_invalid",
                "required_categories 必须是排序、唯一且受支持的非空类别",
            )
        if self.mode == "production":
            if self.minimum_run_count < _MINIMUM_PRODUCTION_RUN_COUNT:
                raise ObservabilityError(
                    "slo_sampling_contract_weakened",
                    (
                        "production minimum_run_count 不得小于 "
                        f"{_MINIMUM_PRODUCTION_RUN_COUNT}"
                    ),
                )
            if not _PRODUCTION_REQUIRED_CATEGORIES.issubset(
                self.required_categories
            ):
                raise ObservabilityError(
                    "slo_sampling_contract_weakened",
                    (
                        "production required_categories 必须至少包含 "
                        "success、failure、cancellation_or_timeout"
                    ),
                )
            if window_end - window_start > _MAXIMUM_PRODUCTION_WINDOW:
                raise ObservabilityError(
                    "slo_sampling_contract_weakened",
                    "production sampling window 不得超过 30 天",
                )
            if (
                self.maximum_run_age_seconds
                > _MAXIMUM_PRODUCTION_RUN_AGE.total_seconds()
            ):
                raise ObservabilityError(
                    "slo_sampling_contract_weakened",
                    "production maximum_run_age_seconds 不得超过 7 天",
                )

    @classmethod
    def from_dict(cls, value: object) -> "SloSamplingContract":
        payload = exact_object(
            "sampling_contract",
            value,
            required={
                "schema_version",
                "mode",
                "registered_at",
                "window_started_at",
                "window_ended_at",
                "maximum_run_age_seconds",
                "minimum_run_count",
                "required_categories",
            },
        )
        if payload["schema_version"] != 1:
            raise ObservabilityError(
                "slo_sampling_schema_unsupported",
                "sampling_contract.schema_version 必须等于 1",
            )
        raw_categories = payload["required_categories"]
        if not isinstance(raw_categories, list):
            raise ObservabilityError(
                "slo_sampling_categories_invalid",
                "required_categories 必须是数组",
            )
        return cls(
            mode=text("sampling_contract.mode", payload["mode"]),
            registered_at=text(
                "sampling_contract.registered_at",
                payload["registered_at"],
            ),
            window_started_at=text(
                "sampling_contract.window_started_at",
                payload["window_started_at"],
            ),
            window_ended_at=text(
                "sampling_contract.window_ended_at",
                payload["window_ended_at"],
            ),
            maximum_run_age_seconds=payload["maximum_run_age_seconds"],
            minimum_run_count=payload["minimum_run_count"],
            required_categories=tuple(raw_categories),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "registered_at": self.registered_at,
            "window_started_at": self.window_started_at,
            "window_ended_at": self.window_ended_at,
            "maximum_run_age_seconds": self.maximum_run_age_seconds,
            "minimum_run_count": self.minimum_run_count,
            "required_categories": list(self.required_categories),
        }


@dataclass(frozen=True, slots=True)
class SloThresholds:
    """架构文档中生产候选 SLO 的预注册阈值。"""

    deadline_p99_excess_seconds: float = 0.0
    cancellation_p95_seconds: float = 2.0
    cleanup_p99_seconds: float = 10.0
    cleanup_hard_limit_seconds: float = 30.0
    handoff_success_rate: float = 0.999
    handoff_p99_seconds: float = 15.0
    artifact_integrity_rate: float = 1.0
    recovery_success_rate: float = 0.99
    recovery_limit_seconds: float = 60.0
    executable_plan_rate: float = 0.98
    convergence_rate: float = 0.95
    observability_coverage_rate: float = 1.0

    def __post_init__(self) -> None:
        rates = {
            "handoff_success_rate",
            "artifact_integrity_rate",
            "recovery_success_rate",
            "executable_plan_rate",
            "convergence_rate",
            "observability_coverage_rate",
        }
        for name, raw in asdict(self).items():
            value = number(f"thresholds.{name}", raw)
            if name in rates and value > 1.0:
                raise ObservabilityError(
                    "slo_threshold_invalid",
                    f"thresholds.{name} 必须位于 0 到 1",
                )
            if (
                name in _MAXIMUM_PRODUCTION_THRESHOLDS
                and value > _MAXIMUM_PRODUCTION_THRESHOLDS[name]
            ):
                raise ObservabilityError(
                    "slo_threshold_weakened",
                    f"thresholds.{name} 不得弱于生产候选上限",
                )
            if (
                name in _MINIMUM_PRODUCTION_THRESHOLDS
                and value < _MINIMUM_PRODUCTION_THRESHOLDS[name]
            ):
                raise ObservabilityError(
                    "slo_threshold_weakened",
                    f"thresholds.{name} 不得弱于生产候选下限",
                )
        if self.cleanup_hard_limit_seconds < self.cleanup_p99_seconds:
            raise ObservabilityError(
                "slo_threshold_order_invalid",
                "cleanup_hard_limit_seconds 不得小于 cleanup_p99_seconds",
            )

    @classmethod
    def from_dict(cls, value: object) -> "SloThresholds":
        names = set(cls.__dataclass_fields__)
        payload = exact_object("thresholds", value, required=names)
        return cls(**{name: payload[name] for name in names})

    def to_dict(self) -> dict[str, float]:
        return {name: float(value) for name, value in asdict(self).items()}


def aggregate_slo(
    records: Iterable[TraceRecord],
    *,
    input_hashes: Mapping[str, str],
    thresholds: SloThresholds | None = None,
) -> dict[str, Any]:
    """聚合 trace-only 分析；该接口永远不能授予生产资格。

    ``TraceRecord`` 的前向哈希只能证明 journal 内部自洽，不能证明它来自某个
    terminal state 和不可变 attempt。生产调用必须使用
    :func:`aggregate_run_directories`。
    """

    return _aggregate_report(
        records,
        input_hashes=input_hashes,
        thresholds=thresholds,
        provenance="synthetic_or_unverified",
        provenance_failures=[
            {
                "gate": "provenance",
                "code": "production_run_proof_required",
                "observed": "trace_only",
                "required": "verified_run_directory",
            }
        ],
        proof_results=[],
    )


def aggregate_run_directories(
    run_dirs: Iterable[str | os.PathLike[str]],
    *,
    thresholds: SloThresholds | None = None,
    additional_input_hashes: Mapping[str, str] | None = None,
    expected_candidate_identity: Mapping[str, Any] | None = None,
    sampling_contract: SloSamplingContract | Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """从现场重验的 run proof roots 聚合生产候选报告。

    每个 root 都调用 ``verify_run_proof``，并重新读取该 root 的规范 trace。
    verifier 可以闭合 success PASS claim，或 failure / cancellation_or_timeout
    terminal observation；后两者的 ``can_claim_pass`` 必须保持 ``False``。
    任一 proof、terminal state、attempt、budget 或 trace 绑定失败都会形成结构化
    provenance gate；只有全部 root 通过且全部 SLO 门通过时 ``qualified`` 才为
    ``True``。
    """

    normalized_roots = _normalize_run_directories(run_dirs)
    candidate_identity = _candidate_identity(expected_candidate_identity)
    configured_sampling = _sampling_contract(sampling_contract)
    trusted_now = _sampling_now(now)
    records: list[TraceRecord] = []
    input_hashes = dict(additional_input_hashes or {})
    candidate_identity_sha256 = canonical_sha256(candidate_identity)
    sampling_contract_sha256 = canonical_sha256(
        configured_sampling.to_dict()
    )
    input_hashes["candidate_identity"] = candidate_identity_sha256
    input_hashes["sampling_contract"] = sampling_contract_sha256
    proof_results: list[dict[str, object]] = []
    provenance_failures: list[dict[str, object]] = []
    total_trace_bytes = 0

    # 局部导入避免 qa_core.proof 初始化 qa_core.observability 时产生循环依赖。
    from qa_core.proof import verify_run_proof

    for root in normalized_roots:
        root_failures: list[dict[str, object]] = []
        proof_payload: dict[str, object] | None = None
        try:
            proof = verify_run_proof(root)
            proof_payload = proof.to_dict()
            proof_hash = sha256(
                f"proof[{root}].proof_graph_sha256",
                proof_payload.get("proof_graph_sha256"),
            )
            input_hashes[f"proof:{root}"] = proof_hash
            outcome_category = proof_payload.get("outcome_category")
            if (
                proof.proof_valid is not True
                or proof.errors
                or outcome_category
                not in _PRODUCTION_REQUIRED_CATEGORIES
                or proof.can_claim_pass
                != (outcome_category == "success")
            ):
                root_failures.append(
                    {
                        "code": "run_proof_rejected",
                        "errors": [dict(item) for item in proof.errors],
                    }
                )
        except Exception as error:  # fail closed at the provenance boundary
            error_payload = {
                "code": "run_proof_verifier_error",
                "error_type": type(error).__name__,
                "message": str(error),
            }
            root_failures.append(error_payload)
            input_hashes[f"proof-error:{root}"] = canonical_sha256(error_payload)

        trace_path = root / _TRACE_JOURNAL_FILENAME
        snapshot = None
        if not trace_path.exists():
            root_failures.append(
                {
                    "code": "production_trace_missing",
                    "path": str(trace_path),
                }
            )
        else:
            try:
                snapshot = TraceJournal(trace_path).snapshot()
            except Exception as error:
                root_failures.append(
                    {
                        "code": "production_trace_invalid",
                        "error_type": type(error).__name__,
                        "message": str(error),
                    }
                )
            else:
                total_trace_bytes += snapshot.byte_size
                if total_trace_bytes > _MAX_SLO_TRACE_BYTES:
                    raise ObservabilityError(
                        "slo_trace_corpus_too_large",
                        "生产 SLO trace corpus 超过字节上限",
                        details={
                            "maximum_bytes": _MAX_SLO_TRACE_BYTES,
                            "observed_bytes": total_trace_bytes,
                        },
                    )
                input_hashes[f"trace:{trace_path}"] = snapshot.sha256

        root_failures.extend(
            _proof_binding_failures(
                root,
                proof_payload=proof_payload,
                snapshot=snapshot,
            )
        )
        proof_identity = _proof_candidate_identity(proof_payload)
        if proof_identity is None:
            root_failures.append(
                {"code": "proof_candidate_identity_missing"}
            )
        elif proof_identity != candidate_identity:
            root_failures.append(
                {"code": "proof_candidate_identity_mismatch"}
            )
        sampled_records = _proof_bound_sample_records(
            proof_payload=proof_payload,
            snapshot=snapshot,
        )
        if sampled_records is None:
            root_failures.append(
                {"code": "proof_sample_run_binding_invalid"}
            )
        else:
            records.extend(sampled_records)
            if len(records) > _MAX_SLO_RECORDS:
                raise ObservabilityError(
                    "slo_trace_record_limit_exceeded",
                    "生产 SLO trace record 数超过上限",
                    details={
                        "maximum_records": _MAX_SLO_RECORDS,
                        "observed_records": len(records),
                    },
                )
        valid = not root_failures
        summary: dict[str, object] = {
            "run_dir": str(root),
            "valid": valid,
            "run_id": (
                proof_payload.get("run_id")
                if proof_payload is not None
                else None
            ),
            "proof_graph_sha256": (
                proof_payload.get("proof_graph_sha256")
                if proof_payload is not None
                else None
            ),
            "proof_kind": (
                proof_payload.get("proof_kind")
                if proof_payload is not None
                else None
            ),
            "outcome_category": (
                proof_payload.get("outcome_category")
                if proof_payload is not None
                else None
            ),
            "can_claim_pass": (
                proof_payload.get("can_claim_pass")
                if proof_payload is not None
                else False
            ),
            "trace_sha256": snapshot.sha256 if snapshot is not None else None,
            "candidate_identity": proof_identity,
            "candidate_identity_sha256": (
                canonical_sha256(proof_identity)
                if proof_identity is not None
                else None
            ),
            "failures": root_failures,
        }
        proof_results.append(summary)
        if not valid:
            provenance_failures.append(
                {
                    "gate": "provenance",
                    "code": "run_proof_invalid",
                    "observed": False,
                    "required": True,
                    "details": {
                        "run_dir": str(root),
                        "failure_codes": [
                            str(item.get("code"))
                            for item in root_failures
                        ],
                    },
                }
            )

    sampling_failures, sampling_summary = _sampling_failures(
        records,
        configured_sampling,
        proof_results=proof_results,
        now=trusted_now,
    )
    return _aggregate_report(
        records,
        input_hashes=input_hashes,
        thresholds=thresholds,
        provenance=(
            "verified_run_proof"
            if not provenance_failures
            else "invalid_run_proof"
        ),
        provenance_failures=provenance_failures,
        proof_results=proof_results,
        candidate_identity=candidate_identity,
        candidate_identity_sha256=candidate_identity_sha256,
        sampling_contract=configured_sampling,
        sampling_contract_sha256=sampling_contract_sha256,
        sampling_failures=sampling_failures,
        sampling_summary=sampling_summary,
    )


def _aggregate_report(
    records: Iterable[TraceRecord],
    *,
    input_hashes: Mapping[str, str],
    thresholds: SloThresholds | None,
    provenance: str,
    provenance_failures: list[dict[str, object]],
    proof_results: list[dict[str, object]],
    candidate_identity: dict[str, Any] | None = None,
    candidate_identity_sha256: str | None = None,
    sampling_contract: SloSamplingContract | None = None,
    sampling_contract_sha256: str | None = None,
    sampling_failures: list[dict[str, object]] | None = None,
    sampling_summary: dict[str, object] | None = None,
) -> dict[str, Any]:
    """共享指标计算；生产资格只由显式 provenance gate 解锁。"""

    configured = thresholds or SloThresholds()
    effective_provenance_failures = list(provenance_failures)
    if (
        not effective_provenance_failures
        and (
            provenance != "verified_run_proof"
            or not proof_results
            or any(item.get("valid") is not True for item in proof_results)
        )
    ):
        effective_provenance_failures.append(
            {
                "gate": "provenance",
                "code": "production_provenance_incomplete",
                "observed": provenance,
                "required": "verified_run_proof",
            }
        )
    try:
        supplied_records = tuple(
            islice(iter(records), _MAX_SLO_RECORDS + 1)
        )
    except TypeError as error:
        raise ObservabilityError(
            "slo_records_invalid",
            "records 必须是 TraceRecord iterable",
        ) from error
    if len(supplied_records) > _MAX_SLO_RECORDS:
        raise ObservabilityError(
            "slo_trace_record_limit_exceeded",
            "SLO trace record 数超过上限",
            details={
                "maximum_records": _MAX_SLO_RECORDS,
                "observed_records": len(supplied_records),
            },
        )
    if not all(isinstance(record, TraceRecord) for record in supplied_records):
        raise ObservabilityError(
            "slo_records_invalid",
            "records 必须全部是已验证的 TraceRecord",
        )
    normalized_records = tuple(
        TraceRecord.from_dict(record.to_dict())
        for record in supplied_records
    )
    record_hashes = [record.event_sha256 for record in normalized_records]
    if len(record_hashes) != len(set(record_hashes)):
        raise ObservabilityError(
            "slo_duplicate_trace_record",
            "SLO 输入包含重复 trace record",
        )
    frozen_inputs = _input_hashes(input_hashes)
    runs, metrics = calculate_metrics(
        normalized_records,
        cleanup_hard_limit_seconds=configured.cleanup_hard_limit_seconds,
        recovery_limit_seconds=configured.recovery_limit_seconds,
    )
    metric_failures = _gate_failures(metrics, configured)
    effective_sampling_failures = list(sampling_failures or [])
    if (
        provenance == "verified_run_proof"
        and sampling_contract is None
    ):
        effective_sampling_failures.append(
            {
                "gate": "sampling",
                "code": "production_sampling_contract_required",
                "observed": None,
                "required": "pre_registered_sampling_contract",
            }
        )
    failures = [
        *effective_provenance_failures,
        *effective_sampling_failures,
        *metric_failures,
    ]
    gate_results = [
        {
            "gate": gate,
            "passed": not any(item["gate"] == gate for item in failures),
            "failure_count": sum(item["gate"] == gate for item in failures),
        }
        for gate in _GATE_ORDER
    ]
    unsigned = {
        "schema_version": 2,
        "qualified": not failures,
        "analysis_qualified": not metric_failures,
        "not_production_qualified": bool(
            effective_provenance_failures
            or effective_sampling_failures
            or sampling_contract is None
            or sampling_contract.mode != "production"
        ),
        "provenance": provenance,
        "blocking_gate": next(
            (item["gate"] for item in gate_results if not item["passed"]),
            None,
        ),
        "event_count": len(normalized_records),
        "run_count": len(runs),
        "metrics": metrics,
        "thresholds": configured.to_dict(),
        "gate_order": list(_GATE_ORDER),
        "gate_results": gate_results,
        "gate_failures": failures,
        "proof_results": proof_results,
        "candidate_identity": candidate_identity,
        "candidate_identity_sha256": candidate_identity_sha256,
        "sampling_contract": (
            sampling_contract.to_dict()
            if sampling_contract is not None
            else None
        ),
        "sampling_contract_sha256": sampling_contract_sha256,
        "sampling": sampling_summary,
        "inputs": {
            "sha256": frozen_inputs,
            "input_set_sha256": canonical_sha256(frozen_inputs),
            "thresholds_sha256": canonical_sha256(configured.to_dict()),
        },
    }
    return {**unsigned, "report_sha256": canonical_sha256(unsigned)}


def _normalize_run_directories(
    run_dirs: Iterable[str | os.PathLike[str]],
) -> tuple[Path, ...]:
    if isinstance(run_dirs, (str, bytes, os.PathLike)):
        raise ObservabilityError(
            "slo_run_dirs_invalid",
            "run_dirs 必须是路径 iterable，不能是单个路径字符串",
        )
    try:
        supplied = tuple(
            islice(iter(run_dirs), _MAX_SLO_RUN_DIRECTORIES + 1)
        )
    except TypeError as error:
        raise ObservabilityError(
            "slo_run_dirs_invalid",
            "run_dirs 必须是路径 iterable",
        ) from error
    if not supplied:
        raise ObservabilityError(
            "slo_run_dirs_empty",
            "生产 SLO 至少需要一个 --run-dir",
        )
    if len(supplied) > _MAX_SLO_RUN_DIRECTORIES:
        raise ObservabilityError(
            "slo_run_dir_limit_exceeded",
            "生产 SLO run directory 数超过上限",
            details={
                "maximum_run_directories": _MAX_SLO_RUN_DIRECTORIES,
                "observed_run_directories": len(supplied),
            },
        )
    normalized: list[Path] = []
    for index, raw in enumerate(supplied):
        try:
            candidate = Path(raw).expanduser()
        except TypeError as error:
            raise ObservabilityError(
                "slo_run_dir_invalid",
                f"run_dirs[{index}] 不是合法路径",
            ) from error
        if candidate.is_symlink():
            raise ObservabilityError(
                "slo_run_dir_symlink_rejected",
                f"run directory 不得是 symlink：{candidate}",
            )
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise ObservabilityError(
                "slo_run_dir_missing",
                f"run directory 不存在：{candidate}",
            ) from error
        if not resolved.is_dir():
            raise ObservabilityError(
                "slo_run_dir_not_directory",
                f"run directory 必须是目录：{resolved}",
            )
        normalized.append(resolved)
    if len(normalized) != len(set(normalized)):
        raise ObservabilityError(
            "slo_run_dir_duplicate",
            "--run-dir 不得重复或通过 alias 指向同一目录",
        )
    return tuple(sorted(normalized, key=str))


def _candidate_identity(
    value: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if value is None:
        raise ObservabilityError(
            "slo_candidate_identity_required",
            "生产 SLO 必须提供完整 candidate identity",
        )
    payload = exact_object(
        "candidate_identity",
        value,
        required=_CANDIDATE_IDENTITY_FIELDS,
    )
    normalized = {
        "agent_bundle_sha256": sha256(
            "candidate_identity.agent_bundle_sha256",
            payload["agent_bundle_sha256"],
        ),
        "policy_sha256": sha256(
            "candidate_identity.policy_sha256",
            payload["policy_sha256"],
        ),
        "tool_registry_sha256": sha256(
            "candidate_identity.tool_registry_sha256",
            payload["tool_registry_sha256"],
        ),
        "model_id": text(
            "candidate_identity.model_id",
            payload["model_id"],
        ),
        "memory_snapshot_sha256": sha256(
            "candidate_identity.memory_snapshot_sha256",
            payload["memory_snapshot_sha256"],
        ),
    }
    return normalized


def _proof_candidate_identity(
    proof_payload: Mapping[str, object] | None,
) -> dict[str, Any] | None:
    if proof_payload is None:
        return None
    refs = proof_payload.get("verified_refs")
    if not isinstance(refs, Mapping):
        return None
    value = refs.get("candidate_identity")
    if not isinstance(value, Mapping):
        return None
    try:
        return _candidate_identity(value)
    except ObservabilityError:
        return None


def _proof_bound_sample_records(
    *,
    proof_payload: Mapping[str, object] | None,
    snapshot: object | None,
) -> tuple[TraceRecord, ...] | None:
    if proof_payload is None or snapshot is None:
        return None
    refs = proof_payload.get("verified_refs")
    if not isinstance(refs, Mapping):
        return None
    attempt = refs.get("attempt")
    if not isinstance(attempt, Mapping):
        return None
    run_id = proof_payload.get("run_id")
    generation = attempt.get("generation")
    attempt_id = attempt.get("attempt_id")
    if (
        not isinstance(run_id, str)
        or not run_id
        or not isinstance(generation, int)
        or isinstance(generation, bool)
        or not isinstance(attempt_id, str)
    ):
        return None
    snapshot_records = tuple(getattr(snapshot, "records", ()))
    if not snapshot_records:
        return None
    terminal = snapshot_records[-1].event
    if (
        terminal.kind != "run"
        or terminal.run_id != run_id
        or terminal.generation != generation
        or terminal.attempt_id != attempt_id
    ):
        return None
    records = tuple(
        record
        for record in snapshot_records
        if (
            isinstance(record, TraceRecord)
            and record.event.run_key == terminal.run_key
        )
    )
    run_markers = [
        record.event
        for record in records
        if record.event.kind == "run"
    ]
    if (
        len(run_markers) != 1
        or records[-1].event is not run_markers[0]
        or run_markers[0].attempt_id != attempt_id
    ):
        return None
    return records


def _sampling_contract(
    value: SloSamplingContract | Mapping[str, Any] | None,
) -> SloSamplingContract:
    if value is None:
        raise ObservabilityError(
            "slo_sampling_contract_required",
            "生产 proof-backed SLO 必须提供预注册 sampling contract",
        )
    if isinstance(value, SloSamplingContract):
        return value
    return SloSamplingContract.from_dict(value)


def _sampling_failures(
    records: list[TraceRecord],
    contract: SloSamplingContract,
    *,
    proof_results: list[dict[str, object]],
    now: datetime,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    failures: list[dict[str, object]] = []
    run_events = [
        record.event for record in records if record.event.kind == "run"
    ]
    verified_outcomes = [
        item.get("outcome_category")
        for item in proof_results
        if item.get("valid") is True
    ]
    categories = {
        str(item)
        for item in verified_outcomes
        if item in _PRODUCTION_REQUIRED_CATEGORIES
    }
    if any(record.event.kind == "recovery" for record in records):
        categories.add("recovery")

    if contract.mode != "production":
        failures.append(
            {
                "gate": "sampling",
                "code": "development_sampling_not_production",
                "observed": contract.mode,
                "required": "production",
            }
        )
    if len(run_events) < contract.minimum_run_count:
        failures.append(
            {
                "gate": "sampling",
                "code": "sampling_run_count_insufficient",
                "observed": len(run_events),
                "required_min": contract.minimum_run_count,
            }
        )
    missing_categories = sorted(
        set(contract.required_categories) - categories
    )
    if missing_categories:
        failures.append(
            {
                "gate": "sampling",
                "code": "sampling_categories_missing",
                "observed": sorted(categories),
                "required": list(contract.required_categories),
                "missing": missing_categories,
            }
        )
    recovery_required_count = sum(
        bool(event.attributes["recovery_required"])
        for event in run_events
    )
    if recovery_required_count and "recovery" not in categories:
        failures.append(
            {
                "gate": "sampling",
                "code": "sampling_recovery_category_missing",
                "observed": False,
                "required": True,
            }
        )

    window_start = _sampling_timestamp(
        "sampling_contract.window_started_at",
        contract.window_started_at,
    )
    window_end = _sampling_timestamp(
        "sampling_contract.window_ended_at",
        contract.window_ended_at,
    )
    if window_end > now:
        failures.append(
            {
                "gate": "sampling",
                "code": "sampling_window_in_future",
                "observed": contract.window_ended_at,
                "required_max": _format_timestamp(now),
            }
        )
    outside_window = [
        event.run_id
        for event in run_events
        if (
            event.started_datetime < window_start
            or event.ended_datetime > window_end
        )
    ]
    if outside_window:
        failures.append(
            {
                "gate": "sampling",
                "code": "sampling_run_outside_window",
                "observed_run_ids": sorted(set(outside_window)),
            }
        )
    stale_runs = [
        event.run_id
        for event in run_events
        if (
            event.ended_datetime > now
            or (now - event.ended_datetime).total_seconds()
            > contract.maximum_run_age_seconds
        )
    ]
    if stale_runs:
        failures.append(
            {
                "gate": "sampling",
                "code": "sampling_run_age_invalid",
                "observed_run_ids": sorted(set(stale_runs)),
                "required_max_age_seconds": (
                    contract.maximum_run_age_seconds
                ),
            }
        )
    summary = {
        "mode": contract.mode,
        "run_count": len(run_events),
        "minimum_run_count": contract.minimum_run_count,
        "observed_categories": sorted(categories),
        "proof_outcome_counts": {
            category: verified_outcomes.count(category)
            for category in sorted(_PRODUCTION_REQUIRED_CATEGORIES)
        },
        "required_categories": list(contract.required_categories),
        "recovery_required_run_count": recovery_required_count,
        "window_started_at": contract.window_started_at,
        "window_ended_at": contract.window_ended_at,
        "maximum_run_age_seconds": contract.maximum_run_age_seconds,
        "observed_earliest_run_started_at": (
            min(event.started_datetime for event in run_events)
            .isoformat()
            .replace("+00:00", "Z")
            if run_events
            else None
        ),
        "observed_latest_run_ended_at": (
            max(event.ended_datetime for event in run_events)
            .isoformat()
            .replace("+00:00", "Z")
            if run_events
            else None
        ),
        "passed": not failures,
    }
    return failures, summary


def _sampling_timestamp(name: str, value: object) -> datetime:
    normalized = text(name, value)
    if not normalized.endswith("Z"):
        raise ObservabilityError(
            "slo_sampling_timestamp_invalid",
            f"{name} 必须是以 Z 结尾的 RFC3339 UTC 时间",
        )
    try:
        parsed = datetime.fromisoformat(
            normalized.removesuffix("Z") + "+00:00"
        )
    except ValueError as error:
        raise ObservabilityError(
            "slo_sampling_timestamp_invalid",
            f"{name} 必须是 RFC3339 UTC 时间",
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ObservabilityError(
            "slo_sampling_timestamp_invalid",
            f"{name} 必须使用 UTC",
        )
    return parsed


def _sampling_now(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise ObservabilityError(
            "slo_sampling_now_invalid",
            "now 必须是 timezone-aware UTC datetime",
        )
    return value.astimezone(UTC)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _proof_binding_failures(
    root: Path,
    *,
    proof_payload: dict[str, object] | None,
    snapshot: object | None,
) -> list[dict[str, object]]:
    failures: list[dict[str, object]] = []
    if proof_payload is None or snapshot is None:
        return failures
    refs = proof_payload.get("verified_refs")
    if not isinstance(refs, dict):
        return [{"code": "proof_verified_refs_invalid"}]
    state = refs.get("state")
    attempt = refs.get("attempt")
    trace = refs.get("trace")
    budget = refs.get("budget")
    outcome = proof_payload.get("outcome_category")
    if outcome not in _PRODUCTION_REQUIRED_CATEGORIES:
        failures.append({"code": "proof_outcome_invalid"})
    if proof_payload.get("proof_valid") is not True:
        failures.append({"code": "proof_not_verified"})
    if proof_payload.get("can_claim_pass") != (outcome == "success"):
        failures.append({"code": "proof_pass_semantics_invalid"})
    expected_state_statuses = (
        {"passed"}
        if outcome == "success"
        else {"blocked", "cancelled", "failed", "inconclusive"}
    )
    if (
        not isinstance(state, dict)
        or state.get("status") not in expected_state_statuses
    ):
        failures.append({"code": "proof_terminal_state_invalid"})
    if not isinstance(attempt, dict):
        failures.append({"code": "proof_attempt_ref_invalid"})
    if not isinstance(budget, dict):
        failures.append({"code": "proof_budget_ref_invalid"})
    if not isinstance(trace, dict):
        failures.append({"code": "proof_trace_ref_invalid"})
        return failures
    expected_trace_path = root / _TRACE_JOURNAL_FILENAME
    raw_path = trace.get("path")
    try:
        observed_path = Path(str(raw_path)).expanduser().resolve(strict=True)
    except OSError:
        observed_path = None
    if observed_path != expected_trace_path:
        failures.append({"code": "proof_trace_path_mismatch"})
    if trace.get("sha256") != getattr(snapshot, "sha256", None):
        failures.append({"code": "proof_trace_hash_mismatch"})
    records = getattr(snapshot, "records", ())
    if not records:
        failures.append({"code": "proof_trace_empty"})
        return failures
    terminal = records[-1].event
    attempt_id = attempt.get("attempt_id") if isinstance(attempt, dict) else None
    observed_outcome = _trace_outcome_category(
        tuple(
            record.event
            for record in records
            if record.event.run_key == terminal.run_key
        )
    )
    if (
        terminal.kind != "run"
        or terminal.run_id != proof_payload.get("run_id")
        or terminal.attempt_id != attempt_id
        or observed_outcome != outcome
    ):
        failures.append({"code": "proof_terminal_trace_invalid"})
    return failures


def _trace_outcome_category(events: tuple[Any, ...]) -> str | None:
    run_events = [event for event in events if event.kind == "run"]
    if len(run_events) != 1:
        return None
    terminal = run_events[0]
    if (
        terminal.status == "succeeded"
        and terminal.attributes.get("converged") is True
    ):
        return "success"
    if (
        terminal.status
        not in {"failed", "blocked", "cancelled", "inconclusive"}
        or terminal.attributes.get("converged") is not False
    ):
        return None
    if any(
        event.kind == "cancellation"
        or event.status == "cancelled"
        or event.reason.code
        in {"cancelled", "deadline_exceeded", "stage_timeout"}
        for event in events
    ):
        return "cancellation_or_timeout"
    return "failure"


def _gate_failures(
    metrics: Mapping[str, Mapping[str, object]],
    thresholds: SloThresholds,
) -> list[dict[str, object]]:
    failures: list[dict[str, object]] = []
    _minimum(
        failures,
        "integrity",
        "artifact_integrity",
        metrics["artifact_integrity"]["integrity_rate"],
        thresholds.artifact_integrity_rate,
    )
    _minimum(
        failures,
        "integrity",
        "observability_coverage",
        metrics["observability_coverage"]["coverage_rate"],
        thresholds.observability_coverage_rate,
    )
    _maximum(
        failures,
        "bounded_execution",
        "deadline_overrun",
        metrics["deadline_overrun"]["p99_excess_seconds"],
        thresholds.deadline_p99_excess_seconds,
    )
    _maximum(
        failures,
        "bounded_execution",
        "cancellation_stop_dispatch",
        metrics["cancellation_stop_dispatch"]["p95_stop_seconds"],
        thresholds.cancellation_p95_seconds,
    )
    _minimum(
        failures,
        "bounded_execution",
        "cancellation_stop_success",
        metrics["cancellation_stop_dispatch"]["stop_success_rate"],
        1.0,
    )
    _zero(
        failures,
        "bounded_execution",
        "post_cancel_dispatch",
        metrics["cancellation_stop_dispatch"]["post_stop_dispatch_count"],
    )
    _minimum(
        failures,
        "bounded_execution",
        "cleanup_success",
        metrics["cleanup"]["success_rate"],
        1.0,
    )
    _maximum(
        failures,
        "bounded_execution",
        "cleanup_latency",
        metrics["cleanup"]["p99_seconds"],
        thresholds.cleanup_p99_seconds,
    )
    _minimum(
        failures,
        "bounded_execution",
        "cleanup_hard_limit",
        metrics["cleanup"]["within_hard_limit_rate"],
        1.0,
    )
    _minimum(
        failures,
        "reliability",
        "handoff_success",
        metrics["handoff"]["structured_success_rate"],
        thresholds.handoff_success_rate,
    )
    _maximum(
        failures,
        "reliability",
        "handoff_latency",
        metrics["handoff"]["p99_seconds"],
        thresholds.handoff_p99_seconds,
    )
    _minimum(
        failures,
        "reliability",
        "recovery_success",
        metrics["recovery"]["success_rate"],
        thresholds.recovery_success_rate,
    )
    _zero(
        failures,
        "reliability",
        "recovery_duplicate_commit",
        metrics["recovery"]["duplicate_committed_action_count"],
    )
    _minimum(
        failures,
        "reliability",
        "plan_executability",
        metrics["plan_executability"]["executable_rate"],
        thresholds.executable_plan_rate,
    )
    _minimum(
        failures,
        "reliability",
        "convergence",
        metrics["convergence"]["convergence_rate"],
        thresholds.convergence_rate,
    )
    return failures


def _minimum(
    failures: list[dict[str, object]],
    gate: str,
    code: str,
    observed: object,
    required: float,
) -> None:
    if observed is None:
        _empty(failures, gate, code)
    elif float(observed) < required:
        failures.append(
            {"gate": gate, "code": code, "observed": observed, "required_min": required}
        )


def _maximum(
    failures: list[dict[str, object]],
    gate: str,
    code: str,
    observed: object,
    required: float,
) -> None:
    if observed is None:
        _empty(failures, gate, code)
    elif float(observed) > required:
        failures.append(
            {"gate": gate, "code": code, "observed": observed, "required_max": required}
        )


def _zero(
    failures: list[dict[str, object]],
    gate: str,
    code: str,
    observed: object,
) -> None:
    if int(observed) != 0:
        failures.append(
            {"gate": gate, "code": code, "observed": observed, "required": 0}
        )


def _empty(failures: list[dict[str, object]], gate: str, code: str) -> None:
    failures.append(
        {
            "gate": gate,
            "code": f"{code}_denominator_empty",
            "observed": None,
            "required": "non_empty_denominator",
        }
    )


def _input_hashes(value: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(value, Mapping) or not value:
        raise ObservabilityError(
            "slo_input_hashes_empty",
            "input_hashes 必须是非空映射",
        )
    if len(value) > _MAX_SLO_INPUT_HASHES:
        raise ObservabilityError(
            "slo_input_hash_limit_exceeded",
            "input_hashes 数量超过上限",
            details={
                "maximum_input_hashes": _MAX_SLO_INPUT_HASHES,
                "observed_input_hashes": len(value),
            },
        )
    normalized: dict[str, str] = {}
    for raw_name, raw_hash in value.items():
        name = text("input_hashes key", raw_name)
        if len(name) > _MAX_SLO_INPUT_NAME_LENGTH:
            raise ObservabilityError(
                "slo_input_name_too_long",
                "input_hashes key 超过长度上限",
                details={
                    "maximum_length": _MAX_SLO_INPUT_NAME_LENGTH,
                    "observed_length": len(name),
                },
            )
        normalized[name] = sha256(f"input_hashes[{name!r}]", raw_hash)
    return dict(sorted(normalized.items()))
