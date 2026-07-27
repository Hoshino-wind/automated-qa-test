"""SLO 指标的确定性样本归并与统计。"""

from __future__ import annotations

import math
from typing import Mapping

from ._validation import ObservabilityError
from .contracts import TraceEvent, TraceRecord

RunKey = tuple[str, int, int]
EventIndex = dict[str, dict[RunKey, list[TraceEvent]]]


def calculate_metrics(
    records: tuple[TraceRecord, ...],
    *,
    cleanup_hard_limit_seconds: float,
    recovery_limit_seconds: float,
) -> tuple[dict[RunKey, TraceEvent], dict[str, dict[str, object]]]:
    runs, events = _index_events(records)
    metrics = {
        "deadline_overrun": _deadline_metric(runs),
        "cancellation_stop_dispatch": _cancellation_metric(events),
        "cleanup": _cleanup_metric(
            runs,
            events,
            hard_limit_seconds=cleanup_hard_limit_seconds,
        ),
        "handoff": _handoff_metric(runs, events),
        "artifact_integrity": _artifact_metric(events),
        "recovery": _recovery_metric(
            runs,
            events,
            limit_seconds=recovery_limit_seconds,
        ),
        "plan_executability": _plan_metric(events),
        "convergence": _convergence_metric(runs),
        "observability_coverage": _coverage_metric(runs, events),
    }
    return runs, metrics


def _index_events(
    records: tuple[TraceRecord, ...],
) -> tuple[dict[RunKey, TraceEvent], EventIndex]:
    events: EventIndex = {}
    for record in records:
        event = record.event
        events.setdefault(event.kind, {}).setdefault(event.run_key, []).append(event)
    runs: dict[RunKey, TraceEvent] = {}
    for key, candidates in events.get("run", {}).items():
        if len(candidates) != 1:
            raise ObservabilityError(
                "slo_run_marker_duplicate",
                f"run {key!r} 必须恰有一个 run span",
            )
        runs[key] = candidates[0]
    for kind, grouped in events.items():
        for key in grouped:
            if kind != "run" and key not in runs:
                raise ObservabilityError(
                    "slo_orphan_trace_event",
                    f"{kind} span 没有对应 run span：{key!r}",
                )
    for kind in (
        "cancellation",
        "cleanup",
        "handoff",
        "recovery",
        "plan_validation",
    ):
        for key, candidates in events.get(kind, {}).items():
            if len(candidates) > 1:
                raise ObservabilityError(
                    "slo_singleton_event_duplicate",
                    f"run {key!r} 包含多个 {kind} span",
                )
    return runs, events


def _deadline_metric(runs: Mapping[RunKey, TraceEvent]) -> dict[str, object]:
    overruns: list[float] = []
    excesses: list[float] = []
    for event in runs.values():
        deadline = event.deadline_datetime
        total = event.budget.total_seconds
        if deadline is None or total is None:
            raise ObservabilityError(
                "slo_run_budget_incomplete",
                f"run {event.run_key!r} 缺少 deadline 预算",
            )
        overrun = max(0.0, (event.ended_datetime - deadline).total_seconds())
        allowed = max(10.0, total * 0.05)
        overruns.append(overrun)
        excesses.append(max(0.0, overrun - allowed))
    return {
        "sample_count": len(overruns),
        "p99_overrun_seconds": _percentile(overruns, 0.99),
        "p99_excess_seconds": _percentile(excesses, 0.99),
        "within_target_rate": _rate(sum(value == 0 for value in excesses), len(excesses)),
        "target": "p99 overrun <= per-run max(10s, budget*5%)",
    }


def _cancellation_metric(events: EventIndex) -> dict[str, object]:
    cancellations = [
        candidate
        for kind, grouped in events.items()
        for candidates in grouped.values()
        for candidate in candidates
        if (
            kind == "cancellation"
            or candidate.status == "cancelled"
            or candidate.reason.code
            in {"cancelled", "deadline_exceeded", "stage_timeout"}
        )
    ]
    post_stop = 0
    for cancellation in cancellations:
        actions = events.get("action", {}).get(cancellation.run_key, [])
        post_stop += sum(
            action.started_datetime > cancellation.ended_datetime
            for action in actions
        )
    durations = [event.duration_seconds for event in cancellations]
    stopped = sum(
        (
            event.kind == "cancellation"
            and event.status == "succeeded"
        )
        or (
            event.kind != "cancellation"
            and (
                event.status in {"blocked", "cancelled"}
                or event.reason.code
                in {"cancelled", "deadline_exceeded", "stage_timeout"}
            )
        )
        for event in cancellations
    )
    return {
        "sample_count": len(cancellations),
        "stop_success_rate": _rate(
            stopped,
            len(cancellations),
        ),
        "p95_stop_seconds": _percentile(durations, 0.95),
        "post_stop_dispatch_count": post_stop,
        "duration_semantics": (
            "explicit cancellation latency, or conservative full boundary "
            "latency for timeout/cancelled stage spans"
        ),
    }


def _cleanup_metric(
    runs: Mapping[RunKey, TraceEvent],
    events: EventIndex,
    *,
    hard_limit_seconds: float,
) -> dict[str, object]:
    eligible = [
        key for key, event in runs.items() if event.attributes["cleanup_required"]
    ]
    observed = [
        events["cleanup"][key][0]
        for key in eligible
        if key in events.get("cleanup", {})
    ]
    successful = sum(
        event.status == "succeeded"
        and event.attributes["managed_resources_remaining"] == 0
        for event in observed
    )
    hard_limit_success = sum(
        event.status == "succeeded"
        and event.attributes["managed_resources_remaining"] == 0
        and event.duration_seconds <= hard_limit_seconds
        for event in observed
    )
    return {
        "eligible_count": len(eligible),
        "observed_count": len(observed),
        "success_rate": _rate(successful, len(eligible)),
        "p99_seconds": _percentile(
            [event.duration_seconds for event in observed],
            0.99,
        ),
        "within_hard_limit_rate": _rate(hard_limit_success, len(eligible)),
    }


def _handoff_metric(
    runs: Mapping[RunKey, TraceEvent],
    events: EventIndex,
) -> dict[str, object]:
    eligible = [
        key for key, event in runs.items() if event.attributes["handoff_required"]
    ]
    observed = [
        events["handoff"][key][0]
        for key in eligible
        if key in events.get("handoff", {})
    ]
    successful = sum(
        event.status == "succeeded"
        and event.attributes["structured"]
        and bool(event.artifact_refs)
        for event in observed
    )
    return {
        "eligible_count": len(eligible),
        "observed_count": len(observed),
        "structured_success_rate": _rate(successful, len(eligible)),
        "p99_seconds": _percentile(
            [event.duration_seconds for event in observed],
            0.99,
        ),
    }


def _artifact_metric(events: EventIndex) -> dict[str, object]:
    validations = [
        event
        for grouped in events.get("artifact_validation", {}).values()
        for event in grouped
    ]
    required = sum(int(event.attributes["required_ref_count"]) for event in validations)
    valid = sum(
        int(event.attributes["valid_ref_count"])
        if event.status == "succeeded"
        else 0
        for event in validations
    )
    return {
        "validation_event_count": len(validations),
        "required_ref_count": required,
        "valid_ref_count": valid,
        "integrity_rate": _rate(valid, required),
    }


def _recovery_metric(
    runs: Mapping[RunKey, TraceEvent],
    events: EventIndex,
    *,
    limit_seconds: float,
) -> dict[str, object]:
    eligible = [
        key for key, event in runs.items() if event.attributes["recovery_required"]
    ]
    observed = [
        events["recovery"][key][0]
        for key in eligible
        if key in events.get("recovery", {})
    ]
    duplicates = sum(
        int(event.attributes["duplicate_committed_actions"])
        for event in observed
    )
    successful = sum(
        event.status == "succeeded"
        and event.attributes["resumed"]
        and event.attributes["duplicate_committed_actions"] == 0
        and event.duration_seconds <= limit_seconds
        for event in observed
    )
    return {
        "eligible_count": len(eligible),
        "observed_count": len(observed),
        "success_rate": _rate(successful, len(eligible)),
        "p99_seconds": _percentile(
            [event.duration_seconds for event in observed],
            0.99,
        ),
        "duplicate_committed_action_count": duplicates,
    }


def _plan_metric(events: EventIndex) -> dict[str, object]:
    candidates = [
        event
        for grouped in events.get("plan_validation", {}).values()
        for event in grouped
        if event.attributes["valid_context"]
    ]
    executable = sum(
        event.status == "succeeded" and event.attributes["executable"]
        for event in candidates
    )
    return {
        "valid_context_count": len(candidates),
        "executable_count": executable,
        "executable_rate": _rate(executable, len(candidates)),
    }


def _convergence_metric(runs: Mapping[RunKey, TraceEvent]) -> dict[str, object]:
    successful = sum(
        (
            event.attributes["converged"]
            or event.status
            in {"failed", "cancelled", "blocked", "inconclusive"}
        )
        and event.deadline_datetime is not None
        and event.ended_datetime <= event.deadline_datetime
        for event in runs.values()
    )
    return {
        "run_count": len(runs),
        "converged_count": successful,
        "convergence_rate": _rate(successful, len(runs)),
        "semantics": "proof-terminal outcome reached within deadline",
    }


def _coverage_metric(
    runs: Mapping[RunKey, TraceEvent],
    events: EventIndex,
) -> dict[str, object]:
    expected = observed = covered = missing = extra = 0
    for key, run in runs.items():
        for kind, field in (
            ("stage", "expected_stage_count"),
            ("action", "expected_action_count"),
        ):
            expected_count = int(run.attributes[field])
            observed_count = len(events.get(kind, {}).get(key, []))
            expected += expected_count
            observed += observed_count
            covered += min(expected_count, observed_count)
            missing += max(0, expected_count - observed_count)
            extra += max(0, observed_count - expected_count)
    return {
        "expected_span_count": expected,
        "observed_span_count": observed,
        "covered_span_count": covered,
        "missing_span_count": missing,
        "extra_span_count": extra,
        "coverage_rate": _rate(covered, expected),
    }


def _percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(quantile * len(ordered)) - 1)
    return ordered[index]


def _rate(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator
