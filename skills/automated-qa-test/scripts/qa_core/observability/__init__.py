"""QA Agent 的严格 tracing 与 SLO 聚合边界。"""

from ._validation import ObservabilityError
from .contracts import (
    TRACE_KINDS,
    TRACE_SCHEMA_VERSION,
    TRACE_STATUSES,
    TraceArtifactRef,
    TraceBudget,
    TraceEvent,
    TraceReason,
    TraceRecord,
)
from .journal import TraceJournal, TraceSnapshot
from .runtime import TRACE_JOURNAL_FILENAME, CycleTracer
from .slo import (
    SloSamplingContract,
    SloThresholds,
    aggregate_run_directories,
    aggregate_slo,
)

__all__ = [
    "TRACE_JOURNAL_FILENAME",
    "TRACE_KINDS",
    "TRACE_SCHEMA_VERSION",
    "TRACE_STATUSES",
    "CycleTracer",
    "ObservabilityError",
    "SloThresholds",
    "SloSamplingContract",
    "TraceArtifactRef",
    "TraceBudget",
    "TraceEvent",
    "TraceJournal",
    "TraceReason",
    "TraceRecord",
    "TraceSnapshot",
    "aggregate_run_directories",
    "aggregate_slo",
]
