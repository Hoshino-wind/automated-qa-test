"""只读验证 run state、attempt manifest 与当前输入形成闭合证明图。"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from qa_common import file_sha256, read_stable_regular_file

from qa_core.context import verify_context_snapshot
from qa_core.contracts.artifacts import ARTIFACT_FILENAMES
from qa_core.human_runtime import (
    verify_human_authorization_artifact,
    verify_human_authorization_for_contracts,
)
from qa_core.observability import TRACE_JOURNAL_FILENAME, TraceJournal
from qa_core.runtime.action_protocol import (
    load_action_contracts,
    verify_action_journal,
)
from qa_core.runtime.attempts import AttemptStore
from qa_core.state import RunEventType, RunStateStore
from qa_core.tools import build_default_tool_registry

from .hashes import canonical_json_sha256, input_file_sha256

_BASE_REQUIRED_INPUT_HASHES = frozenset(
    {
        "cycle_options",
        "tool_registry",
        "plan",
        "matrix",
        "requirement",
        "adapter_context",
        "context_snapshot",
    }
)
_NON_PASS_TERMINAL_STATUSES = frozenset(
    {"blocked", "cancelled", "failed", "inconclusive"}
)
_VERIFIED_OUTCOME_CATEGORIES = frozenset(
    {"success", "failure", "cancellation_or_timeout"}
)
_CANCELLATION_REASON_CODES = frozenset(
    {"cancelled", "deadline_exceeded", "stage_timeout"}
)
_BUDGET_FIELDS = frozenset(
    {
        "started_at",
        "deadline",
        "remaining_time",
        "probes_used",
        "max_probes",
        "output_bytes_used",
        "max_output_bytes",
        "cancelled",
        "cancel_detail",
        "cancelled_at",
    }
)


@dataclass(frozen=True, slots=True)
class ProofVerificationResult:
    """确定性的证明图验证结果；有效观察与 PASS 授权彼此独立。"""

    run_id: str | None
    can_claim_pass: bool
    errors: tuple[dict[str, str], ...]
    verified_refs: dict[str, Any]
    outcome_category: str | None = None

    @property
    def proof_valid(self) -> bool:
        """证明图闭合；不表示该 run 可以声明 PASS。"""

        outcome = self.outcome_category
        if outcome is None and self.can_claim_pass:
            # 兼容只建模历史 PASS 结果的调用方。
            outcome = "success"
        return (
            not self.errors
            and outcome in _VERIFIED_OUTCOME_CATEGORIES
            and self.can_claim_pass == (outcome == "success")
        )

    def to_dict(self) -> dict[str, Any]:
        outcome = self.outcome_category
        if outcome is None and self.can_claim_pass:
            outcome = "success"
        verified_outcome = outcome if self.proof_valid else None
        payload = {
            "schema_version": 2,
            "run_id": self.run_id,
            "proof_valid": self.proof_valid,
            "proof_kind": (
                "pass_claim"
                if verified_outcome == "success"
                else "terminal_observation"
                if verified_outcome is not None
                else "invalid"
            ),
            "outcome_category": verified_outcome,
            "can_claim_pass": self.can_claim_pass,
            "errors": [dict(error) for error in self.errors],
            "verified_refs": self.verified_refs,
        }
        return {
            **payload,
            "proof_graph_sha256": canonical_json_sha256(payload),
        }


def verify_run_proof(run_dir: Path) -> ProofVerificationResult:
    """验证当前磁盘视图中的 PASS claim 或 non-PASS terminal observation。

    ``proof_valid`` 表示一个终局观察的 state/attempt/trace/budget/input
    证明图闭合；``can_claim_pass`` 只对确定性 ``success`` 成立。任何缺失、
    篡改或父哈希漂移都会让二者失败关闭。
    """

    resolved = run_dir.expanduser().resolve()
    errors: list[dict[str, str]] = []
    refs: dict[str, Any] = {}
    run_id: str | None = None

    try:
        store = RunStateStore(resolved)
        events = store.load_events()
        state = store.load_state()
        run_id = state.run_id
        refs["state"] = {
            "sequence": state.sequence,
            "last_event_hash": state.last_event_hash,
            "status": state.status,
        }
    except Exception as error:
        _add_error(errors, "run_state_invalid", error)
        return _result(run_id, errors, refs)

    if state.status != "passed":
        return _verify_non_pass_observation(
            resolved,
            state=state,
            events=events,
            run_id=run_id,
            errors=errors,
            refs=refs,
        )
    if not events or events[-1].event_type is not RunEventType.STATUS_CHANGED:
        _add_error(
            errors,
            "pass_not_terminal",
            "the final event is not status_changed",
        )
        return _result(run_id, errors, refs)
    status_payload = events[-1].payload
    if (
        status_payload.get("status") != "passed"
        or status_payload.get("authority") != "deterministic_verdict"
    ):
        _add_error(
            errors,
            "pass_authority_invalid",
            "the terminal status event lacks deterministic verdict authority",
        )
        return _result(run_id, errors, refs)

    try:
        manifest = AttemptStore(resolved).read_run_manifest()
        if manifest is None:
            raise ValueError("run manifest is missing")
        refs["run_manifest"] = {
            "sequence": manifest["sequence"],
            "generation": manifest["generation"],
            "sha256": manifest["manifest_sha256"],
        }
    except Exception as error:
        _add_error(errors, "run_manifest_invalid", error)
        return _result(run_id, errors, refs)

    attempt_ref = status_payload.get("attempt_ref")
    if not isinstance(attempt_ref, dict):
        _add_error(
            errors,
            "attempt_ref_missing",
            "passed status lacks attempt_ref",
        )
        return _result(run_id, errors, refs)
    if attempt_ref.get("run_manifest_sequence") != manifest["sequence"]:
        _add_error(
            errors,
            "run_manifest_sequence_mismatch",
            "status attempt_ref does not reference current manifest sequence",
        )
    if attempt_ref.get("run_manifest_sha256") != manifest["manifest_sha256"]:
        _add_error(
            errors,
            "run_manifest_hash_mismatch",
            "status attempt_ref does not reference current manifest hash",
        )

    attempt_id = attempt_ref.get("attempt_id")
    try:
        attempt = AttemptStore(resolved).load_attempt(str(attempt_id))
        refs["attempt"] = {
            "attempt_id": attempt.attempt_id,
            "manifest_sha256": attempt.manifest_sha256,
            "generation": attempt.generation,
            "iteration": attempt.iteration,
        }
    except Exception as error:
        _add_error(errors, "attempt_invalid", error)
        return _result(run_id, errors, refs)

    if attempt_ref.get("attempt_manifest_sha256") != attempt.manifest_sha256:
        _add_error(
            errors,
            "attempt_manifest_hash_mismatch",
            "status attempt_ref does not match committed attempt",
        )
    references = {
        item.get("attempt_id"): item.get("manifest_sha256")
        for item in manifest.get("attempts", [])
        if isinstance(item, dict)
    }
    if references.get(attempt.attempt_id) != attempt.manifest_sha256:
        _add_error(
            errors,
            "attempt_not_current",
            "current run manifest does not reference the passed attempt",
        )
    if attempt.run_id != state.run_id or manifest["run_id"] != state.run_id:
        _add_error(
            errors,
            "run_id_mismatch",
            "state, run manifest and attempt must share run_id",
        )
    if attempt.generation != manifest["generation"]:
        _add_error(
            errors,
            "generation_mismatch",
            "attempt is not from the current manifest generation",
        )
    if attempt.iteration != manifest["sequence"]:
        _add_error(
            errors,
            "attempt_not_latest",
            "passed attempt iteration does not match current manifest sequence",
        )
    if attempt.stage != "cycle_complete" or attempt.tool != "run_qa_cycle":
        _add_error(
            errors,
            "attempt_authority_invalid",
            "passed attempt must be a completed run_qa_cycle",
        )

    _verify_parent_hashes(
        resolved,
        state.component_versions,
        attempt.input_hashes,
        errors,
        refs,
    )
    _verify_candidate_identity(
        resolved,
        state.component_versions,
        attempt,
        errors,
        refs,
    )
    _verify_human_authorization(
        resolved,
        state.component_versions,
        attempt,
        errors,
        refs,
    )
    _verify_verdict(
        resolved,
        status_payload.get("verdict_ref"),
        attempt,
        errors,
        refs,
    )
    _verify_context(
        resolved,
        state.component_versions,
        attempt,
        errors,
        refs,
    )
    _verify_action_protocol(
        resolved,
        state.component_versions,
        attempt,
        errors,
        refs,
    )
    _verify_trace(
        resolved,
        state.component_versions,
        attempt,
        events,
        errors,
        refs,
    )
    _verify_terminal_budget(
        state.budget,
        refs,
        errors,
    )
    return _result(
        run_id,
        errors,
        refs,
        outcome_category="success",
    )


def _verify_non_pass_observation(
    run_dir: Path,
    *,
    state: Any,
    events: list[Any],
    run_id: str | None,
    errors: list[dict[str, str]],
    refs: dict[str, Any],
) -> ProofVerificationResult:
    """Verify a terminal observation without granting an affirmative claim."""

    if state.status not in _NON_PASS_TERMINAL_STATUSES:
        _add_error(
            errors,
            "run_not_terminal",
            f"run state is {state.status!r}",
        )
        return _result(run_id, errors, refs)
    if not events or events[-1].event_type is not RunEventType.STATUS_CHANGED:
        _add_error(
            errors,
            "observation_not_terminal",
            "the final state event is not status_changed",
        )
        return _result(run_id, errors, refs)
    status_payload = events[-1].payload
    if (
        status_payload.get("status") != state.status
        or status_payload.get("authority") != "qa-cycle-orchestrator"
    ):
        _add_error(
            errors,
            "observation_authority_invalid",
            (
                "a non-PASS observation must be terminal and published by "
                "qa-cycle-orchestrator"
            ),
        )
        return _result(run_id, errors, refs)

    try:
        manifest = AttemptStore(run_dir).read_run_manifest()
        if manifest is None:
            raise ValueError("run manifest is missing")
        refs["run_manifest"] = {
            "sequence": manifest["sequence"],
            "generation": manifest["generation"],
            "sha256": manifest["manifest_sha256"],
        }
    except Exception as error:
        _add_error(errors, "run_manifest_invalid", error)
        return _result(run_id, errors, refs)

    attempt_ref = status_payload.get("attempt_ref")
    if not isinstance(attempt_ref, dict):
        _add_error(
            errors,
            "observation_attempt_ref_missing",
            "terminal observation lacks an immutable attempt_ref",
        )
        return _result(run_id, errors, refs)
    if attempt_ref.get("run_manifest_sequence") != manifest["sequence"]:
        _add_error(
            errors,
            "run_manifest_sequence_mismatch",
            "terminal observation does not reference current manifest sequence",
        )
    if attempt_ref.get("run_manifest_sha256") != manifest["manifest_sha256"]:
        _add_error(
            errors,
            "run_manifest_hash_mismatch",
            "terminal observation does not reference current manifest hash",
        )

    attempt_id = attempt_ref.get("attempt_id")
    try:
        attempt = AttemptStore(run_dir).load_attempt(str(attempt_id))
        refs["attempt"] = {
            "attempt_id": attempt.attempt_id,
            "manifest_sha256": attempt.manifest_sha256,
            "generation": attempt.generation,
            "iteration": attempt.iteration,
            "stage": attempt.stage,
        }
    except Exception as error:
        _add_error(errors, "attempt_invalid", error)
        return _result(run_id, errors, refs)

    if attempt_ref.get("attempt_manifest_sha256") != attempt.manifest_sha256:
        _add_error(
            errors,
            "attempt_manifest_hash_mismatch",
            "terminal observation does not match the committed attempt",
        )
    references = {
        item.get("attempt_id"): item.get("manifest_sha256")
        for item in manifest.get("attempts", [])
        if isinstance(item, dict)
    }
    if references.get(attempt.attempt_id) != attempt.manifest_sha256:
        _add_error(
            errors,
            "attempt_not_current",
            "current run manifest does not reference the observed attempt",
        )
    if attempt.run_id != state.run_id or manifest["run_id"] != state.run_id:
        _add_error(
            errors,
            "run_id_mismatch",
            "state, run manifest and observed attempt must share run_id",
        )
    if attempt.generation != manifest["generation"]:
        _add_error(
            errors,
            "generation_mismatch",
            "observed attempt is not from the current manifest generation",
        )
    if attempt.iteration != manifest["sequence"]:
        _add_error(
            errors,
            "attempt_not_latest",
            "observed attempt iteration does not match current manifest sequence",
        )
    if attempt.stage != "cycle_handoff" or attempt.tool != "run_qa_cycle":
        _add_error(
            errors,
            "observation_attempt_authority_invalid",
            "non-PASS observation must bind a run_qa_cycle handoff attempt",
        )

    _verify_parent_hashes(
        run_dir,
        state.component_versions,
        attempt.input_hashes,
        errors,
        refs,
    )
    _verify_candidate_identity(
        run_dir,
        state.component_versions,
        attempt,
        errors,
        refs,
    )
    _verify_human_authorization(
        run_dir,
        state.component_versions,
        attempt,
        errors,
        refs,
    )
    if "candidate_identity" not in refs:
        _add_error(
            errors,
            "observation_candidate_identity_required",
            "terminal observation must bind a current candidate identity",
        )
    _verify_non_pass_verdict(
        run_dir,
        status_payload.get("verdict_ref"),
        state_status=state.status,
        attempt=attempt,
        errors=errors,
        refs=refs,
    )
    outcome = _verify_non_pass_trace(
        run_dir,
        state=state,
        attempt=attempt,
        state_events=events,
        errors=errors,
        refs=refs,
    )
    _verify_terminal_budget(
        state.budget,
        refs,
        errors,
    )
    if outcome is not None:
        refs["terminal_observation"] = {
            "outcome_category": outcome,
            "state_status": state.status,
            "not_pass_evidence": True,
        }
    return _result(
        run_id,
        errors,
        refs,
        outcome_category=outcome,
    )


def _verify_non_pass_verdict(
    run_dir: Path,
    raw_ref: Any,
    *,
    state_status: str,
    attempt: Any,
    errors: list[dict[str, str]],
    refs: dict[str, Any],
) -> None:
    if not isinstance(raw_ref, dict):
        _add_error(
            errors,
            "observation_verdict_ref_missing",
            "terminal observation lacks verdict_ref",
        )
        return
    path = run_dir / ARTIFACT_FILENAMES["verdict"]
    try:
        observed_path = Path(str(raw_ref.get("path"))).expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as error:
        _add_error(errors, "verdict_path_invalid", error)
        return
    if observed_path != path:
        _add_error(
            errors,
            "verdict_path_invalid",
            "terminal observation must use the canonical verdict path",
        )
        return
    digest = file_sha256(path)
    refs["verdict"] = {
        "path": str(path),
        "sha256": digest,
        "claim": "non_pass",
    }
    if digest is None or raw_ref.get("sha256") != digest:
        _add_error(
            errors,
            "verdict_hash_mismatch",
            "current verdict does not match the terminal state event",
        )
        return
    artifact = next(
        (
            item
            for item in attempt.artifacts
            if item.name == ARTIFACT_FILENAMES["verdict"]
        ),
        None,
    )
    if artifact is None or artifact.sha256 != digest:
        _add_error(
            errors,
            "verdict_not_committed",
            "non-PASS verdict is not committed in the observed attempt",
        )
        return
    try:
        verdict = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        _add_error(errors, "verdict_invalid", error)
        return
    status_map = {
        "attention": "inconclusive",
        "blocked": "blocked",
        "cancelled": "cancelled",
        "failed": "failed",
        "inconclusive": "inconclusive",
        "untested": "inconclusive",
    }
    declared = verdict.get("verdict") if isinstance(verdict, dict) else None
    if (
        not isinstance(verdict, dict)
        or verdict.get("schema_version") != 1
        or verdict.get("can_claim_pass") is not False
        or not isinstance(declared, str)
        or status_map.get(declared.strip().lower()) != state_status
    ):
        _add_error(
            errors,
            "observation_verdict_invalid",
            (
                "canonical verdict must be schema-v1, explicitly non-PASS, "
                "and agree with terminal state"
            ),
        )


def _verify_non_pass_trace(
    run_dir: Path,
    *,
    state: Any,
    attempt: Any,
    state_events: list[Any],
    errors: list[dict[str, str]],
    refs: dict[str, Any],
) -> str | None:
    if state.component_versions.get("observability") != "1":
        _add_error(
            errors,
            "observability_version_missing",
            "terminal state does not declare observability version 1",
        )
        return None
    expected_hash = state.component_versions.get("trace_journal_sha256")
    if not _is_sha256(expected_hash):
        _add_error(
            errors,
            "trace_hash_missing",
            "terminal state lacks a valid trace journal hash",
        )
        return None
    path = run_dir / TRACE_JOURNAL_FILENAME
    try:
        snapshot = TraceJournal(path).snapshot()
    except Exception as error:
        _add_error(errors, "trace_journal_invalid", error)
        return None
    refs["trace"] = {
        "path": str(path),
        "sha256": snapshot.sha256,
        "event_count": len(snapshot.records),
    }
    if snapshot.sha256 != expected_hash:
        _add_error(
            errors,
            "trace_hash_mismatch",
            "current trace journal does not match terminal state",
        )
        return None
    if not snapshot.records:
        _add_error(errors, "trace_empty", "trace journal contains no events")
        return None
    completed_keys: set[tuple[str, int, int]] = set()
    for record in snapshot.records:
        key = record.event.run_key
        if key in completed_keys:
            _add_error(
                errors,
                "trace_event_after_terminal_run",
                "trace contains events after a run key's terminal span",
            )
            return None
        if record.event.kind == "run":
            completed_keys.add(key)
    final_record = snapshot.records[-1]
    final = final_record.event
    if (
        final.kind != "run"
        or final.run_id != attempt.run_id
        or final.generation != attempt.generation
        or final.attempt_id != attempt.attempt_id
    ):
        _add_error(
            errors,
            "trace_terminal_run_invalid",
            "final trace record is not the observed handoff attempt",
        )
        return None
    refs["trace"].update(
        {
            "terminal_event_sha256": final_record.event_sha256,
            "terminal_status": final.status,
            "terminal_reason": final.reason.code,
            "terminal_budget": final.budget.to_dict(),
        }
    )
    if (
        final.status not in {"failed", "cancelled", "blocked", "inconclusive"}
        or final.attributes.get("converged") is not False
        or final.reason.code != "cycle_handoff"
    ):
        _add_error(
            errors,
            "observation_trace_terminal_invalid",
            "non-PASS trace must close as a non-converged cycle handoff",
        )

    run_records = tuple(
        record.event
        for record in snapshot.records
        if record.event.run_key == final.run_key
    )
    by_kind: dict[str, list[Any]] = {}
    for event in run_records:
        by_kind.setdefault(event.kind, []).append(event)
    if len(by_kind.get("run", [])) != 1:
        _add_error(
            errors,
            "trace_run_marker_count_invalid",
            "observed trace key must contain exactly one run span",
        )
    stage_events = by_kind.get("stage", [])
    action_events = by_kind.get("action", [])
    if final.attributes.get("expected_stage_count") != len(stage_events):
        _add_error(
            errors,
            "trace_stage_coverage_incomplete",
            "observed stage spans do not match the terminal run count",
        )
    if final.attributes.get("expected_action_count") != len(action_events):
        _add_error(
            errors,
            "trace_action_coverage_incomplete",
            "observed action spans do not match the terminal run count",
        )
    if len(
        {
            (
                event.stage,
                event.action,
                event.started_at,
                event.ended_at,
            )
            for event in stage_events
        }
    ) != len(stage_events):
        _add_error(
            errors,
            "trace_stage_duplicate",
            "duplicate stage spans cannot satisfy observation coverage",
        )
    state_start = final.attributes.get("state_start_sequence")
    state_end = final.attributes.get("state_end_sequence")
    if (
        not isinstance(state_start, int)
        or isinstance(state_start, bool)
        or not isinstance(state_end, int)
        or isinstance(state_end, bool)
        or state_start < 0
        or state_end < state_start
        or state_end > state_events[-1].sequence
    ):
        _add_error(
            errors,
            "trace_state_window_invalid",
            "trace run does not bind a valid state-event window",
        )
    else:
        state_stage_bindings = [
            (
                str(event.payload.get("phase")),
                event.payload.get("command_sha256"),
            )
            for event in state_events
            if state_start < event.sequence <= state_end
            and event.event_type is RunEventType.PHASE_CHANGED
            and event.payload.get("trace_required") is True
        ]
        trace_stage_bindings = [
            (event.stage, event.attributes.get("command_sha256"))
            for event in stage_events
        ]
        if trace_stage_bindings != state_stage_bindings:
            _add_error(
                errors,
                "trace_stage_state_mismatch",
                "trace stages do not exactly match command-bound state phases",
            )

    artifacts = {item.name: item for item in attempt.artifacts}
    if ARTIFACT_FILENAMES["results"] in artifacts:
        _verify_trace_actions(
            run_dir,
            attempt,
            action_events,
            errors,
        )
    elif action_events:
        _add_error(
            errors,
            "trace_results_not_committed",
            "observed actions require committed results.json",
        )
    protocol_names = {
        ARTIFACT_FILENAMES["action_contracts"],
        ARTIFACT_FILENAMES["action_journal"],
    }
    present_protocol = protocol_names & set(artifacts)
    if present_protocol:
        if present_protocol != protocol_names or ARTIFACT_FILENAMES[
            "results"
        ] not in artifacts:
            _add_error(
                errors,
                "action_protocol_incomplete",
                "partial action protocol cannot support a terminal observation",
            )
        else:
            _verify_action_protocol(
                run_dir,
                state.component_versions,
                attempt,
                errors,
                refs,
            )

    validations = by_kind.get("plan_validation", [])
    if len(validations) > 1:
        _add_error(
            errors,
            "trace_plan_validation_duplicate",
            "terminal observation contains duplicate plan validations",
        )
    elif validations:
        validation = validations[0]
        if (
            validation.attributes.get("plan_sha256")
            != attempt.input_hashes.get("plan")
        ):
            _add_error(
                errors,
                "trace_plan_hash_unbound",
                "plan validation is not bound to the observed attempt input",
            )
        raw_context_hash = validation.attributes.get("context_sha256")
        if raw_context_hash is not None:
            context_path = run_dir / ARTIFACT_FILENAMES["agent_context"]
            context_result = verify_context_snapshot(
                run_dir,
                context_path,
                require_repository_current=False,
                require_knowledge_current=False,
            )
            context_artifact = artifacts.get(
                ARTIFACT_FILENAMES["agent_context"]
            )
            if (
                not context_result.valid
                or context_result.context_sha256 != raw_context_hash
                or context_artifact is None
                or context_artifact.sha256 != file_sha256(context_path)
            ):
                _add_error(
                    errors,
                    "trace_context_hash_unbound",
                    "plan validation context is not current and committed",
                )

    if final.attributes.get("handoff_required") is not True:
        _add_error(
            errors,
            "trace_handoff_not_required",
            "every non-PASS terminal observation requires an immutable handoff",
        )
    _verify_required_trace_event(
        final,
        by_kind,
        kind="cleanup",
        required_attribute="cleanup_required",
        errors=errors,
    )
    _verify_required_trace_event(
        final,
        by_kind,
        kind="handoff",
        required_attribute="handoff_required",
        errors=errors,
    )
    _verify_required_trace_event(
        final,
        by_kind,
        kind="recovery",
        required_attribute="recovery_required",
        errors=errors,
    )
    _verify_terminal_attempt_refs(
        attempt,
        by_kind,
        errors,
    )
    return _terminal_outcome_category(
        state.status,
        state.budget,
        run_records,
    )


def _verify_terminal_attempt_refs(
    attempt: Any,
    by_kind: dict[str, list[Any]],
    errors: list[dict[str, str]],
) -> None:
    expected = sorted(
        (
            item.attempt_id,
            item.name,
            item.path,
            item.sha256,
            item.size,
        )
        for item in attempt.artifacts
    )
    handoffs = by_kind.get("handoff", [])
    if handoffs:
        observed = sorted(
            (
                item.attempt_id,
                item.name,
                item.path,
                item.sha256,
                item.size,
            )
            for item in handoffs[0].artifact_refs
        )
        if (
            handoffs[0].attempt_id != attempt.attempt_id
            or observed != expected
        ):
            _add_error(
                errors,
                "trace_handoff_attempt_mismatch",
                "handoff must bind the observed attempt and all artifacts",
            )
    validations = by_kind.get("artifact_validation", [])
    if len(validations) != 1:
        _add_error(
            errors,
            "trace_artifact_validation_missing",
            "terminal observation requires one artifact validation span",
        )
        return
    validation = validations[0]
    observed = sorted(
        (
            item.attempt_id,
            item.name,
            item.path,
            item.sha256,
            item.size,
        )
        for item in validation.artifact_refs
    )
    if (
        validation.status != "succeeded"
        or validation.attempt_id != attempt.attempt_id
        or validation.attributes.get("required_ref_count") != len(expected)
        or validation.attributes.get("valid_ref_count") != len(expected)
        or observed != expected
    ):
        _add_error(
            errors,
            "trace_artifact_validation_invalid",
            "artifact validation does not match the observed attempt",
        )


def _terminal_outcome_category(
    state_status: str,
    budget: Any,
    run_records: tuple[Any, ...],
) -> str:
    cancelled = (
        state_status == "cancelled"
        or (
            isinstance(budget, dict)
            and budget.get("cancelled") is True
        )
        or any(
            event.kind == "cancellation"
            or event.status == "cancelled"
            or event.reason.code in _CANCELLATION_REASON_CODES
            for event in run_records
        )
    )
    return "cancellation_or_timeout" if cancelled else "failure"


def _verify_terminal_budget(
    state_budget: Any,
    refs: dict[str, Any],
    errors: list[dict[str, str]],
) -> None:
    trace_ref = refs.get("trace")
    trace_budget = (
        trace_ref.get("terminal_budget")
        if isinstance(trace_ref, dict)
        else None
    )
    if (
        not isinstance(state_budget, dict)
        or set(state_budget) != _BUDGET_FIELDS
        or not isinstance(trace_budget, dict)
    ):
        _add_error(
            errors,
            "terminal_budget_invalid",
            "state and terminal trace must expose complete budget snapshots",
        )
        return
    try:
        started = _finite_number(
            "state.budget.started_at",
            state_budget["started_at"],
        )
        deadline = _finite_number(
            "state.budget.deadline",
            state_budget["deadline"],
        )
        remaining = _optional_finite_number(
            "state.budget.remaining_time",
            state_budget["remaining_time"],
        )
        probes_used = _nonnegative_integer(
            "state.budget.probes_used",
            state_budget["probes_used"],
        )
        max_probes = _optional_nonnegative_integer(
            "state.budget.max_probes",
            state_budget["max_probes"],
        )
        output_used = _nonnegative_integer(
            "state.budget.output_bytes_used",
            state_budget["output_bytes_used"],
        )
        max_output = _optional_nonnegative_integer(
            "state.budget.max_output_bytes",
            state_budget["max_output_bytes"],
        )
        cancelled = state_budget["cancelled"]
        if not isinstance(cancelled, bool):
            raise ValueError("state.budget.cancelled must be boolean")
        cancel_detail = state_budget["cancel_detail"]
        if cancel_detail is not None and not isinstance(cancel_detail, str):
            raise ValueError("state.budget.cancel_detail must be text or null")
        cancelled_at = _optional_finite_number(
            "state.budget.cancelled_at",
            state_budget["cancelled_at"],
        )
    except (TypeError, ValueError) as error:
        _add_error(errors, "terminal_budget_invalid", error)
        return
    if (
        deadline <= started
        or (remaining is not None and remaining < 0)
        or (max_probes is not None and probes_used > max_probes)
        or (max_output is not None and output_used > max_output)
        or cancelled != (cancelled_at is not None)
        or (cancelled and remaining != 0.0)
    ):
        _add_error(
            errors,
            "terminal_budget_invalid",
            "state budget counters, deadline or cancellation fields conflict",
        )
    expected = {
        "total_seconds": deadline - started,
        "probes_used": probes_used,
        "max_probes": max_probes,
        "output_bytes_used": output_used,
        "max_output_bytes": max_output,
        "cancelled": cancelled,
    }
    if any(trace_budget.get(name) != value for name, value in expected.items()):
        _add_error(
            errors,
            "terminal_budget_trace_mismatch",
            "terminal trace budget does not match current state budget",
        )
    trace_remaining = trace_budget.get("remaining_seconds_at_end")
    if (
        trace_remaining is not None
        and (
            isinstance(trace_remaining, bool)
            or not isinstance(trace_remaining, (int, float))
            or not math.isfinite(float(trace_remaining))
            or float(trace_remaining) < 0
            or (
                remaining is not None
                and float(trace_remaining) > remaining + 1e-6
            )
        )
    ):
        _add_error(
            errors,
            "terminal_budget_remaining_invalid",
            "terminal trace remaining budget is not a later state snapshot",
        )
    refs["budget"] = {
        "state_budget_sha256": canonical_json_sha256(state_budget),
        "terminal_trace_budget_sha256": canonical_json_sha256(trace_budget),
        "cancelled": cancelled,
        "probes_used": probes_used,
        "output_bytes_used": output_used,
    }


def _finite_number(name: str, value: Any) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise ValueError(f"{name} must be finite")
    return float(value)


def _optional_finite_number(name: str, value: Any) -> float | None:
    return None if value is None else _finite_number(name, value)


def _nonnegative_integer(name: str, value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
    ):
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _optional_nonnegative_integer(name: str, value: Any) -> int | None:
    return None if value is None else _nonnegative_integer(name, value)


def _verify_parent_hashes(
    run_dir: Path,
    component_versions: dict[str, Any],
    observed: dict[str, str],
    errors: list[dict[str, str]],
    refs: dict[str, Any],
) -> None:
    observed_names = set(observed)
    allowed_names = {
        frozenset(
            {
                *_BASE_REQUIRED_INPUT_HASHES,
                *optional,
            }
        )
        for optional in (
            (),
            ("candidate_identity",),
            ("human_authorization",),
            ("candidate_identity", "human_authorization"),
        )
    }
    if frozenset(observed_names) not in allowed_names:
        _add_error(
            errors,
            "input_hash_set_invalid",
            "attempt input hash names are incomplete or unknown",
        )
        return
    expected = {
        "cycle_options": component_versions.get(
            "cycle_options_sha256"
        ),
        "tool_registry": build_default_tool_registry().canonical_sha256,
        "plan": input_file_sha256(
            "plan",
            run_dir / ARTIFACT_FILENAMES["plan"],
        ),
        "matrix": input_file_sha256(
            "matrix",
            run_dir / ARTIFACT_FILENAMES["matrix"],
        ),
        "requirement": input_file_sha256(
            "requirement",
            run_dir / ARTIFACT_FILENAMES["requirement"],
        ),
        "adapter_context": input_file_sha256(
            "adapter_context",
            run_dir / ARTIFACT_FILENAMES["adapter_context"],
        ),
        "context_snapshot": input_file_sha256(
            "context_snapshot",
            run_dir / ARTIFACT_FILENAMES["agent_context"],
        ),
    }
    if "candidate_identity" in observed:
        expected["candidate_identity"] = input_file_sha256(
            "candidate_identity",
            run_dir / ARTIFACT_FILENAMES[
                "candidate_identity_snapshot"
            ],
        )
    if "human_authorization" in observed:
        expected["human_authorization"] = input_file_sha256(
            "human_authorization",
            run_dir / ARTIFACT_FILENAMES[
                "human_authorization"
            ],
        )
    refs["input_hashes"] = expected
    if component_versions.get("tool_registry_sha256") != expected["tool_registry"]:
        _add_error(
            errors,
            "tool_registry_version_mismatch",
            "state component version does not match the current tool registry",
        )
    for name, expected_hash in expected.items():
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            _add_error(
                errors,
                "state_component_hash_missing",
                f"state lacks a valid {name} hash",
            )
        elif observed.get(name) != expected_hash:
            _add_error(
                errors,
                "input_hash_mismatch",
                f"current {name} does not match the passed attempt",
            )


def _verify_verdict(
    run_dir: Path,
    raw_ref: Any,
    attempt: Any,
    errors: list[dict[str, str]],
    refs: dict[str, Any],
) -> None:
    if not isinstance(raw_ref, dict):
        _add_error(errors, "verdict_ref_missing", "passed state lacks verdict_ref")
        return
    verdict_path = run_dir / ARTIFACT_FILENAMES["verdict"]
    if Path(str(raw_ref.get("path"))).expanduser().resolve() != verdict_path:
        _add_error(
            errors,
            "verdict_path_invalid",
            "passed verdict must use the canonical run path",
        )
        return
    verdict_hash = file_sha256(verdict_path)
    refs["verdict"] = {
        "path": str(verdict_path),
        "sha256": verdict_hash,
    }
    if verdict_hash is None or raw_ref.get("sha256") != verdict_hash:
        _add_error(
            errors,
            "verdict_hash_mismatch",
            "current verdict does not match the terminal state event",
        )
        return
    artifact = next(
        (
            item
            for item in attempt.artifacts
            if item.name == ARTIFACT_FILENAMES["verdict"]
        ),
        None,
    )
    if artifact is None or artifact.sha256 != verdict_hash:
        _add_error(
            errors,
            "verdict_not_committed",
            "current verdict is not the verdict committed in the attempt",
        )
    try:
        verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _add_error(errors, "verdict_invalid", error)
        return
    if (
        not isinstance(verdict, dict)
        or verdict.get("schema_version") != 1
        or verdict.get("verdict") != "passed"
        or verdict.get("can_claim_pass") is not True
    ):
        _add_error(
            errors,
            "verdict_not_passed",
            "canonical verdict is not an explicit schema-v1 pass",
        )


def _verify_candidate_identity(
    run_dir: Path,
    component_versions: dict[str, Any],
    attempt: Any,
    errors: list[dict[str, str]],
    refs: dict[str, Any],
) -> None:
    """Re-verify the immutable pre-dispatch candidate identity snapshot."""

    if "candidate_identity" not in attempt.input_hashes:
        return
    path = run_dir / ARTIFACT_FILENAMES["candidate_identity_snapshot"]
    file_hash = file_sha256(path)
    if not _is_sha256(file_hash):
        _add_error(
            errors,
            "candidate_identity_snapshot_invalid",
            "candidate identity snapshot is missing or unsafe",
        )
        return
    if (
        attempt.input_hashes.get("candidate_identity") != file_hash
        or component_versions.get("candidate_identity_file_sha256")
        != file_hash
    ):
        _add_error(
            errors,
            "candidate_identity_file_hash_mismatch",
            "candidate identity snapshot is not bound to state and attempt",
        )
        return
    artifact = next(
        (
            item
            for item in attempt.artifacts
            if item.name
            == ARTIFACT_FILENAMES["candidate_identity_snapshot"]
        ),
        None,
    )
    if artifact is None or artifact.sha256 != file_hash:
        _add_error(
            errors,
            "candidate_identity_not_committed",
            "candidate identity snapshot is not an immutable attempt artifact",
        )
        return
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        _add_error(errors, "candidate_identity_snapshot_invalid", error)
        return
    if file_sha256(path) != file_hash:
        _add_error(
            errors,
            "candidate_identity_snapshot_changed",
            "candidate identity snapshot changed while being verified",
        )
        return
    top_fields = {
        "schema_version",
        "candidate_identity",
        "candidate_identity_sha256",
        "registration",
        "registration_sha256",
        "source_bindings",
        "not_authorization",
    }
    identity_fields = {
        "agent_bundle_sha256",
        "policy_sha256",
        "tool_registry_sha256",
        "model_id",
        "memory_snapshot_sha256",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != top_fields
        or payload.get("schema_version") != 2
        or payload.get("not_authorization") is not True
        or component_versions.get("candidate_identity") != "2"
    ):
        _add_error(
            errors,
            "candidate_identity_snapshot_schema_invalid",
            "candidate identity snapshot has unknown or missing fields",
        )
        return
    identity = payload.get("candidate_identity")
    registration = payload.get("registration")
    sources = payload.get("source_bindings")
    if (
        not isinstance(identity, dict)
        or set(identity) != identity_fields
        or not isinstance(registration, dict)
        or set(registration) != {"schema_version", *identity_fields}
        or registration.get("schema_version") != 1
        or not isinstance(sources, dict)
        or set(sources)
        != {
            "agent_bundle_tree_sha256",
            "policy_file_sha256",
            "tool_registry_sha256",
            "model_id",
            "memory_snapshot_file_sha256",
            "execution_sources",
            "execution_sources_sha256",
        }
    ):
        _add_error(
            errors,
            "candidate_identity_snapshot_schema_invalid",
            "candidate identity nested contracts are incomplete",
        )
        return
    execution_sources = sources.get("execution_sources")
    if not isinstance(execution_sources, list) or not execution_sources:
        _add_error(
            errors,
            "candidate_identity_execution_sources_invalid",
            "candidate identity lacks actual execution source bindings",
        )
        return
    normalized_execution_sources: list[dict[str, str]] = []
    seen_components: set[str] = set()
    seen_paths: set[str] = set()
    for item in execution_sources:
        if not isinstance(item, dict) or set(item) != {
            "component",
            "path",
            "sha256",
        }:
            _add_error(
                errors,
                "candidate_identity_execution_sources_invalid",
                "candidate execution source entry has an invalid schema",
            )
            return
        component = item.get("component")
        source_path = item.get("path")
        source_sha256 = item.get("sha256")
        parsed_path = (
            PurePosixPath(source_path)
            if isinstance(source_path, str)
            else None
        )
        if (
            not isinstance(component, str)
            or not component
            or component.strip() != component
            or len(component) > 256
            or "/" in component
            or "\\" in component
            or "\x00" in component
            or parsed_path is None
            or parsed_path.is_absolute()
            or not parsed_path.parts
            or any(part in {"", ".", ".."} for part in parsed_path.parts)
            or parsed_path.as_posix() != source_path
            or not _is_sha256(source_sha256)
            or component in seen_components
            or source_path in seen_paths
            or source_path
            not in _candidate_execution_component_paths(component)
        ):
            _add_error(
                errors,
                "candidate_identity_execution_sources_invalid",
                "candidate execution source entry is not canonical",
            )
            return
        seen_components.add(component)
        seen_paths.add(source_path)
        normalized_execution_sources.append(
            {
                "component": component,
                "path": source_path,
                "sha256": source_sha256,
            }
        )
    if (
        normalized_execution_sources
        != sorted(
            normalized_execution_sources,
            key=lambda item: item["component"],
        )
        or not {
            "entrypoint.run_qa_cycle",
            "runner.playwright_probe",
            "qa_common",
            "qa_core",
            "qa_eval",
        }.issubset(seen_components)
        or sources.get("execution_sources_sha256")
        != canonical_json_sha256(normalized_execution_sources)
    ):
        _add_error(
            errors,
            "candidate_identity_execution_sources_invalid",
            (
                "candidate execution source set is incomplete, unordered, "
                "or hash-inconsistent"
            ),
        )
        return
    if (
        not all(
            _is_sha256(identity.get(field))
            for field in (
                "agent_bundle_sha256",
                "policy_sha256",
                "tool_registry_sha256",
                "memory_snapshot_sha256",
            )
        )
        or not isinstance(identity.get("model_id"), str)
        or not identity["model_id"]
        or identity["model_id"].strip() != identity["model_id"]
    ):
        _add_error(
            errors,
            "candidate_identity_value_invalid",
            "candidate identity values are not canonical",
        )
        return
    normalized_registration = {"schema_version": 1, **identity}
    identity_sha256 = canonical_json_sha256(identity)
    registration_sha256 = canonical_json_sha256(
        normalized_registration
    )
    if (
        registration != normalized_registration
        or payload.get("candidate_identity_sha256") != identity_sha256
        or payload.get("registration_sha256") != registration_sha256
        or component_versions.get("candidate_identity_sha256")
        != identity_sha256
        or component_versions.get(
            "candidate_identity_registration_sha256"
        )
        != registration_sha256
        or sources
        != {
            "agent_bundle_tree_sha256": identity[
                "agent_bundle_sha256"
            ],
            "policy_file_sha256": identity["policy_sha256"],
            "tool_registry_sha256": identity[
                "tool_registry_sha256"
            ],
            "model_id": identity["model_id"],
            "memory_snapshot_file_sha256": identity[
                "memory_snapshot_sha256"
            ],
            "execution_sources": normalized_execution_sources,
            "execution_sources_sha256": canonical_json_sha256(
                normalized_execution_sources
            ),
        }
        or identity["tool_registry_sha256"]
        != build_default_tool_registry().canonical_sha256
    ):
        _add_error(
            errors,
            "candidate_identity_binding_mismatch",
            "candidate identity hashes or source bindings do not close",
        )
        return
    refs["candidate_identity"] = dict(identity)
    refs["candidate_execution_sources"] = {
        "sha256": canonical_json_sha256(
            normalized_execution_sources
        ),
        "source_count": len(normalized_execution_sources),
        "verification_boundary": (
            "filesystem_source_snapshot_not_process_memory"
        ),
    }


def _candidate_execution_component_paths(
    component: str,
) -> frozenset[str]:
    fixed = {
        "entrypoint.run_qa_cycle": frozenset({"run_qa_cycle.py"}),
        "runner.playwright_probe": frozenset(
            {"playwright_probe.mjs"}
        ),
        "qa_common": frozenset({"qa_common.py"}),
        "qa_core": frozenset({"qa_core/__init__.py"}),
        "qa_eval": frozenset({"qa_eval/__init__.py"}),
    }
    if component in fixed:
        return fixed[component]
    if component.startswith("qa_core.") or component.startswith(
        "qa_eval."
    ):
        relative = component.replace(".", "/")
        return frozenset(
            {
                f"{relative}.py",
                f"{relative}/__init__.py",
            }
        )
    return frozenset()


def _verify_context(
    run_dir: Path,
    component_versions: dict[str, Any],
    attempt: Any,
    errors: list[dict[str, str]],
    refs: dict[str, Any],
) -> None:
    if component_versions.get("context_snapshot") != "1":
        _add_error(
            errors,
            "context_version_missing",
            "passed state does not declare ContextSnapshot version 1",
        )
        return
    path = run_dir / ARTIFACT_FILENAMES["agent_context"]
    result = verify_context_snapshot(
        run_dir,
        path,
        require_repository_current=False,
        require_knowledge_current=False,
    )
    refs["context"] = {
        "path": str(path),
        "context_sha256": result.context_sha256,
        "file_sha256": file_sha256(path),
    }
    if not result.valid:
        detail = ",".join(
            item["code"] for item in result.errors
        )
        _add_error(
            errors,
            "context_snapshot_invalid",
            detail or "context snapshot validation failed",
        )
        return
    knowledge = (
        result.snapshot.get("knowledge")
        if isinstance(result.snapshot, dict)
        and isinstance(result.snapshot.get("knowledge"), dict)
        else None
    )
    if knowledge is not None:
        currentness = knowledge.get("currentness")
        refs["context"]["knowledge"] = {
            "requested": knowledge.get("requested"),
            "knowledge_snapshot_sha256": knowledge.get(
                "knowledge_snapshot_sha256"
            ),
            "query_rules_sha256": (
                currentness.get("rules_sha256")
                if isinstance(currentness, dict)
                else None
            ),
            "attempt_bound": True,
            "runtime_store_currentness_replayed": False,
        }
    if (
        component_versions.get("context_snapshot_sha256")
        != result.context_sha256
    ):
        _add_error(
            errors,
            "context_component_hash_mismatch",
            "state does not bind the verified ContextSnapshot hash",
        )
    raw_hash = file_sha256(path)
    artifact = next(
        (
            item
            for item in attempt.artifacts
            if item.name == ARTIFACT_FILENAMES["agent_context"]
        ),
        None,
    )
    if (
        raw_hash is None
        or artifact is None
        or artifact.sha256 != raw_hash
    ):
        _add_error(
            errors,
            "context_snapshot_not_committed",
            "the verified ContextSnapshot is not in the passed attempt",
        )


def _verify_human_authorization(
    run_dir: Path,
    component_versions: dict[str, Any],
    attempt: Any,
    errors: list[dict[str, str]],
    refs: dict[str, Any],
) -> None:
    """Verify the exact runtime-gate artifact bound to a gated attempt."""

    if "human_authorization" not in attempt.input_hashes:
        return
    path = run_dir / ARTIFACT_FILENAMES["human_authorization"]
    expected_hash = attempt.input_hashes.get(
        "human_authorization"
    )
    if not _is_sha256(expected_hash):
        _add_error(
            errors,
            "human_authorization_input_hash_invalid",
            "attempt lacks a valid human authorization input hash",
        )
        return
    try:
        raw = read_stable_regular_file(
            path,
            max_bytes=4 * 1024 * 1024,
        )
        observed_hash = hashlib.sha256(raw).hexdigest()
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
        )
        if not isinstance(payload, dict):
            raise ValueError("human authorization root must be an object")
        verified = verify_human_authorization_artifact(
            payload,
            expected_file_sha256=expected_hash,
            artifact_bytes=raw,
        )
        contracts = load_action_contracts(
            run_dir / ARTIFACT_FILENAMES["action_contracts"]
        )
        if contracts.get(
            "human_authorization_sha256"
        ) != expected_hash:
            raise ValueError(
                "action contracts do not bind the human authorization file"
            )
        verify_human_authorization_for_contracts(
            verified,
            contracts,
        )
        if (
            read_stable_regular_file(
                path,
                max_bytes=4 * 1024 * 1024,
            )
            != raw
        ):
            raise ValueError(
                "human authorization changed while proof was verified"
            )
    except Exception as error:
        _add_error(errors, "human_authorization_invalid", error)
        return
    artifact = next(
        (
            item
            for item in attempt.artifacts
            if item.name
            == ARTIFACT_FILENAMES["human_authorization"]
        ),
        None,
    )
    if (
        observed_hash != expected_hash
        or component_versions.get(
            "human_authorization_file_sha256"
        )
        != expected_hash
        or component_versions.get("human_authorization_sha256")
        != verified.get("human_authorization_sha256")
        or artifact is None
        or artifact.sha256 != expected_hash
    ):
        _add_error(
            errors,
            "human_authorization_hash_mismatch",
            "human authorization is not state-bound and committed",
        )
        return
    refs["human_authorization"] = {
        "path": str(path),
        "file_sha256": expected_hash,
        "semantic_sha256": verified[
            "human_authorization_sha256"
        ],
        "execution_intent_sha256": verified["bindings"][
            "execution_intent_sha256"
        ],
        "human_execution_epoch": verified["bindings"][
            "human_execution_epoch"
        ],
        "verification_boundary": "runtime_gate_artifact_binding",
        "external_signature_reverified": False,
    }


def _verify_action_protocol(
    run_dir: Path,
    component_versions: dict[str, Any],
    attempt: Any,
    errors: list[dict[str, str]],
    refs: dict[str, Any],
) -> None:
    if component_versions.get("action_protocol") != "1":
        _add_error(
            errors,
            "action_protocol_version_missing",
            "passed state does not declare action protocol version 1",
        )
        return
    contracts_path = run_dir / ARTIFACT_FILENAMES["action_contracts"]
    journal_path = run_dir / ARTIFACT_FILENAMES["action_journal"]
    results_path = run_dir / ARTIFACT_FILENAMES["results"]
    try:
        contracts = load_action_contracts(contracts_path)
        results = json.loads(
            results_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
        )
        if not isinstance(results, dict):
            raise ValueError("results root must be an object")
        verification = verify_action_journal(
            journal_path,
            contracts,
            results=results,
        )
    except Exception as error:
        _add_error(errors, "action_protocol_invalid", error)
        return
    refs["action_protocol"] = {
        "contracts_path": str(contracts_path),
        "contracts_sha256": file_sha256(contracts_path),
        "journal_path": str(journal_path),
        "journal_sha256": verification.sha256,
        "event_count": verification.event_count,
        "current_action_count": verification.current_action_count,
    }
    if not verification.valid:
        _add_error(
            errors,
            "action_protocol_invalid",
            ",".join(item["code"] for item in verification.errors),
        )
        return
    expected_hashes = {
        ARTIFACT_FILENAMES["action_contracts"]: (
            component_versions.get("action_contracts_sha256")
        ),
        ARTIFACT_FILENAMES["action_journal"]: (
            component_versions.get("action_journal_sha256")
        ),
    }
    observed_hashes = {
        ARTIFACT_FILENAMES["action_contracts"]: file_sha256(
            contracts_path
        ),
        ARTIFACT_FILENAMES["action_journal"]: verification.sha256,
    }
    artifacts = {item.name: item for item in attempt.artifacts}
    for name, expected_hash in expected_hashes.items():
        observed_hash = observed_hashes[name]
        artifact = artifacts.get(name)
        if (
            not _is_sha256(expected_hash)
            or observed_hash != expected_hash
            or artifact is None
            or artifact.sha256 != observed_hash
        ):
            _add_error(
                errors,
                "action_protocol_hash_mismatch",
                f"{name} is not state-bound and committed",
            )


def _verify_trace(
    run_dir: Path,
    component_versions: dict[str, Any],
    attempt: Any,
    state_events: list[Any],
    errors: list[dict[str, str]],
    refs: dict[str, Any],
) -> None:
    """验证 PASS 的实际阶段、动作和不可变产物都进入同一条 trace。"""

    if component_versions.get("observability") != "1":
        _add_error(
            errors,
            "observability_version_missing",
            "passed state does not declare observability version 1",
        )
        return
    expected_hash = component_versions.get("trace_journal_sha256")
    if not _is_sha256(expected_hash):
        _add_error(
            errors,
            "trace_hash_missing",
            "passed state lacks a valid trace journal hash",
        )
        return
    path = run_dir / TRACE_JOURNAL_FILENAME
    if not path.exists():
        _add_error(
            errors,
            "trace_journal_missing",
            f"trace journal is missing: {path}",
        )
        return
    try:
        snapshot = TraceJournal(path).snapshot()
    except Exception as error:
        _add_error(errors, "trace_journal_invalid", error)
        return
    refs["trace"] = {
        "path": str(path),
        "sha256": snapshot.sha256,
        "event_count": len(snapshot.records),
    }
    if snapshot.sha256 != expected_hash:
        _add_error(
            errors,
            "trace_hash_mismatch",
            "current trace journal does not match the terminal state",
        )
        return
    if not snapshot.records:
        _add_error(errors, "trace_empty", "trace journal contains no events")
        return
    completed_keys: set[tuple[str, int, int]] = set()
    for record in snapshot.records:
        key = record.event.run_key
        if key in completed_keys:
            _add_error(
                errors,
                "trace_event_after_terminal_run",
                "trace contains events after a run key's terminal span",
            )
            return
        if record.event.kind == "run":
            completed_keys.add(key)
    final = snapshot.records[-1].event
    if (
        final.kind != "run"
        or final.run_id != attempt.run_id
        or final.generation != attempt.generation
        or final.attempt_id != attempt.attempt_id
    ):
        _add_error(
            errors,
            "trace_terminal_run_invalid",
            "the final trace record is not the passed attempt run span",
        )
        return
    refs["trace"].update(
        {
            "terminal_event_sha256": snapshot.records[-1].event_sha256,
            "terminal_status": final.status,
            "terminal_reason": final.reason.code,
            "terminal_budget": final.budget.to_dict(),
        }
    )
    if (
        final.status != "succeeded"
        or final.attributes.get("converged") is not True
    ):
        _add_error(
            errors,
            "trace_terminal_status_invalid",
            "the passed attempt trace did not finish successfully",
        )

    run_records = tuple(
        record.event
        for record in snapshot.records
        if record.event.run_key == final.run_key
    )
    by_kind: dict[str, list[Any]] = {}
    for event in run_records:
        by_kind.setdefault(event.kind, []).append(event)
    if len(by_kind.get("run", [])) != 1:
        _add_error(
            errors,
            "trace_run_marker_count_invalid",
            "the passed trace key must contain exactly one run span",
        )
    stage_events = by_kind.get("stage", [])
    action_events = by_kind.get("action", [])
    if final.attributes.get("expected_stage_count") != len(stage_events):
        _add_error(
            errors,
            "trace_stage_coverage_incomplete",
            "observed stage spans do not match the terminal run count",
        )
    if final.attributes.get("expected_action_count") != len(action_events):
        _add_error(
            errors,
            "trace_action_coverage_incomplete",
            "observed action spans do not match the terminal run count",
        )
    if any(event.status != "succeeded" for event in stage_events):
        _add_error(
            errors,
            "trace_stage_failed",
            "a passed run contains a non-succeeded stage span",
        )
    if any(event.status != "succeeded" for event in action_events):
        _add_error(
            errors,
            "trace_action_failed",
            "a passed run contains a non-succeeded action span",
        )
    if len(
        {
            (
                event.stage,
                event.action,
                event.started_at,
                event.ended_at,
            )
            for event in stage_events
        }
    ) != len(stage_events):
        _add_error(
            errors,
            "trace_stage_duplicate",
            "duplicate stage spans cannot satisfy observability coverage",
        )
    state_start = final.attributes.get("state_start_sequence")
    state_end = final.attributes.get("state_end_sequence")
    if (
        not isinstance(state_start, int)
        or isinstance(state_start, bool)
        or not isinstance(state_end, int)
        or isinstance(state_end, bool)
        or state_start < 0
        or state_end < state_start
        or state_end > state_events[-1].sequence
    ):
        _add_error(
            errors,
            "trace_state_window_invalid",
            "trace run does not bind a valid current state-event window",
        )
    else:
        state_stage_bindings = [
            (
                str(event.payload.get("phase")),
                event.payload.get("command_sha256"),
            )
            for event in state_events
            if state_start < event.sequence <= state_end
            and event.event_type is RunEventType.PHASE_CHANGED
            and event.payload.get("trace_required") is True
        ]
        trace_stage_bindings = [
            (
                event.stage,
                event.attributes.get("command_sha256"),
            )
            for event in stage_events
        ]
        if trace_stage_bindings != state_stage_bindings:
            _add_error(
                errors,
                "trace_stage_state_mismatch",
                "trace stages do not exactly match command-bound state phases "
                "for the current run window",
            )
    _verify_trace_actions(
        run_dir,
        attempt,
        action_events,
        errors,
    )
    validations = by_kind.get("plan_validation", [])
    if (
        len(validations) != 1
        or validations[0].status != "succeeded"
        or validations[0].attributes.get("valid_context") is not True
        or validations[0].attributes.get("executable") is not True
    ):
        _add_error(
            errors,
            "trace_plan_validation_invalid",
            "a passed run requires one successful executable plan validation",
        )
    else:
        validation = validations[0]
        validate_stages = [
            event
            for event in stage_events
            if event.stage == "validate_plan"
        ]
        context_stages = [
            event
            for event in stage_events
            if event.stage == "compile_agent_context"
        ]
        if (
            len(validate_stages) != 1
            or len(context_stages) != 1
            or validation.stage != "planning"
            or validation.action != "validate_plan_and_context"
            or validation.started_at
            != validate_stages[0].started_at
            or validation.ended_at
            != context_stages[0].ended_at
        ):
            _add_error(
                errors,
                "trace_plan_stage_unbound",
                "plan_validation must span the real plan and context stages",
            )
        if (
            validation.attributes.get("plan_sha256")
            != attempt.input_hashes.get("plan")
            or validation.attributes.get("context_sha256")
            != component_versions.get("context_snapshot_sha256")
        ):
            _add_error(
                errors,
                "trace_plan_hash_unbound",
                "plan_validation hashes do not match the committed proof graph",
            )
    if by_kind.get("cancellation"):
        _add_error(
            errors,
            "trace_pass_after_cancellation",
            "a cancelled trace key cannot authorize PASS",
        )
    _verify_required_trace_event(
        final,
        by_kind,
        kind="cleanup",
        required_attribute="cleanup_required",
        errors=errors,
    )
    _verify_required_trace_event(
        final,
        by_kind,
        kind="handoff",
        required_attribute="handoff_required",
        errors=errors,
    )
    _verify_required_trace_event(
        final,
        by_kind,
        kind="recovery",
        required_attribute="recovery_required",
        errors=errors,
    )
    handoffs = by_kind.get("handoff", [])
    if handoffs:
        expected_handoff_refs = sorted(
            (
                item.attempt_id,
                item.name,
                item.path,
                item.sha256,
                item.size,
            )
            for item in attempt.artifacts
        )
        observed_handoff_refs = sorted(
            (
                item.attempt_id,
                item.name,
                item.path,
                item.sha256,
                item.size,
            )
            for item in handoffs[0].artifact_refs
        )
        if (
            handoffs[0].attempt_id != attempt.attempt_id
            or observed_handoff_refs != expected_handoff_refs
        ):
            _add_error(
                errors,
                "trace_handoff_attempt_mismatch",
                "handoff must bind the current attempt and all its artifacts",
            )

    artifact_events = by_kind.get("artifact_validation", [])
    expected_artifacts = sorted(
        (
            item.attempt_id,
            item.name,
            item.path,
            item.sha256,
            item.size,
        )
        for item in attempt.artifacts
    )
    if len(artifact_events) != 1:
        _add_error(
            errors,
            "trace_artifact_validation_missing",
            "a passed run requires exactly one artifact validation span",
        )
        return
    validation = artifact_events[0]
    observed_artifacts = sorted(
        (
            item.attempt_id,
            item.name,
            item.path,
            item.sha256,
            item.size,
        )
        for item in validation.artifact_refs
    )
    if (
        validation.status != "succeeded"
        or validation.attempt_id != attempt.attempt_id
        or validation.attributes.get("required_ref_count")
        != len(expected_artifacts)
        or validation.attributes.get("valid_ref_count")
        != len(expected_artifacts)
        or observed_artifacts != expected_artifacts
    ):
        _add_error(
            errors,
            "trace_artifact_validation_invalid",
            "trace artifact refs do not exactly match the committed attempt",
        )


def _verify_trace_actions(
    run_dir: Path,
    attempt: Any,
    observed: list[Any],
    errors: list[dict[str, str]],
) -> None:
    artifact = next(
        (
            item
            for item in attempt.artifacts
            if item.name == ARTIFACT_FILENAMES["results"]
        ),
        None,
    )
    if artifact is None:
        _add_error(
            errors,
            "trace_results_not_committed",
            "a passed attempt must commit results.json",
        )
        return
    try:
        payload = json.loads(
            (run_dir / artifact.path).read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
        )
        if not isinstance(payload, dict):
            raise ValueError("results root must be an object")
        scenarios = payload.get("scenarios")
        if not isinstance(scenarios, list):
            raise ValueError("results.scenarios must be an array")
        expected: list[
            tuple[str, str, str, str, str]
        ] = []
        status_map = {
            "passed": "succeeded",
            "failed": "failed",
            "skipped": "blocked",
        }
        identities: set[tuple[str, str]] = set()
        for scenario in scenarios:
            if not isinstance(scenario, dict):
                raise ValueError("results scenario must be an object")
            scenario_id = scenario.get("id")
            steps = scenario.get("steps")
            if not isinstance(scenario_id, str) or not scenario_id:
                raise ValueError("results scenario id is invalid")
            if not isinstance(steps, list):
                raise ValueError("results scenario steps must be an array")
            for step in steps:
                if not isinstance(step, dict):
                    raise ValueError("results step must be an object")
                step_id = step.get("stepId")
                action = step.get("action")
                status = step.get("status")
                started_at = step.get("startedAt")
                ended_at = step.get("finishedAt")
                step_scenario = step.get("scenarioId")
                if (
                    not isinstance(step_id, str)
                    or not step_id
                    or not isinstance(action, str)
                    or not action
                    or step_scenario != scenario_id
                    or status not in status_map
                    or not isinstance(started_at, str)
                    or not isinstance(ended_at, str)
                ):
                    raise ValueError(
                        "results step identity, timing or status is invalid"
                    )
                identity = (scenario_id, step_id)
                if identity in identities:
                    raise ValueError("results step identity is duplicated")
                identities.add(identity)
                expected.append(
                    (
                        f"probe:{scenario_id}",
                        f"{step_id}:{action}",
                        status_map[status],
                        started_at,
                        ended_at,
                    )
                )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        _add_error(errors, "trace_results_invalid", error)
        return
    actual = [
        (
            event.stage,
            event.action,
            event.status,
            event.started_at,
            event.ended_at,
        )
        for event in observed
    ]
    if actual != expected:
        _add_error(
            errors,
            "trace_action_results_mismatch",
            "action spans do not exactly match committed results steps",
        )


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _verify_required_trace_event(
    run_event: Any,
    by_kind: dict[str, list[Any]],
    *,
    kind: str,
    required_attribute: str,
    errors: list[dict[str, str]],
) -> None:
    required = run_event.attributes.get(required_attribute) is True
    events = by_kind.get(kind, [])
    if not required:
        if events:
            _add_error(
                errors,
                f"trace_{kind}_unexpected",
                f"trace declares {kind} unnecessary but records it",
            )
        return
    if len(events) != 1 or events[0].status != "succeeded":
        _add_error(
            errors,
            f"trace_{kind}_invalid",
            f"trace requires exactly one successful {kind} span",
        )
        return
    event = events[0]
    if (
        kind == "cleanup"
        and event.attributes.get("managed_resources_remaining") != 0
    ):
        _add_error(
            errors,
            "trace_cleanup_incomplete",
            "cleanup left managed resources behind",
        )
    if (
        kind == "handoff"
        and (
            event.attributes.get("structured") is not True
            or not event.artifact_refs
        )
    ):
        _add_error(
            errors,
            "trace_handoff_incomplete",
            "required handoff is not structured and artifact-bound",
        )
    if (
        kind == "recovery"
        and (
            event.attributes.get("resumed") is not True
            or event.attributes.get("duplicate_committed_actions") != 0
        )
    ):
        _add_error(
            errors,
            "trace_recovery_invalid",
            "recovery did not resume cleanly without duplicate commits",
        )


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return value == value.lower()


def _result(
    run_id: str | None,
    errors: list[dict[str, str]],
    refs: dict[str, Any],
    *,
    outcome_category: str | None = None,
) -> ProofVerificationResult:
    can_claim_pass = (
        not errors and outcome_category == "success"
    )
    return ProofVerificationResult(
        run_id=run_id,
        can_claim_pass=can_claim_pass,
        errors=tuple(errors),
        verified_refs=refs,
        outcome_category=outcome_category,
    )


def _add_error(
    errors: list[dict[str, str]],
    code: str,
    error: BaseException | str,
) -> None:
    errors.append(
        {
            "code": code,
            "message": str(error),
        }
    )
