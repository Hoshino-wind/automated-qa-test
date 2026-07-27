#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import agent_slo_report  # noqa: E402
from qa_core.observability import (  # noqa: E402
    ObservabilityError,
    SloSamplingContract,
    SloThresholds,
    TraceEvent,
    TraceJournal,
    TraceRecord,
    aggregate_run_directories,
    aggregate_slo,
)
from qa_core.proof import ProofVerificationResult  # noqa: E402

_ORIGIN = datetime(2026, 7, 26, tzinfo=UTC)
_ATTEMPT_ID = "att_" + "2" * 32
_INPUT_HASHES = {"trace:fixture": "f" * 64}
_CANDIDATE_IDENTITY = {
    "agent_bundle_sha256": "a" * 64,
    "policy_sha256": "b" * 64,
    "tool_registry_sha256": "c" * 64,
    "model_id": "candidate-model-v1",
    "memory_snapshot_sha256": "d" * 64,
}


def _development_sampling_contract() -> dict:
    return {
        "schema_version": 1,
        "mode": "development",
        "registered_at": "2026-07-25T23:00:00Z",
        "window_started_at": "2026-07-26T00:00:00Z",
        "window_ended_at": "2026-07-26T00:01:00Z",
        "maximum_run_age_seconds": 86400,
        "minimum_run_count": 1,
        "required_categories": [
            "cancellation_or_timeout",
            "success",
        ],
    }


def _write_slo_contract_inputs(root: Path) -> tuple[Path, Path]:
    identity_path = root / "candidate-identity.json"
    sampling_path = root / "sampling-contract.json"
    identity_path.write_text(
        json.dumps(_CANDIDATE_IDENTITY),
        encoding="utf-8",
    )
    sampling_path.write_text(
        json.dumps(_development_sampling_contract()),
        encoding="utf-8",
    )
    return identity_path, sampling_path


def _time(seconds: float) -> str:
    return (_ORIGIN + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _artifact() -> dict:
    return {
        "attempt_id": _ATTEMPT_ID,
        "name": "results.json",
        "path": f"attempts/{_ATTEMPT_ID}/committed/artifacts/results.json",
        "sha256": "a" * 64,
        "size": 12,
    }


def _event(
    kind: str,
    *,
    started: float,
    duration: float,
    attributes: dict,
    status: str = "succeeded",
    artifacts: list[dict] | None = None,
    action: str | None = None,
    run_id: str = "run-1",
) -> dict:
    normalized_attributes = dict(attributes)
    if kind == "run":
        normalized_attributes.setdefault("state_start_sequence", 0)
        normalized_attributes.setdefault("state_end_sequence", 1)
    elif kind == "stage":
        normalized_attributes.setdefault("command_sha256", "c" * 64)
    elif kind == "plan_validation":
        normalized_attributes.setdefault("plan_sha256", "d" * 64)
        normalized_attributes.setdefault("context_sha256", "e" * 64)
    return {
        "schema_version": 1,
        "run_id": run_id,
        "generation": 1,
        "iteration": 1,
        "attempt_id": _ATTEMPT_ID,
        "kind": kind,
        "stage": "agent",
        "action": action or kind,
        "status": status,
        "started_at": _time(started),
        "ended_at": _time(started + duration),
        "duration_seconds": duration,
        "budget": {
            "total_seconds": 60.0,
            "deadline_at": _time(60),
            "remaining_seconds_at_start": max(0.0, 60 - started),
            "remaining_seconds_at_end": max(0.0, 60 - started - duration),
            "probes_used": 2,
            "max_probes": 10,
            "output_bytes_used": 100,
            "max_output_bytes": 1000,
            "cancelled": kind == "cancellation",
        },
        "reason": {"code": "completed", "detail": None},
        "artifact_refs": artifacts or [],
        "attributes": normalized_attributes,
    }


def _perfect_events(
    *,
    run_id: str = "run-1",
    terminal_run: bool = False,
) -> list[dict]:
    artifact = _artifact()
    events = [
        _event(
            "run",
            started=0,
            duration=50,
            attributes={
                "expected_stage_count": 1,
                "expected_action_count": 1,
                "cleanup_required": True,
                "handoff_required": True,
                "recovery_required": True,
                "converged": True,
            },
            run_id=run_id,
        ),
        _event("stage", started=1, duration=5, attributes={}, run_id=run_id),
        _event(
            "action",
            started=7,
            duration=5,
            attributes={},
            action="probe",
            run_id=run_id,
        ),
        _event("plan_validation", started=0.5, duration=0.5, attributes={
            "valid_context": True,
            "executable": True,
        }, run_id=run_id),
        _event("recovery", started=13, duration=5, attributes={
            "resumed": True,
            "duplicate_committed_actions": 0,
        }, run_id=run_id),
        _event(
            "cancellation",
            started=20,
            duration=1,
            attributes={},
            run_id=run_id,
        ),
        _event("cleanup", started=25, duration=5, attributes={
            "managed_resources_remaining": 0,
        }, run_id=run_id),
        _event(
            "handoff",
            started=31,
            duration=5,
            attributes={"structured": True},
            artifacts=[artifact],
            run_id=run_id,
        ),
        _event(
            "artifact_validation",
            started=37,
            duration=1,
            attributes={"required_ref_count": 1, "valid_ref_count": 1},
            artifacts=[artifact],
            run_id=run_id,
        ),
    ]
    return [*events[1:], events[0]] if terminal_run else events


def _records(events: list[dict]) -> tuple[TraceRecord, ...]:
    records = []
    previous = None
    for sequence, payload in enumerate(events, start=1):
        record = TraceRecord.create(
            TraceEvent.from_dict(payload),
            sequence=sequence,
            previous_event_sha256=previous,
        )
        records.append(record)
        previous = record.event_sha256
    return tuple(records)


def _proof_result(
    run_dir: Path,
    *,
    trace_sha256: str,
    valid: bool,
    run_id: str = "run-1",
    outcome_category: str = "success",
) -> ProofVerificationResult:
    state_status = (
        "passed"
        if outcome_category == "success"
        else "inconclusive"
    )
    return ProofVerificationResult(
        run_id=run_id,
        can_claim_pass=valid and outcome_category == "success",
        errors=(
            ()
            if valid
            else (
                {
                    "code": "fixture_proof_invalid",
                    "message": "fixture proof is intentionally invalid",
                },
            )
        ),
        verified_refs={
            "state": {
                "sequence": 7,
                "last_event_hash": "f" * 64,
                "status": state_status,
            },
            "attempt": {
                "attempt_id": _ATTEMPT_ID,
                "manifest_sha256": "b" * 64,
                "generation": 1,
                "iteration": 1,
            },
            "trace": {
                "path": str((run_dir / "agent-trace.jsonl").resolve()),
                "sha256": trace_sha256,
                "event_count": 9,
            },
            "candidate_identity": dict(_CANDIDATE_IDENTITY),
            "budget": {
                "state_budget_sha256": "e" * 64,
                "terminal_trace_budget_sha256": "f" * 64,
            },
        },
        outcome_category=outcome_category,
    )


class AgentSloReportTests(unittest.TestCase):
    def test_perfect_self_reported_trace_is_analysis_only(self) -> None:
        report = aggregate_slo(
            _records(_perfect_events()),
            input_hashes=_INPUT_HASHES,
        )

        self.assertFalse(report["qualified"])
        self.assertTrue(report["analysis_qualified"])
        self.assertTrue(report["not_production_qualified"])
        self.assertEqual(report["provenance"], "synthetic_or_unverified")
        self.assertEqual(report["blocking_gate"], "provenance")
        self.assertIn(
            "production_run_proof_required",
            {item["code"] for item in report["gate_failures"]},
        )
        self.assertEqual(
            report["metrics"]["artifact_integrity"]["integrity_rate"],
            1.0,
        )
        self.assertEqual(
            report["metrics"]["cancellation_stop_dispatch"]["p95_stop_seconds"],
            1.0,
        )
        self.assertEqual(
            report["metrics"]["cancellation_stop_dispatch"]["stop_success_rate"],
            1.0,
        )
        self.assertEqual(
            report["metrics"]["observability_coverage"]["coverage_rate"],
            1.0,
        )
        self.assertEqual(report["inputs"]["sha256"], _INPUT_HASHES)
        unsigned = dict(report)
        recorded_hash = unsigned.pop("report_sha256")
        expected_hash = hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(recorded_hash, expected_hash)

    def test_empty_denominators_are_none_and_fail_closed(self) -> None:
        only_run = _event(
            "run",
            started=0,
            duration=10,
            attributes={
                "expected_stage_count": 0,
                "expected_action_count": 0,
                "cleanup_required": False,
                "handoff_required": False,
                "recovery_required": False,
                "converged": True,
            },
        )

        report = aggregate_slo(
            _records([only_run]),
            input_hashes=_INPUT_HASHES,
        )

        self.assertFalse(report["qualified"])
        self.assertIsNone(
            report["metrics"]["artifact_integrity"]["integrity_rate"]
        )
        self.assertIsNone(
            report["metrics"]["cancellation_stop_dispatch"]["p95_stop_seconds"]
        )
        self.assertIsNone(
            report["metrics"]["observability_coverage"]["coverage_rate"]
        )
        codes = {failure["code"] for failure in report["gate_failures"]}
        self.assertIn("artifact_integrity_denominator_empty", codes)
        self.assertIn("cancellation_stop_dispatch_denominator_empty", codes)
        self.assertIn("plan_executability_denominator_empty", codes)

    def test_gate_order_is_lexicographic_across_multiple_failures(self) -> None:
        events = _perfect_events()
        events[5]["ended_at"] = _time(23)
        events[5]["duration_seconds"] = 3
        events[7]["attributes"]["structured"] = False
        events[8]["attributes"]["valid_ref_count"] = 0
        events[8]["status"] = "failed"

        report = aggregate_slo(
            _records(events),
            input_hashes=_INPUT_HASHES,
        )

        self.assertFalse(report["qualified"])
        self.assertEqual(report["blocking_gate"], "provenance")
        ranks = {
            name: index
            for index, name in enumerate(report["gate_order"])
        }
        observed = [ranks[item["gate"]] for item in report["gate_failures"]]
        self.assertEqual(observed, sorted(observed))
        self.assertIn(
            "artifact_integrity",
            {item["code"] for item in report["gate_failures"]},
        )
        self.assertIn(
            "cancellation_stop_dispatch",
            {item["code"] for item in report["gate_failures"]},
        )
        self.assertIn(
            "handoff_success",
            {item["code"] for item in report["gate_failures"]},
        )

    def test_action_dispatched_after_cancel_stop_is_release_blocker(self) -> None:
        events = _perfect_events()
        events[2]["started_at"] = _time(22)
        events[2]["ended_at"] = _time(27)

        report = aggregate_slo(
            _records(events),
            input_hashes=_INPUT_HASHES,
        )

        self.assertEqual(
            report["metrics"]["cancellation_stop_dispatch"][
                "post_stop_dispatch_count"
            ],
            1,
        )
        self.assertIn(
            "post_cancel_dispatch",
            {item["code"] for item in report["gate_failures"]},
        )

    def test_deadline_overrun_uses_per_run_budget_tolerance(self) -> None:
        events = _perfect_events()
        events[0]["ended_at"] = _time(75)
        events[0]["duration_seconds"] = 75
        events[0]["attributes"]["converged"] = False

        report = aggregate_slo(
            _records(events),
            input_hashes=_INPUT_HASHES,
        )

        deadline = report["metrics"]["deadline_overrun"]
        self.assertEqual(deadline["p99_overrun_seconds"], 15.0)
        self.assertEqual(deadline["p99_excess_seconds"], 5.0)
        self.assertIn(
            "deadline_overrun",
            {item["code"] for item in report["gate_failures"]},
        )

    def test_stage_counts_cannot_hide_missing_action_trace(self) -> None:
        events = _perfect_events()
        events[2]["kind"] = "stage"
        events[2]["attributes"] = {"command_sha256": "c" * 64}

        report = aggregate_slo(
            _records(events),
            input_hashes=_INPUT_HASHES,
        )

        coverage = report["metrics"]["observability_coverage"]
        self.assertEqual(coverage["coverage_rate"], 0.5)
        self.assertEqual(coverage["missing_span_count"], 1)
        self.assertEqual(coverage["extra_span_count"], 1)

    def test_threshold_contract_rejects_unknown_fields(self) -> None:
        value = SloThresholds().to_dict()
        value["weighted_score"] = 1.0

        with self.assertRaises(ObservabilityError) as caught:
            SloThresholds.from_dict(value)

        self.assertEqual(caught.exception.code, "schema_unknown_fields")

        weakened = SloThresholds().to_dict()
        weakened["artifact_integrity_rate"] = 0.99
        with self.assertRaises(ObservabilityError) as weakened_error:
            SloThresholds.from_dict(weakened)
        self.assertEqual(
            weakened_error.exception.code,
            "slo_threshold_weakened",
        )

    def test_production_sampling_contract_cannot_be_reduced_to_one_run(
        self,
    ) -> None:
        weakened = _development_sampling_contract()
        weakened["mode"] = "production"

        with self.assertRaises(ObservabilityError) as caught:
            SloSamplingContract.from_dict(weakened)

        self.assertEqual(
            caught.exception.code,
            "slo_sampling_contract_weakened",
        )

        missing_categories = _development_sampling_contract()
        missing_categories["mode"] = "production"
        missing_categories["minimum_run_count"] = 20
        missing_categories["maximum_run_age_seconds"] = 604800
        missing_categories["required_categories"] = ["success"]
        with self.assertRaises(ObservabilityError) as categories:
            SloSamplingContract.from_dict(missing_categories)
        self.assertEqual(
            categories.exception.code,
            "slo_sampling_contract_weakened",
        )

    def test_proof_must_bind_every_candidate_identity_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            journal = TraceJournal(run_dir / "agent-trace.jsonl")
            for event in _perfect_events(terminal_run=True):
                journal.append(event)
            snapshot = journal.snapshot()
            proof = _proof_result(
                run_dir,
                trace_sha256=snapshot.sha256,
                valid=True,
            )
            del proof.verified_refs["candidate_identity"]["policy_sha256"]

            with patch(
                "qa_core.proof.verify_run_proof",
                return_value=proof,
            ), patch(
                "qa_core.observability.slo._sampling_now",
                return_value=datetime(2026, 7, 26, 1, 0, tzinfo=UTC),
            ):
                report = aggregate_run_directories(
                    [run_dir],
                    expected_candidate_identity=_CANDIDATE_IDENTITY,
                    sampling_contract=_development_sampling_contract(),
                    now=datetime(2026, 7, 26, 1, 0, tzinfo=UTC),
                )

        self.assertFalse(report["qualified"])
        self.assertIn(
            "proof_candidate_identity_missing",
            {
                failure["code"]
                for failure in report["proof_results"][0]["failures"]
            },
        )

    def test_historical_generations_do_not_inflate_sample_count(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            journal = TraceJournal(run_dir / "agent-trace.jsonl")
            for event in _perfect_events(
                run_id="historical-run",
                terminal_run=True,
            ):
                journal.append(event)
            for event in _perfect_events(
                run_id="run-1",
                terminal_run=True,
            ):
                journal.append(event)
            snapshot = journal.snapshot()
            proof = _proof_result(
                run_dir,
                trace_sha256=snapshot.sha256,
                valid=True,
            )
            contract = _development_sampling_contract()
            contract["minimum_run_count"] = 2

            with patch(
                "qa_core.proof.verify_run_proof",
                return_value=proof,
            ):
                report = aggregate_run_directories(
                    [run_dir],
                    expected_candidate_identity=_CANDIDATE_IDENTITY,
                    sampling_contract=contract,
                    now=datetime(2026, 7, 26, 1, 0, tzinfo=UTC),
                )

        self.assertEqual(report["sampling"]["run_count"], 1)
        self.assertIn(
            "sampling_run_count_insufficient",
            {failure["code"] for failure in report["gate_failures"]},
        )

    def test_trace_only_cli_binds_bytes_but_never_qualifies_production(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace_path = root / "trace.jsonl"
            output_path = root / "slo.json"
            journal = TraceJournal(trace_path)
            for event in _perfect_events():
                journal.append(event)
            expected_hash = hashlib.sha256(trace_path.read_bytes()).hexdigest()

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = agent_slo_report.main(
                    [
                        "--trace",
                        str(trace_path),
                        "--out",
                        str(output_path),
                    ]
                )

            self.assertEqual(exit_code, 1, stderr.getvalue())
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertFalse(report["qualified"])
            self.assertTrue(report["analysis_qualified"])
            self.assertTrue(report["not_production_qualified"])
            self.assertEqual(
                report["provenance"],
                "synthetic_or_unverified",
            )
            self.assertEqual(
                report["inputs"]["sha256"][f"trace:{trace_path.resolve()}"],
                expected_hash,
            )
            self.assertEqual(stdout.getvalue().strip(), str(output_path.resolve()))

    def test_run_dir_cli_development_sampling_never_qualifies_production(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            run_dir.mkdir()
            trace_path = run_dir / "agent-trace.jsonl"
            journal = TraceJournal(trace_path)
            for event in _perfect_events(terminal_run=True):
                journal.append(event)
            snapshot = journal.snapshot()
            proof = _proof_result(
                run_dir,
                trace_sha256=snapshot.sha256,
                valid=True,
            )
            output_path = root / "slo.json"
            identity_path, sampling_path = _write_slo_contract_inputs(root)

            with patch(
                "qa_core.proof.verify_run_proof",
                return_value=proof,
            ):
                exit_code = agent_slo_report.main(
                    [
                        "--run-dir",
                        str(run_dir),
                        "--candidate-identity",
                        str(identity_path),
                        "--sampling-contract",
                        str(sampling_path),
                        "--out",
                        str(output_path),
                    ]
                )

            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 1)
            self.assertFalse(report["qualified"])
            self.assertTrue(report["analysis_qualified"])
            self.assertTrue(report["not_production_qualified"])
            self.assertEqual(report["provenance"], "verified_run_proof")
            self.assertEqual(report["proof_results"][0]["valid"], True)
            self.assertEqual(
                report["candidate_identity"],
                _CANDIDATE_IDENTITY,
            )
            self.assertEqual(
                report["inputs"]["sha256"][f"trace:{trace_path.resolve()}"],
                snapshot.sha256,
            )
            self.assertEqual(
                report["sampling"]["proof_outcome_counts"],
                {
                    "cancellation_or_timeout": 0,
                    "failure": 0,
                    "success": 1,
                },
            )
            self.assertIn(
                "sampling_categories_missing",
                {
                    failure["code"]
                    for failure in report["gate_failures"]
                    if failure["gate"] == "sampling"
                },
            )

    def test_mixed_valid_and_invalid_run_roots_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid_root = root / "valid"
            invalid_root = root / "invalid"
            valid_root.mkdir()
            invalid_root.mkdir()
            snapshots = {}
            for index, run_dir in enumerate((valid_root, invalid_root), start=1):
                journal = TraceJournal(run_dir / "agent-trace.jsonl")
                for event in _perfect_events(
                    run_id=f"run-{index}",
                    terminal_run=True,
                ):
                    journal.append(event)
                snapshots[run_dir.resolve()] = journal.snapshot()

            def verify(candidate: Path) -> ProofVerificationResult:
                resolved = candidate.resolve()
                if resolved == invalid_root.resolve():
                    return _proof_result(
                        resolved,
                        trace_sha256=snapshots[resolved].sha256,
                        valid=False,
                        run_id="run-2",
                    )
                return _proof_result(
                    resolved,
                    trace_sha256=snapshots[resolved].sha256,
                    valid=True,
                    run_id="run-1",
                )

            output_path = root / "slo.json"
            identity_path, sampling_path = _write_slo_contract_inputs(root)
            with patch(
                "qa_core.proof.verify_run_proof",
                side_effect=verify,
            ), patch(
                "qa_core.observability.slo._sampling_now",
                return_value=datetime(2026, 7, 26, 1, 0, tzinfo=UTC),
            ):
                exit_code = agent_slo_report.main(
                    [
                        "--run-dir",
                        str(valid_root),
                        "--run-dir",
                        str(invalid_root),
                        "--candidate-identity",
                        str(identity_path),
                        "--sampling-contract",
                        str(sampling_path),
                        "--out",
                        str(output_path),
                    ]
                )

            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 1)
            self.assertFalse(report["qualified"])
            self.assertTrue(report["analysis_qualified"])
            self.assertTrue(report["not_production_qualified"])
            self.assertEqual(report["blocking_gate"], "provenance")
            failures = [
                item
                for item in report["gate_failures"]
                if item["gate"] == "provenance"
            ]
            self.assertEqual(len(failures), 1)
            self.assertEqual(failures[0]["code"], "run_proof_invalid")
            self.assertIn(
                "run_proof_rejected",
                failures[0]["details"]["failure_codes"],
            )

    def test_production_aggregate_rejects_trace_hash_not_bound_by_proof(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            journal = TraceJournal(run_dir / "agent-trace.jsonl")
            for event in _perfect_events(terminal_run=True):
                journal.append(event)
            forged = _proof_result(
                run_dir,
                trace_sha256="0" * 64,
                valid=True,
            )

            with patch(
                "qa_core.proof.verify_run_proof",
                return_value=forged,
            ):
                report = aggregate_run_directories(
                    [run_dir],
                    expected_candidate_identity=_CANDIDATE_IDENTITY,
                    sampling_contract=_development_sampling_contract(),
                    now=datetime(2026, 7, 26, 1, 0, tzinfo=UTC),
                )

            self.assertFalse(report["qualified"])
            codes = {
                item["code"]
                for item in report["proof_results"][0]["failures"]
            }
            self.assertIn(
                "proof_trace_hash_mismatch",
                codes,
            )

    def test_cli_rejects_duplicate_and_nonfinite_threshold_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace_path = root / "agent-trace.jsonl"
            journal = TraceJournal(trace_path)
            for event in _perfect_events():
                journal.append(event)
            base = json.dumps(
                SloThresholds().to_dict(),
                separators=(",", ":"),
            )
            invalid_payloads = {
                "duplicate": (
                    base[:-1]
                    + ',"deadline_p99_excess_seconds":0.0}'
                ),
                "nonfinite": base.replace(
                    '"deadline_p99_excess_seconds":0.0',
                    '"deadline_p99_excess_seconds":NaN',
                ),
            }
            for name, payload in invalid_payloads.items():
                with self.subTest(name=name):
                    thresholds_path = root / f"{name}.json"
                    output_path = root / f"{name}-report.json"
                    thresholds_path.write_text(payload, encoding="utf-8")

                    with redirect_stdout(io.StringIO()), redirect_stderr(
                        io.StringIO()
                    ):
                        exit_code = agent_slo_report.main(
                            [
                                "--trace",
                                str(trace_path),
                                "--thresholds",
                                str(thresholds_path),
                                "--out",
                                str(output_path),
                            ]
                        )

                    self.assertEqual(exit_code, 2)
                    error = json.loads(
                        output_path.read_text(encoding="utf-8")
                    )
                    self.assertEqual(
                        error["error"],
                        "observability_contract_error",
                    )

    def test_run_dir_aliases_and_count_are_bounded_before_verification(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            run_dir.mkdir()
            for name, arguments in {
                "alias": [str(run_dir), str(run_dir / ".")],
                "limit": [str(run_dir)] * 33,
            }.items():
                with self.subTest(name=name):
                    output_path = root / f"{name}.json"
                    argv = [
                        item
                        for value in arguments
                        for item in ("--run-dir", value)
                    ]
                    with patch(
                        "qa_core.proof.verify_run_proof",
                    ) as verifier, redirect_stdout(
                        io.StringIO()
                    ), redirect_stderr(
                        io.StringIO()
                    ):
                        exit_code = agent_slo_report.main(
                            [
                                *argv,
                                "--out",
                                str(output_path),
                            ]
                        )

                    self.assertEqual(exit_code, 2)
                    verifier.assert_not_called()


if __name__ == "__main__":
    unittest.main()
