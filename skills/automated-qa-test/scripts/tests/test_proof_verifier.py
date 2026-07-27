#!/usr/bin/env python3
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_common import file_sha256  # noqa: E402
from qa_core.context import compile_context_snapshot  # noqa: E402
from qa_core.observability import (  # noqa: E402
    TraceJournal,
    aggregate_run_directories,
)
from qa_core.proof import verify_run_proof  # noqa: E402
from qa_core.runtime import (  # noqa: E402
    CYCLE_OWNER_PREFIX,
    AttemptStore,
    RunSession,
    build_action_contracts,
)
from qa_core.state import RunEventType, RunStateStore  # noqa: E402
from qa_eval import hash_evaluator_bundle  # noqa: E402


def load_cycle_module():
    spec = importlib.util.spec_from_file_location(
        "run_qa_cycle_proof_verifier",
        SCRIPT_DIR / "run_qa_cycle.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load run_qa_cycle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProofVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_cycle_module()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create_passed_run(self, *, with_candidate_identity: bool = False) -> None:
        for filename, content in (
            ("test-plan.json", '{"schemaVersion":2,"scenarios":[]}'),
            ("test-matrix.json", '{"schemaVersion":2,"tests":[]}'),
            ("requirement.md", "# Proof fixture\n"),
            (
                "adapter-context.json",
                json.dumps(
                    {
                        "adapter": "fixture",
                        "environment_boundary": {
                            "runtime_mode": "test",
                            "data_boundary_status": "isolated fixtures",
                        },
                    }
                ),
            ),
        ):
            (self.run_dir / filename).write_text(
                content,
                encoding="utf-8",
            )
        argv = ["--run-dir", str(self.run_dir)]
        if with_candidate_identity:
            source_root = self.run_dir / "candidate-sources"
            source_root.mkdir(parents=True)
            bundle_root = SCRIPT_DIR
            policy_path = source_root / "policy.json"
            memory_path = source_root / "memory.json"
            policy_path.write_text(
                '{"schema_version":1,"policy":"deterministic"}',
                encoding="utf-8",
            )
            memory_path.write_text(
                '{"schema_version":1,"entries":[]}',
                encoding="utf-8",
            )
            identity = {
                "schema_version": 1,
                "agent_bundle_sha256": hash_evaluator_bundle(
                    bundle_root
                ),
                "policy_sha256": file_sha256(policy_path),
                "tool_registry_sha256": (
                    self.module.build_default_tool_registry()
                    .canonical_sha256
                ),
                "model_id": "fixture-model-v1",
                "memory_snapshot_sha256": file_sha256(memory_path),
            }
            registration_path = source_root / "identity.json"
            registration_path.write_text(
                json.dumps(identity),
                encoding="utf-8",
            )
            argv.extend(
                [
                    "--candidate-identity-registration",
                    str(registration_path),
                    "--agent-bundle-dir",
                    str(bundle_root),
                    "--candidate-policy",
                    str(policy_path),
                    "--candidate-memory-snapshot",
                    str(memory_path),
                    "--candidate-model-id",
                    "fixture-model-v1",
                ]
            )
        args = self.module.parse_cycle_options(argv)
        session = RunSession.open(
            self.run_dir,
            owner_prefix=CYCLE_OWNER_PREFIX,
        )
        try:
            runtime = self.module.CycleRuntime(args, session=session)
            validation = runtime.execute_stage(
                "validate_plan",
                [sys.executable, "-c", "raise SystemExit(0)"],
                self.run_dir,
                0,
            )
            self.assertEqual(validation["exit_code"], 0)
            context = compile_context_snapshot(self.run_dir)
            runtime.agent_context_path.write_text(
                json.dumps(context.to_dict()),
                encoding="utf-8",
            )
            runtime.current_artifacts.add(
                runtime.agent_context_path.resolve()
            )
            runtime.plan_audit_summary_path.write_text(
                json.dumps(
                    {
                        "passed": True,
                        "artifact_hashes": {
                            "plan_sha256": file_sha256(
                                runtime.plan_path
                            )
                        },
                    }
                ),
                encoding="utf-8",
            )
            action_contracts = build_action_contracts(
                runtime.plan_path,
                runtime.agent_context_path,
                runtime.plan_audit_summary_path,
                run_id=session.run_id,
                generation=session.generation,
                iteration=runtime.tracer.iteration,
            )
            runtime.action_contracts_path.write_text(
                json.dumps(action_contracts),
                encoding="utf-8",
            )
            runtime.action_contracts_file_sha256 = file_sha256(
                runtime.action_contracts_path
            )
            runtime.action_contracts_semantic_sha256 = (
                action_contracts["contracts_sha256"]
            )
            runtime.current_artifacts.update(
                {
                    runtime.plan_audit_summary_path.resolve(),
                    runtime.action_contracts_path.resolve(),
                }
            )
            context_validation = runtime.execute_stage(
                "compile_agent_context",
                [sys.executable, "-c", "raise SystemExit(0)"],
                self.run_dir,
                0,
            )
            self.assertEqual(context_validation["exit_code"], 0)
            self.assertTrue(
                runtime.record_plan_trace(
                    valid_context=True,
                    executable=True,
                )
            )
            runtime.results_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 2,
                        "status": "passed",
                        "scenarios": [],
                    }
                ),
                encoding="utf-8",
            )
            runtime.current_artifacts.add(
                runtime.results_path.resolve()
            )
            runtime.action_journal_path.write_text("", encoding="utf-8")
            self.assertTrue(runtime.verify_action_dispatch())
            self.assertTrue(runtime.record_probe_trace())
            runtime.verdict_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "verdict": "passed",
                        "can_claim_pass": True,
                    }
                ),
                encoding="utf-8",
            )
            runtime.current_artifacts.add(
                runtime.verdict_path.resolve()
            )
            self.assertEqual(runtime.complete_state(0), 0)
        finally:
            session.close()

    def test_closed_graph_verifies_and_cli_returns_zero(self) -> None:
        self.create_passed_run()

        result = verify_run_proof(self.run_dir)
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "verify_run_proof.py"),
                "--run-dir",
                str(self.run_dir),
            ],
            text=True,
            capture_output=True,
        )

        self.assertTrue(result.can_claim_pass)
        self.assertEqual(result.errors, ())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(json.loads(completed.stdout)["can_claim_pass"])

    def test_proof_verifier_does_not_mutate_read_only_trace_tree(self) -> None:
        self.create_passed_run()
        trace_path = self.run_dir / "agent-trace.jsonl"
        guard_path = self.run_dir / ".agent-trace.jsonl.guard"
        os.chmod(trace_path, 0o444)
        os.chmod(guard_path, 0o444)
        os.chmod(self.run_dir, 0o555)
        before = self._tree_fingerprint()

        try:
            result = verify_run_proof(self.run_dir)
            after = self._tree_fingerprint()
        finally:
            os.chmod(self.run_dir, 0o755)
            os.chmod(trace_path, 0o600)
            os.chmod(guard_path, 0o600)

        self.assertTrue(result.can_claim_pass, result.errors)
        self.assertEqual(after, before)

    def _tree_fingerprint(self) -> tuple[tuple[object, ...], ...]:
        paths = [self.run_dir, *sorted(self.run_dir.rglob("*"))]
        result: list[tuple[object, ...]] = []
        for path in paths:
            metadata = path.lstat()
            relative = (
                "."
                if path == self.run_dir
                else path.relative_to(self.run_dir).as_posix()
            )
            result.append(
                (
                    relative,
                    metadata.st_mode,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    path.read_bytes() if path.is_file() else None,
                )
            )
        return tuple(result)

    def test_real_run_identity_flows_into_proof_and_slo(self) -> None:
        self.create_passed_run(with_candidate_identity=True)

        proof = verify_run_proof(self.run_dir)
        identity = proof.verified_refs["candidate_identity"]
        now = datetime.now(UTC)
        contract = {
            "schema_version": 1,
            "mode": "development",
            "registered_at": (
                now - timedelta(hours=2)
            ).isoformat().replace("+00:00", "Z"),
            "window_started_at": (
                now - timedelta(hours=1)
            ).isoformat().replace("+00:00", "Z"),
            "window_ended_at": (
                now + timedelta(minutes=1)
            ).isoformat().replace("+00:00", "Z"),
            "maximum_run_age_seconds": 3600,
            "minimum_run_count": 1,
            "required_categories": ["success"],
        }
        report = aggregate_run_directories(
            [self.run_dir],
            expected_candidate_identity=identity,
            sampling_contract=contract,
            now=now + timedelta(minutes=1),
        )

        self.assertTrue(proof.can_claim_pass)
        execution_sources = proof.verified_refs[
            "candidate_execution_sources"
        ]
        self.assertGreaterEqual(execution_sources["source_count"], 5)
        self.assertEqual(
            execution_sources["verification_boundary"],
            "filesystem_source_snapshot_not_process_memory",
        )
        self.assertEqual(
            report["proof_results"][0]["candidate_identity"],
            identity,
        )
        self.assertTrue(report["proof_results"][0]["valid"])
        self.assertEqual(report["provenance"], "verified_run_proof")
        self.assertNotIn(
            "proof_candidate_identity_missing",
            {
                failure["code"]
                for failure in report["proof_results"][0]["failures"]
            },
        )

    def test_replacing_parent_input_invalidates_old_pass(self) -> None:
        self.create_passed_run()
        (self.run_dir / "test-plan.json").write_text(
            '{"schemaVersion":2,"changed":true}',
            encoding="utf-8",
        )

        result = verify_run_proof(self.run_dir)

        self.assertFalse(result.can_claim_pass)
        self.assertIn(
            "input_hash_mismatch",
            {error["code"] for error in result.errors},
        )

    def test_candidate_identity_snapshot_tamper_invalidates_pass(self) -> None:
        self.create_passed_run(with_candidate_identity=True)
        identity_path = self.run_dir / "candidate-identity.json"
        payload = json.loads(identity_path.read_text(encoding="utf-8"))
        payload["candidate_identity"]["model_id"] = "tampered-model"
        identity_path.write_text(json.dumps(payload), encoding="utf-8")

        result = verify_run_proof(self.run_dir)

        self.assertFalse(result.can_claim_pass)
        self.assertTrue(
            {
                "input_hash_mismatch",
                "candidate_identity_file_hash_mismatch",
            }
            & {error["code"] for error in result.errors}
        )

    def test_late_trace_append_invalidates_pass(self) -> None:
        self.create_passed_run()
        journal = TraceJournal(self.run_dir / "agent-trace.jsonl")
        journal.append(journal.read()[-1].event)

        trace_result = verify_run_proof(self.run_dir)

        self.assertFalse(trace_result.can_claim_pass)
        self.assertIn(
            "trace_hash_mismatch",
            {error["code"] for error in trace_result.errors},
        )

    def test_context_tamper_invalidates_pass(self) -> None:
        self.create_passed_run()
        context_path = self.run_dir / "agent-context.json"
        context = json.loads(context_path.read_text(encoding="utf-8"))
        context["not_evidence"] = False
        context_path.write_text(json.dumps(context), encoding="utf-8")

        context_result = verify_run_proof(self.run_dir)

        self.assertFalse(context_result.can_claim_pass)
        self.assertTrue(
            {
                "context_snapshot_invalid",
                "input_hash_mismatch",
            }
            & {error["code"] for error in context_result.errors}
        )

    def test_replacing_verdict_or_attempt_artifact_fails_closed(self) -> None:
        self.create_passed_run()
        (self.run_dir / "qa-verdict.json").write_text(
            '{"schema_version":1,"verdict":"passed",'
            '"can_claim_pass":true,"changed":true}',
            encoding="utf-8",
        )

        verdict_result = verify_run_proof(self.run_dir)

        self.assertFalse(verdict_result.can_claim_pass)
        self.assertIn(
            "verdict_hash_mismatch",
            {error["code"] for error in verdict_result.errors},
        )

        self.create_passed_run()
        manifest = AttemptStore(self.run_dir).read_run_manifest()
        assert manifest is not None
        attempt = AttemptStore(self.run_dir).load_attempt(
            manifest["attempts"][-1]["attempt_id"]
        )
        verdict_artifact = next(
            item
            for item in attempt.artifacts
            if item.name == "qa-verdict.json"
        )
        artifact_path = self.run_dir / verdict_artifact.path
        os.chmod(artifact_path, 0o600)
        artifact_path.write_text("tampered", encoding="utf-8")

        attempt_result = verify_run_proof(self.run_dir)

        self.assertFalse(attempt_result.can_claim_pass)
        self.assertIn(
            "run_manifest_invalid",
            {error["code"] for error in attempt_result.errors},
        )

    def test_non_terminal_event_invalidates_pass_projection(self) -> None:
        self.create_passed_run()
        RunStateStore(self.run_dir).append(
            RunEventType.FACT_RECORDED,
            {
                "id": "late-fact",
                "statement": "unauthorized late mutation",
                "source_refs": [],
            },
            actor="rogue-writer",
        )

        result = verify_run_proof(self.run_dir)

        self.assertFalse(result.can_claim_pass)
        self.assertIn(
            "pass_not_terminal",
            {error["code"] for error in result.errors},
        )

    def test_old_attempt_cannot_authorize_current_manifest_pass(self) -> None:
        self.create_passed_run()
        first_pass = RunStateStore(self.run_dir).load_events()[-1]
        old_attempt_ref = dict(first_pass.payload["attempt_ref"])
        old_verdict_ref = dict(first_pass.payload["verdict_ref"])
        self.create_passed_run()
        RunStateStore(self.run_dir).append(
            RunEventType.STATUS_CHANGED,
            {
                "status": "passed",
                "authority": "deterministic_verdict",
                "attempt_ref": old_attempt_ref,
                "verdict_ref": old_verdict_ref,
            },
            actor="rogue-writer",
        )

        result = verify_run_proof(self.run_dir)

        self.assertFalse(result.can_claim_pass)
        self.assertIn(
            "attempt_not_latest",
            {error["code"] for error in result.errors},
        )


if __name__ == "__main__":
    unittest.main()
