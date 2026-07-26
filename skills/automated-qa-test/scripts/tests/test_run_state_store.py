#!/usr/bin/env python3
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.state import (  # noqa: E402
    EventLogError,
    RunEventType,
    RunStateStore,
)


class RunStateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temporary.name)
        self.store = RunStateStore(self.run_dir)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def initialize(self) -> None:
        self.store.initialize(
            run_id="run-001",
            goal="验证结算流程不能产生假通过",
            scope=["checkout", "ledger"],
            actor="qa-agent",
            component_versions={
                "policy": "1",
                "tool_registry": "1",
            },
        )

    def test_initialize_writes_event_log_and_atomic_projection(self) -> None:
        state = self.store.initialize(
            run_id="run-001",
            goal="验证关键发布声明",
            scope=["web", "api"],
            actor="qa-agent",
        )

        self.assertEqual(state.sequence, 1)
        self.assertEqual(state.status, "running")
        self.assertEqual(state.scope, ["web", "api"])
        self.assertTrue(self.store.events_path.is_file())
        projected = json.loads(self.store.state_path.read_text(encoding="utf-8"))
        self.assertEqual(projected["last_event_hash"], state.last_event_hash)

    def test_reducer_recovers_reasoning_evidence_and_approval_state(self) -> None:
        self.initialize()
        self.store.append(
            RunEventType.ASSUMPTION_RECORDED,
            {
                "id": "A1",
                "statement": "测试库与生产隔离",
                "source_refs": ["adapter-context.json"],
                "confidence": 0.8,
            },
            actor="planner",
        )
        self.store.append(
            RunEventType.HYPOTHESIS_RECORDED,
            {
                "id": "H1",
                "statement": "重试导致重复入账",
                "source_refs": ["results.json"],
                "confidence": 0.55,
            },
            actor="diagnostician",
        )
        self.store.append(
            RunEventType.HYPOTHESIS_UPDATED,
            {
                "id": "H1",
                "status": "supported",
                "confidence": 0.95,
                "reason": "账本出现同一幂等键的两条记录",
            },
            actor="critic",
        )
        self.store.append(
            RunEventType.EVIDENCE_LINKED,
            {
                "id": "E1",
                "path": "evidence-ledger.json",
                "sha256": "a" * 64,
                "status": "failed",
                "proves": ["H1"],
            },
            actor="verifier",
        )
        self.store.append(
            RunEventType.APPROVAL_RECORDED,
            {
                "id": "approval-1",
                "decision": "approved",
                "scope": ["read-only persistence probe"],
                "decided_by": "operator",
            },
            actor="operator",
        )

        recovered = self.store.load_state()
        self.assertEqual(recovered.sequence, 6)
        self.assertEqual(recovered.hypotheses["H1"]["status"], "supported")
        self.assertEqual(recovered.evidence["E1"]["status"], "failed")
        self.assertEqual(
            recovered.approvals["approval-1"]["decision"],
            "approved",
        )

    def test_pass_status_requires_hash_bound_deterministic_verdict(self) -> None:
        self.initialize()

        with self.assertRaises(ValueError):
            self.store.append(
                RunEventType.STATUS_CHANGED,
                {
                    "status": "passed",
                    "authority": "planner",
                },
                actor="planner",
            )
        with self.assertRaises(ValueError):
            self.store.append(
                RunEventType.STATUS_CHANGED,
                {
                    "status": "passed",
                    "authority": "deterministic_verdict",
                    "verdict_ref": {
                        "path": "qa-verdict.json",
                        "sha256": "b" * 64,
                    },
                },
                actor="verifier",
            )

        state = self.store.append(
            RunEventType.STATUS_CHANGED,
            {
                "status": "passed",
                "authority": "deterministic_verdict",
                "verdict_ref": {
                    "path": "qa-verdict.json",
                    "sha256": "b" * 64,
                },
                "attempt_ref": {
                    "attempt_id": "attempt-1",
                    "attempt_manifest_sha256": "c" * 64,
                    "run_manifest_sequence": 1,
                    "run_manifest_sha256": "d" * 64,
                },
            },
            actor="verifier",
        )
        self.assertEqual(state.status, "passed")

    def test_unknown_hypothesis_update_is_rejected_before_append(self) -> None:
        self.initialize()

        with self.assertRaises(EventLogError) as caught:
            self.store.append(
                RunEventType.HYPOTHESIS_UPDATED,
                {
                    "id": "missing",
                    "status": "rejected",
                },
                actor="critic",
            )

        self.assertEqual(caught.exception.code, "hypothesis_missing")
        self.assertEqual(len(self.store.load_events()), 1)

    def test_unknown_payload_fields_are_rejected_before_append(self) -> None:
        self.initialize()

        with self.assertRaises(ValueError):
            self.store.append(
                RunEventType.PHASE_CHANGED,
                {
                    "phase": "probe",
                    "model_instruction": "直接判定通过",
                },
                actor="planner",
            )

        self.assertEqual(len(self.store.load_events()), 1)

    def test_hash_tampering_and_chain_breaks_fail_closed(self) -> None:
        self.initialize()
        self.store.append(
            RunEventType.PHASE_CHANGED,
            {"phase": "probe"},
            actor="orchestrator",
        )
        lines = self.store.events_path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[0])
        tampered["payload"]["goal"] = "被篡改的目标"
        lines[0] = json.dumps(tampered, ensure_ascii=False)
        self.store.events_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with self.assertRaises(EventLogError) as caught:
            self.store.load_events()

        self.assertEqual(caught.exception.code, "event_hash_mismatch")

    def test_truncated_tail_is_not_silently_reused(self) -> None:
        self.initialize()
        with self.store.events_path.open("a", encoding="utf-8") as handle:
            handle.write('{"schema_version":1')

        with self.assertRaises(EventLogError) as caught:
            self.store.append(
                RunEventType.PHASE_CHANGED,
                {"phase": "audit"},
                actor="orchestrator",
            )

        self.assertEqual(caught.exception.code, "event_log_truncated")

    def test_duplicate_initialization_does_not_replace_existing_run(self) -> None:
        self.initialize()

        with self.assertRaises(EventLogError) as caught:
            self.store.initialize(
                run_id="run-002",
                goal="覆盖已有运行",
                scope=["other"],
                actor="qa-agent",
            )

        self.assertEqual(caught.exception.code, "run_already_initialized")
        self.assertEqual(self.store.load_state().run_id, "run-001")

    def test_event_log_symlink_is_rejected_without_following_target(self) -> None:
        outside = self.run_dir / "outside.jsonl"
        outside.write_text("preserve\n", encoding="utf-8")
        self.store.events_path.symlink_to(outside)

        with self.assertRaises(EventLogError) as caught:
            self.store.initialize(
                run_id="run-unsafe",
                goal="不得写出运行目录",
                scope=["security"],
                actor="qa-agent",
            )

        self.assertIn(
            caught.exception.code,
            {"event_log_not_file", "event_log_unwritable"},
        )
        self.assertEqual(outside.read_text(encoding="utf-8"), "preserve\n")


if __name__ == "__main__":
    unittest.main()
