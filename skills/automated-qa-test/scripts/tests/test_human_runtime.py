#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_common import atomic_write_json, file_sha256  # noqa: E402
from qa_core.context import (  # noqa: E402
    compile_context_snapshot,
    verify_context_snapshot,
)
from qa_core.hitl import (  # noqa: E402
    ApprovalOperation,
    ApprovalReceipt,
    HITLDecision,
    HITLStore,
    HumanDecision,
    OperatorIdentity,
    canonical_checkpoint_bytes,
    checkpoint_signing_payload,
    public_key_pem,
    signed_receipt_dict,
)
from qa_core.hitl._journal import (  # noqa: E402
    GENESIS_HASH,
    AppendOnlyJsonJournal,
)
from qa_core.human_runtime import (  # noqa: E402
    HumanGateConfig,
    KnowledgeRuntimeConfig,
    evaluate_high_risk_human_gate,
    human_execution_iteration,
    verify_human_authorization_artifact,
    verify_human_authorization_for_contracts,
)
from qa_core.knowledge import (  # noqa: E402
    KnowledgeCandidate,
    KnowledgeProvenance,
    KnowledgeStore,
)
from qa_core.proof.verifier import (  # noqa: E402
    _verify_human_authorization,
)
from qa_core.runtime import (  # noqa: E402
    ACTION_AUTHORITY_KEY_ENV,
    ACTION_AUTHORIZATION_TICKET_ENV,
    ActionProtocolError,
    build_action_contracts,
    issue_action_authorization_ticket,
    preflight_action_journal,
    verify_action_journal,
)

T0 = "2026-07-26T00:00:00Z"
T1 = "2026-07-26T00:10:00Z"
T2 = "2026-07-26T00:20:00Z"
T3 = "2026-07-26T00:30:00Z"
CHECKPOINT_ISSUED = "2026-07-25T00:00:00Z"
# 共享有效性夹具不依赖真实时钟；过期行为由显式测试时钟单独覆盖。
CHECKPOINT_EXPIRES = "2099-07-27T00:00:00Z"


def parsed(value: str) -> datetime:
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    ).astimezone(UTC)


def signature(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode(
        "ascii"
    )


class HumanRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()
        self.hitl_dir = self.root / "hitl"
        self.approval_key = Ed25519PrivateKey.generate()
        self.checkpoint_key = Ed25519PrivateKey.generate()
        self.trust_path = self.root / "trust.json"
        self.trust_payload = {
            "schema_version": 1,
            "authorities": [
                {
                    "authority": "approval-service",
                    "keys": [
                        {
                            "key_id": "approval-key",
                            "algorithm": "Ed25519",
                            "public_key_pem": public_key_pem(
                                self.approval_key
                            ),
                        }
                    ],
                }
            ],
            "checkpoint_authorities": [
                {
                    "authority": "checkpoint-service",
                    "keys": [
                        {
                            "key_id": "checkpoint-key",
                            "algorithm": "Ed25519",
                            "public_key_pem": public_key_pem(
                                self.checkpoint_key
                            ),
                        }
                    ],
                }
            ],
        }
        atomic_write_json(self.trust_path, self.trust_payload)
        self.checkpoint_path = self.root / "hitl-checkpoint.json"
        self.operator = OperatorIdentity(
            operator_id="operator-1",
            identity_provider="corp-sso",
            identity_subject="user:operator-1",
        )
        self.marker_path = self.root / "dispatch-marker.txt"
        self._write_run_inputs()

    def _write_run_inputs(self) -> None:
        plan_path = self.run_dir / "test-plan.json"
        plan_path.write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "artifactDir": str(self.run_dir),
                    "scenarios": [
                        {
                            "id": "mutating-command",
                            "steps": [
                                {
                                    "id": "append-marker",
                                    "action": "command",
                                    "command": [
                                        "node",
                                        "-e",
                                        (
                                            "require('fs').appendFileSync("
                                            + json.dumps(
                                                str(self.marker_path)
                                            )
                                            + ",'dispatch\\n')"
                                        ),
                                    ],
                                    "expectExitCode": 0,
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (self.run_dir / "test-matrix.json").write_text(
            '{"schemaVersion":2,"tests":[]}',
            encoding="utf-8",
        )
        (self.run_dir / "requirement.md").write_text(
            "# Human-gated dispatch\n",
            encoding="utf-8",
        )
        (self.run_dir / "adapter-context.json").write_text(
            json.dumps(
                {
                    "adapter": "fixture",
                    "environment_boundary": {
                        "runtime_mode": "test",
                        "data_boundary_status": "isolated fixtures",
                    },
                }
            ),
            encoding="utf-8",
        )
        audit_path = self.run_dir / "plan-audit-summary.json"
        audit_path.write_text(
            json.dumps(
                {
                    "passed": True,
                    "plan": str(plan_path),
                    "artifact_hashes": {
                        "plan_sha256": file_sha256(plan_path)
                    },
                }
            ),
            encoding="utf-8",
        )
        context = compile_context_snapshot(self.run_dir)
        atomic_write_json(
            self.run_dir / "agent-context.json",
            context.to_dict(),
        )

    def _checkpoint(
        self,
        directory: Path,
        *,
        name: str,
        destination: Path,
    ) -> None:
        journal = AppendOnlyJsonJournal(directory, name=name)
        events = journal.load_events()
        terminal = (
            events[-1].event_hash if events else GENESIS_HASH
        )
        payload = checkpoint_signing_payload(
            journal_kind=name,
            events_path=journal.events_path,
            event_count=len(events),
            terminal_event_hash=terminal,
            issued_at=CHECKPOINT_ISSUED,
            expires_at=CHECKPOINT_EXPIRES,
            authority="checkpoint-service",
            key_id="checkpoint-key",
        )
        atomic_write_json(
            destination,
            {
                **payload,
                "signature": signature(
                    self.checkpoint_key.sign(
                        canonical_checkpoint_bytes(payload)
                    )
                ),
            },
        )

    def _gate_config(
        self,
        *,
        mode: str = "production",
        epoch: int = 1,
    ) -> HumanGateConfig:
        return HumanGateConfig(
            store_dir=self.hitl_dir,
            trust_config_path=self.trust_path,
            journal_mode=mode,
            checkpoint_path=(
                self.checkpoint_path
                if mode == "production"
                else None
            ),
            request_ttl_seconds=3600,
            human_execution_epoch=epoch,
        )

    def _contracts(self, iteration: int) -> dict:
        return build_action_contracts(
            self.run_dir / "test-plan.json",
            self.run_dir / "agent-context.json",
            self.run_dir / "plan-audit-summary.json",
            run_id="run-human-runtime",
            generation=1,
            iteration=iteration,
        )

    def _bindings(self, artifact: dict) -> dict:
        bindings = artifact["bindings"]
        return {
            "expected_run_id": bindings["run_id"],
            "expected_lease_generation": bindings[
                "lease_generation"
            ],
            "expected_context_sha256": bindings[
                "context_sha256"
            ],
            "expected_action_sha256": bindings[
                "action_sha256"
            ],
            "expected_policy_sha256": bindings[
                "policy_sha256"
            ],
            "expected_authorization_sha256": bindings[
                "authorization_sha256"
            ],
        }

    def _approval_receipt(
        self,
        *,
        subject_sha256: str,
        decision: HumanDecision = HumanDecision.APPROVED,
    ) -> ApprovalReceipt:
        return ApprovalReceipt.from_dict(
            signed_receipt_dict(
                {
                    "schema_version": 1,
                    "receipt_id": "receipt-1",
                    "operation": ApprovalOperation.HITL_DECISION.value,
                    "operator_id": self.operator.operator_id,
                    "subject_sha256": subject_sha256,
                    "decision": decision.value,
                    "approved_at": T1,
                    "authority": "approval-service",
                    "key_id": "approval-key",
                    "external_receipt_sha256": hashlib.sha256(
                        b"external-receipt-1"
                    ).hexdigest(),
                },
                private_key=self.approval_key,
            )
        )

    @unittest.skipUnless(shutil.which("node"), "node is required")
    def test_three_checkpoint_flow_is_stable_and_replay_safe(
        self,
    ) -> None:
        self._checkpoint(
            self.hitl_dir,
            name="hitl",
            destination=self.checkpoint_path,
        )
        first_contracts = self._contracts(iteration=11)
        first = evaluate_high_risk_human_gate(
            self._gate_config(),
            contracts=first_contracts,
            run_id="run-human-runtime",
            lease_generation=1,
            context_sha256=first_contracts["context_sha256"],
            now=parsed(T0),
        )
        self.assertEqual(first.status, "pending_approval")
        self.assertFalse(first.dispatch_authorized)
        self.assertFalse(self.marker_path.exists())

        self._checkpoint(
            self.hitl_dir,
            name="hitl",
            destination=self.checkpoint_path,
        )
        store = HITLStore(
            self.hitl_dir,
            trusted_authority_keys={
                "approval-service": {
                    "approval-key": public_key_pem(
                        self.approval_key
                    )
                }
            },
            journal_mode="production",
            checkpoint_path=self.checkpoint_path,
            trusted_checkpoint_keys={
                "checkpoint-service": {
                    "checkpoint-key": public_key_pem(
                        self.checkpoint_key
                    )
                }
            },
            clock=lambda: parsed(T1),
        )
        request = first.artifact["request"]
        subject = store.decision_subject_sha256(
            request["request_id"],
            decision_id="decision-1",
            decision=HumanDecision.APPROVED,
            reason="isolated boundary and exact action set confirmed",
            decided_at=T1,
            operator=self.operator,
            **self._bindings(first.artifact),
        )
        store.record_decision(
            HITLDecision(
                decision_id="decision-1",
                request_id=request["request_id"],
                run_id=request["run_id"],
                lease_generation=request["lease_generation"],
                context_sha256=request["context_sha256"],
                action_sha256=request["action_sha256"],
                policy_sha256=request["policy_sha256"],
                authorization_sha256=request[
                    "authorization_sha256"
                ],
                decision=HumanDecision.APPROVED,
                reason="isolated boundary and exact action set confirmed",
                decided_at=T1,
                operator=self.operator,
                approval_receipt=self._approval_receipt(
                    subject_sha256=subject
                ),
            ),
            **self._bindings(first.artifact),
        )

        self._checkpoint(
            self.hitl_dir,
            name="hitl",
            destination=self.checkpoint_path,
        )
        second_contracts = self._contracts(iteration=97)
        second = evaluate_high_risk_human_gate(
            self._gate_config(),
            contracts=second_contracts,
            run_id="run-human-runtime",
            lease_generation=1,
            context_sha256=second_contracts["context_sha256"],
            now=parsed(T2),
        )
        self.assertEqual(
            second.status,
            "awaiting_consumption_checkpoint",
        )
        self.assertEqual(
            first.artifact["request"]["request_id"],
            second.artifact["request"]["request_id"],
        )
        self.assertFalse(second.dispatch_authorized)
        self.assertFalse(self.marker_path.exists())

        stale = evaluate_high_risk_human_gate(
            self._gate_config(),
            contracts=self._contracts(iteration=123),
            run_id="run-human-runtime",
            lease_generation=1,
            context_sha256=second_contracts["context_sha256"],
            now=parsed(T2),
        )
        self.assertEqual(stale.status, "checkpoint_refresh_required")
        self.assertFalse(stale.dispatch_authorized)

        self._checkpoint(
            self.hitl_dir,
            name="hitl",
            destination=self.checkpoint_path,
        )
        third_contracts = self._contracts(iteration=211)
        third = evaluate_high_risk_human_gate(
            self._gate_config(),
            contracts=third_contracts,
            run_id="run-human-runtime",
            lease_generation=1,
            context_sha256=third_contracts["context_sha256"],
            now=parsed(T3),
        )
        self.assertEqual(third.status, "authorized")
        self.assertTrue(third.dispatch_authorized)
        self.assertEqual(
            third.artifact["checkpoint"]["tail_count"],
            1,
        )
        self.assertFalse(
            third.artifact["checkpoint"]["complete"]
        )
        human_path = self.run_dir / "human-authorization.json"
        atomic_write_json(human_path, third.artifact)
        human_bytes = human_path.read_bytes()
        human_file_sha256 = hashlib.sha256(human_bytes).hexdigest()
        verify_human_authorization_artifact(
            third.artifact,
            expected_file_sha256=human_file_sha256,
            artifact_bytes=human_bytes,
        )

        final_contracts = build_action_contracts(
            self.run_dir / "test-plan.json",
            self.run_dir / "agent-context.json",
            self.run_dir / "plan-audit-summary.json",
            run_id="run-human-runtime",
            generation=1,
            iteration=human_execution_iteration(third.artifact),
            human_authorization_sha256=human_file_sha256,
        )
        verify_human_authorization_for_contracts(
            third.artifact,
            final_contracts,
        )
        contracts_path = self.run_dir / "action-contracts.json"
        atomic_write_json(contracts_path, final_contracts)
        proof_attempt = SimpleNamespace(
            input_hashes={
                "human_authorization": human_file_sha256
            },
            artifacts=[
                SimpleNamespace(
                    name="human-authorization.json",
                    sha256=human_file_sha256,
                )
            ],
        )
        proof_errors: list[dict[str, str]] = []
        proof_refs: dict[str, object] = {}
        _verify_human_authorization(
            self.run_dir,
            {
                "human_authorization_file_sha256": (
                    human_file_sha256
                ),
                "human_authorization_sha256": third.artifact[
                    "human_authorization_sha256"
                ],
            },
            proof_attempt,
            proof_errors,
            proof_refs,
        )
        self.assertEqual(proof_errors, [])
        self.assertEqual(
            proof_refs["human_authorization"][
                "verification_boundary"
            ],
            "runtime_gate_artifact_binding",
        )
        self.assertFalse(
            proof_refs["human_authorization"][
                "external_signature_reverified"
            ]
        )
        authority_key = b"k" * 32
        ticket = issue_action_authorization_ticket(
            final_contracts,
            plan_path=self.run_dir / "test-plan.json",
            context_path=self.run_dir / "agent-context.json",
            plan_audit_path=(
                self.run_dir / "plan-audit-summary.json"
            ),
            authority_key=authority_key,
            human_authorization_path=human_path,
        )
        journal_path = self.run_dir / "action-journal.jsonl"
        completed = subprocess.run(
            [
                "node",
                str(SCRIPT_DIR / "playwright_probe.mjs"),
                "--plan",
                str(self.run_dir / "test-plan.json"),
                "--plan-audit-summary",
                str(self.run_dir / "plan-audit-summary.json"),
                "--agent-context",
                str(self.run_dir / "agent-context.json"),
                "--action-contracts",
                str(contracts_path),
                "--action-journal",
                str(journal_path),
            ],
            cwd=self.run_dir,
            env={
                **os.environ,
                ACTION_AUTHORITY_KEY_ENV: authority_key.hex(),
                ACTION_AUTHORIZATION_TICKET_ENV: ticket,
            },
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            self.marker_path.read_text(encoding="utf-8"),
            "dispatch\n",
        )
        results = json.loads(
            (self.run_dir / "results.json").read_text(
                encoding="utf-8"
            )
        )
        verification = verify_action_journal(
            journal_path,
            final_contracts,
            results=results,
        )
        self.assertTrue(verification.valid, verification.errors)
        replay_preflight = preflight_action_journal(
            journal_path,
            final_contracts,
        )
        self.assertFalse(replay_preflight.valid)
        self.assertEqual(
            replay_preflight.errors[0]["code"],
            "human_dispatch_already_claimed",
        )

        # 重放屏障位于 HITL 日志而非可替换的动作日志；删除后者也不能再次兑换。
        journal_path.unlink()
        blocked_by_old_checkpoint = evaluate_high_risk_human_gate(
            self._gate_config(),
            contracts=self._contracts(iteration=377),
            run_id="run-human-runtime",
            lease_generation=1,
            context_sha256=third_contracts["context_sha256"],
            now=parsed(T3),
        )
        self.assertEqual(
            blocked_by_old_checkpoint.status,
            "checkpoint_refresh_required",
        )
        self._checkpoint(
            self.hitl_dir,
            name="hitl",
            destination=self.checkpoint_path,
        )
        replay = evaluate_high_risk_human_gate(
            self._gate_config(),
            contracts=self._contracts(iteration=610),
            run_id="run-human-runtime",
            lease_generation=1,
            context_sha256=third_contracts["context_sha256"],
            now=parsed(T3),
        )
        self.assertEqual(replay.status, "already_redeemed")
        self.assertFalse(replay.dispatch_authorized)
        self.assertEqual(
            self.marker_path.read_text(encoding="utf-8"),
            "dispatch\n",
        )

        tampered_human = json.loads(json.dumps(third.artifact))
        tampered_human["bindings"]["plan_sha256"] = "f" * 64
        atomic_write_json(human_path, tampered_human)
        with self.assertRaises(ActionProtocolError):
            issue_action_authorization_ticket(
                final_contracts,
                plan_path=self.run_dir / "test-plan.json",
                context_path=self.run_dir / "agent-context.json",
                plan_audit_path=(
                    self.run_dir / "plan-audit-summary.json"
                ),
                authority_key=authority_key,
                human_authorization_path=human_path,
            )
        tampered_proof_errors: list[dict[str, str]] = []
        _verify_human_authorization(
            self.run_dir,
            {
                "human_authorization_file_sha256": (
                    human_file_sha256
                ),
                "human_authorization_sha256": third.artifact[
                    "human_authorization_sha256"
                ],
            },
            proof_attempt,
            tampered_proof_errors,
            {},
        )
        self.assertTrue(tampered_proof_errors)
        self.assertEqual(
            tampered_proof_errors[0]["code"],
            "human_authorization_invalid",
        )

        recovered = evaluate_high_risk_human_gate(
            self._gate_config(epoch=2),
            contracts=self._contracts(iteration=987),
            run_id="run-human-runtime",
            lease_generation=1,
            context_sha256=third_contracts["context_sha256"],
            now=parsed(T3),
        )
        self.assertEqual(recovered.status, "pending_approval")
        self.assertFalse(recovered.dispatch_authorized)
        self.assertNotEqual(
            recovered.artifact["request"]["request_id"],
            first.artifact["request"]["request_id"],
        )
        self.assertEqual(
            recovered.artifact["bindings"][
                "human_execution_epoch"
            ],
            2,
        )
        self.assertEqual(
            self.marker_path.read_text(encoding="utf-8"),
            "dispatch\n",
        )

    def test_gate_is_explicit_for_no_risk_and_local_test(
        self,
    ) -> None:
        no_risk = self._contracts(iteration=1)
        no_risk["actions"] = []
        terminal = evaluate_high_risk_human_gate(
            self._gate_config(),
            contracts=no_risk,
            run_id="run-human-runtime",
            lease_generation=1,
            context_sha256=no_risk["context_sha256"],
            now=parsed(T0),
        )
        self.assertEqual(terminal.status, "not_required")
        self.assertTrue(terminal.dispatch_authorized)
        verify_human_authorization_artifact(terminal.artifact)

        high_risk = self._contracts(iteration=2)
        local = evaluate_high_risk_human_gate(
            self._gate_config(mode="local-test"),
            contracts=high_risk,
            run_id="run-human-runtime",
            lease_generation=1,
            context_sha256=high_risk["context_sha256"],
            now=parsed(T0),
        )
        self.assertEqual(
            local.status,
            "production_checkpoint_required",
        )
        self.assertFalse(local.dispatch_authorized)
        self.assertFalse(self.marker_path.exists())

    def test_signed_rejection_never_dispatches(self) -> None:
        self._checkpoint(
            self.hitl_dir,
            name="hitl",
            destination=self.checkpoint_path,
        )
        contracts = self._contracts(iteration=3)
        pending = evaluate_high_risk_human_gate(
            self._gate_config(),
            contracts=contracts,
            run_id="run-human-runtime",
            lease_generation=1,
            context_sha256=contracts["context_sha256"],
            now=parsed(T0),
        )
        self._checkpoint(
            self.hitl_dir,
            name="hitl",
            destination=self.checkpoint_path,
        )
        store = HITLStore(
            self.hitl_dir,
            trusted_authority_keys={
                "approval-service": {
                    "approval-key": public_key_pem(
                        self.approval_key
                    )
                }
            },
            journal_mode="production",
            checkpoint_path=self.checkpoint_path,
            trusted_checkpoint_keys={
                "checkpoint-service": {
                    "checkpoint-key": public_key_pem(
                        self.checkpoint_key
                    )
                }
            },
            clock=lambda: parsed(T1),
        )
        request = pending.artifact["request"]
        reason = "operator denied the side effect"
        subject = store.decision_subject_sha256(
            request["request_id"],
            decision_id="decision-rejected",
            decision=HumanDecision.REJECTED,
            reason=reason,
            decided_at=T1,
            operator=self.operator,
            **self._bindings(pending.artifact),
        )
        store.record_decision(
            HITLDecision(
                decision_id="decision-rejected",
                request_id=request["request_id"],
                run_id=request["run_id"],
                lease_generation=request["lease_generation"],
                context_sha256=request["context_sha256"],
                action_sha256=request["action_sha256"],
                policy_sha256=request["policy_sha256"],
                authorization_sha256=request[
                    "authorization_sha256"
                ],
                decision=HumanDecision.REJECTED,
                reason=reason,
                decided_at=T1,
                operator=self.operator,
                approval_receipt=self._approval_receipt(
                    subject_sha256=subject,
                    decision=HumanDecision.REJECTED,
                ),
            ),
            **self._bindings(pending.artifact),
        )
        self._checkpoint(
            self.hitl_dir,
            name="hitl",
            destination=self.checkpoint_path,
        )
        rejected = evaluate_high_risk_human_gate(
            self._gate_config(),
            contracts=self._contracts(iteration=9),
            run_id="run-human-runtime",
            lease_generation=1,
            context_sha256=contracts["context_sha256"],
            now=parsed(T2),
        )
        self.assertEqual(rejected.status, "rejected")
        self.assertFalse(rejected.dispatch_authorized)
        self.assertFalse(self.marker_path.exists())

    def test_confirmed_knowledge_is_current_not_evidence_context(
        self,
    ) -> None:
        knowledge_dir = self.root / "knowledge"
        store = KnowledgeStore(
            knowledge_dir,
            trusted_authority_keys={
                "approval-service": {
                    "approval-key": public_key_pem(
                        self.approval_key
                    )
                }
            },
            clock=lambda: parsed(T2),
        )
        candidate = KnowledgeCandidate(
            entry_id="runtime-boundary",
            topic="runtime-boundary",
            statement="The fixture uses an isolated test database.",
            provenance=(
                KnowledgeProvenance(
                    source_id="adapter-context",
                    source_type="run_artifact",
                    reference="run/adapter-context.json",
                    sha256="a" * 64,
                    observed_at=T0,
                ),
            ),
            scope=("environment:test", "project:fixture"),
            version=1,
            proposed_at=T1,
        )
        subject = store.write_subject_sha256(
            candidate,
            operator=self.operator,
        )
        receipt = ApprovalReceipt.from_dict(
            signed_receipt_dict(
                {
                    "schema_version": 1,
                    "receipt_id": "knowledge-receipt",
                    "operation": ApprovalOperation.KNOWLEDGE_WRITE.value,
                    "operator_id": self.operator.operator_id,
                    "subject_sha256": subject,
                    "decision": HumanDecision.APPROVED.value,
                    "approved_at": T2,
                    "authority": "approval-service",
                    "key_id": "approval-key",
                    "external_receipt_sha256": hashlib.sha256(
                        b"knowledge-external"
                    ).hexdigest(),
                },
                private_key=self.approval_key,
            )
        )
        store.write(
            candidate,
            operator=self.operator,
            approval_receipt=receipt,
        )
        checkpoint_path = self.root / "knowledge-checkpoint.json"
        self._checkpoint(
            knowledge_dir,
            name="knowledge",
            destination=checkpoint_path,
        )
        config = KnowledgeRuntimeConfig(
            store_dir=knowledge_dir,
            scope=("project:fixture", "environment:test"),
            trust_config_path=self.trust_path,
            journal_mode="production",
            checkpoint_path=checkpoint_path,
        )
        snapshot = compile_context_snapshot(
            self.run_dir,
            knowledge_config=config,
        )
        context_path = self.run_dir / "knowledge-agent-context.json"
        atomic_write_json(context_path, snapshot.to_dict())
        verification = verify_context_snapshot(
            self.run_dir,
            context_path,
            knowledge_config=config,
        )
        self.assertTrue(verification.valid, verification.errors)
        self.assertTrue(snapshot.knowledge["not_evidence"])
        self.assertEqual(
            [item["entry_id"] for item in snapshot.knowledge["entries"]],
            ["runtime-boundary"],
        )
        self.assertTrue(
            snapshot.knowledge["checkpoint"]["complete"]
        )

        # 即使密钥白名单语义等价，信任配置仍刻意要求字节级当前性。
        self.trust_path.write_text(
            json.dumps(self.trust_payload, sort_keys=True),
            encoding="utf-8",
        )
        stale = verify_context_snapshot(
            self.run_dir,
            context_path,
            knowledge_config=config,
        )
        self.assertFalse(stale.valid)
        self.assertIn(
            "context_knowledge_not_current",
            {item["code"] for item in stale.errors},
        )


if __name__ == "__main__":
    unittest.main()
