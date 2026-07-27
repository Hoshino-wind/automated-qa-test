#!/usr/bin/env python3
import hashlib
import json
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.hitl import (  # noqa: E402
    ApprovalOperation,
    ApprovalReceipt,
    HITLDecision,
    HITLRequest,
    HITLStore,
    HITLStoreError,
    HumanControlContractError,
    HumanControlJournalError,
    HumanDecision,
    OperatorIdentity,
    public_key_pem,
    signed_receipt_dict,
)
from qa_core.hitl._journal import JournalEvent  # noqa: E402

CONTEXT = "a" * 64
ACTION = "b" * 64
POLICY = "c" * 64
AUTHORIZATION = "d" * 64
T0 = "2026-07-26T00:00:00Z"
T1 = "2026-07-26T01:00:00Z"
T2 = "2026-07-26T02:00:00Z"
T3 = "2026-07-26T03:00:00Z"


def parsed(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def operator() -> OperatorIdentity:
    return OperatorIdentity(
        operator_id="operator-1",
        identity_provider="corp-sso",
        identity_subject="user:operator-1",
    )


def request(request_id: str = "request-1") -> HITLRequest:
    return HITLRequest(
        request_id=request_id,
        run_id="run-1",
        lease_generation=7,
        context_sha256=CONTEXT,
        action_sha256=ACTION,
        policy_sha256=POLICY,
        authorization_sha256=AUTHORIZATION,
        action_summary="允许在隔离测试库执行迁移验证",
        question="是否允许执行该动作？",
        allowed_decisions=(
            HumanDecision.APPROVED,
            HumanDecision.REJECTED,
        ),
        created_at=T0,
        expires_at=T3,
    )


class HITLStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private_key = Ed25519PrivateKey.generate()
        self.trust = {
            "corp-approval-service": {
                "approval-key-1": public_key_pem(self.private_key),
            },
        }
        self.now = parsed(T2)
        self.store = self.make_store(self.root / "hitl")
        self.operator = operator()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_store(self, path: Path) -> HITLStore:
        return HITLStore(
            path,
            trusted_authority_keys=self.trust,
            clock=lambda: self.now,
        )

    @property
    def bindings(self) -> dict:
        return {
            "expected_run_id": "run-1",
            "expected_lease_generation": 7,
            "expected_context_sha256": CONTEXT,
            "expected_action_sha256": ACTION,
            "expected_policy_sha256": POLICY,
            "expected_authorization_sha256": AUTHORIZATION,
        }

    def signed_receipt(
        self,
        *,
        receipt_id: str,
        subject_sha256: str,
        outcome: HumanDecision,
        approved_at: str = T1,
        authority: str = "corp-approval-service",
        key_id: str = "approval-key-1",
        private_key=None,
    ) -> ApprovalReceipt:
        payload = {
            "schema_version": 1,
            "receipt_id": receipt_id,
            "operation": ApprovalOperation.HITL_DECISION.value,
            "operator_id": self.operator.operator_id,
            "subject_sha256": subject_sha256,
            "decision": outcome.value,
            "approved_at": approved_at,
            "authority": authority,
            "key_id": key_id,
            "external_receipt_sha256": hashlib.sha256(
                receipt_id.encode(),
            ).hexdigest(),
        }
        return ApprovalReceipt.from_dict(
            signed_receipt_dict(
                payload,
                private_key=private_key or self.private_key,
            ),
        )

    def make_decision(
        self,
        *,
        outcome: HumanDecision = HumanDecision.APPROVED,
        decision_id: str = "decision-1",
        reason: str = "已确认隔离环境与可回滚边界",
        receipt_mutator=None,
    ) -> HITLDecision:
        subject = self.store.decision_subject_sha256(
            "request-1",
            decision_id=decision_id,
            decision=outcome,
            reason=reason,
            decided_at=T1,
            operator=self.operator,
            **self.bindings,
        )
        receipt = self.signed_receipt(
            receipt_id=f"receipt-{decision_id}",
            subject_sha256=subject,
            outcome=outcome,
        )
        if receipt_mutator is not None:
            raw = receipt.to_dict()
            receipt_mutator(raw)
            receipt = ApprovalReceipt.from_dict(raw)
        return HITLDecision(
            decision_id=decision_id,
            request_id="request-1",
            run_id="run-1",
            lease_generation=7,
            context_sha256=CONTEXT,
            action_sha256=ACTION,
            policy_sha256=POLICY,
            authorization_sha256=AUTHORIZATION,
            decision=outcome,
            reason=reason,
            decided_at=T1,
            operator=self.operator,
            approval_receipt=receipt,
        )

    def record(self, decision: HITLDecision):
        return self.store.record_decision(decision, **self.bindings)

    def test_signed_approval_is_recoverable_and_consumed_once(self) -> None:
        self.store.create_request(request())
        decided = self.record(self.make_decision())
        self.assertEqual(decided.status, "decided")

        consumed = self.store.consume_approved(
            "request-1",
            consumption_id="consume-1",
            **self.bindings,
        )
        self.assertEqual(consumed.status, "consumed")
        self.assertTrue(consumed.consumption.not_evidence)
        restarted = self.make_store(self.store.directory).resume(
            "request-1",
            **self.bindings,
        )
        self.assertEqual(restarted.status, "consumed")
        with self.assertRaises(HITLStoreError) as replay:
            self.store.consume_approved(
                "request-1",
                consumption_id="consume-1",
                **self.bindings,
            )
        self.assertEqual(replay.exception.code, "decision_already_consumed")

    def test_rejected_decision_cannot_be_consumed(self) -> None:
        self.store.create_request(request())
        self.record(self.make_decision(outcome=HumanDecision.REJECTED))
        with self.assertRaises(HITLStoreError) as caught:
            self.store.consume_approved(
                "request-1",
                consumption_id="consume-rejected",
                **self.bindings,
            )
        self.assertEqual(caught.exception.code, "decision_not_approved")

    def test_stale_generation_policy_and_authorization_fail_closed(self) -> None:
        self.store.create_request(request())
        cases = (
            ("expected_lease_generation", 8, "lease_generation_stale"),
            ("expected_policy_sha256", "e" * 64, "policy_sha256_stale"),
            (
                "expected_authorization_sha256",
                "f" * 64,
                "authorization_sha256_stale",
            ),
        )
        for field, value, expected_code in cases:
            bindings = {**self.bindings, field: value}
            with self.subTest(field=field):
                with self.assertRaises(HITLStoreError) as caught:
                    self.store.resume("request-1", **bindings)
                self.assertEqual(caught.exception.code, expected_code)

    def test_tampered_signature_unknown_key_and_authority_are_rejected(self) -> None:
        self.store.create_request(request())
        tampered = self.make_decision(
            receipt_mutator=lambda raw: raw.__setitem__(
                "subject_sha256",
                "0" * 64,
            ),
        )
        with self.assertRaises(HumanControlContractError) as caught:
            self.record(tampered)
        self.assertEqual(caught.exception.code, "approval_signature_invalid")

        unknown_key = self.make_decision(
            receipt_mutator=lambda raw: raw.__setitem__(
                "key_id",
                "unknown-key",
            ),
        )
        with self.assertRaises(HumanControlContractError) as caught:
            self.record(unknown_key)
        self.assertEqual(caught.exception.code, "approval_key_unknown")

        unknown_authority = self.make_decision(
            receipt_mutator=lambda raw: raw.__setitem__(
                "authority",
                "attacker",
            ),
        )
        with self.assertRaises(HumanControlContractError) as caught:
            self.record(unknown_authority)
        self.assertEqual(caught.exception.code, "approval_authority_untrusted")

        second_key = Ed25519PrivateKey.generate()
        multi_authority = HITLStore(
            self.store.directory,
            trusted_authority_keys={
                **self.trust,
                "other-approval-service": {
                    "approval-key-1": public_key_pem(second_key),
                },
            },
            clock=lambda: self.now,
        )
        substituted = self.make_decision(
            receipt_mutator=lambda raw: raw.__setitem__(
                "authority",
                "other-approval-service",
            ),
        )
        with self.assertRaises(HumanControlContractError) as caught:
            multi_authority.record_decision(
                substituted,
                **self.bindings,
            )
        self.assertEqual(caught.exception.code, "approval_signature_invalid")
        self.assertEqual(len(self.store.events_path.read_text().splitlines()), 1)

    def test_forged_private_key_and_unsigned_receipt_fail_closed(self) -> None:
        self.store.create_request(request())
        attacker = Ed25519PrivateKey.generate()
        subject = self.store.decision_subject_sha256(
            "request-1",
            decision_id="forged",
            decision=HumanDecision.APPROVED,
            reason="forged",
            decided_at=T1,
            operator=self.operator,
            **self.bindings,
        )
        forged_receipt = self.signed_receipt(
            receipt_id="forged-receipt",
            subject_sha256=subject,
            outcome=HumanDecision.APPROVED,
            private_key=attacker,
        )
        forged = HITLDecision.from_dict(
            {
                **self.make_decision().to_dict(),
                "decision_id": "forged",
                "reason": "forged",
                "approval_receipt": forged_receipt.to_dict(),
            },
        )
        with self.assertRaises(HumanControlContractError) as caught:
            self.record(forged)
        self.assertEqual(caught.exception.code, "approval_signature_invalid")

        raw = forged_receipt.to_dict()
        del raw["signature"]
        with self.assertRaises(HumanControlContractError) as unsigned:
            ApprovalReceipt.from_dict(raw)
        self.assertEqual(unsigned.exception.code, "fields_missing")

    def test_missing_trust_configuration_fails_closed(self) -> None:
        self.store.create_request(request())
        decision = self.make_decision()
        untrusted = HITLStore(
            self.store.directory,
            clock=lambda: self.now,
        )
        with self.assertRaises(HumanControlContractError) as caught:
            untrusted.record_decision(decision, **self.bindings)
        self.assertEqual(caught.exception.code, "approval_trust_unconfigured")

    def test_expired_unconsumed_decision_cannot_resume_or_consume(self) -> None:
        self.store.create_request(request())
        self.record(self.make_decision())
        self.now = parsed(T3)
        for operation in ("resume", "consume"):
            with self.subTest(operation=operation):
                with self.assertRaises(HITLStoreError) as caught:
                    if operation == "resume":
                        self.store.resume("request-1", **self.bindings)
                    else:
                        self.store.consume_approved(
                            "request-1",
                            consumption_id="late",
                            **self.bindings,
                        )
                self.assertEqual(caught.exception.code, "request_expired")

    def test_allowed_decisions_must_include_approve_and_reject(self) -> None:
        raw = request().to_dict()
        raw["allowed_decisions"] = ["approved"]
        with self.assertRaises(HumanControlContractError) as caught:
            HITLRequest.from_dict(raw)
        self.assertEqual(caught.exception.code, "allowed_decisions_incomplete")
        raw = request().to_dict()
        raw["model_approved"] = True
        with self.assertRaises(HumanControlContractError) as unknown:
            HITLRequest.from_dict(raw)
        self.assertEqual(unknown.exception.code, "fields_unknown")

    def test_journal_tampering_is_rejected(self) -> None:
        self.store.create_request(request())
        lines = self.store.events_path.read_text().splitlines()
        tampered = json.loads(lines[0])
        tampered["payload"]["request"]["lease_generation"] = 8
        self.store.events_path.write_text(
            json.dumps(tampered) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(HumanControlJournalError) as caught:
            self.store.projection()
        self.assertEqual(caught.exception.code, "event_hash_mismatch")

    def test_rehashed_forged_journal_still_fails_receipt_verification(self) -> None:
        self.store.create_request(request())
        self.record(self.make_decision())
        lines = self.store.events_path.read_text().splitlines()
        decision_event = json.loads(lines[1])
        decision_event["payload"]["decision"]["approval_receipt"][
            "subject_sha256"
        ] = "0" * 64
        rebuilt = JournalEvent.create(
            sequence=decision_event["sequence"],
            event_type=decision_event["event_type"],
            occurred_at=decision_event["occurred_at"],
            payload=decision_event["payload"],
            previous_hash=decision_event["previous_hash"],
        )
        lines[1] = json.dumps(rebuilt.to_dict())
        self.store.events_path.write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(HumanControlContractError) as caught:
            self.store.projection()
        self.assertEqual(caught.exception.code, "approval_signature_invalid")


if __name__ == "__main__":
    unittest.main()
