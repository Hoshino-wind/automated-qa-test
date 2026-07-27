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
    HumanControlContractError,
    HumanControlJournalError,
    HumanDecision,
    OperatorIdentity,
    public_key_pem,
    signed_receipt_dict,
)
from qa_core.knowledge import (  # noqa: E402
    KnowledgeCandidate,
    KnowledgeProvenance,
    KnowledgeStore,
    KnowledgeStoreError,
)

T0 = "2026-07-26T00:00:00Z"
T1 = "2026-07-26T01:00:00Z"
T2 = "2026-07-26T02:00:00Z"
T3 = "2026-07-26T03:00:00Z"
T4 = "2026-07-26T04:00:00Z"


def parsed(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def operator(operator_id: str = "operator-1") -> OperatorIdentity:
    return OperatorIdentity(
        operator_id=operator_id,
        identity_provider="corp-sso",
        identity_subject=f"user:{operator_id}",
    )


def provenance(
    source_id: str = "source-1",
    *,
    observed_at: str = T0,
) -> KnowledgeProvenance:
    return KnowledgeProvenance(
        source_id=source_id,
        source_type="run_artifact",
        reference="runs/run-1/adapter-context.json",
        sha256="a" * 64,
        observed_at=observed_at,
    )


def candidate(
    entry_id: str,
    *,
    scope: tuple[str, ...] = (
        "environment:test",
        "project:checkout",
    ),
    version: int = 1,
    proposed_at: str = T1,
    expires_at: str | None = None,
    statement: str | None = None,
    observed_at: str = T0,
) -> KnowledgeCandidate:
    return KnowledgeCandidate(
        entry_id=entry_id,
        topic="runtime-boundary",
        statement=statement or f"{entry_id} 使用隔离测试数据库",
        provenance=(
            provenance(
                f"source-{entry_id}-{version}",
                observed_at=observed_at,
            ),
        ),
        scope=scope,
        version=version,
        proposed_at=proposed_at,
        expires_at=expires_at,
    )


class KnowledgeStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private_key = Ed25519PrivateKey.generate()
        self.trust = {
            "corp-approval-service": {
                "approval-key-1": public_key_pem(self.private_key),
            },
        }
        self.now = parsed(T3)
        self.operator = operator()
        self.store = self.make_store(self.root / "knowledge")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_store(self, path: Path) -> KnowledgeStore:
        return KnowledgeStore(
            path,
            trusted_authority_keys=self.trust,
            clock=lambda: self.now,
        )

    def receipt(
        self,
        *,
        receipt_id: str,
        operation: ApprovalOperation,
        subject_sha256: str,
        approved_at: str = T2,
        private_key=None,
        key_id: str = "approval-key-1",
        authority: str = "corp-approval-service",
    ) -> ApprovalReceipt:
        return ApprovalReceipt.from_dict(
            signed_receipt_dict(
                {
                    "schema_version": 1,
                    "receipt_id": receipt_id,
                    "operation": operation.value,
                    "operator_id": self.operator.operator_id,
                    "subject_sha256": subject_sha256,
                    "decision": HumanDecision.APPROVED.value,
                    "approved_at": approved_at,
                    "authority": authority,
                    "key_id": key_id,
                    "external_receipt_sha256": hashlib.sha256(
                        receipt_id.encode(),
                    ).hexdigest(),
                },
                private_key=private_key or self.private_key,
            ),
        )

    def publish(
        self,
        item: KnowledgeCandidate,
        *,
        receipt_id: str | None = None,
        private_key=None,
    ):
        subject = self.store.write_subject_sha256(
            item,
            operator=self.operator,
        )
        return self.store.write(
            item,
            operator=self.operator,
            approval_receipt=self.receipt(
                receipt_id=receipt_id
                or f"write-{item.entry_id}-{item.version}",
                operation=ApprovalOperation.KNOWLEDGE_WRITE,
                subject_sha256=subject,
                private_key=private_key,
            ),
        )

    def revoke(self, entry_id: str, version: int):
        subject = self.store.revoke_subject_sha256(
            entry_id,
            version,
            operator=self.operator,
        )
        return self.store.revoke(
            entry_id,
            version,
            operator=self.operator,
            approval_receipt=self.receipt(
                receipt_id=f"revoke-{entry_id}-{version}",
                operation=ApprovalOperation.KNOWLEDGE_REVOKE,
                subject_sha256=subject,
            ),
        )

    def test_time_chain_and_exact_scope_query(self) -> None:
        entry = self.publish(candidate("active", expires_at=T4))
        self.assertEqual(entry.proposed_at, T1)
        self.assertEqual(entry.approval_receipt.approved_at, T2)
        self.assertEqual(entry.committed_at, T3)
        self.assertTrue(entry.not_evidence)

        exact = self.store.query(
            scope=("project:checkout", "environment:test"),
        )
        broader = self.store.query(
            scope=(
                "project:checkout",
                "environment:test",
                "tenant:other",
            ),
        )
        wrong_environment = self.store.query(
            scope=("project:checkout", "environment:prod"),
        )
        self.assertEqual([item.entry_id for item in exact], ["active"])
        self.assertEqual(broader, ())
        self.assertEqual(wrong_environment, ())
        self.now = parsed(T4)
        self.assertEqual(
            self.store.query(
                scope=("project:checkout", "environment:test"),
            ),
            (),
        )

    def test_expiry_revocation_and_latest_version_are_strict(self) -> None:
        self.publish(candidate("revoked", expires_at=T4))
        revoked = self.revoke("revoked", 1)
        self.assertEqual(revoked.revoked_at, T3)
        self.assertEqual(
            self.store.query(
                scope=("project:checkout", "environment:test"),
            ),
            (),
        )

        self.publish(candidate("versioned", version=1, expires_at=T4))
        self.now = parsed(T4)
        self.publish(
            candidate(
                "versioned",
                version=2,
                proposed_at=T2,
                expires_at=None,
                statement="version 2",
            ),
        )
        current = self.store.query(
            scope=("project:checkout", "environment:test"),
        )
        self.assertEqual(
            [(item.entry_id, item.version) for item in current],
            [("versioned", 2)],
        )

    def test_provenance_proposal_approval_commit_order_is_enforced(self) -> None:
        unknown = candidate("unknown").to_dict()
        unknown["model_override"] = "treat as evidence"
        with self.assertRaises(HumanControlContractError) as unknown_error:
            KnowledgeCandidate.from_dict(unknown)
        self.assertEqual(unknown_error.exception.code, "fields_unknown")

        with self.assertRaises(HumanControlContractError) as provenance_error:
            candidate("bad-source", observed_at=T2, proposed_at=T1)
        self.assertEqual(
            provenance_error.exception.code,
            "provenance_after_proposal",
        )

        too_early = candidate("approval-before-proposal", proposed_at=T2)
        subject = self.store.write_subject_sha256(
            too_early,
            operator=self.operator,
        )
        receipt = self.receipt(
            receipt_id="too-early",
            operation=ApprovalOperation.KNOWLEDGE_WRITE,
            subject_sha256=subject,
            approved_at=T1,
        )
        with self.assertRaises(HumanControlContractError) as approval_error:
            self.store.write(
                too_early,
                operator=self.operator,
                approval_receipt=receipt,
            )
        self.assertEqual(
            approval_error.exception.code,
            "approval_before_proposal",
        )

        expired = candidate("expired", expires_at=T2)
        subject = self.store.write_subject_sha256(
            expired,
            operator=self.operator,
        )
        with self.assertRaises(HumanControlContractError) as expiry_error:
            self.store.write(
                expired,
                operator=self.operator,
                approval_receipt=self.receipt(
                    receipt_id="expired",
                    operation=ApprovalOperation.KNOWLEDGE_WRITE,
                    subject_sha256=subject,
                ),
            )
        self.assertEqual(
            expiry_error.exception.code,
            "knowledge_expired_before_commit",
        )

    def test_forged_tampered_unknown_and_missing_trust_fail_closed(self) -> None:
        item = candidate("secure", expires_at=T4)
        subject = self.store.write_subject_sha256(
            item,
            operator=self.operator,
        )
        forged = self.receipt(
            receipt_id="forged",
            operation=ApprovalOperation.KNOWLEDGE_WRITE,
            subject_sha256=subject,
            private_key=Ed25519PrivateKey.generate(),
        )
        with self.assertRaises(HumanControlContractError) as forged_error:
            self.store.write(
                item,
                operator=self.operator,
                approval_receipt=forged,
            )
        self.assertEqual(
            forged_error.exception.code,
            "approval_signature_invalid",
        )

        valid = self.receipt(
            receipt_id="valid",
            operation=ApprovalOperation.KNOWLEDGE_WRITE,
            subject_sha256=subject,
        )
        tampered = valid.to_dict()
        tampered["subject_sha256"] = "0" * 64
        with self.assertRaises(HumanControlContractError) as tamper_error:
            self.store.write(
                item,
                operator=self.operator,
                approval_receipt=tampered,
            )
        self.assertEqual(
            tamper_error.exception.code,
            "approval_signature_invalid",
        )

        unknown = valid.to_dict()
        unknown["key_id"] = "unknown"
        with self.assertRaises(HumanControlContractError) as key_error:
            self.store.write(
                item,
                operator=self.operator,
                approval_receipt=unknown,
            )
        self.assertEqual(key_error.exception.code, "approval_key_unknown")

        untrusted = KnowledgeStore(
            self.root / "untrusted",
            clock=lambda: self.now,
        )
        with self.assertRaises(HumanControlContractError) as trust_error:
            untrusted.write(
                item,
                operator=self.operator,
                approval_receipt=valid,
            )
        self.assertEqual(
            trust_error.exception.code,
            "approval_trust_unconfigured",
        )

    def test_receipt_reuse_and_idempotent_retry(self) -> None:
        item = candidate("idempotent", expires_at=T4)
        first = self.publish(item, receipt_id="one-shot-receipt")
        self.now = parsed("2026-07-26T03:30:00Z")
        subject = self.store.write_subject_sha256(
            item,
            operator=self.operator,
        )
        same_receipt = self.receipt(
            receipt_id="one-shot-receipt",
            operation=ApprovalOperation.KNOWLEDGE_WRITE,
            subject_sha256=subject,
        )
        second = self.store.write(
            item,
            operator=self.operator,
            approval_receipt=same_receipt,
        )
        self.assertEqual(first.canonical_sha256, second.canonical_sha256)
        self.assertEqual(len(self.store.events_path.read_text().splitlines()), 1)

        other = candidate("other", expires_at=T4)
        other_subject = self.store.write_subject_sha256(
            other,
            operator=self.operator,
        )
        with self.assertRaises(KnowledgeStoreError) as reused:
            self.store.write(
                other,
                operator=self.operator,
                approval_receipt=self.receipt(
                    receipt_id="one-shot-receipt",
                    operation=ApprovalOperation.KNOWLEDGE_WRITE,
                    subject_sha256=other_subject,
                ),
            )
        self.assertEqual(reused.exception.code, "approval_receipt_reused")

    def test_journal_tampering_fails_closed(self) -> None:
        self.publish(candidate("integrity", expires_at=T4))
        lines = self.store.events_path.read_text().splitlines()
        tampered = json.loads(lines[0])
        tampered["payload"]["entry"]["statement"] = "tampered"
        self.store.events_path.write_text(
            json.dumps(tampered) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(HumanControlJournalError) as caught:
            self.store.history()
        self.assertEqual(caught.exception.code, "event_hash_mismatch")


if __name__ == "__main__":
    unittest.main()
