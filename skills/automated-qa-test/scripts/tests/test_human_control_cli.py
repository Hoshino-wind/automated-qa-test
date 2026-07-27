#!/usr/bin/env python3
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPT_DIR = Path(__file__).resolve().parents[1]
CLI_PATH = SCRIPT_DIR / "human_control_cli.py"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.hitl import (  # noqa: E402
    canonical_checkpoint_bytes,
    checkpoint_signing_payload,
    public_key_pem,
    signed_receipt_dict,
)
from qa_core.hitl._journal import GENESIS_HASH  # noqa: E402

CONTEXT = "a" * 64
ACTION = "b" * 64
POLICY = "c" * 64
AUTHORIZATION = "d" * 64


def timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def operator_payload() -> dict:
    return {
        "schema_version": 1,
        "operator_id": "operator-1",
        "identity_provider": "corp-sso",
        "identity_subject": "user:operator-1",
    }


class HumanControlCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private_key = Ed25519PrivateKey.generate()
        self.operator_path = self.root / "operator.json"
        self.trust_path = self.root / "trust.json"
        write_json(self.operator_path, operator_payload())
        write_json(
            self.trust_path,
            {
                "schema_version": 1,
                "authorities": [
                    {
                        "authority": "corp-approval-service",
                        "keys": [
                            {
                                "key_id": "approval-key-1",
                                "algorithm": "Ed25519",
                                "public_key_pem": public_key_pem(
                                    self.private_key,
                                ),
                            },
                        ],
                    },
                ],
                "checkpoint_authorities": [
                    {
                        "authority": "checkpoint-service",
                        "keys": [
                            {
                                "key_id": "checkpoint-key-1",
                                "algorithm": "Ed25519",
                                "public_key_pem": public_key_pem(
                                    self.private_key,
                                ),
                            },
                        ],
                    },
                ],
            },
        )
        now = datetime.now(UTC).replace(microsecond=0)
        self.observed_at = timestamp(now - timedelta(minutes=4))
        self.proposed_at = timestamp(now - timedelta(minutes=3))
        self.approved_at = timestamp(now - timedelta(minutes=1))
        self.expires_at = timestamp(now + timedelta(hours=1))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(
        self,
        *arguments: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CLI_PATH), *arguments],
            text=True,
            capture_output=True,
        )

    def store_args(self, store: Path) -> list[str]:
        return [
            "--store",
            str(store),
            "--trust-config",
            str(self.trust_path),
        ]

    def binding_args(self) -> list[str]:
        return [
            "--expected-run-id",
            "run-1",
            "--expected-lease-generation",
            "7",
            "--expected-context-sha256",
            CONTEXT,
            "--expected-action-sha256",
            ACTION,
            "--expected-policy-sha256",
            POLICY,
            "--expected-authorization-sha256",
            AUTHORIZATION,
        ]

    def receipt(
        self,
        *,
        receipt_id: str,
        operation: str,
        subject_sha256: str,
        decision: str = "approved",
    ) -> dict:
        return signed_receipt_dict(
            {
                "schema_version": 1,
                "receipt_id": receipt_id,
                "operation": operation,
                "operator_id": "operator-1",
                "subject_sha256": subject_sha256,
                "decision": decision,
                "approved_at": self.approved_at,
                "authority": "corp-approval-service",
                "key_id": "approval-key-1",
                "external_receipt_sha256": hashlib.sha256(
                    receipt_id.encode(),
                ).hexdigest(),
            },
            private_key=self.private_key,
        )

    def publish_checkpoint(
        self,
        *,
        store: Path,
        journal_kind: str,
        checkpoint_path: Path,
    ) -> int:
        events_path = store / f"{journal_kind}-events.jsonl"
        events = (
            [
                json.loads(line)
                for line in events_path.read_text(
                    encoding="utf-8",
                ).splitlines()
            ]
            if events_path.exists()
            else []
        )
        event_count = len(events)
        terminal_hash = (
            events[-1]["event_hash"]
            if events
            else GENESIS_HASH
        )
        payload = checkpoint_signing_payload(
            journal_kind=journal_kind,
            events_path=events_path,
            event_count=event_count,
            terminal_event_hash=terminal_hash,
            issued_at=self.approved_at,
            expires_at=self.expires_at,
            authority="checkpoint-service",
            key_id="checkpoint-key-1",
        )
        encoded_signature = base64.urlsafe_b64encode(
            self.private_key.sign(canonical_checkpoint_bytes(payload)),
        ).rstrip(b"=").decode("ascii")
        write_json(
            checkpoint_path,
            {
                **payload,
                "signature": encoded_signature,
            },
        )
        return event_count

    def test_knowledge_write_and_runtime_query_use_public_trust_only(self) -> None:
        store = self.root / "knowledge"
        candidate_path = self.root / "candidate.json"
        subject_path = self.root / "subject.json"
        receipt_path = self.root / "receipt.json"
        query_path = self.root / "query.json"
        write_json(
            candidate_path,
            {
                "schema_version": 1,
                "entry_id": "knowledge-1",
                "topic": "runtime",
                "statement": "目标使用隔离测试数据库",
                "provenance": [
                    {
                        "schema_version": 1,
                        "source_id": "source-1",
                        "source_type": "operator_observation",
                        "reference": "approval/session-1",
                        "sha256": "e" * 64,
                        "observed_at": self.observed_at,
                    },
                ],
                "scope": [
                    "environment:test",
                    "project:checkout",
                ],
                "version": 1,
                "proposed_at": self.proposed_at,
                "expires_at": self.expires_at,
            },
        )
        subject = self.run_cli(
            "knowledge-write-subject",
            *self.store_args(store),
            "--candidate",
            str(candidate_path),
            "--operator",
            str(self.operator_path),
            "--out",
            str(subject_path),
        )
        self.assertEqual(subject.returncode, 0, subject.stderr)
        subject_hash = json.loads(
            subject_path.read_text(),
        )["subject_sha256"]
        write_json(
            receipt_path,
            self.receipt(
                receipt_id="write-1",
                operation="knowledge_write",
                subject_sha256=subject_hash,
            ),
        )
        written = self.run_cli(
            "knowledge-write",
            *self.store_args(store),
            "--candidate",
            str(candidate_path),
            "--operator",
            str(self.operator_path),
            "--receipt",
            str(receipt_path),
        )
        self.assertEqual(written.returncode, 0, written.stderr)
        entry = json.loads(written.stdout)["entry"]
        self.assertTrue(entry["not_evidence"])
        self.assertLessEqual(entry["proposed_at"], self.approved_at)
        self.assertLessEqual(self.approved_at, entry["committed_at"])

        queried = self.run_cli(
            "knowledge-query",
            *self.store_args(store),
            "--scope",
            "project:checkout",
            "--scope",
            "environment:test",
            "--out",
            str(query_path),
        )
        self.assertEqual(queried.returncode, 0, queried.stderr)
        self.assertEqual(
            json.loads(query_path.read_text())["entries"][0]["entry_id"],
            "knowledge-1",
        )

    def test_hitl_decide_consume_and_replay_rejection(self) -> None:
        store = self.root / "hitl"
        request_path = self.root / "request.json"
        subject_path = self.root / "decision-subject.json"
        receipt_path = self.root / "decision-receipt.json"
        decision_path = self.root / "decision.json"
        write_json(
            request_path,
            {
                "schema_version": 1,
                "request_id": "request-1",
                "run_id": "run-1",
                "lease_generation": 7,
                "context_sha256": CONTEXT,
                "action_sha256": ACTION,
                "policy_sha256": POLICY,
                "authorization_sha256": AUTHORIZATION,
                "action_summary": "执行隔离环境迁移验证",
                "question": "是否允许？",
                "allowed_decisions": ["approved", "rejected"],
                "created_at": self.proposed_at,
                "expires_at": self.expires_at,
                "not_evidence": True,
            },
        )
        created = self.run_cli(
            "hitl-create",
            *self.store_args(store),
            "--request",
            str(request_path),
        )
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertEqual(
            json.loads(created.stdout)["journal_assurance"],
            {
                "mode": "local-test",
                "checkpoint_required": False,
                "production_ready": False,
                "covered_count": None,
                "current_count": 1,
                "tail_count": None,
            },
        )

        subject = self.run_cli(
            "hitl-decision-subject",
            *self.store_args(store),
            "--request-id",
            "request-1",
            "--decision-id",
            "decision-1",
            "--decision",
            "approved",
            "--reason",
            "边界已确认",
            "--decided-at",
            self.approved_at,
            "--operator",
            str(self.operator_path),
            *self.binding_args(),
            "--out",
            str(subject_path),
        )
        self.assertEqual(subject.returncode, 0, subject.stderr)
        subject_hash = json.loads(
            subject_path.read_text(),
        )["subject_sha256"]
        receipt = self.receipt(
            receipt_id="decision-1",
            operation="hitl_decision",
            subject_sha256=subject_hash,
        )
        write_json(receipt_path, receipt)
        write_json(
            decision_path,
            {
                "schema_version": 1,
                "decision_id": "decision-1",
                "request_id": "request-1",
                "run_id": "run-1",
                "lease_generation": 7,
                "context_sha256": CONTEXT,
                "action_sha256": ACTION,
                "policy_sha256": POLICY,
                "authorization_sha256": AUTHORIZATION,
                "decision": "approved",
                "reason": "边界已确认",
                "decided_at": self.approved_at,
                "operator": operator_payload(),
                "approval_receipt": receipt,
                "not_evidence": True,
            },
        )
        decided = self.run_cli(
            "hitl-decide",
            *self.store_args(store),
            "--decision-file",
            str(decision_path),
            *self.binding_args(),
        )
        self.assertEqual(decided.returncode, 0, decided.stderr)

        consumed = self.run_cli(
            "hitl-consume",
            *self.store_args(store),
            "--request-id",
            "request-1",
            "--consumption-id",
            "consume-1",
            *self.binding_args(),
        )
        self.assertEqual(consumed.returncode, 0, consumed.stderr)
        self.assertEqual(json.loads(consumed.stdout)["hitl"]["status"], "consumed")

        replay = self.run_cli(
            "hitl-consume",
            *self.store_args(store),
            "--request-id",
            "request-1",
            "--consumption-id",
            "consume-1",
            *self.binding_args(),
        )
        self.assertEqual(replay.returncode, 1)
        self.assertEqual(
            json.loads(replay.stdout)["error"]["code"],
            "decision_already_consumed",
        )

    def test_cli_rejects_private_key_trust_config(self) -> None:
        unsafe = self.root / "unsafe-trust.json"
        write_json(
            unsafe,
            {
                "schema_version": 1,
                "authorities": [
                    {
                        "authority": "corp-approval-service",
                        "keys": [
                            {
                                "key_id": "key-1",
                                "algorithm": "Ed25519",
                                "public_key_pem": (
                                    "-----BEGIN PRIVATE KEY-----\nunsafe"
                                ),
                            },
                        ],
                    },
                ],
            },
        )
        result = self.run_cli(
            "knowledge-query",
            "--store",
            str(self.root / "store"),
            "--trust-config",
            str(unsafe),
            "--scope",
            "project:checkout",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("包含私钥", result.stderr)

    def test_production_cli_requires_and_verifies_external_checkpoint(
        self,
    ) -> None:
        store = self.root / "production-hitl"
        request_path = self.root / "production-request.json"
        checkpoint_path = self.root / "hitl-checkpoint.json"
        write_json(
            request_path,
            {
                "schema_version": 1,
                "request_id": "production-request",
                "run_id": "run-1",
                "lease_generation": 7,
                "context_sha256": CONTEXT,
                "action_sha256": ACTION,
                "policy_sha256": POLICY,
                "authorization_sha256": AUTHORIZATION,
                "action_summary": "执行隔离环境验证",
                "question": "是否允许？",
                "allowed_decisions": ["approved", "rejected"],
                "created_at": self.proposed_at,
                "expires_at": self.expires_at,
                "not_evidence": True,
            },
        )
        missing = self.run_cli(
            "hitl-create",
            *self.store_args(store),
            "--journal-mode",
            "production",
            "--request",
            str(request_path),
        )
        self.assertEqual(missing.returncode, 1)
        self.assertEqual(
            json.loads(missing.stdout)["error"]["code"],
            "checkpoint_required",
        )

        self.publish_checkpoint(
            store=store,
            journal_kind="hitl",
            checkpoint_path=checkpoint_path,
        )
        created = self.run_cli(
            "hitl-create",
            *self.store_args(store),
            "--journal-mode",
            "production",
            "--checkpoint",
            str(checkpoint_path),
            "--request",
            str(request_path),
        )
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertEqual(
            json.loads(created.stdout)["journal_assurance"],
            {
                "mode": "production",
                "checkpoint_required": True,
                "production_ready": False,
                "covered_count": 0,
                "current_count": 1,
                "tail_count": 1,
            },
        )

        stale_resume = self.run_cli(
            "hitl-resume",
            *self.store_args(store),
            "--journal-mode",
            "production",
            "--checkpoint",
            str(checkpoint_path),
            "--request-id",
            "production-request",
            *self.binding_args(),
        )
        self.assertEqual(stale_resume.returncode, 1)
        stale_payload = json.loads(stale_resume.stdout)
        self.assertEqual(
            stale_payload["error"]["code"],
            "checkpoint_tail_uncovered",
        )
        self.assertEqual(
            stale_payload["journal_assurance"],
            {
                "mode": "production",
                "checkpoint_required": True,
                "production_ready": False,
                "covered_count": 0,
                "current_count": 1,
                "tail_count": 1,
            },
        )

        self.assertEqual(
            self.publish_checkpoint(
                store=store,
                journal_kind="hitl",
                checkpoint_path=checkpoint_path,
            ),
            1,
        )
        resumed = self.run_cli(
            "hitl-resume",
            *self.store_args(store),
            "--journal-mode",
            "production",
            "--checkpoint",
            str(checkpoint_path),
            "--request-id",
            "production-request",
            *self.binding_args(),
        )
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(
            json.loads(resumed.stdout)["journal_assurance"],
            {
                "mode": "production",
                "checkpoint_required": True,
                "production_ready": True,
                "covered_count": 1,
                "current_count": 1,
                "tail_count": 0,
            },
        )

        subject_path = self.root / "production-decision-subject.json"
        receipt_path = self.root / "production-decision-receipt.json"
        decision_path = self.root / "production-decision.json"
        subject = self.run_cli(
            "hitl-decision-subject",
            *self.store_args(store),
            "--journal-mode",
            "production",
            "--checkpoint",
            str(checkpoint_path),
            "--request-id",
            "production-request",
            "--decision-id",
            "production-decision",
            "--decision",
            "approved",
            "--reason",
            "production boundary confirmed",
            "--decided-at",
            self.approved_at,
            "--operator",
            str(self.operator_path),
            *self.binding_args(),
            "--out",
            str(subject_path),
        )
        self.assertEqual(subject.returncode, 0, subject.stderr)
        subject_sha256 = json.loads(
            subject_path.read_text(encoding="utf-8"),
        )["subject_sha256"]
        receipt = self.receipt(
            receipt_id="production-decision",
            operation="hitl_decision",
            subject_sha256=subject_sha256,
        )
        write_json(receipt_path, receipt)
        write_json(
            decision_path,
            {
                "schema_version": 1,
                "decision_id": "production-decision",
                "request_id": "production-request",
                "run_id": "run-1",
                "lease_generation": 7,
                "context_sha256": CONTEXT,
                "action_sha256": ACTION,
                "policy_sha256": POLICY,
                "authorization_sha256": AUTHORIZATION,
                "decision": "approved",
                "reason": "production boundary confirmed",
                "decided_at": self.approved_at,
                "operator": operator_payload(),
                "approval_receipt": receipt,
                "not_evidence": True,
            },
        )
        decided = self.run_cli(
            "hitl-decide",
            *self.store_args(store),
            "--journal-mode",
            "production",
            "--checkpoint",
            str(checkpoint_path),
            "--decision-file",
            str(decision_path),
            *self.binding_args(),
        )
        self.assertEqual(decided.returncode, 0, decided.stderr)
        self.assertEqual(
            json.loads(decided.stdout)["journal_assurance"]["tail_count"],
            1,
        )

        self.assertEqual(
            self.publish_checkpoint(
                store=store,
                journal_kind="hitl",
                checkpoint_path=checkpoint_path,
            ),
            2,
        )
        consumed = self.run_cli(
            "hitl-consume",
            *self.store_args(store),
            "--journal-mode",
            "production",
            "--checkpoint",
            str(checkpoint_path),
            "--request-id",
            "production-request",
            "--consumption-id",
            "production-consumption",
            *self.binding_args(),
        )
        self.assertEqual(consumed.returncode, 1)
        self.assertTrue(consumed.stdout, consumed.stderr)
        consumed_payload = json.loads(consumed.stdout)
        self.assertEqual(
            consumed_payload["error"]["code"],
            "checkpoint_refresh_required",
        )
        self.assertEqual(
            consumed_payload["journal_assurance"],
            {
                "mode": "production",
                "checkpoint_required": True,
                "production_ready": False,
                "covered_count": 2,
                "current_count": 3,
                "tail_count": 1,
            },
        )

        unanchored_resume = self.run_cli(
            "hitl-resume",
            *self.store_args(store),
            "--journal-mode",
            "production",
            "--checkpoint",
            str(checkpoint_path),
            "--request-id",
            "production-request",
            *self.binding_args(),
        )
        self.assertEqual(unanchored_resume.returncode, 1)
        self.assertEqual(
            json.loads(unanchored_resume.stdout)["error"]["code"],
            "checkpoint_tail_uncovered",
        )

        self.assertEqual(
            self.publish_checkpoint(
                store=store,
                journal_kind="hitl",
                checkpoint_path=checkpoint_path,
            ),
            3,
        )
        confirmed = self.run_cli(
            "hitl-resume",
            *self.store_args(store),
            "--journal-mode",
            "production",
            "--checkpoint",
            str(checkpoint_path),
            "--request-id",
            "production-request",
            *self.binding_args(),
        )
        self.assertEqual(confirmed.returncode, 0, confirmed.stderr)
        confirmed_payload = json.loads(confirmed.stdout)
        self.assertEqual(confirmed_payload["hitl"]["status"], "consumed")
        self.assertEqual(
            confirmed_payload["hitl"]["consumption"]["consumption_id"],
            "production-consumption",
        )
        self.assertEqual(
            confirmed_payload["journal_assurance"]["tail_count"],
            0,
        )


if __name__ == "__main__":
    unittest.main()
