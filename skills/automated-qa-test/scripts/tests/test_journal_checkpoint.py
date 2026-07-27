#!/usr/bin/env python3
import base64
import json
import os
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
    HITLStore,
    JournalCheckpointVerifier,
    canonical_checkpoint_bytes,
    checkpoint_signing_payload,
    public_key_pem,
)
from qa_core.hitl._journal import (  # noqa: E402
    GENESIS_HASH,
    AppendOnlyJsonJournal,
    HumanControlJournalError,
    JournalEvent,
    JournalMutation,
)
from qa_core.knowledge import KnowledgeStore  # noqa: E402

T0 = "2026-07-26T00:00:00Z"
T1 = "2026-07-26T01:00:00Z"
T2 = "2026-07-26T02:00:00Z"
T3 = "2026-07-26T03:00:00Z"


def parsed(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def signature(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class JournalCheckpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private_key = Ed25519PrivateKey.generate()
        self.trust = {
            "checkpoint-service": {
                "checkpoint-key-1": public_key_pem(self.private_key),
            },
        }
        self.now = parsed(T2)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def append(
        self,
        directory: Path,
        *,
        name: str,
        count: int,
    ) -> AppendOnlyJsonJournal:
        journal = AppendOnlyJsonJournal(directory, name=name)
        for index in range(count):
            journal.transact(
                prepare=lambda _events, index=index: JournalMutation(
                    event_type="test_event",
                    occurred_at=T0,
                    payload={"index": index},
                ),
                project=lambda events: {"count": len(events)},
            )
        return journal

    def write_checkpoint(
        self,
        journal: AppendOnlyJsonJournal,
        *,
        checkpoint_path: Path | None = None,
        event_count: int | None = None,
        journal_kind: str | None = None,
        authority: str = "checkpoint-service",
        key_id: str = "checkpoint-key-1",
        private_key: Ed25519PrivateKey | None = None,
        issued_at: str = T1,
        expires_at: str = T3,
    ) -> Path:
        events = journal.load_events()
        anchored_count = (
            len(events)
            if event_count is None
            else event_count
        )
        terminal_hash = (
            GENESIS_HASH
            if anchored_count == 0
            else events[anchored_count - 1].event_hash
        )
        payload = checkpoint_signing_payload(
            journal_kind=journal_kind or journal.name,
            events_path=journal.events_path,
            event_count=anchored_count,
            terminal_event_hash=terminal_hash,
            issued_at=issued_at,
            expires_at=expires_at,
            authority=authority,
            key_id=key_id,
        )
        signer = private_key or self.private_key
        checkpoint = {
            **payload,
            "signature": signature(
                signer.sign(canonical_checkpoint_bytes(payload)),
            ),
        }
        destination = checkpoint_path or (
            self.root / f"{journal.name}-checkpoint.json"
        )
        destination.write_text(
            json.dumps(checkpoint, separators=(",", ":")),
            encoding="utf-8",
        )
        return destination

    def production_journal(
        self,
        journal: AppendOnlyJsonJournal,
        checkpoint_path: Path,
        *,
        trust=None,
    ) -> AppendOnlyJsonJournal:
        guard = JournalCheckpointVerifier.configured(
            mode="production",
            checkpoint_path=checkpoint_path,
            trusted_authority_keys=trust or self.trust,
            clock=lambda: self.now,
        )
        return AppendOnlyJsonJournal(
            journal.directory,
            name=journal.name,
            checkpoint_guard=guard,
        )

    def test_production_checkpoint_must_cover_the_exact_current_tail(
        self,
    ) -> None:
        for kind in ("hitl", "knowledge"):
            with self.subTest(kind=kind):
                journal = self.append(
                    self.root / kind,
                    name=kind,
                    count=2,
                )
                checkpoint = self.write_checkpoint(
                    journal,
                    event_count=1,
                )
                anchored = self.production_journal(
                    journal,
                    checkpoint,
                )
                with self.assertRaises(
                    HumanControlJournalError,
                ) as caught:
                    anchored.load_events()
                self.assertEqual(
                    caught.exception.code,
                    "checkpoint_tail_uncovered",
                )
                self.assertEqual(
                    caught.exception.to_dict()
                    | {},
                    {
                        "schema_version": 1,
                        "error": "human_control_journal_error",
                        "code": "checkpoint_tail_uncovered",
                        "message": (
                            "production journal 存在 checkpoint 未覆盖的 "
                            "tail：2 current, 1 covered"
                        ),
                        "covered_count": 1,
                        "current_count": 2,
                        "tail_count": 1,
                    },
                )
                self.assertEqual(
                    anchored._checkpoint_guard.assurance,
                    {
                        "mode": "production",
                        "checkpoint_required": True,
                        "production_ready": False,
                        "covered_count": 1,
                        "current_count": 2,
                        "tail_count": 1,
                    },
                )

    def test_complete_tail_truncation_fails_closed(self) -> None:
        journal = self.append(
            self.root / "rollback",
            name="hitl",
            count=3,
        )
        checkpoint = self.write_checkpoint(journal)
        lines = journal.events_path.read_text(encoding="utf-8").splitlines()
        journal.events_path.write_text(
            "\n".join(lines[:2]) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(HumanControlJournalError) as caught:
            self.production_journal(
                journal,
                checkpoint,
            ).load_events()
        self.assertEqual(
            caught.exception.code,
            "checkpoint_journal_rollback",
        )

    def test_checkpoint_from_different_path_or_kind_is_rejected(self) -> None:
        source = self.append(
            self.root / "source",
            name="hitl",
            count=1,
        )
        target = self.append(
            self.root / "target",
            name="hitl",
            count=1,
        )
        different_path = self.write_checkpoint(source)
        with self.assertRaises(HumanControlJournalError) as path_error:
            self.production_journal(
                target,
                different_path,
            ).load_events()
        self.assertEqual(
            path_error.exception.code,
            "checkpoint_journal_identity_mismatch",
        )

        wrong_kind = self.write_checkpoint(
            target,
            checkpoint_path=self.root / "wrong-kind.json",
            journal_kind="knowledge",
        )
        with self.assertRaises(HumanControlJournalError) as kind_error:
            self.production_journal(
                target,
                wrong_kind,
            ).load_events()
        self.assertEqual(
            kind_error.exception.code,
            "checkpoint_journal_kind_mismatch",
        )

    def test_validly_rehashed_fork_at_checkpoint_position_is_rejected(
        self,
    ) -> None:
        journal = self.append(
            self.root / "fork",
            name="knowledge",
            count=2,
        )
        checkpoint = self.write_checkpoint(journal)
        original = journal.load_events()
        forked = JournalEvent.create(
            sequence=2,
            event_type="test_event",
            occurred_at=T0,
            payload={"index": "attacker-fork"},
            previous_hash=original[0].event_hash,
        )
        journal.events_path.write_text(
            "\n".join(
                json.dumps(
                    event.to_dict(),
                    separators=(",", ":"),
                )
                for event in (original[0], forked)
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(HumanControlJournalError) as caught:
            self.production_journal(
                journal,
                checkpoint,
            ).load_events()
        self.assertEqual(
            caught.exception.code,
            "checkpoint_prefix_mismatch",
        )

    def test_unknown_key_and_bad_signature_fail_closed(self) -> None:
        journal = self.append(
            self.root / "signature",
            name="knowledge",
            count=1,
        )
        unknown = self.write_checkpoint(
            journal,
            key_id="unknown-key",
        )
        with self.assertRaises(HumanControlJournalError) as key_error:
            self.production_journal(
                journal,
                unknown,
            ).load_events()
        self.assertEqual(
            key_error.exception.code,
            "checkpoint_key_unknown",
        )

        forged = self.write_checkpoint(
            journal,
            checkpoint_path=self.root / "forged.json",
            private_key=Ed25519PrivateKey.generate(),
        )
        with self.assertRaises(HumanControlJournalError) as signature_error:
            self.production_journal(
                journal,
                forged,
            ).load_events()
        self.assertEqual(
            signature_error.exception.code,
            "checkpoint_signature_invalid",
        )

    def test_future_and_expired_checkpoints_fail_closed(self) -> None:
        journal = self.append(
            self.root / "time",
            name="hitl",
            count=1,
        )
        future = self.write_checkpoint(
            journal,
            issued_at=T3,
            expires_at="2026-07-26T04:00:00Z",
        )
        with self.assertRaises(HumanControlJournalError) as future_error:
            self.production_journal(
                journal,
                future,
            ).load_events()
        self.assertEqual(
            future_error.exception.code,
            "checkpoint_issued_in_future",
        )

        expired = self.write_checkpoint(
            journal,
            checkpoint_path=self.root / "expired.json",
            issued_at=T0,
            expires_at=T1,
        )
        with self.assertRaises(HumanControlJournalError) as expired_error:
            self.production_journal(
                journal,
                expired,
            ).load_events()
        self.assertEqual(
            expired_error.exception.code,
            "checkpoint_expired",
        )

    def test_checkpoint_strict_json_symlink_and_hardlink_boundaries(self) -> None:
        journal = self.append(
            self.root / "files",
            name="knowledge",
            count=1,
        )
        checkpoint = self.write_checkpoint(journal)

        duplicate = self.root / "duplicate.json"
        body = checkpoint.read_text(encoding="utf-8")
        duplicate.write_text(
            '{"schema_version":1,' + body[1:],
            encoding="utf-8",
        )
        with self.assertRaises(HumanControlJournalError) as duplicate_error:
            self.production_journal(
                journal,
                duplicate,
            ).load_events()
        self.assertEqual(
            duplicate_error.exception.code,
            "checkpoint_json_duplicate_key",
        )

        symlink = self.root / "checkpoint-symlink.json"
        symlink.symlink_to(checkpoint)
        with self.assertRaises(HumanControlJournalError) as symlink_error:
            self.production_journal(
                journal,
                symlink,
            ).load_events()
        self.assertEqual(symlink_error.exception.code, "checkpoint_not_file")

        hardlink = self.root / "checkpoint-hardlink.json"
        os.link(checkpoint, hardlink)
        with self.assertRaises(HumanControlJournalError) as hardlink_error:
            self.production_journal(
                journal,
                hardlink,
            ).load_events()
        self.assertEqual(
            hardlink_error.exception.code,
            "checkpoint_hardlink_unsafe",
        )

    def test_journal_duplicate_json_keys_are_rejected(self) -> None:
        journal = self.append(
            self.root / "duplicate-event",
            name="hitl",
            count=1,
        )
        body = journal.events_path.read_text(encoding="utf-8")
        journal.events_path.write_text(
            '{"schema_version":1,' + body[1:],
            encoding="utf-8",
        )
        with self.assertRaises(HumanControlJournalError) as caught:
            journal.load_events()
        self.assertEqual(
            caught.exception.code,
            "journal_json_duplicate_key",
        )

    def test_production_configuration_is_required_and_store_wiring_is_exact(
        self,
    ) -> None:
        with self.assertRaises(HumanControlJournalError) as missing:
            JournalCheckpointVerifier.configured(mode="production")
        self.assertEqual(missing.exception.code, "checkpoint_required")

        for store_type, kind in (
            (HITLStore, "hitl"),
            (KnowledgeStore, "knowledge"),
        ):
            with self.subTest(kind=kind):
                directory = self.root / f"store-{kind}"
                journal = self.append(
                    directory,
                    name=kind,
                    count=1,
                )
                checkpoint = self.write_checkpoint(
                    journal,
                    checkpoint_path=self.root / f"store-{kind}.json",
                )
                store = store_type(
                    directory,
                    journal_mode="production",
                    checkpoint_path=checkpoint,
                    trusted_checkpoint_keys=self.trust,
                    clock=lambda: self.now,
                )
                self.assertTrue(
                    store.journal_assurance["production_ready"],
                )
                self.assertEqual(
                    {
                        key: store.journal_assurance[key]
                        for key in (
                            "covered_count",
                            "current_count",
                            "tail_count",
                        )
                    },
                    {
                        "covered_count": 1,
                        "current_count": 1,
                        "tail_count": 0,
                    },
                )

        local = HITLStore(self.root / "local")
        self.assertEqual(local.journal_assurance["mode"], "local-test")
        self.assertFalse(local.journal_assurance["production_ready"])
        self.assertIsNone(local.journal_assurance["covered_count"])
        self.assertIsNone(local.journal_assurance["current_count"])
        self.assertIsNone(local.journal_assurance["tail_count"])


if __name__ == "__main__":
    unittest.main()
