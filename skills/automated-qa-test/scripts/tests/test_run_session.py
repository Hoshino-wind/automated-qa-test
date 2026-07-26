#!/usr/bin/env python3
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.runtime.lease import LeaseAlreadyHeldError, RunLease  # noqa: E402
from qa_core.runtime.session import (  # noqa: E402
    AGENT_OWNER_PREFIX,
    CYCLE_OWNER_PREFIX,
    LEASE_FILENAME,
    RunSession,
)
from qa_core.state import EventLogError, RunStateStore  # noqa: E402


class RunSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temporary.name)
        self.sessions: list[RunSession] = []

    def tearDown(self) -> None:
        for session in reversed(self.sessions):
            session.close()
        self.temporary.cleanup()

    def keep(self, session: RunSession) -> RunSession:
        self.sessions.append(session)
        return session

    def test_standalone_session_acquires_and_idempotently_releases(self) -> None:
        session = RunSession.open(
            self.run_dir,
            owner_prefix=CYCLE_OWNER_PREFIX,
            pid=101,
            parent_pid=100,
        )

        self.assertFalse(session.inherited)
        self.assertTrue(session.owner.startswith("qa-cycle:101:"))
        self.assertEqual(session.generation, 1)
        self.assertTrue((self.run_dir / LEASE_FILENAME).is_file())

        session.close()
        session.close()
        self.assertFalse((self.run_dir / LEASE_FILENAME).exists())

    def test_second_writer_is_rejected(self) -> None:
        first = self.keep(
            RunSession.open(
                self.run_dir,
                owner_prefix=AGENT_OWNER_PREFIX,
                pid=201,
            )
        )

        with self.assertRaises(LeaseAlreadyHeldError):
            RunSession.open(
                self.run_dir,
                owner_prefix=AGENT_OWNER_PREFIX,
                pid=202,
            )

    def test_direct_child_cycle_can_join_parent_agent_lease(self) -> None:
        parent = self.keep(
            RunSession.open(
                self.run_dir,
                owner_prefix=AGENT_OWNER_PREFIX,
                pid=301,
            )
        )

        child = RunSession.open(
            self.run_dir,
            owner_prefix=CYCLE_OWNER_PREFIX,
            allow_parent_inheritance=True,
            pid=302,
            parent_pid=301,
        )

        self.assertTrue(child.inherited)
        self.assertEqual(child.run_id, parent.run_id)
        self.assertEqual(child.owner, parent.owner)
        child.close()
        self.assertIsNotNone(parent.lease.read())

    def test_non_parent_or_non_agent_lease_cannot_be_inherited(self) -> None:
        unrelated = self.keep(
            RunSession.open(
                self.run_dir,
                owner_prefix=CYCLE_OWNER_PREFIX,
                pid=401,
            )
        )

        with self.assertRaises(LeaseAlreadyHeldError):
            RunSession.open(
                self.run_dir,
                owner_prefix=CYCLE_OWNER_PREFIX,
                allow_parent_inheritance=True,
                pid=402,
                parent_pid=401,
            )

    def test_existing_event_log_run_id_is_reused(self) -> None:
        store = RunStateStore(self.run_dir)
        store.initialize(
            run_id="run-existing",
            goal="恢复已有任务",
            scope=["api"],
            actor="qa-agent",
        )

        session = self.keep(
            RunSession.open(
                self.run_dir,
                owner_prefix=AGENT_OWNER_PREFIX,
                pid=501,
            )
        )

        self.assertEqual(session.run_id, "run-existing")

    def test_corrupt_event_log_blocks_new_identity(self) -> None:
        (self.run_dir / "run-events.jsonl").write_text(
            '{"schema_version":1',
            encoding="utf-8",
        )

        with self.assertRaises(EventLogError):
            RunSession.open(
                self.run_dir,
                owner_prefix=AGENT_OWNER_PREFIX,
                pid=601,
            )

        self.assertFalse((self.run_dir / LEASE_FILENAME).exists())

    def test_inherited_session_rejects_run_id_mismatch(self) -> None:
        store = RunStateStore(self.run_dir)
        store.initialize(
            run_id="state-run",
            goal="校验身份",
            scope=["web"],
            actor="qa-agent",
        )
        lease = RunLease(self.run_dir / LEASE_FILENAME)
        lease.acquire(
            "different-run",
            f"{AGENT_OWNER_PREFIX}:701:owner",
            pid=701,
        )

        with self.assertRaises(LeaseAlreadyHeldError):
            RunSession.open(
                self.run_dir,
                owner_prefix=CYCLE_OWNER_PREFIX,
                allow_parent_inheritance=True,
                pid=702,
                parent_pid=701,
            )

        lease.release(
            "different-run",
            f"{AGENT_OWNER_PREFIX}:701:owner",
            1,
        )

    def test_session_projection_is_json_serializable(self) -> None:
        session = self.keep(
            RunSession.open(
                self.run_dir,
                owner_prefix=AGENT_OWNER_PREFIX,
                pid=801,
            )
        )

        payload = session.to_dict()

        self.assertEqual(payload["run_id"], session.run_id)
        json.dumps(payload)


if __name__ == "__main__":
    unittest.main()
