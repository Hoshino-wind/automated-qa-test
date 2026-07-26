#!/usr/bin/env python3
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.proof import verify_run_proof  # noqa: E402
from qa_core.runtime import (  # noqa: E402
    CYCLE_OWNER_PREFIX,
    AttemptStore,
    RunSession,
)
from qa_core.state import RunEventType, RunStateStore  # noqa: E402


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

    def create_passed_run(self) -> None:
        for filename, content in (
            ("test-plan.json", '{"schemaVersion":2}'),
            ("test-matrix.json", '{"schemaVersion":2}'),
            ("requirement.md", "# Proof fixture\n"),
        ):
            (self.run_dir / filename).write_text(
                content,
                encoding="utf-8",
            )
        args = self.module.parse_cycle_options(
            ["--run-dir", str(self.run_dir)]
        )
        session = RunSession.open(
            self.run_dir,
            owner_prefix=CYCLE_OWNER_PREFIX,
        )
        try:
            runtime = self.module.CycleRuntime(args, session=session)
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
