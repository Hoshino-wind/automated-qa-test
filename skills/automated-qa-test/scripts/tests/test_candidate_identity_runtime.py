#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_common import file_sha256  # noqa: E402
from qa_core.runtime import CYCLE_OWNER_PREFIX, RunSession  # noqa: E402
from qa_eval import EvaluationContractError, hash_evaluator_bundle  # noqa: E402


def load_cycle_module():
    spec = importlib.util.spec_from_file_location(
        "run_qa_cycle_candidate_identity_runtime",
        SCRIPT_DIR / "run_qa_cycle.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load run_qa_cycle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CandidateIdentityRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_cycle_module()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _candidate_args(
        self,
        bundle_root: Path,
    ):
        policy_path = self.root / "policy.json"
        memory_path = self.root / "memory.json"
        registration_path = self.root / "candidate-registration.json"
        policy_path.write_text(
            '{"schema_version":1,"policy":"fixed"}',
            encoding="utf-8",
        )
        memory_path.write_text(
            '{"schema_version":1,"entries":[]}',
            encoding="utf-8",
        )
        registration_path.write_text(
            json.dumps(
                {
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
                    "memory_snapshot_sha256": file_sha256(
                        memory_path
                    ),
                }
            ),
            encoding="utf-8",
        )
        return self.module.parse_cycle_options(
            [
                "--run-dir",
                str(self.run_dir),
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

    def _fake_execution_bundle(
        self,
    ) -> tuple[Path, dict[str, Path]]:
        bundle_root = self.root / "bundle"
        bundle_root.mkdir()
        sources: dict[str, Path] = {}
        for component, filename in (
            ("entrypoint.run_qa_cycle", "run_qa_cycle.py"),
            ("runner.playwright_probe", "playwright_probe.mjs"),
            ("qa_common", "qa_common.py"),
            ("qa_core", "qa_core/__init__.py"),
            ("qa_eval", "qa_eval/__init__.py"),
        ):
            path = bundle_root / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                f"# fixed candidate source: {component}\n",
                encoding="utf-8",
            )
            sources[component] = path
        return bundle_root, sources

    def test_bundle_without_actual_runtime_sources_fails_closed(
        self,
    ) -> None:
        bundle_root = self.root / "unrelated-bundle"
        bundle_root.mkdir()
        (bundle_root / "agent.py").write_text(
            "# unrelated candidate\n",
            encoding="utf-8",
        )
        args = self._candidate_args(bundle_root)

        with self.assertRaises(EvaluationContractError) as raised:
            self.module.prepare_candidate_identity_snapshot(
                args,
                self.run_dir / "candidate-identity.json",
            )

        self.assertEqual(
            raised.exception.code,
            "candidate_identity_execution_bundle_mismatch",
        )

    def test_runtime_source_change_blocks_terminal_attempt_commit(
        self,
    ) -> None:
        bundle_root, execution_sources = self._fake_execution_bundle()
        args = self._candidate_args(bundle_root)
        session = RunSession.open(
            self.run_dir,
            owner_prefix=CYCLE_OWNER_PREFIX,
        )
        try:
            with patch.object(
                self.module,
                "candidate_execution_source_paths",
                return_value=execution_sources,
            ):
                runtime = self.module.CycleRuntime(
                    args,
                    session=session,
                )
                execution_sources["qa_core"].write_text(
                    "# replaced after pre-dispatch identity verification\n",
                    encoding="utf-8",
                )

                exit_code = runtime.complete_state(1)
        finally:
            session.close()

        self.assertNotEqual(exit_code, 0)
        self.assertEqual(
            runtime.summary["attempt_commit"]["code"],
            "candidate_identity_reverification_failed",
        )
        self.assertFalse((self.run_dir / "run-manifest.json").exists())

    def test_snapshot_replacement_blocks_terminal_attempt_commit(
        self,
    ) -> None:
        bundle_root, execution_sources = self._fake_execution_bundle()
        args = self._candidate_args(bundle_root)
        session = RunSession.open(
            self.run_dir,
            owner_prefix=CYCLE_OWNER_PREFIX,
        )
        try:
            with patch.object(
                self.module,
                "candidate_execution_source_paths",
                return_value=execution_sources,
            ):
                runtime = self.module.CycleRuntime(
                    args,
                    session=session,
                )
                runtime.candidate_identity_snapshot_path.write_text(
                    '{"schema_version":2,"replaced":true}',
                    encoding="utf-8",
                )

                exit_code = runtime.complete_state(1)
        finally:
            session.close()

        self.assertNotEqual(exit_code, 0)
        attempt_error = runtime.summary["attempt_commit"]
        self.assertEqual(
            attempt_error["code"],
            "candidate_identity_reverification_failed",
        )
        self.assertEqual(
            attempt_error["details"]["cause_code"],
            "candidate_identity_snapshot_changed",
        )
        self.assertFalse((self.run_dir / "run-manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
