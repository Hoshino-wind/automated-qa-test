#!/usr/bin/env python3
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.context import (  # noqa: E402
    ContextCompileError,
    compile_context_snapshot,
    verify_context_snapshot,
)
from qa_core.proof.hashes import (  # noqa: E402
    canonical_json_sha256,
    input_file_sha256,
)
from qa_core.tools import ToolRegistry  # noqa: E402


class ContextVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()
        self.snapshot_path = self.run_dir / "agent-context.json"
        self._write_inputs()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_inputs(self) -> None:
        (self.run_dir / "requirement.md").write_text(
            "# Checkout\n\nVerify checkout.\n",
            encoding="utf-8",
        )
        (self.run_dir / "test-plan.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "scenarios": [
                        {
                            "id": "checkout",
                            "steps": [{"id": "open", "action": "goto"}],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (self.run_dir / "test-matrix.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "tests": [{"id": "t1", "status": "planned"}],
                }
            ),
            encoding="utf-8",
        )
        (self.run_dir / "adapter-context.json").write_text(
            json.dumps(
                {
                    "adapter": "fixture",
                    "environment_boundary": {
                        "runtime_mode": "test",
                        "data_boundary_status": "isolated",
                    },
                    "services": [{"name": "web"}],
                    "capabilities": ["checkout"],
                }
            ),
            encoding="utf-8",
        )

    def _compile(self, **kwargs: object) -> dict:
        snapshot = compile_context_snapshot(self.run_dir, **kwargs)
        payload = snapshot.to_dict()
        self.snapshot_path.write_text(
            json.dumps(payload),
            encoding="utf-8",
        )
        return payload

    def _rewrite_with_context_hash(self, payload: dict) -> None:
        unsigned = dict(payload)
        unsigned.pop("context_sha256", None)
        payload["context_sha256"] = canonical_json_sha256(unsigned)
        self.snapshot_path.write_text(
            json.dumps(payload),
            encoding="utf-8",
        )

    def test_valid_snapshot_returns_verified_plain_dict_without_writes(
        self,
    ) -> None:
        payload = self._compile()
        before = self.snapshot_path.read_bytes()

        result = verify_context_snapshot(
            self.run_dir,
            self.snapshot_path,
        )

        self.assertTrue(result.valid, result.errors)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.context_sha256, payload["context_sha256"])
        self.assertEqual(result.snapshot, payload)
        self.assertIs(type(result.snapshot), dict)
        self.assertEqual(self.snapshot_path.read_bytes(), before)

    def test_unknown_top_level_field_is_rejected_even_with_new_hash(
        self,
    ) -> None:
        payload = self._compile()
        payload["untrusted_extension"] = True
        self._rewrite_with_context_hash(payload)

        result = verify_context_snapshot(
            self.run_dir,
            self.snapshot_path,
        )

        self.assertFalse(result.valid)
        self.assertIsNone(result.snapshot)
        self.assertIn(
            "context_schema_fields_invalid",
            {error["code"] for error in result.errors},
        )

    def test_stale_source_is_rejected_even_with_valid_outer_hash(self) -> None:
        payload = self._compile()
        (self.run_dir / "test-plan.json").write_text(
            json.dumps({"schemaVersion": 2, "scenarios": []}),
            encoding="utf-8",
        )
        self._rewrite_with_context_hash(payload)

        result = verify_context_snapshot(
            self.run_dir,
            self.snapshot_path,
        )

        self.assertFalse(result.valid)
        self.assertIn(
            "context_source_not_current",
            {error["code"] for error in result.errors},
        )

    def test_optional_missing_requirement_uses_proof_sentinel(self) -> None:
        requirement = self.run_dir / "requirement.md"
        requirement.unlink()
        payload = self._compile(require_requirement=False)
        requirement_source = payload["sources"][0]

        result = verify_context_snapshot(
            self.run_dir,
            self.snapshot_path,
        )

        self.assertTrue(result.valid, result.errors)
        self.assertFalse(requirement_source["required"])
        self.assertEqual(requirement_source["status"], "missing")
        self.assertEqual(
            requirement_source["sha256"],
            input_file_sha256("requirement", requirement),
        )

    def test_required_missing_requirement_is_not_verifiable(self) -> None:
        (self.run_dir / "requirement.md").unlink()
        payload = compile_context_snapshot(
            self.run_dir,
            require_requirement=True,
        ).to_dict()
        self.snapshot_path.write_text(json.dumps(payload), encoding="utf-8")

        result = verify_context_snapshot(
            self.run_dir,
            self.snapshot_path,
        )

        self.assertFalse(result.valid)
        self.assertIn(
            "context_not_ready",
            {error["code"] for error in result.errors},
        )

    def test_changed_registry_rejects_hash_and_graph(self) -> None:
        self._compile()

        result = verify_context_snapshot(
            self.run_dir,
            self.snapshot_path,
            ToolRegistry(),
        )

        codes = {error["code"] for error in result.errors}
        self.assertFalse(result.valid)
        self.assertIn("context_tool_registry_hash_mismatch", codes)
        self.assertIn("context_capability_graph_mismatch", codes)
        self.assertIn("context_capability_blocked", codes)

    def test_graph_tamper_is_rejected_after_rehash(self) -> None:
        payload = self._compile()
        payload["capability_graph"]["edges"].pop()
        self._rewrite_with_context_hash(payload)

        result = verify_context_snapshot(
            self.run_dir,
            self.snapshot_path,
        )

        self.assertFalse(result.valid)
        self.assertIn(
            "context_capability_graph_mismatch",
            {error["code"] for error in result.errors},
        )

    def test_repository_hash_tamper_is_rejected_after_rehash(self) -> None:
        project = self.root / "project"
        project.mkdir()
        (project / "app.py").write_text("print('ok')\n", encoding="utf-8")
        payload = self._compile(project_root=project)
        payload["repository"]["snapshot_sha256"] = "0" * 64
        self._rewrite_with_context_hash(payload)

        result = verify_context_snapshot(
            self.run_dir,
            self.snapshot_path,
            project_root=project,
        )

        self.assertFalse(result.valid)
        self.assertIn(
            "context_repository_hash_mismatch",
            {error["code"] for error in result.errors},
        )

    def test_repository_mutation_invalidates_current_context(self) -> None:
        project = self.root / "project"
        project.mkdir()
        source = project / "app.py"
        source.write_text("value = 1\n", encoding="utf-8")
        self._compile(project_root=project)

        before = verify_context_snapshot(
            self.run_dir,
            self.snapshot_path,
            project_root=project,
        )
        source.write_text("value = 999\n", encoding="utf-8")
        after = verify_context_snapshot(
            self.run_dir,
            self.snapshot_path,
            project_root=project,
        )

        self.assertTrue(before.valid, before.errors)
        self.assertFalse(after.valid)
        self.assertIn(
            "context_repository_not_current",
            {error["code"] for error in after.errors},
        )

    def test_requested_repository_requires_explicit_current_root(self) -> None:
        project = self.root / "project"
        project.mkdir()
        (project / "app.py").write_text("value = 1\n", encoding="utf-8")
        self._compile(project_root=project)

        result = verify_context_snapshot(
            self.run_dir,
            self.snapshot_path,
        )

        self.assertFalse(result.valid)
        self.assertIn(
            "context_project_root_required",
            {error["code"] for error in result.errors},
        )

    def test_historical_repository_cannot_forge_total_byte_budget(
        self,
    ) -> None:
        project = self.root / "project"
        project.mkdir()
        (project / "app.py").write_text("value = 1\n", encoding="utf-8")
        payload = self._compile(project_root=project)
        files = [
            {
                "path": f"file-{index:02d}.py",
                "sha256": f"{index:064x}",
                "size": 8 * 1024 * 1024,
                "language": "python",
            }
            for index in range(9)
        ]
        repository = payload["repository"]
        repository["files"] = files
        repository["languages"] = {"python": len(files)}
        repository["dependencies"] = []
        repository["snapshot_sha256"] = canonical_json_sha256(
            {
                "files": files,
                "languages": repository["languages"],
                "dependencies": [],
            }
        )
        self._rewrite_with_context_hash(payload)

        result = verify_context_snapshot(
            self.run_dir,
            self.snapshot_path,
            require_repository_current=False,
        )

        self.assertFalse(result.valid)
        self.assertIn(
            "context_repository_total_bytes_exceeded",
            {error["code"] for error in result.errors},
        )

    def test_duplicate_json_key_is_rejected(self) -> None:
        self.snapshot_path.write_text(
            '{"schema_version":1,"schema_version":1}',
            encoding="utf-8",
        )

        result = verify_context_snapshot(
            self.run_dir,
            self.snapshot_path,
        )

        self.assertFalse(result.valid)
        self.assertEqual(
            result.errors[0]["code"],
            "context_snapshot_duplicate_key",
        )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unsupported")
    def test_symlinked_snapshot_is_rejected(self) -> None:
        outside = self.root / "outside.json"
        outside.write_text("{}", encoding="utf-8")
        self.snapshot_path.symlink_to(outside)

        result = verify_context_snapshot(
            self.run_dir,
            self.snapshot_path,
        )

        self.assertFalse(result.valid)
        self.assertEqual(
            result.errors[0]["code"],
            "context_snapshot_unreadable",
        )

    def test_require_requirement_must_be_boolean(self) -> None:
        with self.assertRaises(ContextCompileError) as raised:
            compile_context_snapshot(
                self.run_dir,
                require_requirement=1,  # type: ignore[arg-type]
            )
        self.assertEqual(raised.exception.code, "require_requirement_invalid")


if __name__ == "__main__":
    unittest.main()
