#!/usr/bin/env python3
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

from qa_core.context import (  # noqa: E402
    ContextCompileError,
    compile_context_snapshot,
)
from qa_core.context import compiler as context_compiler  # noqa: E402


class ContextCompilerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()
        self.write_inputs()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_inputs(self, *, action: str = "goto") -> None:
        (self.run_dir / "requirement.md").write_text(
            "# Checkout\n\nValidate the test checkout.\n",
            encoding="utf-8",
        )
        (self.run_dir / "test-plan.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "scenarios": [
                        {
                            "id": "checkout",
                            "steps": [{"id": "open", "action": action}],
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
                        "data_boundary_status": "isolated fixtures",
                    },
                    "services": [{"name": "web"}],
                    "capabilities": ["checkout"],
                }
            ),
            encoding="utf-8",
        )

    def test_snapshot_is_deterministic_and_not_evidence(self) -> None:
        first = compile_context_snapshot(self.run_dir)
        second = compile_context_snapshot(self.run_dir)

        self.assertTrue(first.ready)
        self.assertEqual(first.canonical_sha256, second.canonical_sha256)
        self.assertTrue(first.to_dict()["not_evidence"])
        self.assertEqual(
            first.semantic_summary["plan"]["actions"],
            ["goto"],
        )

        plan = json.loads((self.run_dir / "test-plan.json").read_text())
        plan["scenarios"][0]["steps"].append(
            {"id": "reload", "action": "reload"}
        )
        (self.run_dir / "test-plan.json").write_text(
            json.dumps(plan),
            encoding="utf-8",
        )
        changed = compile_context_snapshot(self.run_dir)
        self.assertNotEqual(first.canonical_sha256, changed.canonical_sha256)

    def test_unknown_action_and_unconfirmed_boundary_are_blockers(self) -> None:
        self.write_inputs(action="modelShell")
        (self.run_dir / "adapter-context.json").unlink()

        snapshot = compile_context_snapshot(self.run_dir)

        self.assertFalse(snapshot.ready)
        self.assertEqual(
            {
                blocker["code"]
                for blocker in snapshot.blockers
            },
            {
                "environment_boundary_unconfirmed",
                "unknown_plan_action",
            },
        )

    def test_placeholder_environment_values_are_not_confirmation(self) -> None:
        adapter_path = self.run_dir / "adapter-context.json"
        adapter = json.loads(adapter_path.read_text(encoding="utf-8"))
        adapter["environment_boundary"] = {
            "runtime_mode": "unknown",
            "data_boundary_status": "must be stated before pass/fail",
        }
        adapter_path.write_text(json.dumps(adapter), encoding="utf-8")

        snapshot = compile_context_snapshot(self.run_dir)

        self.assertFalse(snapshot.ready)
        self.assertIn(
            "environment_boundary_unconfirmed",
            {blocker["code"] for blocker in snapshot.blockers},
        )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unsupported")
    def test_symlinked_required_input_is_rejected(self) -> None:
        outside = self.root / "outside.md"
        outside.write_text("# Outside\n", encoding="utf-8")
        (self.run_dir / "requirement.md").unlink()
        (self.run_dir / "requirement.md").symlink_to(outside)

        snapshot = compile_context_snapshot(self.run_dir)

        self.assertFalse(snapshot.ready)
        self.assertIn(
            "context_source_unreadable",
            {blocker["code"] for blocker in snapshot.blockers},
        )

    def test_repository_inventory_excludes_secrets_and_tracks_dependencies(
        self,
    ) -> None:
        project = self.root / "project"
        project.mkdir()
        (project / "app.py").write_text("print('ok')\n", encoding="utf-8")
        (project / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
        (project / "pyproject.toml").write_text(
            '[project]\nname="fixture"\ndependencies=["httpx>=1"]\n',
            encoding="utf-8",
        )

        snapshot = compile_context_snapshot(
            self.run_dir,
            project_root=project,
        )

        self.assertTrue(snapshot.ready)
        paths = {item["path"] for item in snapshot.repository["files"]}
        self.assertNotIn(".env", paths)
        self.assertIn("app.py", paths)
        self.assertIn("httpx", snapshot.repository["dependencies"])
        self.assertEqual(snapshot.repository["languages"], {"python": 1})

    def test_cli_writes_snapshot_and_returns_ready(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "compile_agent_context.py"),
                "--run-dir",
                str(self.run_dir),
            ],
            text=True,
            capture_output=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = Path(completed.stdout.strip())
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(payload["ready"])
        self.assertTrue(payload["not_evidence"])

    def test_repository_snapshot_excludes_dynamic_run_directory(self) -> None:
        (self.root / "app.py").write_text("print('stable')\n", encoding="utf-8")
        first = compile_context_snapshot(
            self.run_dir,
            project_root=self.root,
        )
        (self.run_dir / "agent-context.json").write_text(
            '{"dynamic":true}',
            encoding="utf-8",
        )
        second = compile_context_snapshot(
            self.run_dir,
            project_root=self.root,
        )

        self.assertEqual(
            first.repository["snapshot_sha256"],
            second.repository["snapshot_sha256"],
        )
        self.assertEqual(first.canonical_sha256, second.canonical_sha256)

    def test_repository_limits_cannot_exceed_hard_caps(self) -> None:
        cases = (
            {
                "max_repository_files": (
                    context_compiler._MAX_REPOSITORY_FILES + 1
                ),
            },
            {
                "max_repository_bytes": (
                    context_compiler._MAX_REPOSITORY_TOTAL_BYTES + 1
                ),
            },
        )
        for arguments in cases:
            with (
                self.subTest(arguments=arguments),
                self.assertRaises(ContextCompileError) as caught,
            ):
                compile_context_snapshot(self.run_dir, **arguments)
            self.assertEqual(
                caught.exception.code,
                "repository_limit_invalid",
            )

    def test_repository_file_count_limit_fails_closed(self) -> None:
        project = self.root / "many-files"
        project.mkdir()
        (project / "a.py").write_text("a = 1\n", encoding="utf-8")
        (project / "b.py").write_text("b = 2\n", encoding="utf-8")

        snapshot = compile_context_snapshot(
            self.run_dir,
            project_root=project,
            max_repository_files=1,
        )

        self.assertFalse(snapshot.ready)
        self.assertFalse(snapshot.repository["complete"])
        self.assertIn(
            "repository_snapshot_incomplete",
            {blocker["code"] for blocker in snapshot.blockers},
        )
        self.assertIn("more than 1 eligible files", snapshot.repository["error"])

    def test_repository_total_read_budget_fails_closed(self) -> None:
        project = self.root / "large-repository"
        project.mkdir()
        (project / "a.py").write_bytes(b"a" * 8)
        (project / "b.py").write_bytes(b"b" * 8)

        snapshot = compile_context_snapshot(
            self.run_dir,
            project_root=project,
            max_repository_bytes=10,
        )

        self.assertFalse(snapshot.ready)
        self.assertFalse(snapshot.repository["complete"])
        self.assertIn(
            "repository_snapshot_incomplete",
            {blocker["code"] for blocker in snapshot.blockers},
        )
        self.assertIn("total read budget", snapshot.repository["error"])


if __name__ == "__main__":
    unittest.main()
