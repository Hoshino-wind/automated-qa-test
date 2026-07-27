#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SCRIPT_DIR.parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/nightly-agent-reliability.yml"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from nightly_agent_matrix import (  # noqa: E402
    MatrixDefinitionError,
    build_nightly_definition,
    github_matrix,
)


class NightlyAgentMatrixTests(unittest.TestCase):
    def _minimal_repo(self, root: Path) -> None:
        for relative in (
            "skills/automated-qa-test/scripts/regression_check.py",
            "skills/automated-qa-test/scripts/nightly_fault_injection.py",
        ):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# fixture\n", encoding="utf-8")

    def test_current_repository_exposes_only_real_supported_targets(self) -> None:
        definition = build_nightly_definition(REPO_ROOT)

        self.assertTrue(definition["not_evidence"])
        self.assertEqual(
            [item["id"] for item in definition["include"][:3]],
            [
                "full-regression",
                "chromium-regression",
                "fault-injection",
            ],
        )
        chromium = definition["include"][1]
        self.assertTrue(chromium["requires_chromium"])
        self.assertEqual(
            chromium["command"],
            [
                "python3",
                "skills/automated-qa-test/scripts/regression_check.py",
                "--with-browser",
            ],
        )
        known_optional = {
            "browser-policy-benchmark",
            "component-surface-verifier",
            "component-resilience-verifier",
        }
        enabled_optional = {
            item["id"]
            for item in definition["include"]
            if item["optional"]
        }
        unsupported_optional = {
            item["id"]
            for item in definition["unsupported_optional_targets"]
        }
        self.assertFalse(enabled_optional & unsupported_optional)
        self.assertEqual(
            enabled_optional | unsupported_optional,
            known_optional,
        )
        self.assertEqual(
            github_matrix(definition),
            {"include": definition["include"]},
        )

    def test_optional_benchmark_is_included_only_when_entrypoint_exists(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qa-nightly-matrix-") as raw:
            root = Path(raw)
            self._minimal_repo(root)
            optional = root / "scripts/run_browser_policy_benchmark.py"
            optional.parent.mkdir(parents=True)
            optional.write_text("# fixture\n", encoding="utf-8")

            definition = build_nightly_definition(root)

        self.assertEqual(
            [item["id"] for item in definition["include"]],
            [
                "full-regression",
                "chromium-regression",
                "fault-injection",
                "browser-policy-benchmark",
            ],
        )
        self.assertNotIn(
            "browser-policy-benchmark",
            [item["id"] for item in definition["unsupported_optional_targets"]],
        )

    def test_missing_required_entrypoint_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qa-nightly-matrix-") as raw:
            with self.assertRaisesRegex(
                MatrixDefinitionError,
                "full-regression",
            ):
                build_nightly_definition(Path(raw))

    def test_cli_writes_auditable_definition_and_github_matrix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qa-nightly-matrix-cli-") as raw:
            root = Path(raw)
            output = root / "definition.json"
            github_output = root / "github-output.txt"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "nightly_agent_matrix.py"),
                    "--repo-root",
                    str(REPO_ROOT),
                    "--out",
                    str(output),
                    "--github-output",
                    str(github_output),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            definition = json.loads(output.read_text(encoding="utf-8"))
            github_line = github_output.read_text(encoding="utf-8").strip()

        self.assertEqual(
            json.loads(completed.stdout),
            definition,
        )
        self.assertTrue(github_line.startswith("matrix="))
        self.assertEqual(
            json.loads(github_line.removeprefix("matrix=")),
            github_matrix(definition),
        )

    def test_workflow_has_bounded_dispatch_and_retention_guards(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        definition = build_nightly_definition(REPO_ROOT)

        self.assertIn('cron: "23 18 * * *"', workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("concurrency:", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("timeout-minutes:", workflow)
        self.assertIn("retention-days: 14", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("matrix.command", workflow)
        for target in definition["include"]:
            self.assertIn(
                f"matrix.id == '{target['id']}'",
                workflow,
            )


if __name__ == "__main__":
    unittest.main()
