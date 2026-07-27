#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import agent_eval  # noqa: E402

from tests.test_agent_evaluation import (  # noqa: E402
    EVALUATOR_BUNDLE_ROOT,
    PRODUCTION_VERIFICATION_NOW,
    manifest,
    observations,
    signed_production_inputs,
)


class AgentEvaluationCliSecurityTests(unittest.TestCase):
    def _write_inputs(self, root: Path) -> tuple[Path, Path]:
        manifest_path = root / "manifest.json"
        observations_path = root / "observations.json"
        manifest_path.write_text(
            json.dumps(manifest()),
            encoding="utf-8",
        )
        observations_path.write_text(
            json.dumps(observations()),
            encoding="utf-8",
        )
        return manifest_path, observations_path

    def _run(
        self,
        manifest_path: Path,
        observations_path: Path,
        output_path: Path,
    ) -> int:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return agent_eval.main(
                [
                    "--manifest",
                    str(manifest_path),
                    "--observations",
                    str(observations_path),
                    "--out",
                    str(output_path),
                ]
            )

    def test_duplicate_key_and_nonfinite_json_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, observations_path = self._write_inputs(root)
            manifest_path.write_text(
                '{"schema_version":1,"schema_version":1}',
                encoding="utf-8",
            )
            output_path = root / "duplicate-report.json"

            self.assertEqual(
                self._run(
                    manifest_path,
                    observations_path,
                    output_path,
                ),
                2,
            )
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(
                report["code"],
                "input_json_key_duplicate",
            )
            self.assertTrue(report["not_authorization"])

            manifest_path.write_text(
                '{"schema_version": NaN}',
                encoding="utf-8",
            )
            output_path = root / "nonfinite-report.json"
            self.assertEqual(
                self._run(
                    manifest_path,
                    observations_path,
                    output_path,
                ),
                2,
            )
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(report["code"], "input_json_nonfinite")

    def test_symlink_hardlink_and_cross_input_aliases_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, observations_path = self._write_inputs(root)

            symlink_path = root / "manifest-symlink.json"
            symlink_path.symlink_to(manifest_path)
            output_path = root / "symlink-report.json"
            self.assertEqual(
                self._run(
                    symlink_path,
                    observations_path,
                    output_path,
                ),
                2,
            )
            self.assertEqual(
                json.loads(output_path.read_text(encoding="utf-8"))["code"],
                "input_open_failed",
            )

            hardlink_path = root / "manifest-hardlink.json"
            os.link(manifest_path, hardlink_path)
            output_path = root / "hardlink-report.json"
            self.assertEqual(
                self._run(
                    hardlink_path,
                    observations_path,
                    output_path,
                ),
                2,
            )
            self.assertEqual(
                json.loads(output_path.read_text(encoding="utf-8"))["code"],
                "input_hardlink_rejected",
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, _ = self._write_inputs(root)
            output_path = root / "alias-report.json"
            self.assertEqual(
                self._run(manifest_path, manifest_path, output_path),
                2,
            )
            self.assertEqual(
                json.loads(output_path.read_text(encoding="utf-8"))["code"],
                "input_alias_rejected",
            )

    def test_output_alias_and_symlink_never_overwrite_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, observations_path = self._write_inputs(root)
            original_manifest = manifest_path.read_bytes()

            self.assertEqual(
                self._run(
                    manifest_path,
                    observations_path,
                    manifest_path,
                ),
                2,
            )
            self.assertEqual(manifest_path.read_bytes(), original_manifest)

            protected_target = root / "protected.json"
            protected_target.write_text("do-not-rewrite", encoding="utf-8")
            symlink_output = root / "report-symlink.json"
            symlink_output.symlink_to(protected_target)
            self.assertEqual(
                self._run(
                    manifest_path,
                    observations_path,
                    symlink_output,
                ),
                2,
            )
            self.assertEqual(
                protected_target.read_text(encoding="utf-8"),
                "do-not-rewrite",
            )

    def test_input_byte_limit_is_enforced_before_json_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, observations_path = self._write_inputs(root)
            output_path = root / "report.json"

            with patch.object(agent_eval, "_MAX_MANIFEST_BYTES", 8):
                self.assertEqual(
                    self._run(
                        manifest_path,
                        observations_path,
                        output_path,
                    ),
                    2,
                )
            self.assertEqual(
                json.loads(output_path.read_text(encoding="utf-8"))["code"],
                "input_too_large",
            )

    def test_production_cli_requires_and_verifies_signed_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = signed_production_inputs()
            names = (
                "manifest",
                "observations",
                "baseline",
                "registration",
                "trust",
            )
            paths = {}
            for name, value in zip(names, values):
                path = root / f"{name}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                paths[name] = path
            output_path = root / "production-report.json"

            with patch(
                "qa_eval.registration._trusted_now",
                return_value=PRODUCTION_VERIFICATION_NOW,
            ), redirect_stdout(io.StringIO()), redirect_stderr(
                io.StringIO()
            ):
                exit_code = agent_eval.main(
                    [
                        "--manifest",
                        str(paths["manifest"]),
                        "--observations",
                        str(paths["observations"]),
                        "--baseline",
                        str(paths["baseline"]),
                        "--registration",
                        str(paths["registration"]),
                        "--trust-config",
                        str(paths["trust"]),
                        "--evaluator-bundle-dir",
                        str(EVALUATOR_BUNDLE_ROOT),
                        "--production",
                        "--out",
                        str(output_path),
                    ]
                )

            self.assertEqual(exit_code, 0)
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(report["qualified"])
            self.assertTrue(report["not_authorization"])
            self.assertFalse(report["p2_admission_allowed"])

            test_clock_output = root / "test-clock-report.json"
            with redirect_stdout(io.StringIO()), redirect_stderr(
                io.StringIO()
            ):
                test_clock_exit = agent_eval.main(
                    [
                        "--manifest",
                        str(paths["manifest"]),
                        "--observations",
                        str(paths["observations"]),
                        "--baseline",
                        str(paths["baseline"]),
                        "--registration",
                        str(paths["registration"]),
                        "--trust-config",
                        str(paths["trust"]),
                        "--evaluator-bundle-dir",
                        str(EVALUATOR_BUNDLE_ROOT),
                        "--production",
                        "--test-verification-now",
                        "2026-07-26T09:00:00Z",
                        "--allow-test-clock-override",
                        "--out",
                        str(test_clock_output),
                    ]
                )
            self.assertEqual(test_clock_exit, 1)
            test_clock_report = json.loads(
                test_clock_output.read_text(encoding="utf-8")
            )
            self.assertFalse(test_clock_report["qualified"])
            self.assertTrue(
                test_clock_report["test_clock_override_not_production"]
            )

            common_args = [
                "--manifest",
                str(paths["manifest"]),
                "--observations",
                str(paths["observations"]),
                "--baseline",
                str(paths["baseline"]),
                "--registration",
                str(paths["registration"]),
                "--trust-config",
                str(paths["trust"]),
                "--evaluator-bundle-dir",
                str(EVALUATOR_BUNDLE_ROOT),
                "--production",
            ]
            for protected_name in (
                "manifest",
                "observations",
                "baseline",
            ):
                protected = paths[protected_name]
                before = protected.read_bytes()
                with redirect_stdout(io.StringIO()), redirect_stderr(
                    io.StringIO()
                ):
                    alias_exit = agent_eval.main(
                        [
                            *common_args,
                            "--out",
                            str(protected),
                        ]
                    )
                self.assertEqual(alias_exit, 2)
                self.assertEqual(protected.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
