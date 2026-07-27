#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from nightly_fault_injection import SCENARIOS, run_fault_suite  # noqa: E402


class NightlyFaultInjectionTests(unittest.TestCase):
    def test_all_scenarios_prove_fail_closed_boundaries(self) -> None:
        first = run_fault_suite()
        second = run_fault_suite()

        self.assertEqual(first, second)
        self.assertEqual(first["status"], "passed")
        self.assertTrue(first["not_evidence"])
        self.assertEqual(first["scenario_count"], len(SCENARIOS))
        self.assertEqual(
            [item["id"] for item in first["scenarios"]],
            list(SCENARIOS),
        )
        self.assertTrue(
            all(item["status"] == "passed" for item in first["scenarios"])
        )
        observed = {
            item["id"]: item["observed"]
            for item in first["scenarios"]
        }
        self.assertEqual(observed["timeout"]["exit_code"], 124)
        self.assertEqual(
            observed["output-limit-and-truncation"]["exit_code"],
            125,
        )
        self.assertTrue(
            observed["lease-conflict"]["second_writer_rejected"]
        )
        self.assertEqual(observed["process-crash"]["exit_code"], 23)
        self.assertTrue(observed["corrupt-lease"]["acquire_rejected"])

    def test_selected_scenarios_keep_declaration_order(self) -> None:
        report = run_fault_suite(
            ["process-crash", "timeout", "process-crash"]
        )

        self.assertEqual(report["status"], "passed")
        self.assertEqual(
            [item["id"] for item in report["scenarios"]],
            ["timeout", "process-crash"],
        )

    def test_unknown_scenario_fails_before_execution(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown fault scenarios"):
            run_fault_suite(["not-a-scenario"])

    def test_cli_writes_same_bounded_report_it_prints(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qa-nightly-fault-cli-") as raw:
            output = Path(raw) / "fault-report.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "nightly_fault_injection.py"),
                    "--scenario",
                    "lease-conflict",
                    "--scenario",
                    "corrupt-lease",
                    "--out",
                    str(output),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            written = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(json.loads(completed.stdout), written)
        self.assertEqual(written["scenario_count"], 2)
        self.assertEqual(written["status"], "passed")


if __name__ == "__main__":
    unittest.main()
