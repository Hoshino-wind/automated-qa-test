#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

CLI_PATH = SCRIPT_DIR / "agent_schedule_cli.py"

import agent_schedule_cli as schedule_cli  # noqa: E402
import qa_common  # noqa: E402
from qa_core.tools import build_default_tool_registry  # noqa: E402


def request_payload(*, estimated_cost: float = 1) -> dict:
    registry = build_default_tool_registry()
    first = registry.get("expectText")
    second = registry.get("expectUrlContains")
    return {
        "schema_version": 1,
        "tool_registry_sha256": registry.canonical_sha256,
        "budget": {
            "max_total_cost": 10,
            "max_total_time_seconds": 10,
            "max_actions": 2,
            "max_parallelism": 2,
        },
        "candidates": [
            {
                "id": "probe-a",
                "action": first.action,
                "tool_version": first.version,
                "tool_spec_sha256": first.canonical_sha256,
                "estimated_cost": estimated_cost,
                "estimated_time_seconds": 1,
                "information_gain": 5,
                "dependencies": [],
            },
            {
                "id": "probe-b",
                "action": second.action,
                "tool_version": second.version,
                "tool_spec_sha256": second.canonical_sha256,
                "estimated_cost": estimated_cost,
                "estimated_time_seconds": 1,
                "information_gain": 4,
                "dependencies": [],
            },
        ],
    }


class AgentScheduleCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(
        self,
        request_path: Path,
        output_path: Path,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "--request",
                str(request_path),
                "--out",
                str(output_path),
            ],
            text=True,
            capture_output=True,
        )

    def test_cli_emits_deterministic_non_authorization_schedule(
        self,
    ) -> None:
        request_path = self.run_dir / "request.json"
        first_output = self.run_dir / "first.json"
        second_output = self.run_dir / "second.json"
        request_path.write_text(
            json.dumps(request_payload()),
            encoding="utf-8",
        )

        first = self.run_cli(request_path, first_output)
        second = self.run_cli(request_path, second_output)

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(
            first_output.read_bytes(),
            second_output.read_bytes(),
        )
        result = json.loads(first_output.read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "advice_ready")
        self.assertTrue(result["not_authorization"])
        self.assertFalse(result["admission_allowed"])
        self.assertTrue(result["schedule"]["not_authorization"])
        self.assertEqual(
            result["schedule"]["batches"][0]["mode"],
            "parallel_suggestion",
        )
        self.assertFalse(result["schedule"]["admission_allowed"])
        self.assertFalse(
            result["schedule"]["execution_authorization_verified"]
        )
        self.assertNotIn("signature", result["schedule"])

    def test_cli_rejects_nonfinite_json_and_unknown_fields(self) -> None:
        cases = (
            (
                '{"schema_version":1,"budget":NaN,"candidates":[]}',
                "json_number_nonfinite",
            ),
            (
                json.dumps(
                    {
                        **request_payload(),
                        "execute": True,
                    },
                ),
                "request_fields_unknown",
            ),
        )
        for index, (raw, expected_code) in enumerate(cases):
            with self.subTest(expected_code=expected_code):
                request_path = self.run_dir / f"invalid-{index}.json"
                output_path = self.run_dir / f"invalid-{index}-out.json"
                request_path.write_text(raw, encoding="utf-8")

                process = self.run_cli(request_path, output_path)

                self.assertEqual(process.returncode, 1)
                result = json.loads(
                    output_path.read_text(encoding="utf-8"),
                )
                self.assertEqual(result["status"], "error")
                self.assertTrue(result["not_authorization"])
                self.assertEqual(
                    result["error"]["code"],
                    expected_code,
                )
                self.assertNotIn("Traceback", process.stderr)

    def test_cli_returns_distinct_failure_for_insufficient_budget(
        self,
    ) -> None:
        request_path = self.run_dir / "budget.json"
        output_path = self.run_dir / "budget-out.json"
        value = request_payload(estimated_cost=20)
        request_path.write_text(
            json.dumps(value),
            encoding="utf-8",
        )

        process = self.run_cli(request_path, output_path)

        self.assertEqual(process.returncode, 2)
        result = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(
            result["error"]["code"],
            "budget_insufficient",
        )
        self.assertTrue(result["not_authorization"])

    def test_cli_rejects_duplicate_keys_symlinks_and_large_files(
        self,
    ) -> None:
        duplicate = self.run_dir / "duplicate.json"
        duplicate.write_text(
            '{"schema_version":1,"schema_version":1}',
            encoding="utf-8",
        )
        duplicate_out = self.run_dir / "duplicate-out.json"
        duplicate_process = self.run_cli(duplicate, duplicate_out)
        duplicate_result = json.loads(
            duplicate_out.read_text(encoding="utf-8")
        )
        self.assertEqual(duplicate_process.returncode, 1)
        self.assertEqual(
            duplicate_result["error"]["code"],
            "json_duplicate_key",
        )
        self.assertNotIn("Traceback", duplicate_process.stderr)

        source = self.run_dir / "source.json"
        source.write_text(
            json.dumps(request_payload()),
            encoding="utf-8",
        )
        symlink = self.run_dir / "request-link.json"
        symlink.symlink_to(source)
        symlink_out = self.run_dir / "symlink-out.json"
        symlink_process = self.run_cli(symlink, symlink_out)
        symlink_result = json.loads(
            symlink_out.read_text(encoding="utf-8")
        )
        self.assertEqual(symlink_process.returncode, 1)
        self.assertEqual(
            symlink_result["error"]["code"],
            "request_symlink_rejected",
        )
        self.assertNotIn("Traceback", symlink_process.stderr)

        large = self.run_dir / "large.json"
        large.write_bytes(b" " * 1_048_577)
        large_out = self.run_dir / "large-out.json"
        large_process = self.run_cli(large, large_out)
        large_result = json.loads(
            large_out.read_text(encoding="utf-8")
        )
        self.assertEqual(large_process.returncode, 1)
        self.assertEqual(
            large_result["error"]["code"],
            "request_too_large",
        )
        self.assertNotIn("Traceback", large_process.stderr)

    @unittest.skipUnless(hasattr(os, "link"), "hard links unsupported")
    def test_cli_rejects_hardlinked_request(self) -> None:
        source = self.run_dir / "source.json"
        source.write_text(
            json.dumps(request_payload()),
            encoding="utf-8",
        )
        hardlink = self.run_dir / "request-hardlink.json"
        os.link(source, hardlink)
        output = self.run_dir / "hardlink-out.json"

        process = self.run_cli(hardlink, output)

        self.assertEqual(process.returncode, 1)
        result = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(
            result["error"]["code"],
            "request_hardlink_rejected",
        )
        self.assertTrue(result["not_authorization"])
        self.assertNotIn("Traceback", process.stderr)

    def test_reader_rejects_in_place_mutation_during_read(self) -> None:
        request = self.run_dir / "mutable.json"
        request.write_text(
            json.dumps(request_payload()),
            encoding="utf-8",
        )
        original_read = os.read
        mutated = False

        def read_then_mutate(descriptor: int, count: int) -> bytes:
            nonlocal mutated
            chunk = original_read(descriptor, count)
            if chunk and not mutated:
                with request.open("ab") as handle:
                    handle.write(b" ")
                    handle.flush()
                    os.fsync(handle.fileno())
                mutated = True
            return chunk

        with (
            mock.patch.object(
                qa_common.os,
                "read",
                side_effect=read_then_mutate,
            ),
            self.assertRaises(
                schedule_cli.SchedulingContractError,
            ) as caught,
        ):
            schedule_cli._read_object(request)

        self.assertTrue(mutated)
        self.assertEqual(caught.exception.code, "request_changed")


if __name__ == "__main__":
    unittest.main()
