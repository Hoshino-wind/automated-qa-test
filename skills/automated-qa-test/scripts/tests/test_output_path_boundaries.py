#!/usr/bin/env python3
from __future__ import annotations

import hashlib
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

import qa_common  # noqa: E402
from qa_common import (  # noqa: E402
    atomic_write_json,
    file_sha256,
    safe_output_path,
)


class OutputPathBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(self, script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT_DIR / script), *arguments],
            text=True,
            capture_output=True,
        )

    def test_hardlink_alias_is_rejected(self) -> None:
        source = self.root / "source.json"
        alias = self.root / "alias.json"
        source.write_text("{}", encoding="utf-8")
        alias.hardlink_to(source)

        with self.assertRaises(ValueError):
            safe_output_path(alias, protected_paths=(source,))

    def test_symlink_output_never_rewrites_its_target(self) -> None:
        victim = self.root / "victim.json"
        alias = self.root / "report.json"
        victim.write_text('{"protected":true}', encoding="utf-8")
        alias.symlink_to(victim)

        with self.assertRaises(ValueError):
            safe_output_path(alias)
        with self.assertRaises(ValueError):
            atomic_write_json(alias, {"overwritten": True})

        self.assertEqual(
            victim.read_text(encoding="utf-8"),
            '{"protected":true}',
        )

    def test_critic_and_scheduler_never_overwrite_request(self) -> None:
        for script in ("agent_critic_cli.py", "agent_schedule_cli.py"):
            with self.subTest(script=script):
                request = self.root / f"{script}.json"
                original = '{"protected":true}'
                request.write_text(original, encoding="utf-8")

                completed = self.run_cli(
                    script,
                    "--request",
                    str(request),
                    "--out",
                    str(request),
                )

                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(request.read_text(encoding="utf-8"), original)

    def test_slo_report_never_overwrites_trace(self) -> None:
        trace = self.root / "agent-trace.jsonl"
        original = '{"forensic":"keep"}\n'
        trace.write_text(original, encoding="utf-8")

        completed = self.run_cli(
            "agent_slo_report.py",
            "--trace",
            str(trace),
            "--out",
            str(trace),
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(trace.read_text(encoding="utf-8"), original)

    def test_context_compiler_never_overwrites_canonical_input(self) -> None:
        run_dir = self.root / "run"
        run_dir.mkdir()
        plan = run_dir / "test-plan.json"
        original = json.dumps({"schemaVersion": 2})
        plan.write_text(original, encoding="utf-8")

        completed = self.run_cli(
            "compile_agent_context.py",
            "--run-dir",
            str(run_dir),
            "--out",
            str(plan),
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(plan.read_text(encoding="utf-8"), original)

    def test_human_control_output_cannot_enter_authority_store(self) -> None:
        store = self.root / "knowledge"
        target = store / "knowledge-events.jsonl"

        completed = self.run_cli(
            "human_control_cli.py",
            "knowledge-query",
            "--store",
            str(store),
            "--scope",
            "project:test",
            "--at",
            "2026-07-26T00:00:00Z",
            "--out",
            str(target),
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(target.exists())

    def test_file_sha256_hashes_stable_single_link_file(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"stable")

        self.assertEqual(
            file_sha256(source),
            hashlib.sha256(b"stable").hexdigest(),
        )
        self.assertIsNone(file_sha256(self.root / "missing.bin"))
        self.assertIsNone(file_sha256(None))

    @unittest.skipUnless(hasattr(os, "link"), "hard links unsupported")
    def test_file_sha256_rejects_symlink_hardlink_and_special_file(
        self,
    ) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"protected")
        symlink = self.root / "source-link.bin"
        symlink.symlink_to(source)
        hardlink = self.root / "source-hardlink.bin"
        os.link(source, hardlink)

        for path in (symlink, hardlink, self.root):
            with self.subTest(path=path):
                self.assertIsNone(file_sha256(path))

    def test_file_sha256_rejects_in_place_mutation(self) -> None:
        source = self.root / "mutable.bin"
        source.write_bytes(b"a" * (1024 * 1024 + 1))
        original_read = os.read
        mutated = False

        def read_then_mutate(descriptor: int, count: int) -> bytes:
            nonlocal mutated
            chunk = original_read(descriptor, count)
            if chunk and not mutated:
                with source.open("ab") as handle:
                    handle.write(b"x")
                    handle.flush()
                    os.fsync(handle.fileno())
                mutated = True
            return chunk

        with mock.patch.object(
            qa_common.os,
            "read",
            side_effect=read_then_mutate,
        ):
            result = file_sha256(source)

        self.assertTrue(mutated)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
