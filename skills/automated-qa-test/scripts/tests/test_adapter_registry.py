#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import adapter_registry  # noqa: E402
from adapter_registry import (  # noqa: E402
    AdapterContractError,
    load_adapter_definition,
    validate_adapter_definition,
    validate_adapter_onboarding,
)


class AdapterRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        bundled = (
            SCRIPT_DIR.parent
            / "references"
            / "adapters"
            / "opc-project.json"
        )
        self.definition = json.loads(
            bundled.read_text(encoding="utf-8")
        )

    def write_definition(
        self,
        name: str,
        value: dict[str, object] | None = None,
    ) -> Path:
        path = self.root / name
        path.write_text(
            json.dumps(value or self.definition),
            encoding="utf-8",
        )
        return path

    def test_bundled_adapter_has_strict_onboarding_report(self) -> None:
        path = self.write_definition("adapter.json")

        report = validate_adapter_onboarding(path)

        self.assertTrue(report["ready"])
        self.assertTrue(report["not_evidence"])
        self.assertTrue(report["not_authorization"])
        self.assertEqual(report["adapter_id"], "opc_project")
        self.assertEqual(len(report["report_sha256"]), 64)
        self.assertEqual(report["blockers"], [])

    def test_project_marker_mismatch_blocks_report_and_cli(self) -> None:
        definition = json.loads(json.dumps(self.definition))
        definition["markers"] = ["required-marker.txt"]
        path = self.write_definition("mismatch.json", definition)
        project = self.root / "project"
        project.mkdir()

        report = validate_adapter_onboarding(
            path,
            project_root=project,
        )

        self.assertFalse(report["ready"])
        self.assertFalse(report["project_matches"])
        self.assertEqual(
            report["blockers"],
            [
                {
                    "code": "adapter_markers_not_matched",
                    "message": (
                        "adapter definition markers do not match the "
                        "supplied project root"
                    ),
                    "project_root": str(project.resolve()),
                    "unmatched_markers": ["required-marker.txt"],
                },
            ],
        )

        output = self.root / "adapter-onboarding.json"
        exit_code = adapter_registry.main(
            [
                "--definition",
                str(path),
                "--project-root",
                str(project),
                "--out",
                str(output),
            ],
        )
        self.assertEqual(exit_code, 2)
        persisted = json.loads(output.read_text(encoding="utf-8"))
        self.assertFalse(persisted["ready"])
        self.assertEqual(
            persisted["blockers"][0]["code"],
            "adapter_markers_not_matched",
        )

    def test_duplicate_key_and_nonfinite_json_fail_closed(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            '{"schema_version":1,"schema_version":1}',
            encoding="utf-8",
        )
        nonfinite = self.root / "nonfinite.json"
        nonfinite.write_text(
            '{"schema_version":NaN}',
            encoding="utf-8",
        )

        for path in (duplicate, nonfinite):
            with self.subTest(path=path):
                with self.assertRaises(AdapterContractError) as caught:
                    load_adapter_definition(path)
                self.assertEqual(
                    caught.exception.code,
                    "adapter_json_invalid",
                )

    def test_traversal_and_unknown_service_reference_are_rejected(
        self,
    ) -> None:
        traversal = json.loads(json.dumps(self.definition))
        traversal["markers"][0] = "../outside"
        with self.assertRaises(AdapterContractError) as caught:
            validate_adapter_definition(traversal)
        self.assertEqual(caught.exception.code, "adapter_path_invalid")

        unknown = json.loads(json.dumps(self.definition))
        unknown["preflight"]["base_url_contains"]["9999"] = [
            "missing_service"
        ]
        with self.assertRaises(AdapterContractError) as caught:
            validate_adapter_definition(unknown)
        self.assertEqual(
            caught.exception.code,
            "adapter_service_reference_unknown",
        )

    def test_symlink_and_hardlink_definition_are_rejected(self) -> None:
        source = self.write_definition("source.json")
        symlink = self.root / "symlink.json"
        symlink.symlink_to(source)
        with self.assertRaises(OSError):
            load_adapter_definition(symlink)

        hardlink = self.root / "hardlink.json"
        os.link(source, hardlink)
        with self.assertRaises(AdapterContractError) as caught:
            load_adapter_definition(hardlink)
        self.assertEqual(
            caught.exception.code,
            "adapter_input_hardlinked",
        )

    def test_ambiguous_project_detection_fails_closed(self) -> None:
        registry = self.root / "registry"
        registry.mkdir()
        project = self.root / "project"
        project.mkdir()
        (project / "marker.txt").write_text("marker", encoding="utf-8")
        first = json.loads(json.dumps(self.definition))
        second = json.loads(json.dumps(self.definition))
        first["id"] = "first"
        second["id"] = "second"
        first["markers"] = ["marker.txt"]
        second["markers"] = ["marker.txt"]
        (registry / "first.json").write_text(
            json.dumps(first),
            encoding="utf-8",
        )
        (registry / "second.json").write_text(
            json.dumps(second),
            encoding="utf-8",
        )

        with patch.object(adapter_registry, "ADAPTER_DIR", registry):
            with self.assertRaises(AdapterContractError) as caught:
                adapter_registry.detect_adapter_id(project)

        self.assertEqual(
            caught.exception.code,
            "adapter_detection_ambiguous",
        )

    def test_missing_project_root_routes_to_structured_generic_blocker(
        self,
    ) -> None:
        self.assertEqual(
            adapter_registry.detect_adapter_id(
                self.root / "missing-project"
            ),
            "generic",
        )

    def test_cli_output_alias_does_not_overwrite_definition(self) -> None:
        path = self.write_definition("adapter.json")
        before = path.read_bytes()

        exit_code = adapter_registry.main(
            [
                "--definition",
                str(path),
                "--out",
                str(path),
            ]
        )

        self.assertEqual(exit_code, 2)
        self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
