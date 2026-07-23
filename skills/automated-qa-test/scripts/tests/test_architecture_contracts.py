#!/usr/bin/env python3
import ast
import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import scaffold_requirement
from qa_core.contracts import ArtifactPaths
from qa_core.contracts.evidence import (
    collect_result_steps,
    evidence_artifact_paths,
    runner_result_binding_error,
)
from qa_core.contracts.schema import validate_artifact_schema
from qa_core.pipeline import CycleContext, StageRunner, parse_cycle_options
from qa_regression import agent as agent_fixtures
from qa_regression import agent_routes, source_coverage
from qa_regression import code_pr as code_pr_fixtures
from qa_regression import contracts as contract_fixtures
from qa_scaffold import command_secret_boundary_violation
from qa_scaffold import entry as scaffold_entry
from qa_scaffold import intents as scaffold_intents
from qa_scaffold import modeling as scaffold_modeling
from qa_scaffold import rules as scaffold_rules


class ArchitectureContractTests(unittest.TestCase):
    def test_scaffold_compatibility_entry_exports_owned_functions(self) -> None:
        self.assertIs(scaffold_requirement.scaffold, scaffold_entry.scaffold)
        self.assertIs(scaffold_requirement.input_error_artifacts, scaffold_entry.input_error_artifacts)
        self.assertIs(scaffold_requirement.build_business_model, scaffold_modeling.build_business_model)
        self.assertIs(scaffold_requirement.build_oracle_model, scaffold_modeling.build_oracle_model)
        self.assertTrue(callable(scaffold_requirement.has_secret_exposure_command))
        self.assertTrue(callable(scaffold_requirement.split_shell_script_parts))
        self.assertTrue(callable(command_secret_boundary_violation))

    def test_internal_module_dependencies_only_point_downward(self) -> None:
        layer_sets = {
            "qa_scaffold": ["support", "intents", "modeling", "rules", "entry"],
            "qa_regression": [
                "support",
                "code_pr",
                "source_coverage",
                "agent_routes",
                "agent",
                "contracts",
                "evidence",
            ],
        }
        for package, layers in layer_sets.items():
            order = {name: index for index, name in enumerate(layers)}
            for current in layers:
                path = SCRIPT_DIR / package / f"{current}.py"
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                imported_layers = {
                    node.module
                    for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom)
                    and node.level == 1
                    and node.module in order
                }
                for imported in imported_layers:
                    self.assertLess(
                        order[imported],
                        order[current],
                        f"{package}.{current} must not import upward from {imported}",
                    )

    def test_code_pr_fixture_facade_keeps_scenario_families_private(self) -> None:
        self.assertIs(
            contract_fixtures.run_code_pr_scaffold_fixture,
            code_pr_fixtures.run_code_pr_scaffold_fixture,
        )
        self.assertEqual(len(code_pr_fixtures._CODE_PR_SCENARIO_FAMILIES), 7)
        self.assertTrue(
            all(
                family.__name__.startswith("_verify_")
                for family in code_pr_fixtures._CODE_PR_SCENARIO_FAMILIES
            )
        )
        security_registries = (
            (code_pr_fixtures._BUILD_RELEASE_SCENARIO_FAMILIES, 3),
            (code_pr_fixtures._SECRET_READ_SCENARIO_FAMILIES, 4),
            (code_pr_fixtures._SECRET_WRITE_AND_INTERPRETER_SCENARIO_FAMILIES, 5),
        )
        for registry, expected_count in security_registries:
            self.assertEqual(len(registry), expected_count)
            self.assertTrue(all(family.__name__.startswith("_verify_") for family in registry))
            self.assertLessEqual(
                max(len(inspect.getsourcelines(family)[0]) for family in registry),
                250,
            )

    def test_specialized_regression_facades_keep_families_private(self) -> None:
        self.assertIs(
            contract_fixtures.run_unmapped_source_allow_gate_fixture,
            source_coverage.run_unmapped_source_allow_gate_fixture,
        )
        self.assertIs(
            agent_fixtures.run_agent_next_action_fixture,
            agent_routes.run_agent_next_action_fixture,
        )
        self.assertEqual(len(source_coverage._SOURCE_COVERAGE_FAMILIES), 3)
        self.assertEqual(len(agent_routes._AGENT_ROUTE_FAMILIES), 4)

    def test_scaffold_rule_facades_keep_domain_collectors_private(self) -> None:
        self.assertEqual(len(scaffold_intents._EVIDENCE_LAYER_COLLECTORS), 6)
        self.assertEqual(len(scaffold_rules._ADVANCED_RULE_FAMILIES), 4)
        self.assertEqual(len(scaffold_modeling._CLASSIFICATION_TAG_FAMILIES), 3)
        rule_registries = (
            (scaffold_rules._FOUNDATION_RULE_FAMILIES, 5),
            (scaffold_rules._RESILIENCE_RULE_FAMILIES, 4),
            (scaffold_rules._AUTHENTICATION_RULE_FAMILIES, 4),
            (scaffold_rules._INTEGRITY_RULE_FAMILIES, 5),
            (scaffold_rules._ADVANCED_RULE_FAMILIES, 4),
            (scaffold_rules._UI_INTERACTION_RULE_FAMILIES, 3),
        )
        for registry, expected_count in rule_registries:
            self.assertEqual(len(registry), expected_count)
            self.assertTrue(all(family.__name__.startswith("_apply_") for family in registry))
            self.assertLessEqual(
                max(len(inspect.getsourcelines(family)[0]) for family in registry),
                250,
            )
        runtime_helpers = (
            scaffold_rules._runtime_rule_applies,
            scaffold_rules._runtime_evidence_layers,
            scaffold_rules._runtime_probe_steps,
            scaffold_rules._append_runtime_gap,
        )
        self.assertLessEqual(
            max(len(inspect.getsourcelines(helper)[0]) for helper in runtime_helpers),
            250,
        )
        self.assertTrue(
            all(
                collector.__name__.startswith("_collect_")
                for collector in scaffold_intents._EVIDENCE_LAYER_COLLECTORS
            )
        )
        self.assertTrue(
            all(
                family.__name__.startswith("_apply_")
                for family in scaffold_rules._ADVANCED_RULE_FAMILIES
            )
        )
        self.assertTrue(
            all(
                family.__name__.startswith("_apply_")
                for family in scaffold_modeling._CLASSIFICATION_TAG_FAMILIES
            )
        )

    def test_artifact_paths_are_centralized_and_overridable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw)
            external = run_dir / "custom-results.json"
            paths = ArtifactPaths.from_overrides(run_dir, {"results": str(external)})

            resolved_run_dir = run_dir.resolve()
            self.assertEqual(paths.plan, resolved_run_dir / "test-plan.json")
            self.assertEqual(paths.results, external.resolve())
            self.assertIn(("verdict", resolved_run_dir / "qa-verdict.json"), paths.terminal_outputs())
            self.assertNotIn(("plan", paths.plan), paths.named_outputs())

    def test_cycle_context_builds_stable_summary_contract(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw)
            context = CycleContext.create(
                script_dir=Path(__file__).resolve().parents[1],
                run_dir=run_dir,
                overrides={},
                skip_report=False,
            )

            self.assertEqual(context.summary["paths"]["plan"], str(run_dir.resolve() / "test-plan.json"))
            self.assertEqual(context.summary["paths"]["report"], str(run_dir.resolve() / "report.md"))
            self.assertEqual(context.summary["status"], "running")

    def test_cycle_options_keep_environment_boundary_fail_closed(self) -> None:
        strict = parse_cycle_options(["--run-dir", "/tmp/qa"])
        explicitly_relaxed = parse_cycle_options(
            ["--run-dir", "/tmp/qa", "--allow-unconfirmed-environment"]
        )

        self.assertTrue(strict.require_environment_boundary)
        self.assertFalse(explicitly_relaxed.require_environment_boundary)

    def test_stage_runner_owns_execution_and_summary_journaling(self) -> None:
        summary: dict[str, object] = {"steps": []}
        calls: list[tuple[list[str], Path | None]] = []

        def execute(command: list[str], cwd: Path | None) -> dict[str, object]:
            calls.append((command, cwd))
            return {"exit_code": 0, "stdout": "ok"}

        runner = StageRunner(summary, execute)
        result = runner.run("validate_plan", ["python3", "validate_plan.py"], cwd=Path("/tmp/qa"))
        runner.skip("generate_report", "--skip-report")

        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(calls, [(["python3", "validate_plan.py"], Path("/tmp/qa"))])
        self.assertEqual(
            [step["name"] for step in summary["steps"]],  # type: ignore[index]
            ["validate_plan", "generate_report"],
        )

    def test_regression_groups_are_discoverable_without_execution(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "regression_check.py"), "--list-groups"],
            check=True,
            text=True,
            capture_output=True,
        )
        payload = json.loads(completed.stdout)

        self.assertEqual(
            list(payload),
            ["contracts", "modeling", "evidence", "runtime", "agent", "browser"],
        )
        self.assertGreaterEqual(sum(len(fixtures) for fixtures in payload.values()), 80)

    def test_runtime_schema_loader_rejects_contract_drift(self) -> None:
        invalid_plan = {"schemaVersion": 3, "baseUrl": "", "artifactDir": "/tmp/qa", "scenarios": []}
        errors = validate_artifact_schema("plan", invalid_plan)

        self.assertTrue(any("schemaVersion" in error for error in errors))

    def test_runner_binding_uses_one_strict_field_contract(self) -> None:
        results = {
            "scenarios": [
                {
                    "id": "scenario-1",
                    "steps": [
                        {
                            "stepId": "step-1",
                            "action": "api",
                            "status": "passed",
                            "requirementIds": ["R1"],
                            "testIds": ["T1"],
                            "statusCode": 200,
                        }
                    ],
                }
            ]
        }
        evidence = {
            "id": "E1",
            "scenario_id": "scenario-1",
            "step_id": "step-1",
            "action": "api",
            "status": "passed",
            "requirement_ids": ["R1"],
            "test_ids": ["T1"],
            "status_code": 200,
            "body_preview": "not present in results",
        }

        error = runner_result_binding_error(evidence, collect_result_steps(results), Path("/tmp/qa"))

        self.assertIsNotNone(error)
        self.assertIn("body_preview", error or "")

    def test_evidence_paths_accept_ledger_or_evidence_list(self) -> None:
        ledger = {"evidence": [{"body_path": "body.json"}]}
        base_dir = Path("/tmp/run")

        expected = [(base_dir / "body.json").resolve()]
        self.assertEqual(evidence_artifact_paths(ledger, base_dir), expected)
        self.assertEqual(evidence_artifact_paths(ledger["evidence"], base_dir), expected)


if __name__ == "__main__":
    unittest.main()
