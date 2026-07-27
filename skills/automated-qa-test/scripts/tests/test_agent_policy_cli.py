#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_core.tools import (  # noqa: E402
    DEFAULT_EVIDENCE_ACTIONS,
    DEFAULT_TOOL_ACTIONS,
    RiskClass,
    build_default_tool_registry,
)

CLI_PATH = SCRIPT_DIR / "agent_policy_cli.py"
CONTEXT_SHA256 = "a" * 64
STATE_SHA256 = "b" * 64
POLICY_VERSION = "cli-test-policy@1"
HMAC_ENV = "QA_POLICY_HMAC_KEY"
HMAC_VALUE = "test-policy-key-that-is-longer-than-32-bytes"


def write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def proposal_payload(
    *,
    action: str,
    arguments: dict,
) -> dict:
    registry = build_default_tool_registry()
    return {
        "proposal_id": f"plan-{action}",
        "context_sha256": CONTEXT_SHA256,
        "state_sha256": STATE_SHA256,
        "tool_registry_sha256": registry.canonical_sha256,
        "model_id": "planner-model@cli-test",
        "objective": f"验证 {action} 探针只能在策略批准后执行",
        "hypotheses": [
            {
                "hypothesis_id": "H1",
                "statement": "当前需求需要一个受约束探针",
                "evidence_refs": ["requirement.md#R1"],
            },
        ],
        "evidence_refs": ["requirement.md#R1"],
        "probes": [
            {
                "probe_id": "P1",
                "context_sha256": CONTEXT_SHA256,
                "state_sha256": STATE_SHA256,
                "tool_registry_sha256": registry.canonical_sha256,
                "model_id": "planner-model@cli-test",
                "hypothesis_ids": ["H1"],
                "evidence_refs": ["requirement.md#R1"],
                "rationale": "收集当前运行证据",
                "invocation": {
                    "action": action,
                    "arguments": arguments,
                },
                "timeout_seconds": 10,
                "output_limit_bytes": 2048,
            },
        ],
    }


class DefaultToolRegistryTests(unittest.TestCase):
    def test_registry_matches_the_runner_dispatch_surface(self) -> None:
        runner = (SCRIPT_DIR / "playwright_probe.mjs").read_text(
            encoding="utf-8",
        )
        runner_actions = frozenset(
            re.findall(r'step\.action === "([^"]+)"', runner),
        )

        self.assertEqual(DEFAULT_TOOL_ACTIONS, runner_actions)
        self.assertEqual(
            DEFAULT_TOOL_ACTIONS - DEFAULT_EVIDENCE_ACTIONS,
            {"wait", "waitForLoadState"},
        )

    def test_goto_and_command_have_explicit_risk_boundaries(self) -> None:
        registry = build_default_tool_registry()
        goto = registry.get("goto")
        command = registry.get("command")

        self.assertEqual(goto.risk_class, RiskClass.LOW)
        self.assertEqual(
            goto.required_authorizations,
            ("isolated_test_environment",),
        )
        self.assertEqual(command.risk_class, RiskClass.HIGH)
        self.assertEqual(
            command.required_authorizations,
            (
                "command_execution",
                "isolated_test_environment",
            ),
        )
        self.assertIn("command", command.input_schema["properties"])
        self.assertNotIn("shell", command.input_schema["properties"])


class AgentPolicyCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temporary.name)
        self.environment = {
            **os.environ,
            HMAC_ENV: HMAC_VALUE,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(
        self,
        command: list[str],
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CLI_PATH), *command],
            text=True,
            capture_output=True,
            env=self.environment,
        )

    def validate(
        self,
        payload: dict,
        *,
        grants: tuple[str, ...],
        max_risk: str,
        max_probes: int = 1,
        expected_context_sha256: str = CONTEXT_SHA256,
    ) -> tuple[subprocess.CompletedProcess[str], dict, Path]:
        proposal_path = self.run_dir / "proposal.json"
        output_path = self.run_dir / "decision.json"
        write_json(proposal_path, payload)
        command = [
            "validate",
            "--proposal",
            str(proposal_path),
            "--probe-id",
            "P1",
            "--context-sha256",
            expected_context_sha256,
            "--state-sha256",
            STATE_SHA256,
            "--model-id",
            "planner-model@cli-test",
            "--evidence-ref",
            "requirement.md#R1",
            "--max-risk",
            max_risk,
            "--total-timeout",
            "60",
            "--max-probes",
            str(max_probes),
            "--max-output-bytes",
            "8192",
            "--policy-version",
            POLICY_VERSION,
            "--now",
            "100",
            "--out",
            str(output_path),
        ]
        for grant in grants:
            command.extend(["--grant", grant])
        proc = self.run_cli(command)
        result = json.loads(output_path.read_text(encoding="utf-8"))
        return proc, result, proposal_path

    def test_legal_goto_and_command_receive_verifiable_authorization(
        self,
    ) -> None:
        cases = (
            (
                "goto",
                {"path": "/checkout"},
                ("isolated_test_environment",),
                "low",
            ),
            (
                "command",
                {
                    "command": [
                        sys.executable,
                        "-c",
                        "print('ok')",
                    ],
                },
                (
                    "isolated_test_environment",
                    "command_execution",
                ),
                "high",
            ),
        )

        for action, arguments, grants, max_risk in cases:
            with self.subTest(action=action):
                proc, result, proposal_path = self.validate(
                    proposal_payload(
                        action=action,
                        arguments=arguments,
                    ),
                    grants=grants,
                    max_risk=max_risk,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(result["status"], "allowed")
                authorization = result["decision"]["authorization"]
                self.assertIsInstance(authorization["signature"], str)

                authorization_path = (
                    self.run_dir / f"{action}-authorization.json"
                )
                verification_path = (
                    self.run_dir / f"{action}-verification.json"
                )
                write_json(authorization_path, authorization)
                verify = self.run_cli(
                    [
                        "verify",
                        "--proposal",
                        str(proposal_path),
                        "--probe-id",
                        "P1",
                        "--authorization-file",
                        str(authorization_path),
                        "--context-sha256",
                        CONTEXT_SHA256,
                        "--state-sha256",
                        STATE_SHA256,
                        "--model-id",
                        "planner-model@cli-test",
                        "--evidence-ref",
                        "requirement.md#R1",
                        "--policy-version",
                        POLICY_VERSION,
                        "--now",
                        "101",
                        "--out",
                        str(verification_path),
                    ],
                )
                self.assertEqual(verify.returncode, 0, verify.stderr)
                verification = json.loads(
                    verification_path.read_text(encoding="utf-8"),
                )
                self.assertTrue(verification["verified"])

    def test_unknown_and_model_authority_fields_fail_before_policy(self) -> None:
        registry_drift = proposal_payload(
            action="goto",
            arguments={"path": "/"},
        )
        registry_drift["tool_registry_sha256"] = "c" * 64
        registry_drift["probes"][0][
            "tool_registry_sha256"
        ] = "c" * 64
        invalid_cases = (
            (
                proposal_payload(
                    action="unknown.runnerAction",
                    arguments={},
                ),
                "unknown_action",
            ),
            (
                {
                    **proposal_payload(
                        action="goto",
                        arguments={"path": "/"},
                    ),
                    "authorization": "model-approved",
                },
                "model_field_forbidden",
            ),
            (
                proposal_payload(
                    action="command",
                    arguments={
                        "command": ["echo", "unsafe"],
                        "shell": True,
                    },
                ),
                "model_field_forbidden",
            ),
            (
                registry_drift,
                "tool_registry_hash_drift",
            ),
        )

        for payload, expected_code in invalid_cases:
            with self.subTest(expected_code=expected_code):
                proc, result, _ = self.validate(
                    payload,
                    grants=("isolated_test_environment",),
                    max_risk="high",
                )
                self.assertEqual(proc.returncode, 1)
                self.assertEqual(result["status"], "error")
                self.assertEqual(result["error"]["code"], expected_code)

    def test_currentness_permission_risk_and_budget_fail_closed(self) -> None:
        command = proposal_payload(
            action="command",
            arguments={"command": ["echo", "ok"]},
        )
        cases = (
            (
                command,
                ("isolated_test_environment", "command_execution"),
                "high",
                1,
                "d" * 64,
                "context_hash_drift",
            ),
            (
                command,
                ("isolated_test_environment",),
                "high",
                1,
                CONTEXT_SHA256,
                "required_authorization_missing",
            ),
            (
                command,
                (
                    "isolated_test_environment",
                    "command_execution",
                ),
                "medium",
                1,
                CONTEXT_SHA256,
                "risk_class_not_allowed",
            ),
            (
                proposal_payload(
                    action="goto",
                    arguments={"path": "/"},
                ),
                ("isolated_test_environment",),
                "low",
                0,
                CONTEXT_SHA256,
                "probe_budget_insufficient",
            ),
        )

        for (
            payload,
            grants,
            max_risk,
            max_probes,
            context_sha256,
            expected_reason,
        ) in cases:
            with self.subTest(expected_reason=expected_reason):
                proc, result, _ = self.validate(
                    payload,
                    grants=grants,
                    max_risk=max_risk,
                    max_probes=max_probes,
                    expected_context_sha256=context_sha256,
                )
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(result["status"], "rejected")
                self.assertIn(
                    expected_reason,
                    result["decision"]["reason_codes"],
                )
                self.assertIsNone(
                    result["decision"]["authorization"],
                )

    def test_policy_cli_rejects_input_aliases_and_unstable_files(
        self,
    ) -> None:
        proposal_path = self.run_dir / "proposal-boundary.json"
        write_json(
            proposal_path,
            proposal_payload(
                action="goto",
                arguments={"path": "/"},
            ),
        )
        original = proposal_path.read_bytes()
        base_command = [
            "validate",
            "--proposal",
            str(proposal_path),
            "--probe-id",
            "P1",
            "--context-sha256",
            CONTEXT_SHA256,
            "--state-sha256",
            STATE_SHA256,
            "--model-id",
            "planner-model@cli-test",
            "--evidence-ref",
            "requirement.md#R1",
            "--grant",
            "isolated_test_environment",
            "--max-risk",
            "low",
            "--now",
            "100",
        ]

        alias_result = self.run_cli(
            [*base_command, "--out", str(proposal_path)],
        )

        self.assertEqual(alias_result.returncode, 1)
        self.assertEqual(proposal_path.read_bytes(), original)

        symlink_path = self.run_dir / "proposal-symlink.json"
        symlink_path.symlink_to(proposal_path)
        symlink_output = self.run_dir / "symlink-result.json"
        symlink_result = self.run_cli(
            [
                *base_command[:2],
                str(symlink_path),
                *base_command[3:],
                "--out",
                str(symlink_output),
            ],
        )

        self.assertEqual(symlink_result.returncode, 1)
        symlink_payload = json.loads(
            symlink_output.read_text(encoding="utf-8"),
        )
        self.assertEqual(
            symlink_payload["error"]["code"],
            "proposal_symlink_rejected",
        )

    def test_validate_plan_rejects_unknown_runner_action(self) -> None:
        plan_path = self.run_dir / "test-plan.json"
        matrix_path = self.run_dir / "test-matrix.json"
        summary_path = self.run_dir / "plan-audit-summary.json"
        write_json(
            plan_path,
            {
                "schemaVersion": 2,
                "scenarios": [
                    {
                        "id": "unknown-action",
                        "steps": [
                            {
                                "action": "futureUnsupportedAction",
                                "id": "T1-step",
                                "testIds": ["T1"],
                                "requirementIds": ["R1"],
                                "proves": "未知动作不得到达 runner。",
                            },
                        ],
                    },
                ],
            },
        )
        write_json(
            matrix_path,
            {
                "schemaVersion": 2,
                "requirements": [
                    {
                        "id": "R1",
                        "text": "未知动作必须在执行前失败。",
                        "test_ids": ["T1"],
                    },
                ],
                "tests": [
                    {
                        "id": "T1",
                        "requirement_ids": ["R1"],
                        "type": "runtime",
                        "expected": "校验器拒绝未知动作。",
                    },
                ],
            },
        )

        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "validate_plan.py"),
                "--plan",
                str(plan_path),
                "--matrix",
                str(matrix_path),
                "--summary",
                str(summary_path),
            ],
            text=True,
            capture_output=True,
        )

        self.assertNotEqual(proc.returncode, 0)
        summary = json.loads(
            summary_path.read_text(encoding="utf-8"),
        )
        self.assertTrue(
            any(
                "unsupported action" in str(error).lower()
                for error in summary["errors"]
            ),
            summary["errors"],
        )


if __name__ == "__main__":
    unittest.main()
