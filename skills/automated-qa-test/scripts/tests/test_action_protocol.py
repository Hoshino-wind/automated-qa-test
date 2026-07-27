#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qa_common import file_sha256  # noqa: E402
from qa_core.context import compile_context_snapshot  # noqa: E402
from qa_core.runtime import (  # noqa: E402
    ACTION_AUTHORITY_KEY_ENV,
    ACTION_AUTHORIZATION_TICKET_ENV,
    RESOLUTION_POLICY_SHA256,
    ActionProtocolError,
    build_action_contracts,
    issue_action_authorization_ticket,
    preflight_action_journal,
    verify_action_journal,
)
from qa_core.runtime import action_protocol as action_protocol_module  # noqa: E402


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


@unittest.skipUnless(shutil.which("node"), "node is required")
class ActionProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.run_dir = Path(self.temporary.name)
        self.plan_path = self.run_dir / "test-plan.json"
        self.audit_path = self.run_dir / "plan-audit-summary.json"
        self.context_path = self.run_dir / "agent-context.json"
        self.contracts_path = self.run_dir / "action-contracts.json"
        self.journal_path = self.run_dir / "action-journal.jsonl"
        self.results_path = self.run_dir / "results.json"
        self.node_bin = str(Path(shutil.which("node") or "node").resolve())
        self.command_base_cwd: Path | None = None
        self._write_fixture()

    def _write_fixture(
        self,
        step: dict[str, object] | None = None,
        *,
        base_url: object | None = None,
        plan_overrides: dict[str, object] | None = None,
        runtime_vars: dict[str, object] | None = None,
        command_base_cwd: Path | None = None,
    ) -> None:
        self.command_base_cwd = command_base_cwd
        selected_step = step or {
            "id": "command-step",
            "action": "command",
            "command": [
                "node",
                "-e",
                "process.stdout.write('ok')",
            ],
            "expectExitCode": 0,
        }
        self.plan_path.write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "artifactDir": str(self.run_dir),
                    **(
                        {"baseUrl": base_url}
                        if base_url is not None
                        else {}
                    ),
                    **(
                        {"runtimeVars": runtime_vars}
                        if runtime_vars is not None
                        else {}
                    ),
                    **(plan_overrides or {}),
                    "scenarios": [
                        {
                            "id": "command-scenario",
                            "steps": [selected_step],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (self.run_dir / "test-matrix.json").write_text(
            '{"schemaVersion":2,"tests":[]}',
            encoding="utf-8",
        )
        (self.run_dir / "requirement.md").write_text(
            "# Durable action\n",
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
                }
            ),
            encoding="utf-8",
        )
        self.audit_path.write_text(
            json.dumps(
                {
                    "passed": True,
                    "plan": str(self.plan_path),
                    "artifact_hashes": {
                        "plan_sha256": file_sha256(self.plan_path)
                    },
                }
            ),
            encoding="utf-8",
        )
        context = compile_context_snapshot(self.run_dir)
        self.context_path.write_text(
            json.dumps(context.to_dict()),
            encoding="utf-8",
        )
        contracts = build_action_contracts(
            self.plan_path,
            self.context_path,
            self.audit_path,
            run_id="run-action-protocol",
            generation=1,
            iteration=1,
            command_base_cwd=command_base_cwd,
        )
        self.contracts_path.write_text(
            json.dumps(contracts),
            encoding="utf-8",
        )

    def test_high_risk_api_target_cannot_be_swapped_by_environment(
        self,
    ) -> None:
        with self.assertRaises(ActionProtocolError) as caught:
            self._write_fixture(
                {
                    "id": "mutating-api",
                    "action": "api",
                    "method": "POST",
                    "path": "/fixtures/1",
                    "expectStatus": 200,
                },
                base_url={"$env": "QA_HIGH_RISK_API_BASE_URL"},
            )
        self.assertEqual(
            caught.exception.code,
            "action_high_risk_target_dynamic",
        )

        for target in (
            "http://127.0.0.1:4101",
            "https://attacker.invalid",
        ):
            with self.subTest(target=target):
                completed = self.run_probe(
                    environment={
                        "QA_HIGH_RISK_API_BASE_URL": target,
                    },
                    with_contracts=False,
                )
                self.assertEqual(
                    completed.returncode,
                    2,
                    completed.stderr,
                )
                self.assertIn(
                    "static plan.baseUrl",
                    completed.stderr,
                )
        self.assertFalse(self.journal_path.exists())

    def test_high_risk_api_rejects_dynamic_object_and_routing_controls(
        self,
    ) -> None:
        cases = (
            (
                {
                    "id": "mutating-api",
                    "action": "cleanupApi",
                    "method": "DELETE",
                    "path": "/fixtures",
                    "json": {
                        "userId": {"$env": "QA_TARGET_USER"}
                    },
                    "expectStatus": 200,
                },
                {"base_url": "https://approved.invalid"},
                "Dynamic references are forbidden",
            ),
            (
                {
                    "id": "mutating-api",
                    "action": "api",
                    "method": "POST",
                    "path": "/fixtures/1",
                },
                {
                    "base_url": "https://approved.invalid",
                    "plan_overrides": {
                        "contextOptions": {
                            "baseURL": {
                                "$env": "QA_CONTEXT_BASE_URL"
                            }
                        }
                    },
                },
                "contextOptions.baseURL",
            ),
            (
                {
                    "id": "mutating-api",
                    "action": "api",
                    "method": "POST",
                    "path": "/fixtures/1",
                },
                {
                    "base_url": "https://approved.invalid",
                    "plan_overrides": {
                        "launchOptions": {
                            "proxy": {
                                "$env": "QA_PROXY_SERVER"
                            }
                        }
                    },
                },
                "launchOptions.proxy",
            ),
            (
                {
                    "id": "mutating-api",
                    "action": "api",
                    "method": "POST",
                    "path": "/fixtures/1",
                    "headers": {
                        "Host": {
                            "$env": "QA_VIRTUAL_HOST"
                        }
                    },
                },
                {"base_url": "https://approved.invalid"},
                "routing header",
            ),
        )
        for step, kwargs, expected_message in cases:
            with self.subTest(expected_message=expected_message):
                with self.assertRaises(ActionProtocolError):
                    self._write_fixture(step, **kwargs)
                completed = self.run_probe(
                    environment={
                        "QA_TARGET_USER": "attacker",
                        "QA_CONTEXT_BASE_URL": (
                            "https://attacker.invalid"
                        ),
                        "QA_PROXY_SERVER": (
                            "http://attacker.invalid:8080"
                        ),
                        "QA_VIRTUAL_HOST": "attacker.invalid",
                    },
                    with_contracts=False,
                )
                self.assertEqual(
                    completed.returncode,
                    2,
                    completed.stderr,
                )
                self.assertIn(expected_message, completed.stderr)
                self.assertFalse(self.journal_path.exists())

    def test_high_risk_api_allows_dynamic_credentials_only(self) -> None:
        self._write_fixture(
            {
                "id": "credentialed-api",
                "action": "api",
                "method": "POST",
                "path": "/fixtures/1",
                "headers": {
                    "Authorization": {
                        "$env": "QA_API_TOKEN",
                        "prefix": "Bearer ",
                    },
                    "X-Request-Class": "qa-fixture",
                },
            },
            base_url="https://approved.invalid",
        )
        contracts = json.loads(
            self.contracts_path.read_text(encoding="utf-8")
        )
        self.assertEqual(
            contracts["actions"][0]["risk_class"],
            "high",
        )

    def run_probe(
        self,
        *,
        environment: dict[str, str] | None = None,
        with_contracts: bool = True,
        before_launch: Callable[[], None] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            self.node_bin,
            str(SCRIPT_DIR / "playwright_probe.mjs"),
            "--plan",
            str(self.plan_path),
            "--plan-audit-summary",
            str(self.audit_path),
        ]
        if with_contracts:
            command.extend(
                [
                    "--agent-context",
                    str(self.context_path),
                    "--action-contracts",
                    str(self.contracts_path),
                    "--action-journal",
                    str(self.journal_path),
                ]
            )
        probe_environment = {**os.environ, **(environment or {})}
        if with_contracts:
            try:
                contracts = json.loads(
                    self.contracts_path.read_text(encoding="utf-8")
                )
                authority_key = b"\x11" * 32
                ticket = issue_action_authorization_ticket(
                    contracts,
                    plan_path=self.plan_path,
                    context_path=self.context_path,
                    plan_audit_path=self.audit_path,
                    authority_key=authority_key,
                    command_base_cwd=self.command_base_cwd,
                )
                probe_environment.update(
                    {
                        ACTION_AUTHORITY_KEY_ENV: authority_key.hex(),
                        ACTION_AUTHORIZATION_TICKET_ENV: ticket,
                    }
                )
            except (OSError, ValueError):
                pass
        if before_launch is not None:
            before_launch()
        return subprocess.run(
            command,
            cwd=self.run_dir,
            text=True,
            capture_output=True,
            env=probe_environment,
        )

    def test_runner_commits_intent_before_result(self) -> None:
        completed = self.run_probe()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        results = json.loads(self.results_path.read_text(encoding="utf-8"))
        contracts = json.loads(
            self.contracts_path.read_text(encoding="utf-8")
        )

        verification = verify_action_journal(
            self.journal_path,
            contracts,
            results=results,
        )

        self.assertTrue(verification.valid, verification.errors)
        self.assertEqual(verification.event_count, 2)
        self.assertEqual(verification.current_action_count, 1)
        events = [
            json.loads(line)
            for line in self.journal_path.read_text(
                encoding="utf-8"
            ).splitlines()
        ]
        self.assertEqual(
            [event["kind"] for event in events],
            ["intent", "commit"],
        )
        self.assertEqual(
            events[1]["intent_sequence"],
            events[0]["sequence"],
        )
        contract = contracts["actions"][0]
        raw_step = json.loads(
            self.plan_path.read_text(encoding="utf-8")
        )["scenarios"][0]["steps"][0]
        self.assertEqual(
            contract["raw_step_sha256"],
            canonical_sha256(raw_step),
        )
        self.assertEqual(
            contract["resolution_policy_sha256"],
            RESOLUTION_POLICY_SHA256,
        )
        self.assertEqual(
            events[0]["resolved_invocation_sha256"],
            events[1]["resolved_invocation_sha256"],
        )
        self.assertEqual(
            events[0]["execution_authorization_sha256"],
            events[1]["execution_authorization_sha256"],
        )
        command_binding = contract["command_execution_binding"]
        self.assertEqual(
            command_binding["executable"]["real_path"],
            self.node_bin,
        )
        self.assertEqual(
            command_binding["inherited_environment_names"],
            [
                "CI",
                "LANG",
                "LC_ALL",
                "LC_CTYPE",
                "NODE_PATH",
                "PATH",
                "PYTHONPATH",
                "TERM",
                "TMPDIR",
            ],
        )

    def test_explicit_command_base_cwd_is_bound_and_used(self) -> None:
        project_dir = self.run_dir / "project"
        project_dir.mkdir()
        self._write_fixture(
            {
                "id": "command-step",
                "action": "command",
                "command": [
                    self.node_bin,
                    "-e",
                    "process.stdout.write(process.cwd())",
                ],
                "expectStdoutContains": str(project_dir),
            },
            command_base_cwd=project_dir,
        )

        completed = self.run_probe()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        contracts = json.loads(
            self.contracts_path.read_text(encoding="utf-8")
        )
        binding = contracts["actions"][0][
            "command_execution_binding"
        ]
        self.assertEqual(binding["base_cwd"], str(project_dir.resolve()))
        self.assertEqual(binding["cwd"], str(project_dir.resolve()))
        results = json.loads(
            self.results_path.read_text(encoding="utf-8")
        )
        self.assertIn(
            str(project_dir.resolve()),
            results["scenarios"][0]["steps"][0]["stdoutPreview"],
        )

    def test_contract_hashes_the_same_plan_snapshot_it_parses(
        self,
    ) -> None:
        approved_bytes = self.plan_path.read_bytes()
        malicious = json.loads(approved_bytes)
        malicious["scenarios"][0]["steps"][0]["command"] = [
            self.node_bin,
            "-e",
            "process.stdout.write('substituted')",
        ]
        self.plan_path.write_text(
            json.dumps(malicious),
            encoding="utf-8",
        )
        replacement_path = self.run_dir / "approved-plan.json"
        replacement_path.write_bytes(approved_bytes)
        self.audit_path.write_text(
            json.dumps(
                {
                    "passed": True,
                    "plan": str(self.plan_path),
                    "artifact_hashes": {
                        "plan_sha256": hashlib.sha256(
                            approved_bytes
                        ).hexdigest(),
                    },
                }
            ),
            encoding="utf-8",
        )
        original_read = action_protocol_module._read_regular
        substituted = False

        def replace_after_read(
            path: Path,
            *,
            max_bytes: int,
            single_link: bool,
        ) -> bytes:
            nonlocal substituted
            raw = original_read(
                path,
                max_bytes=max_bytes,
                single_link=single_link,
            )
            if Path(path) == self.plan_path and not substituted:
                os.replace(replacement_path, self.plan_path)
                substituted = True
            return raw

        with mock.patch.object(
            action_protocol_module,
            "_read_regular",
            side_effect=replace_after_read,
        ):
            with self.assertRaises(ActionProtocolError) as caught:
                build_action_contracts(
                    self.plan_path,
                    self.context_path,
                    self.audit_path,
                    run_id="run-action-protocol",
                    generation=1,
                    iteration=1,
                )

        self.assertEqual(
            caught.exception.code,
            "action_plan_audit_stale",
        )

    def test_ticket_rejects_replaced_interpreter_script(self) -> None:
        marker = self.run_dir / "ticket-script-ran"
        script = self.run_dir / "ticket-script.mjs"
        script.write_text(
            "process.stdout.write('approved');\n",
            encoding="utf-8",
        )
        self._write_fixture(
            {
                "id": "command-step",
                "action": "command",
                "command": [self.node_bin, str(script)],
                "expectStdoutContains": "approved",
            }
        )
        contracts = json.loads(
            self.contracts_path.read_text(encoding="utf-8")
        )
        script.write_text(
            (
                "require('fs').writeFileSync("
                f"{str(marker)!r}, 'ran');\n"
            ),
            encoding="utf-8",
        )

        with self.assertRaises(ActionProtocolError) as caught:
            issue_action_authorization_ticket(
                contracts,
                plan_path=self.plan_path,
                context_path=self.context_path,
                plan_audit_path=self.audit_path,
                authority_key=b"\x11" * 32,
            )

        self.assertEqual(
            caught.exception.code,
            "action_command_binding_stale",
        )
        self.assertFalse(marker.exists())
        self.assertFalse(self.journal_path.exists())

    def test_node_rejects_script_replacement_before_intent(self) -> None:
        marker = self.run_dir / "node-script-ran"
        script = self.run_dir / "node-script.mjs"
        script.write_text(
            "process.stdout.write('approved');\n",
            encoding="utf-8",
        )
        self._write_fixture(
            {
                "id": "command-step",
                "action": "command",
                "command": [self.node_bin, str(script)],
                "expectStdoutContains": "approved",
            }
        )

        def replace_script() -> None:
            script.write_text(
                (
                    "require('fs').writeFileSync("
                    f"{str(marker)!r}, 'ran');\n"
                ),
                encoding="utf-8",
            )

        completed = self.run_probe(before_launch=replace_script)

        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertIn(
            "Command direct input changed after authorization",
            completed.stderr,
        )
        self.assertFalse(marker.exists())
        self.assertFalse(self.journal_path.exists())

    def test_command_environment_handoff_drift_fails_before_intent(
        self,
    ) -> None:
        for name in ("PYTHONPATH", "NODE_PATH"):
            with self.subTest(name=name), mock.patch.dict(
                os.environ,
                {name: f"/approved/{name.lower()}"},
            ):
                self._write_fixture()
                completed = self.run_probe(
                    environment={
                        name: f"/attacker/{name.lower()}"
                    }
                )
                self.assertEqual(
                    completed.returncode,
                    3,
                    completed.stderr,
                )
                self.assertIn(
                    "Command child environment changed after authorization",
                    completed.stderr,
                )
                self.assertFalse(self.journal_path.exists())

    def test_path_executable_swap_fails_before_intent(self) -> None:
        approved_dir = self.run_dir / "approved-bin"
        attacker_dir = self.run_dir / "attacker-bin"
        approved_dir.mkdir()
        attacker_dir.mkdir()
        marker = self.run_dir / "path-swap-ran"
        approved_tool = approved_dir / "qa-bound-tool"
        attacker_tool = attacker_dir / "qa-bound-tool"
        approved_tool.write_text(
            "#!/bin/sh\nprintf approved\n",
            encoding="utf-8",
        )
        attacker_tool.write_text(
            f"#!/bin/sh\ntouch {marker}\n",
            encoding="utf-8",
        )
        approved_tool.chmod(0o755)
        attacker_tool.chmod(0o755)
        with mock.patch.dict(
            os.environ,
            {"PATH": str(approved_dir)},
        ):
            self._write_fixture(
                {
                    "id": "command-step",
                    "action": "command",
                    "command": ["qa-bound-tool"],
                    "expectStdoutContains": "approved",
                }
            )
            completed = self.run_probe(
                environment={"PATH": str(attacker_dir)}
            )

        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertIn(
            "Command child environment changed after authorization",
            completed.stderr,
        )
        self.assertFalse(marker.exists())
        self.assertFalse(self.journal_path.exists())

    def test_unresolved_non_idempotent_intent_blocks_replay(self) -> None:
        completed = self.run_probe()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        first_line = self.journal_path.read_text(
            encoding="utf-8"
        ).splitlines()[0]
        self.journal_path.write_text(
            first_line + "\n",
            encoding="utf-8",
        )
        contracts = json.loads(
            self.contracts_path.read_text(encoding="utf-8")
        )

        verification = verify_action_journal(
            self.journal_path,
            contracts,
        )
        replay = self.run_probe()

        self.assertFalse(verification.valid)
        self.assertIn(
            "action_intent_unresolved",
            {item["code"] for item in verification.errors},
        )
        self.assertEqual(replay.returncode, 3)
        self.assertIn(
            "requires human reconciliation",
            replay.stderr,
        )

    def test_strict_preflight_rejects_duplicate_json_keys(self) -> None:
        completed = self.run_probe()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        first_line = self.journal_path.read_text(
            encoding="utf-8"
        ).splitlines()[0]
        duplicate = first_line.replace(
            '"sequence":1',
            '"sequence":1,"sequence":1',
            1,
        )
        self.journal_path.write_text(
            duplicate + "\n",
            encoding="utf-8",
        )
        contracts = json.loads(
            self.contracts_path.read_text(encoding="utf-8")
        )

        preflight = preflight_action_journal(
            self.journal_path,
            contracts,
        )

        self.assertFalse(preflight.valid)
        self.assertIn(
            "action_journal_json_invalid",
            {item["code"] for item in preflight.errors},
        )

    def test_step_level_env_json_replacement_fails_before_dispatch(self) -> None:
        marker = self.run_dir / "step-env-replacement-ran"
        with self.assertRaises(ActionProtocolError):
            self._write_fixture(
                {
                    "id": "command-step",
                    "action": "command",
                    "command": [
                        "node",
                        "-e",
                        f"require('fs').writeFileSync({str(marker)!r}, 'ran')",
                    ],
                    "env": "QA_STEP_REPLACEMENT",
                    "json": True,
                }
            )
        replacement = json.dumps(
            {
                "id": "replacement",
                "action": "command",
                "command": [
                    "node",
                    "-e",
                    f"require('fs').writeFileSync({str(marker)!r}, 'ran')",
                ],
            }
        )

        completed = self.run_probe(
            environment={"QA_STEP_REPLACEMENT": replacement},
            with_contracts=False,
        )

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("static step object", completed.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(self.journal_path.exists())

    def test_nested_command_env_reference_fails_before_dispatch(self) -> None:
        marker = self.run_dir / "nested-command-env-ran"
        with self.assertRaises(ActionProtocolError):
            self._write_fixture(
                {
                    "id": "command-step",
                    "action": "command",
                    "command": [
                        "node",
                        "-e",
                        f"require('fs').writeFileSync({str(marker)!r}, 'ran')",
                    ],
                    "env": {
                        "INJECTED": {
                            "$env": "QA_COMMAND_ENV_JSON",
                            "json": True,
                        }
                    },
                }
            )

        completed = self.run_probe(
            environment={"QA_COMMAND_ENV_JSON": '{"PATH":"/tmp"}'},
            with_contracts=False,
        )

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn(
            "Dynamic references are forbidden in execution control field",
            completed.stderr,
        )
        self.assertFalse(marker.exists())
        self.assertFalse(self.journal_path.exists())

    def test_runtime_var_command_replacement_fails_before_dispatch(self) -> None:
        marker = self.run_dir / "runtime-command-replacement-ran"
        attack_command = json.dumps(
            [
                "node",
                "-e",
                f"require('fs').writeFileSync({str(marker)!r}, 'ran')",
            ]
        )
        with self.assertRaises(ActionProtocolError):
            self._write_fixture(
                {
                    "id": "command-step",
                    "action": "command",
                    "command": {
                        "$var": "attack_command",
                        "json": True,
                    },
                },
                runtime_vars={"attack_command": attack_command},
            )

        completed = self.run_probe(with_contracts=False)

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn(
            "Dynamic references are forbidden in execution control field",
            completed.stderr,
        )
        self.assertFalse(marker.exists())
        self.assertFalse(self.journal_path.exists())

    def test_legal_secret_references_are_hashed_but_not_persisted(self) -> None:
        secret = "1234"
        self._write_fixture(
            {
                "id": "command-step",
                "action": "command",
                "command": [
                    "node",
                    "-e",
                    "process.stdout.write("
                    "process['env']['QA_DATA_PLANE_VALUE'] || 'missing'"
                    ")",
                ],
                "expectStdoutContains": "missing",
                "headers": {
                    "authorization": {
                        "$env": "QA_DATA_PLANE_VALUE",
                        "prefix": "Bearer ",
                    }
                },
                "cookies": [
                    {
                        "name": "session",
                        "value": {"env": "QA_DATA_PLANE_VALUE"},
                        "domain": "example.test",
                        "path": "/",
                    }
                ],
                "body": {
                    "credential": {"$env": "QA_DATA_PLANE_VALUE"}
                },
            }
        )

        completed = self.run_probe(
            environment={"QA_DATA_PLANE_VALUE": secret}
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        contracts = json.loads(
            self.contracts_path.read_text(encoding="utf-8")
        )
        results = json.loads(self.results_path.read_text(encoding="utf-8"))
        verification = verify_action_journal(
            self.journal_path,
            contracts,
            results=results,
        )
        self.assertTrue(verification.valid, verification.errors)
        event = json.loads(
            self.journal_path.read_text(encoding="utf-8").splitlines()[0]
        )
        raw_step = json.loads(
            self.plan_path.read_text(encoding="utf-8")
        )["scenarios"][0]["steps"][0]

        def resolve_fixture(value: object) -> object:
            if isinstance(value, list):
                return [resolve_fixture(item) for item in value]
            if isinstance(value, dict):
                alias = next(
                    (
                        key
                        for key in ("env", "$env")
                        if isinstance(value.get(key), str)
                    ),
                    None,
                )
                if alias is not None:
                    rendered = (
                        f"{value.get('prefix', '')}"
                        f"{secret}"
                        f"{value.get('suffix', '')}"
                    )
                    return json.loads(rendered) if value.get("json") else rendered
                return {
                    key: resolve_fixture(item)
                    for key, item in value.items()
                }
            return value

        def redact_fixture(
            raw: object,
            resolved: object,
            location: str,
        ) -> object:
            if isinstance(raw, list):
                assert isinstance(resolved, list)
                return [
                    redact_fixture(
                        item,
                        resolved[index],
                        f"{location}[{index}]",
                    )
                    for index, item in enumerate(raw)
                ]
            if isinstance(raw, dict):
                alias = next(
                    (
                        key
                        for key in ("env", "$env")
                        if isinstance(raw.get(key), str)
                    ),
                    None,
                )
                if alias is not None:
                    return {
                        "$dynamic_reference": {
                            "alias": alias,
                            "kind": "env",
                            "location": location,
                            "source": raw[alias],
                            "raw_reference_sha256": canonical_sha256(raw),
                            "resolved_value": "[REDACTED]",
                        }
                    }
                assert isinstance(resolved, dict)
                return {
                    key: redact_fixture(
                        item,
                        resolved[key],
                        f"{location}.{key}",
                    )
                    for key, item in raw.items()
                }
            return resolved

        resolved_step = resolve_fixture(raw_step)
        location = "scenario.command-scenario.step.command-step"
        redacted_payload = {
            "schema_version": 2,
            "kind": "qa_secret_redacted_resolved_invocation",
            "scenario_id": "command-scenario",
            "step_id": "command-step",
            "action": "command",
            "arguments": redact_fixture(
                raw_step,
                resolved_step,
                location,
            ),
            "tool_version": contracts["actions"][0]["tool_version"],
            "tool_spec_sha256": contracts["actions"][0][
                "tool_spec_sha256"
            ],
        }
        real_secret_payload = {
            **redacted_payload,
            "arguments": resolved_step,
        }
        self.assertEqual(
            event["resolved_invocation_sha256"],
            canonical_sha256(redacted_payload),
        )
        self.assertNotEqual(
            event["resolved_invocation_sha256"],
            canonical_sha256(real_secret_payload),
        )
        for artifact in (
            self.contracts_path,
            self.journal_path,
            self.results_path,
        ):
            self.assertNotIn(
                secret,
                artifact.read_text(encoding="utf-8"),
                artifact.name,
            )

    def test_execution_authorization_is_recomputed_by_verifier(self) -> None:
        completed = self.run_probe()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        events = [
            json.loads(line)
            for line in self.journal_path.read_text(
                encoding="utf-8"
            ).splitlines()
        ]
        forged_authorization = "0" * 64
        forged_idempotency = canonical_sha256(
            {
                "run_id": events[0]["run_id"],
                "generation": events[0]["generation"],
                "iteration": events[0]["iteration"],
                "scenario_id": events[0]["scenario_id"],
                "step_id": events[0]["step_id"],
                "action": events[0]["action"],
                "invocation_sha256": events[0]["invocation_sha256"],
                "execution_authorization_sha256": forged_authorization,
            }
        )
        for event in events:
            event["execution_authorization_sha256"] = forged_authorization
            event["idempotency_key"] = forged_idempotency
        events[0]["event_sha256"] = canonical_sha256(
            {
                key: value
                for key, value in events[0].items()
                if key != "event_sha256"
            }
        )
        events[1]["previous_event_sha256"] = events[0]["event_sha256"]
        events[1]["event_sha256"] = canonical_sha256(
            {
                key: value
                for key, value in events[1].items()
                if key != "event_sha256"
            }
        )
        self.journal_path.write_text(
            "".join(
                json.dumps(
                    event,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
                for event in events
            ),
            encoding="utf-8",
        )
        contracts = json.loads(
            self.contracts_path.read_text(encoding="utf-8")
        )

        verification = verify_action_journal(
            self.journal_path,
            contracts,
        )

        self.assertFalse(verification.valid)
        self.assertIn(
            "action_execution_authorization_invalid",
            {item["code"] for item in verification.errors},
        )

    def test_self_hashed_forged_toolspec_fails_before_dispatch(self) -> None:
        marker = self.run_dir / "forged-toolspec-ran"
        self._write_fixture(
            {
                "id": "command-step",
                "action": "command",
                "command": [
                    "node",
                    "-e",
                    f"require('fs').writeFileSync({str(marker)!r}, 'ran')",
                ],
            }
        )
        contracts = json.loads(
            self.contracts_path.read_text(encoding="utf-8")
        )
        contracts["actions"][0]["idempotent"] = True
        contracts["actions"][0][
            "recovery_policy"
        ] = "automatic_same_key"
        unsigned = {
            key: value
            for key, value in contracts.items()
            if key != "contracts_sha256"
        }
        contracts["contracts_sha256"] = canonical_sha256(unsigned)
        self.contracts_path.write_text(
            json.dumps(contracts),
            encoding="utf-8",
        )

        preflight = preflight_action_journal(
            self.journal_path,
            contracts,
        )
        completed = self.run_probe()

        self.assertFalse(preflight.valid)
        self.assertIn(
            "action_tool_spec_drift",
            {item["code"] for item in preflight.errors},
        )
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertIn("trusted ToolSpec", completed.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(self.journal_path.exists())

    def test_self_consistent_contract_cannot_forge_policy_grant(self) -> None:
        marker = self.run_dir / "forged-policy-ran"
        self._write_fixture(
            {
                "id": "command-step",
                "action": "command",
                "command": [
                    "node",
                    "-e",
                    f"require('fs').writeFileSync({str(marker)!r}, 'ran')",
                ],
            }
        )
        context = json.loads(
            self.context_path.read_text(encoding="utf-8")
        )
        context["semantic_summary"]["adapter"][
            "runtime_mode"
        ] = "production"
        unsigned_context = {
            key: value
            for key, value in context.items()
            if key != "context_sha256"
        }
        context["context_sha256"] = canonical_sha256(unsigned_context)
        self.context_path.write_text(
            json.dumps(context),
            encoding="utf-8",
        )
        contracts = json.loads(
            self.contracts_path.read_text(encoding="utf-8")
        )
        contracts["context_sha256"] = context["context_sha256"]
        item = contracts["actions"][0]
        item["authorization_sha256"] = canonical_sha256(
            {
                "run_id": contracts["run_id"],
                "generation": contracts["generation"],
                "iteration": contracts["iteration"],
                "scenario_id": item["scenario_id"],
                "step_id": item["step_id"],
                "action": item["action"],
                "plan_sha256": contracts["plan_sha256"],
                "context_sha256": contracts["context_sha256"],
                "plan_audit_sha256": contracts[
                    "plan_audit_sha256"
                ],
                "human_authorization_sha256": contracts[
                    "human_authorization_sha256"
                ],
                "tool_spec_sha256": item["tool_spec_sha256"],
                "raw_step_sha256": item["raw_step_sha256"],
                "resolution_policy_sha256": item[
                    "resolution_policy_sha256"
                ],
                "command_execution_binding_sha256": item[
                    "command_execution_binding"
                ]["binding_sha256"],
                "required_authorizations": item[
                    "required_authorizations"
                ],
                "granted_authorizations": item[
                    "granted_authorizations"
                ],
            }
        )
        unsigned_contracts = {
            key: value
            for key, value in contracts.items()
            if key != "contracts_sha256"
        }
        contracts["contracts_sha256"] = canonical_sha256(
            unsigned_contracts
        )
        self.contracts_path.write_text(
            json.dumps(contracts),
            encoding="utf-8",
        )

        preflight = preflight_action_journal(
            self.journal_path,
            contracts,
        )
        completed = self.run_probe()

        self.assertTrue(preflight.valid, preflight.errors)
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertIn("policy-authorized context", completed.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(self.journal_path.exists())

    def test_idempotency_key_binds_generation_and_iteration(self) -> None:
        first = self.run_probe()
        self.assertEqual(first.returncode, 0, first.stderr)
        first_event = json.loads(
            self.journal_path.read_text(encoding="utf-8").splitlines()[0]
        )
        contracts = build_action_contracts(
            self.plan_path,
            self.context_path,
            self.audit_path,
            run_id="run-action-protocol",
            generation=2,
            iteration=3,
        )
        self.contracts_path.write_text(
            json.dumps(contracts),
            encoding="utf-8",
        )
        self.journal_path.unlink()
        second = self.run_probe()
        self.assertEqual(second.returncode, 0, second.stderr)
        second_event = json.loads(
            self.journal_path.read_text(encoding="utf-8").splitlines()[0]
        )

        self.assertNotEqual(
            first_event["idempotency_key"],
            second_event["idempotency_key"],
        )
        self.assertEqual(second_event["generation"], 2)
        self.assertEqual(second_event["iteration"], 3)

    def test_timeout_over_toolspec_limit_has_no_side_effect(self) -> None:
        marker = self.run_dir / "timeout-boundary-ran"
        self._write_fixture(
            {
                "id": "command-step",
                "action": "command",
                "command": [
                    "node",
                    "-e",
                    f"require('fs').writeFileSync({str(marker)!r}, 'ran')",
                ],
                "timeoutMs": 300_001,
            }
        )

        completed = self.run_probe()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        results = json.loads(self.results_path.read_text(encoding="utf-8"))
        step = results["scenarios"][0]["steps"][0]
        self.assertEqual(step["status"], "failed")
        self.assertIn("timeout boundary", step["error"])
        self.assertFalse(marker.exists())
        events = [
            json.loads(line)
            for line in self.journal_path.read_text(
                encoding="utf-8"
            ).splitlines()
        ]
        self.assertEqual(events, [])

    def test_runtime_rechecks_destructive_command_after_audit(self) -> None:
        marker = self.run_dir / "destructive-command-ran"
        disposable = self.run_dir / "disposable"
        disposable.mkdir()
        self._write_fixture(
            {
                "id": "command-step",
                "action": "command",
                "command": [
                    "sh",
                    "-lc",
                    f"touch {marker}; rm -rf {disposable}",
                ],
            }
        )

        completed = self.run_probe()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        results = json.loads(self.results_path.read_text(encoding="utf-8"))
        step = results["scenarios"][0]["steps"][0]
        self.assertEqual(step["status"], "failed")
        self.assertIn("destructive command boundary", step["error"])
        self.assertFalse(marker.exists())
        self.assertTrue(disposable.exists())
        self.assertEqual(
            self.journal_path.read_text(encoding="utf-8"),
            "",
        )


if __name__ == "__main__":
    unittest.main()
