"""计划契约、脚手架建模与预检回归夹具。"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .code_pr import run_code_pr_scaffold_fixture
from .source_coverage import run_unmapped_source_allow_gate_fixture
from .support import (
    CN_RESPONSIVE_UI_CONTEXT_REQUIREMENT,
    GRAPHQL_ROOT_ENDPOINT_REQUIREMENT,
    JSON_EXTENSION_API_REQUIREMENT,
    PUBLIC_JSON_ENDPOINT_REQUIREMENT,
    SAME_ROUTE_UI_ACTION_CONTEXT_RESET_REQUIREMENT,
    STALE_API_CONTEXT_RESET_REQUIREMENT,
    VALID_PNG_1X1,
    VERSIONED_API_ENDPOINT_REQUIREMENT,
    assert_true,
    load_json,
    run_cmd,
    write_json,
    write_valid_skip_probe_plan,
)

__all__ = [
    "run_code_pr_scaffold_fixture",
    "run_unmapped_source_allow_gate_fixture",
]


def run_command_prerequisite_validation_fixture(script_dir: Path, tmp_path: Path) -> None:
    prereq_dir = tmp_path / "command-prerequisite-validation"
    prereq_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        prereq_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {"id": "R-cwd", "text": "Command cwd must exist before execution.", "test_ids": ["T-cwd"], "status": "Untested"},
                {"id": "R-mypy", "text": "Mypy config must exist before execution.", "test_ids": ["T-mypy"], "status": "Untested"},
                {"id": "R-mypy-module", "text": "Python module mypy config must exist before execution.", "test_ids": ["T-mypy-module"], "status": "Untested"},
                {"id": "R-mypy-wrapper", "text": "Wrapper-run mypy config must exist before execution.", "test_ids": ["T-mypy-wrapper-uv", "T-mypy-wrapper-poetry"], "status": "Untested"},
                {"id": "R-mypy-env", "text": "Environment-prefixed mypy config must exist before execution.", "test_ids": ["T-mypy-env"], "status": "Untested"},
                {"id": "R-mypy-env-command", "text": "env-command-prefixed mypy config must exist before execution.", "test_ids": ["T-mypy-env-command"], "status": "Untested"},
                {"id": "R-mypy-env-unset", "text": "env-unset-prefixed mypy config must exist before execution.", "test_ids": ["T-mypy-env-unset"], "status": "Untested"},
                {"id": "R-mypy-cross-env", "text": "cross-env-prefixed mypy config must exist before execution.", "test_ids": ["T-mypy-cross-env"], "status": "Untested"},
                {"id": "R-mypy-cross-env-runner-wrapper", "text": "package-runner cross-env-prefixed mypy config must exist before execution.", "test_ids": ["T-mypy-cross-env-runner-wrapper"], "status": "Untested"},
                {"id": "R-fixture", "text": "DB fixture file must exist before execution.", "test_ids": ["T-fixture"], "status": "Untested"},
            ],
            "tests": [
                {"id": "T-cwd", "requirement_ids": ["R-cwd"], "type": "command", "expected": "Command cwd is available.", "status": "Untested"},
                {"id": "T-mypy", "requirement_ids": ["R-mypy"], "type": "command", "expected": "Mypy config is available.", "status": "Untested"},
                {"id": "T-mypy-module", "requirement_ids": ["R-mypy-module"], "type": "command", "expected": "Python module mypy config is available.", "status": "Untested"},
                {"id": "T-mypy-wrapper-uv", "requirement_ids": ["R-mypy-wrapper"], "type": "command", "expected": "uv-run mypy config is available.", "status": "Untested"},
                {"id": "T-mypy-wrapper-poetry", "requirement_ids": ["R-mypy-wrapper"], "type": "command", "expected": "poetry-run mypy config is available.", "status": "Untested"},
                {"id": "T-mypy-env", "requirement_ids": ["R-mypy-env"], "type": "command", "expected": "Environment-prefixed mypy config is available.", "status": "Untested"},
                {"id": "T-mypy-env-command", "requirement_ids": ["R-mypy-env-command"], "type": "command", "expected": "env-command-prefixed mypy config is available.", "status": "Untested"},
                {"id": "T-mypy-env-unset", "requirement_ids": ["R-mypy-env-unset"], "type": "command", "expected": "env-unset-prefixed mypy config is available.", "status": "Untested"},
                {"id": "T-mypy-cross-env", "requirement_ids": ["R-mypy-cross-env"], "type": "command", "expected": "cross-env-prefixed mypy config is available.", "status": "Untested"},
                {"id": "T-mypy-cross-env-runner-wrapper", "requirement_ids": ["R-mypy-cross-env-runner-wrapper"], "type": "command", "expected": "package-runner cross-env-prefixed mypy config is available.", "status": "Untested"},
                {"id": "T-fixture", "requirement_ids": ["R-fixture"], "type": "command", "expected": "DB fixture is available.", "status": "Untested"},
            ],
        },
    )
    write_json(
        prereq_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(prereq_dir),
            "scenarios": [
                {
                    "id": "command-prerequisites",
                    "steps": [
                        {
                            "action": "command",
                            "id": "missing-cwd",
                            "testIds": ["T-cwd"],
                            "requirementIds": ["R-cwd"],
                            "command": [sys.executable, "-c", "print('ok')"],
                            "cwd": "missing-subdir",
                            "evidenceType": "command",
                            "proves": "Command runs from the project test cwd.",
                        },
                        {
                            "action": "command",
                            "id": "missing-mypy-config",
                            "testIds": ["T-mypy"],
                            "requirementIds": ["R-mypy"],
                            "command": ["mypy", "--config-file", "missing-mypy.ini", "src"],
                            "evidenceType": "static_analysis",
                            "proves": "Mypy runs with the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-python-module-mypy-config",
                            "testIds": ["T-mypy-module"],
                            "requirementIds": ["R-mypy-module"],
                            "command": [sys.executable, "-m", "mypy", "--config-file", "missing-module-mypy.ini", "src"],
                            "evidenceType": "static_analysis",
                            "proves": "Python module mypy runs with the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-uv-run-mypy-config",
                            "testIds": ["T-mypy-wrapper-uv"],
                            "requirementIds": ["R-mypy-wrapper"],
                            "command": ["uv", "run", "mypy", "--config-file", "missing-uv-mypy.ini", "src"],
                            "evidenceType": "static_analysis",
                            "proves": "uv run mypy uses the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-poetry-run-mypy-config",
                            "testIds": ["T-mypy-wrapper-poetry"],
                            "requirementIds": ["R-mypy-wrapper"],
                            "command": ["poetry", "run", "mypy", "--config-file", "missing-poetry-mypy.ini", "src"],
                            "evidenceType": "static_analysis",
                            "proves": "poetry run mypy uses the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-env-python-module-mypy-config",
                            "testIds": ["T-mypy-env"],
                            "requirementIds": ["R-mypy-env"],
                            "command": "PYTHONPATH=src python -m mypy --config-file missing-env-mypy.ini src",
                            "evidenceType": "static_analysis",
                            "proves": "Environment-prefixed python module mypy uses the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-env-command-python-module-mypy-config",
                            "testIds": ["T-mypy-env-command"],
                            "requirementIds": ["R-mypy-env-command"],
                            "command": "env PYTHONPATH=src python -m mypy --config-file missing-env-command-mypy.ini src",
                            "evidenceType": "static_analysis",
                            "proves": "env-command-prefixed python module mypy uses the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-env-unset-python-module-mypy-config",
                            "testIds": ["T-mypy-env-unset"],
                            "requirementIds": ["R-mypy-env-unset"],
                            "command": "env -u NODE_OPTIONS python -m mypy --config-file missing-env-unset-mypy.ini src",
                            "evidenceType": "static_analysis",
                            "proves": "env-unset-prefixed python module mypy uses the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-cross-env-python-module-mypy-config",
                            "testIds": ["T-mypy-cross-env"],
                            "requirementIds": ["R-mypy-cross-env"],
                            "command": "cross-env PYTHONPATH=src python -m mypy --config-file missing-cross-env-mypy.ini src",
                            "evidenceType": "static_analysis",
                            "proves": "cross-env-prefixed python module mypy uses the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-npx-cross-env-python-module-mypy-config",
                            "testIds": ["T-mypy-cross-env-runner-wrapper"],
                            "requirementIds": ["R-mypy-cross-env-runner-wrapper"],
                            "command": "npx cross-env PYTHONPATH=src python -m mypy --config-file missing-npx-cross-env-mypy.ini src",
                            "evidenceType": "static_analysis",
                            "proves": "npx cross-env-prefixed python module mypy uses the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-fixture",
                            "testIds": ["T-fixture"],
                            "requirementIds": ["R-fixture"],
                            "command": [sys.executable, "-c", "print('ok')"],
                            "requiredFiles": ["tests/fixtures/db_seed.json"],
                            "evidenceType": "persistence",
                            "proves": "Persistence command has the DB fixture it needs.",
                        },
                    ],
                }
            ],
        },
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "validate_plan.py"),
            "--plan",
            str(prereq_dir / "test-plan.json"),
            "--matrix",
            str(prereq_dir / "test-matrix.json"),
            "--summary",
            str(prereq_dir / "plan-audit-summary.json"),
        ],
        cwd=prereq_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "missing command cwd/config/fixtures should block plan validation before execution.")
    summary = load_json(prereq_dir / "plan-audit-summary.json")
    errors = "\n".join(summary.get("errors", []))
    assert_true("cwd path does not exist" in errors, "validate_plan should report a missing command cwd.")
    assert_true("mypy config file does not exist" in errors, "validate_plan should report a missing mypy config file.")
    assert_true(errors.count("mypy config file does not exist") >= 9, "validate_plan should report missing mypy configs for direct, python -m mypy, wrapper-run, environment-prefixed, env-command-prefixed, env-unset-prefixed, direct cross-env, and package-runner cross-env-prefixed mypy commands.")
    assert_true("required file does not exist" in errors, "validate_plan should report missing command fixture files.")
    assert_true("Traceback" not in proc.stderr, "missing command prerequisites should report without a Python traceback.")


def run_storage_state_validation_fixture(script_dir: Path, tmp_path: Path) -> None:
    state_dir = tmp_path / "storage-state-validation"
    state_dir.mkdir(parents=True, exist_ok=True)
    valid_state = state_dir / "auth-state.json"
    valid_state.write_text(json.dumps({"cookies": [], "origins": []}, indent=2), encoding="utf-8")
    bad_state = state_dir / "bad-state.json"
    bad_state.write_text("{not-json", encoding="utf-8")
    dir_state = state_dir / "state-dir"
    dir_state.mkdir()

    matrix = {
        "schemaVersion": 2,
        "requirements": [
            {
                "id": "R-auth",
                "text": "Authenticated browser checks must fail during planning when the storage state is unavailable.",
                "test_ids": ["T-auth"],
            }
        ],
        "tests": [
            {
                "id": "T-auth",
                "requirement_ids": ["R-auth"],
                "type": "permission",
                "expected": "Plan validation confirms auth storage state before browser execution.",
            }
        ],
    }

    def plan_with(storage_state: Any, *, context_options: bool = False) -> dict[str, Any]:
        plan: dict[str, Any] = {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "scenarios": [
                {
                    "id": "auth",
                    "steps": [
                        {
                            "action": "goto",
                            "id": "T-auth-open",
                            "testIds": ["T-auth"],
                            "requirementIds": ["R-auth"],
                            "path": "/",
                            "evidenceType": "ui_assertion",
                            "proves": "The authenticated entry point is reachable when login state exists.",
                        }
                    ],
                }
            ],
        }
        if context_options:
            plan["contextOptions"] = {"storageState": storage_state}
        else:
            plan["storageState"] = storage_state
        return plan

    def run_case(name: str, plan: dict[str, Any], *, env: dict[str, str] | None = None) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        case_dir = state_dir / name
        case_dir.mkdir(parents=True, exist_ok=True)
        write_json(case_dir / "test-plan.json", plan)
        write_json(case_dir / "test-matrix.json", matrix)
        proc = subprocess.run(
            [
                sys.executable,
                str(script_dir / "validate_plan.py"),
                "--plan",
                str(case_dir / "test-plan.json"),
                "--matrix",
                str(case_dir / "test-matrix.json"),
                "--summary",
                str(case_dir / "plan-audit-summary.json"),
            ],
            cwd=case_dir,
            env=env or os.environ.copy(),
            text=True,
            capture_output=True,
        )
        assert_true((case_dir / "plan-audit-summary.json").exists(), f"{name} should write plan-audit-summary.json.")
        return proc, load_json(case_dir / "plan-audit-summary.json")

    valid_proc, valid_summary = run_case("valid-file", plan_with(str(valid_state)))
    assert_true(valid_proc.returncode == 0, "validate_plan should accept an existing JSON storageState file.")
    assert_true(valid_summary.get("storage_state_check_count") == 1, "valid storageState file should be counted as checked.")

    env_proc, env_summary = run_case(
        "valid-env",
        plan_with({"env": "QA_STORAGE_STATE_PATH"}, context_options=True),
        env={**os.environ.copy(), "QA_STORAGE_STATE_PATH": str(valid_state)},
    )
    assert_true(env_proc.returncode == 0, "validate_plan should accept a storageState path supplied through an env reference.")
    assert_true(env_summary.get("storage_state_check_count") == 1, "env storageState should be counted as checked.")

    inline_cookie_proc, inline_cookie_summary = run_case(
        "inline-storage-state-cookie",
        plan_with(
            {
                "cookies": [
                    {
                        "name": "sid",
                        "value": "fixture-session",
                        "domain": "127.0.0.1",
                        "path": "/",
                    }
                ],
                "origins": [],
            }
        ),
    )
    assert_true(inline_cookie_proc.returncode != 0, "inline storageState cookies should block plan validation.")
    assert_true(any("storageState embeds cookies/origins directly" in error for error in inline_cookie_summary.get("errors", [])), "inline storageState cookies should produce a specific file-path requirement error.")

    inline_origin_proc, inline_origin_summary = run_case(
        "inline-storage-state-origin",
        plan_with(
            {
                "cookies": [],
                "origins": [
                    {
                        "origin": "http://127.0.0.1:9527",
                        "localStorage": [{"name": "oc_token", "value": "fixture-token"}],
                    }
                ],
            }
        ),
    )
    assert_true(inline_origin_proc.returncode != 0, "inline storageState origins should block plan validation.")
    assert_true(any("storageState embeds cookies/origins directly" in error for error in inline_origin_summary.get("errors", [])), "inline storageState origins should produce a specific file-path requirement error.")

    def plan_with_step(step: dict[str, Any]) -> dict[str, Any]:
        plan = plan_with(str(valid_state))
        plan["scenarios"][0]["steps"] = [step]
        return plan

    direct_local_storage_proc, direct_local_storage_summary = run_case(
        "direct-local-storage-token",
        plan_with_step(
            {
                "action": "setLocalStorage",
                "id": "T-auth-local-storage",
                "testIds": ["T-auth"],
                "requirementIds": ["R-auth"],
                "path": "/",
                "values": {"oc_token": "fixture-token"},
                "evidenceType": "auth_setup",
                "proves": "The browser receives auth setup.",
            }
        ),
    )
    assert_true(direct_local_storage_proc.returncode != 0, "direct auth-like localStorage values should block plan validation.")
    assert_true(any("setLocalStorage.oc_token writes auth-like material directly" in error for error in direct_local_storage_summary.get("errors", [])), "direct localStorage token should produce a specific auth-material error.")

    env_local_storage_proc, _ = run_case(
        "env-local-storage-token",
        plan_with_step(
            {
                "action": "setLocalStorage",
                "id": "T-auth-local-storage-env",
                "testIds": ["T-auth"],
                "requirementIds": ["R-auth"],
                "path": "/",
                "values": {"oc_token": {"env": "QA_DIRECT_TOKEN"}},
                "evidenceType": "auth_setup",
                "proves": "The browser receives auth setup through an environment reference.",
            }
        ),
        env={**os.environ.copy(), "QA_DIRECT_TOKEN": "fixture-token"},
    )
    assert_true(env_local_storage_proc.returncode == 0, "env-referenced localStorage auth setup should pass validation.")

    direct_default_header_plan = plan_with(str(valid_state))
    direct_default_header_plan["defaultHeaders"] = {"Authorization": "Bearer fixture-token"}
    direct_default_header_proc, direct_default_header_summary = run_case("direct-default-header", direct_default_header_plan)
    assert_true(direct_default_header_proc.returncode != 0, "direct auth-like default headers should block plan validation.")
    assert_true(any("plan.defaultHeaders.Authorization writes auth-like header material directly" in error for error in direct_default_header_summary.get("errors", [])), "direct Authorization header should produce a specific auth-material error.")

    env_default_header_plan = plan_with(str(valid_state))
    env_default_header_plan["defaultHeaders"] = {"Authorization": {"env": "QA_AUTH_HEADER", "prefix": "Bearer "}}
    env_default_header_proc, _ = run_case(
        "env-default-header",
        env_default_header_plan,
        env={**os.environ.copy(), "QA_AUTH_HEADER": "fixture-token"},
    )
    assert_true(env_default_header_proc.returncode == 0, "env-referenced auth-like default headers should pass validation.")

    direct_runtime_var_plan = plan_with(str(valid_state))
    direct_runtime_var_plan["runtimeVars"] = {"auth_token": "fixture-token"}
    direct_runtime_var_plan["scenarios"][0]["steps"] = [
        {
            "action": "api",
            "id": "T-auth-api-runtime-token",
            "testIds": ["T-auth"],
            "requirementIds": ["R-auth"],
            "method": "GET",
            "path": "/api/me",
            "headers": {"Authorization": {"var": "auth_token", "prefix": "Bearer "}},
            "evidenceType": "api_response",
            "proves": "The API request carries authenticated state from a runtime variable.",
        }
    ]
    direct_runtime_var_proc, direct_runtime_var_summary = run_case("direct-runtime-var-token", direct_runtime_var_plan)
    assert_true(direct_runtime_var_proc.returncode != 0, "direct auth-like runtime variables should block plan validation.")
    assert_true(any("plan.runtimeVars.auth_token writes auth-like runtime material directly" in error for error in direct_runtime_var_summary.get("errors", [])), "direct auth-like runtime var should produce a specific auth-material error.")

    env_runtime_var_plan = plan_with(str(valid_state))
    env_runtime_var_plan["runtimeVars"] = {"auth_token": {"env": "QA_RUNTIME_AUTH_TOKEN"}}
    env_runtime_var_plan["scenarios"][0]["steps"] = [
        {
            "action": "api",
            "id": "T-auth-api-runtime-token-env",
            "testIds": ["T-auth"],
            "requirementIds": ["R-auth"],
            "method": "GET",
            "path": "/api/me",
            "headers": {"Authorization": {"var": "auth_token", "prefix": "Bearer "}},
            "evidenceType": "api_response",
            "proves": "The API request carries authenticated state from an environment-backed runtime variable.",
        }
    ]
    env_runtime_var_proc, _ = run_case(
        "env-runtime-var-token",
        env_runtime_var_plan,
        env={**os.environ.copy(), "QA_RUNTIME_AUTH_TOKEN": "fixture-token"},
    )
    assert_true(env_runtime_var_proc.returncode == 0, "env-referenced auth-like runtime variables should pass validation.")

    direct_runtime_session_id_plan = plan_with(str(valid_state))
    direct_runtime_session_id_plan["runtimeVars"] = {"session_id": "fixture-session-id"}
    direct_runtime_session_id_plan["scenarios"][0]["steps"] = [
        {
            "action": "api",
            "id": "T-auth-api-session-id",
            "testIds": ["T-auth"],
            "requirementIds": ["R-auth"],
            "method": "GET",
            "pathTemplate": "/api/sessions/{session_id}",
            "evidenceType": "api_response",
            "proves": "The API probe can reuse a non-secret session object id.",
        }
    ]
    direct_runtime_session_id_proc, _ = run_case("direct-runtime-session-id", direct_runtime_session_id_plan)
    assert_true(direct_runtime_session_id_proc.returncode == 0, "direct non-secret session_id runtime variables should pass validation.")

    direct_api_json_secret_proc, direct_api_json_secret_summary = run_case(
        "direct-api-json-password",
        plan_with_step(
            {
                "action": "api",
                "id": "T-auth-api-json-password",
                "testIds": ["T-auth"],
                "requirementIds": ["R-auth"],
                "method": "POST",
                "path": "/api/login",
                "json": {"username": "qa-user", "password": "fixture-password"},
                "evidenceType": "api_response",
                "proves": "The API request submits login material.",
            }
        ),
    )
    assert_true(direct_api_json_secret_proc.returncode != 0, "direct auth-like API JSON values should block plan validation.")
    assert_true(any(".json.password writes auth-like material directly" in error for error in direct_api_json_secret_summary.get("errors", [])), "direct API JSON password should produce a specific auth-material error.")

    env_api_json_secret_proc, _ = run_case(
        "env-api-json-password",
        plan_with_step(
            {
                "action": "api",
                "id": "T-auth-api-json-password-env",
                "testIds": ["T-auth"],
                "requirementIds": ["R-auth"],
                "method": "POST",
                "path": "/api/login",
                "json": {"username": "qa-user", "password": {"env": "QA_API_PASSWORD"}},
                "evidenceType": "api_response",
                "proves": "The API request submits login material through an environment reference.",
            }
        ),
        env={**os.environ.copy(), "QA_API_PASSWORD": "fixture-password"},
    )
    assert_true(env_api_json_secret_proc.returncode == 0, "env-referenced auth-like API JSON values should pass validation.")

    direct_command_env_proc, direct_command_env_summary = run_case(
        "direct-command-env-api-key",
        plan_with_step(
            {
                "action": "command",
                "id": "T-auth-command-env",
                "testIds": ["T-auth"],
                "requirementIds": ["R-auth"],
                "command": ["python3", "-c", "print('ok')"],
                "env": {"API_KEY": "fixture-key"},
                "evidenceType": "command",
                "proves": "The command receives auth setup.",
            }
        ),
    )
    assert_true(direct_command_env_proc.returncode != 0, "direct auth-like command env values should block plan validation.")
    assert_true(any(".env.API_KEY writes auth-like material directly" in error for error in direct_command_env_summary.get("errors", [])), "direct command env API key should produce a specific auth-material error.")

    direct_step_header_proc, direct_step_header_summary = run_case(
        "direct-step-cookie-header",
        plan_with_step(
            {
                "action": "api",
                "id": "T-auth-api-cookie",
                "testIds": ["T-auth"],
                "requirementIds": ["R-auth"],
                "method": "GET",
                "path": "/api/me",
                "headers": {"Cookie": "sid=fixture-session"},
                "evidenceType": "api_response",
                "proves": "The API request carries authenticated state.",
            }
        ),
    )
    assert_true(direct_step_header_proc.returncode != 0, "direct auth-like step headers should block plan validation.")
    assert_true(any("headers.Cookie writes auth-like header material directly" in error for error in direct_step_header_summary.get("errors", [])), "direct Cookie step header should produce a specific auth-material error.")

    direct_cookie_proc, direct_cookie_summary = run_case(
        "direct-cookie",
        plan_with_step(
            {
                "action": "addCookies",
                "id": "T-auth-cookie",
                "testIds": ["T-auth"],
                "requirementIds": ["R-auth"],
                "cookies": [{"name": "sid", "value": "fixture-session", "domain": "127.0.0.1", "path": "/"}],
                "evidenceType": "auth_setup",
                "proves": "The browser receives a session cookie.",
            }
        ),
    )
    assert_true(direct_cookie_proc.returncode != 0, "direct session cookie values should block plan validation.")
    assert_true(any("addCookies cookie sid writes auth-like material directly" in error for error in direct_cookie_summary.get("errors", [])), "direct session cookie should produce a specific auth-material error.")

    missing_proc, missing_summary = run_case("missing-file", plan_with("missing-auth-state.json"))
    assert_true(missing_proc.returncode != 0, "missing storageState file should block plan validation.")
    assert_true(any("storageState file does not exist" in error for error in missing_summary.get("errors", [])), "missing storageState should produce a specific setup error.")

    dir_proc, dir_summary = run_case("directory", plan_with(str(dir_state)))
    assert_true(dir_proc.returncode != 0, "directory-shaped storageState should block plan validation.")
    assert_true(any("storageState path is a directory" in error for error in dir_summary.get("errors", [])), "directory storageState should be classified before Playwright execution.")

    bad_proc, bad_summary = run_case("bad-json", plan_with(str(bad_state)))
    assert_true(bad_proc.returncode != 0, "invalid JSON storageState should block plan validation.")
    assert_true(any("storageState file is not valid JSON" in error for error in bad_summary.get("errors", [])), "bad storageState JSON should be classified by validate_plan.")
    assert_true("Traceback" not in bad_proc.stderr, "bad storageState should report without a traceback.")

    cycle_dir = state_dir / "cycle-missing-file"
    cycle_dir.mkdir(parents=True, exist_ok=True)
    write_json(cycle_dir / "test-plan.json", plan_with("missing-auth-state.json"))
    write_json(cycle_dir / "test-matrix.json", matrix)
    cycle_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(cycle_dir),
            "--skip-probe",
        ],
        cwd=cycle_dir,
        text=True,
        capture_output=True,
    )
    assert_true(cycle_proc.returncode != 0, "missing storageState should stop the QA cycle before probe execution.")
    cycle_summary = load_json(cycle_dir / "qa-run-summary.json")
    cycle_verdict = load_json(cycle_dir / "qa-verdict.json")
    cycle_codes = {reason.get("code") for reason in cycle_verdict.get("reasons", [])}
    assert_true(cycle_summary.get("status") == "blocked", "missing storageState cycle summary should be blocked.")
    assert_true(cycle_verdict.get("verdict") == "blocked", "missing storageState cycle verdict should be blocked.")
    assert_true("plan_validation_failed" in cycle_codes, "missing storageState should surface through plan_validation_failed in the final handoff.")


def run_requirement_coverage_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "requirement-coverage-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    requirement_path = input_dir / "requirement.md"
    matrix_path = input_dir / "test-matrix.json"
    summary_path = input_dir / "nested" / "requirement-coverage.json"
    requirement_path.write_text("- The QA loop must stop before probes when matrix coverage cannot be audited.\n", encoding="utf-8")
    matrix_path.write_text("[]", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(requirement_path),
            "--matrix",
            str(matrix_path),
            "--out",
            str(summary_path),
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "audit_requirement_coverage should exit non-zero for unreadable matrix artifacts.")
    assert_true(summary_path.exists(), "audit_requirement_coverage should write requirement-coverage.json even when inputs are unreadable.")
    summary = load_json(summary_path)
    input_errors = {item.get("name"): item.get("error") for item in summary.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(summary.get("passed") is False, "bad requirement coverage inputs must not pass.")
    assert_true(input_errors.get("matrix") == "json_root_not_object", "audit_requirement_coverage should classify non-object matrix JSON.")
    assert_true(summary.get("matrix_requirement_count") == 0, "bad matrix input should not synthesize matrix requirements.")
    assert_true(summary.get("covered_count") == 0, "bad matrix input should not synthesize covered source units.")
    assert_true("Traceback" not in proc.stderr, "audit_requirement_coverage should report bad inputs without a Python traceback.")




def run_json_extension_api_path_fixture(script_dir: Path, tmp_path: Path) -> None:
    cases = [
        ("json-extension-api-scaffold", JSON_EXTENSION_API_REQUIREMENT, "/api/v1/reports/export.json?range=last_7_days"),
        ("public-json-endpoint-scaffold", PUBLIC_JSON_ENDPOINT_REQUIREMENT, "/exports/report.json?tenant=acme"),
    ]
    for dirname, requirement, api_path in cases:
        run_dir = tmp_path / dirname
        run_dir.mkdir(parents=True, exist_ok=True)
        requirement_path = run_dir / "requirement.md"
        requirement_path.write_text(requirement, encoding="utf-8")

        run_cmd(
            [
                sys.executable,
                str(script_dir / "scaffold_requirement.py"),
                "--requirement-file",
                str(requirement_path),
                "--run-dir",
                str(run_dir),
                "--base-url",
                "http://127.0.0.1:9527",
            ],
            cwd=tmp_path,
        )
        plan = load_json(run_dir / "test-plan.json")
        matrix = load_json(run_dir / "test-matrix.json")
        business_model = load_json(run_dir / "business-model.json")
        oracle_model = load_json(run_dir / "oracle-model.json")
        steps = [
            step
            for scenario in plan.get("scenarios", [])
            for step in scenario.get("steps", [])
            if isinstance(step, dict)
        ]
        api_steps = [step for step in steps if step.get("action") == "api"]
        test_types = {test.get("type") for test in matrix.get("tests", []) if isinstance(test, dict)}
        oracle_text = json.dumps(oracle_model, ensure_ascii=False)

        assert_true(api_path in business_model.get("api_paths", []), "API paths ending in .json must remain product API paths in the business model.")
        assert_true(any(workflow.get("api_paths") == [api_path] for workflow in business_model.get("workflows", []) if isinstance(workflow, dict)), "Workflow API paths should retain .json API endpoints.")
        assert_true(any(step.get("path") == api_path for step in api_steps), "Scaffold should generate an API probe for .json API endpoints.")
        assert_true("api" in test_types and "download" in test_types and "runtime" in test_types, "JSON export requirements should preserve API/download/runtime test types.")
        assert_true("api_response" in oracle_text and "query_params" in oracle_text and "content_type" in oracle_text, "Oracle model should retain API evidence layers for .json endpoints.")


def run_graphql_root_endpoint_fixture(script_dir: Path, tmp_path: Path) -> None:
    run_dir = tmp_path / "graphql-root-endpoint-scaffold"
    run_dir.mkdir(parents=True, exist_ok=True)
    requirement_path = run_dir / "requirement.md"
    requirement_path.write_text(GRAPHQL_ROOT_ENDPOINT_REQUIREMENT, encoding="utf-8")

    run_cmd(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(requirement_path),
            "--run-dir",
            str(run_dir),
            "--base-url",
            "http://127.0.0.1:9527",
        ],
        cwd=tmp_path,
    )
    matrix = load_json(run_dir / "test-matrix.json")
    business_model = load_json(run_dir / "business-model.json")
    oracle_model = load_json(run_dir / "oracle-model.json")
    matrix_text = json.dumps(matrix, ensure_ascii=False)
    semantic_text = json.dumps({"business": business_model, "oracle": oracle_model}, ensure_ascii=False)
    test_types = {test.get("type") for test in matrix.get("tests", []) if isinstance(test, dict)}
    graph_layers = {
        layer
        for test in matrix.get("tests", [])
        if isinstance(test, dict) and test.get("type") == "graphql"
        for layer in test.get("required_evidence", [])
    }

    assert_true("/graphql" in business_model.get("api_paths", []), "Root /graphql should be retained as an API path.")
    assert_true("/graphql" not in business_model.get("entry_points", []), "Root /graphql should not be modeled as a UI entry point.")
    assert_true(any(workflow.get("api_paths") == ["/graphql"] for workflow in business_model.get("workflows", []) if isinstance(workflow, dict)), "GraphQL workflow should bind the root endpoint path.")
    assert_true("graphql" in test_types and "api" in test_types and "runtime" in test_types, "GraphQL root endpoint should preserve GraphQL/API/runtime test types.")
    assert_true({"graphql_operation", "graphql_variables", "api_response", "request body"}.issubset(graph_layers), "GraphQL query should require operation, variables, request body, and response evidence.")
    assert_true("field_authorization" in matrix_text and "graphql_errors" in matrix_text and "partial_data" in matrix_text, "GraphQL field denial should keep field-authorization and partial-error evidence.")
    for forbidden in ("graphql_mutation", "graphql_subscription", "persisted_query_hash", "query_params"):
        assert_true(forbidden not in semantic_text and forbidden not in graph_layers, f"Simple GraphQL query must not over-require {forbidden}.")


def run_versioned_api_endpoint_fixture(script_dir: Path, tmp_path: Path) -> None:
    api_path = "/v1/prices?plan=pro&region=us"
    run_dir = tmp_path / "versioned-api-endpoint-scaffold"
    run_dir.mkdir(parents=True, exist_ok=True)
    requirement_path = run_dir / "requirement.md"
    requirement_path.write_text(VERSIONED_API_ENDPOINT_REQUIREMENT, encoding="utf-8")

    run_cmd(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(requirement_path),
            "--run-dir",
            str(run_dir),
            "--base-url",
            "http://127.0.0.1:9527",
        ],
        cwd=tmp_path,
    )
    plan = load_json(run_dir / "test-plan.json")
    matrix = load_json(run_dir / "test-matrix.json")
    business_model = load_json(run_dir / "business-model.json")
    oracle_model = load_json(run_dir / "oracle-model.json")
    api_steps = [
        step
        for scenario in plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and step.get("action") == "api"
    ]
    test_types = {test.get("type") for test in matrix.get("tests", []) if isinstance(test, dict)}
    oracle_text = json.dumps(oracle_model, ensure_ascii=False)
    matrix_text = json.dumps(matrix, ensure_ascii=False)
    workflows_by_req = {
        tuple(workflow.get("source_requirement_ids", [])): workflow
        for workflow in business_model.get("workflows", [])
        if isinstance(workflow, dict)
    }
    tests_by_req: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for test in matrix.get("tests", []):
        if isinstance(test, dict):
            tests_by_req.setdefault(tuple(test.get("requirement_ids", [])), []).append(test)
    r2_tests = tests_by_req.get(("R2",), [])
    r3_tests = tests_by_req.get(("R3",), [])

    assert_true(api_path in business_model.get("api_paths", []), "Explicit non-/api API endpoint should be retained as an API path.")
    assert_true(api_path not in business_model.get("entry_points", []), "Explicit non-/api API endpoint should not become a UI entry point.")
    assert_true(any(workflow.get("api_paths") == [api_path] for workflow in business_model.get("workflows", []) if isinstance(workflow, dict)), "Versioned API workflow should bind the endpoint path.")
    assert_true(any(step.get("path") == api_path and step.get("method") == "GET" for step in api_steps), "Versioned API endpoint should generate a safe GET API probe.")
    assert_true("api" in test_types and "runtime" in test_types, "Versioned API endpoint should preserve API/runtime test types.")
    assert_true("query_params" in oracle_text and "content_type" in oracle_text and "api_response" in oracle_text, "Oracle model should retain query, content-type, and response evidence for versioned API endpoints.")
    assert_true(workflows_by_req.get(("R2",), {}).get("api_paths") == [api_path], "Response/header follow-up requirement should inherit the prior API endpoint.")
    assert_true(workflows_by_req.get(("R3",), {}).get("api_paths") == [api_path], "Forbidden response-field follow-up requirement should inherit the prior API endpoint.")
    assert_true(any(test.get("type") == "api" for test in r2_tests), "Response/header follow-up should remain an API test.")
    assert_true(any(test.get("type") == "api" for test in r3_tests), "Forbidden response-field follow-up should remain an API test.")
    assert_true(any(api_path in test.get("expected", "") for test in r2_tests), "R2 API test should name the inherited endpoint.")
    assert_true(any(api_path in test.get("expected", "") for test in r3_tests), "R3 API test should name the inherited endpoint.")
    assert_true(any("forbidden text absence" in test.get("required_evidence", []) for test in r3_tests), "R3 should require forbidden response-field absence evidence.")
    assert_true("GET <endpoint>" not in matrix_text, "Inherited API endpoint requirements must not fall back to GET <endpoint>.")


def run_cn_responsive_ui_context_fixture(script_dir: Path, tmp_path: Path) -> None:
    entry_path = "/dashboard"
    api_path = "/api/v1/widgets?tab=overview"
    run_dir = tmp_path / "cn-responsive-ui-context-scaffold"
    run_dir.mkdir(parents=True, exist_ok=True)
    requirement_path = run_dir / "requirement.md"
    requirement_path.write_text(CN_RESPONSIVE_UI_CONTEXT_REQUIREMENT, encoding="utf-8")

    run_cmd(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(requirement_path),
            "--run-dir",
            str(run_dir),
            "--base-url",
            "http://127.0.0.1:9527",
        ],
        cwd=tmp_path,
    )
    plan = load_json(run_dir / "test-plan.json")
    matrix = load_json(run_dir / "test-matrix.json")
    business_model = load_json(run_dir / "business-model.json")
    requirements_by_id = {
        req.get("id"): req
        for req in matrix.get("requirements", [])
        if isinstance(req, dict)
    }
    tests_by_req: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for test in matrix.get("tests", []):
        if isinstance(test, dict):
            tests_by_req.setdefault(tuple(test.get("requirement_ids", [])), []).append(test)
    workflows_by_req = {
        tuple(workflow.get("source_requirement_ids", [])): workflow
        for workflow in business_model.get("workflows", [])
        if isinstance(workflow, dict)
    }
    steps_by_req: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for scenario in plan.get("scenarios", []):
        for step in scenario.get("steps", []):
            if isinstance(step, dict):
                steps_by_req.setdefault(tuple(step.get("requirementIds", [])), []).append(step)

    r2_tests = tests_by_req.get(("R2",), [])
    r3_tests = tests_by_req.get(("R3",), [])
    r2_steps = steps_by_req.get(("R2",), [])
    r3_steps = steps_by_req.get(("R3",), [])

    assert_true(api_path in business_model.get("api_paths", []), "Chinese mixed UI/API requirement should retain the explicit API path.")
    assert_true(entry_path in business_model.get("entry_points", []), "Chinese mixed UI/API requirement should retain the explicit UI entry path.")
    assert_true(requirements_by_id.get("R2", {}).get("inherited_api_paths") in (None, []), "Responsive UI sentence must not inherit API context from 响应式.")
    assert_true(requirements_by_id.get("R2", {}).get("inherited_entry_points") == [entry_path], "Responsive UI sentence should inherit the preceding UI entry path.")
    assert_true(workflows_by_req.get(("R2",), {}).get("api_paths") == [], "Responsive UI workflow must not bind the API endpoint.")
    assert_true(workflows_by_req.get(("R2",), {}).get("entry_points") == [entry_path], "Responsive UI workflow should bind the inherited entry path.")
    assert_true(any(test.get("type") == "responsive" for test in r2_tests), "Responsive UI sentence should keep a responsive test.")
    assert_true(not any(test.get("type") == "api" for test in r2_tests), "Responsive UI sentence must not generate a direct API test.")
    assert_true(any(step.get("action") == "goto" and step.get("path") == entry_path for step in r2_steps), "Responsive UI sentence should generate UI navigation on the inherited entry path.")
    assert_true(requirements_by_id.get("R3", {}).get("inherited_api_paths") == [api_path], "Returned-data empty-state sentence should inherit the API endpoint.")
    assert_true(requirements_by_id.get("R3", {}).get("inherited_entry_points") == [entry_path], "Returned-data empty-state sentence should inherit the UI entry path.")
    assert_true(workflows_by_req.get(("R3",), {}).get("api_paths") == [api_path], "Empty-state workflow should bind the inherited API endpoint.")
    assert_true(workflows_by_req.get(("R3",), {}).get("entry_points") == [entry_path], "Empty-state workflow should bind the inherited UI entry path.")
    assert_true(any(test.get("type") == "api" for test in r3_tests), "Empty-state returned-data sentence should keep an API test.")
    assert_true(any(test.get("type") == "ui" for test in r3_tests), "Empty-state returned-data sentence should keep a UI test.")
    assert_true(any(step.get("action") == "api" and step.get("path") == api_path for step in r3_steps), "Empty-state sentence should generate an API probe for the inherited endpoint.")
    assert_true(any(step.get("action") == "goto" and step.get("path") == entry_path for step in r3_steps), "Empty-state sentence should generate UI navigation on the inherited entry path.")


def run_stale_api_context_reset_fixture(script_dir: Path, tmp_path: Path) -> None:
    old_api_path = "/api/v1/widgets?tab=overview"
    new_entry_path = "/settings/security"
    run_dir = tmp_path / "stale-api-context-reset-scaffold"
    run_dir.mkdir(parents=True, exist_ok=True)
    requirement_path = run_dir / "requirement.md"
    requirement_path.write_text(STALE_API_CONTEXT_RESET_REQUIREMENT, encoding="utf-8")

    run_cmd(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(requirement_path),
            "--run-dir",
            str(run_dir),
            "--base-url",
            "http://127.0.0.1:9527",
        ],
        cwd=tmp_path,
    )
    plan = load_json(run_dir / "test-plan.json")
    matrix = load_json(run_dir / "test-matrix.json")
    business_model = load_json(run_dir / "business-model.json")
    requirements_by_id = {
        req.get("id"): req
        for req in matrix.get("requirements", [])
        if isinstance(req, dict)
    }
    tests_by_req: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for test in matrix.get("tests", []):
        if isinstance(test, dict):
            tests_by_req.setdefault(tuple(test.get("requirement_ids", [])), []).append(test)
    workflows_by_req = {
        tuple(workflow.get("source_requirement_ids", [])): workflow
        for workflow in business_model.get("workflows", [])
        if isinstance(workflow, dict)
    }
    steps_by_req: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for scenario in plan.get("scenarios", []):
        for step in scenario.get("steps", []):
            if isinstance(step, dict):
                steps_by_req.setdefault(tuple(step.get("requirementIds", [])), []).append(step)

    r5_tests = tests_by_req.get(("R5",), [])
    r5_steps = steps_by_req.get(("R5",), [])
    matrix_text = json.dumps(matrix, ensure_ascii=False)

    assert_true(old_api_path in business_model.get("api_paths", []), "Initial mixed UI/API requirement should retain the explicit API path.")
    assert_true(new_entry_path in business_model.get("entry_points", []), "New UI page should be retained as an entry point.")
    assert_true(workflows_by_req.get(("R3",), {}).get("entry_points") == [new_entry_path], "New UI workflow should bind the explicit settings entry path.")
    assert_true(requirements_by_id.get("R5", {}).get("inherited_api_paths") in (None, []), "Response sentence after a different explicit UI page must not inherit the stale API endpoint.")
    assert_true(workflows_by_req.get(("R5",), {}).get("api_paths") == [], "Response sentence after a different UI page must not bind the stale API path.")
    assert_true(not any(test.get("type") == "api" for test in r5_tests), "Response sentence without a current endpoint must not generate a direct API test.")
    assert_true(not any(step.get("action") == "api" and step.get("path") == old_api_path for step in r5_steps), "Response sentence without a current endpoint must not generate a stale API probe.")
    assert_true(f"GET {old_api_path} satisfies requirement: The response must not include" not in matrix_text, "Matrix must not claim the stale API satisfies the later response-field requirement.")


def run_same_route_ui_action_context_reset_fixture(script_dir: Path, tmp_path: Path) -> None:
    old_api_path = "/api/v1/reports?range=7d"
    entry_path = "/reports"
    run_dir = tmp_path / "same-route-ui-action-context-reset-scaffold"
    run_dir.mkdir(parents=True, exist_ok=True)
    requirement_path = run_dir / "requirement.md"
    requirement_path.write_text(SAME_ROUTE_UI_ACTION_CONTEXT_RESET_REQUIREMENT, encoding="utf-8")

    run_cmd(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(requirement_path),
            "--run-dir",
            str(run_dir),
            "--base-url",
            "http://127.0.0.1:9527",
        ],
        cwd=tmp_path,
    )
    plan = load_json(run_dir / "test-plan.json")
    matrix = load_json(run_dir / "test-matrix.json")
    business_model = load_json(run_dir / "business-model.json")
    requirements_by_id = {
        req.get("id"): req
        for req in matrix.get("requirements", [])
        if isinstance(req, dict)
    }
    tests_by_req: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for test in matrix.get("tests", []):
        if isinstance(test, dict):
            tests_by_req.setdefault(tuple(test.get("requirement_ids", [])), []).append(test)
    workflows_by_req = {
        tuple(workflow.get("source_requirement_ids", [])): workflow
        for workflow in business_model.get("workflows", [])
        if isinstance(workflow, dict)
    }
    steps_by_req: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for scenario in plan.get("scenarios", []):
        for step in scenario.get("steps", []):
            if isinstance(step, dict):
                steps_by_req.setdefault(tuple(step.get("requirementIds", [])), []).append(step)

    r4_tests = tests_by_req.get(("R4",), [])
    r4_steps = steps_by_req.get(("R4",), [])
    matrix_text = json.dumps(matrix, ensure_ascii=False)

    assert_true(old_api_path in business_model.get("api_paths", []), "Initial mixed UI/API requirement should retain the explicit reports API path.")
    assert_true(entry_path in business_model.get("entry_points", []), "Reports page should be retained as an entry point.")
    assert_true(workflows_by_req.get(("R3",), {}).get("entry_points") == [entry_path], "Same-route UI action should bind the reports entry path.")
    assert_true(workflows_by_req.get(("R3",), {}).get("api_paths") == [], "Same-route UI-only action should not bind the previous API path.")
    assert_true(requirements_by_id.get("R4", {}).get("inherited_api_paths") in (None, []), "Response sentence after same-route UI-only action must not inherit the stale API endpoint.")
    assert_true(workflows_by_req.get(("R4",), {}).get("api_paths") == [], "Response sentence after same-route UI-only action must not bind the stale API path.")
    assert_true(not any(test.get("type") == "api" for test in r4_tests), "Response sentence without a current endpoint must not generate a direct API test after same-route UI-only action.")
    assert_true(not any(step.get("action") == "api" and step.get("path") == old_api_path for step in r4_steps), "Response sentence must not generate a stale same-route API probe.")
    assert_true(f"GET {old_api_path} satisfies requirement: The response must not include" not in matrix_text, "Matrix must not claim the stale same-route API satisfies the later response-field requirement.")


def run_gold_modeling_benchmark_fixture(script_dir: Path, tmp_path: Path) -> None:
    benchmark_spec = importlib.util.spec_from_file_location("modeling_benchmark", script_dir / "modeling_benchmark.py")
    assert_true(benchmark_spec is not None and benchmark_spec.loader is not None, "modeling benchmark module should be importable for threshold checks.")
    benchmark_module = importlib.util.module_from_spec(benchmark_spec)
    benchmark_spec.loader.exec_module(benchmark_module)
    synthetic_summary = benchmark_module.summarize(
        [
            {
                "id": "coverage-gap-hidden-by-overall",
                "scores": {
                    "modeling_accuracy_percent": 100.0,
                    "coverage_percent": 90.0,
                    "test_accuracy_percent": 100.0,
                    "overall_percent": 96.6,
                },
                "missing_expected_groups": [],
                "forbidden_expected_groups": [],
            }
        ],
        95.0,
    )
    assert_true(
        "coverage-gap-hidden-by-overall" in synthetic_summary.get("cases_below_target", []),
        "gold benchmark summary should flag a case when any individual score dimension is below target, even if overall remains above target.",
    )
    complete_test = {
        "id": "T1",
        "requirement_ids": ["R1"],
        "type": "api",
        "steps": [{"action": "api", "path": "/api/orders"}],
        "expected": "Order API returns 201.",
        "required_evidence": ["api_response"],
        "status": "Planned",
    }
    assert_true(
        benchmark_module.complete_test_definition_percent({"tests": [complete_test]}) == 100.0,
        "complete test definitions should score 100 when steps and required evidence are present.",
    )
    assert_true(
        benchmark_module.complete_test_definition_percent({"tests": [{key: value for key, value in complete_test.items() if key != "steps"}]}) < 100.0,
        "gold benchmark test-definition quality must penalize matrix tests that omit executable steps.",
    )
    assert_true(
        benchmark_module.complete_test_definition_percent({"tests": [{key: value for key, value in complete_test.items() if key != "required_evidence"}]}) < 100.0,
        "gold benchmark test-definition quality must penalize matrix tests that omit required evidence.",
    )

    benchmark_dir = tmp_path / "gold-modeling-benchmark"
    benchmark_dir.mkdir(parents=True, exist_ok=True)
    out_path = benchmark_dir / "modeling-benchmark.json"
    run_cmd(
        [
            sys.executable,
            str(script_dir / "modeling_benchmark.py"),
            "--work-dir",
            str(benchmark_dir / "runs"),
            "--out",
            str(out_path),
            "--target-percent",
            "95",
        ],
        cwd=benchmark_dir,
    )
    benchmark = load_json(out_path)
    summary = benchmark.get("summary") or {}
    assert_true(benchmark.get("passed") is True, "gold modeling benchmark should pass before claiming 95% modeling accuracy.")
    assert_true(summary.get("case_count", 0) >= 3, "gold modeling benchmark should cover multiple requirement styles.")
    assert_true(summary.get("modeling_accuracy_percent", 0) >= 95.0, "gold benchmark should measure modeling accuracy at or above 95%.")
    assert_true(summary.get("coverage_percent", 0) >= 95.0, "gold benchmark should measure requirement/test coverage at or above 95%.")
    assert_true(summary.get("test_accuracy_percent", 0) >= 95.0, "gold benchmark should measure test-definition accuracy at or above 95%.")
    assert_true(
        all((case.get("scores") or {}).get("overall_percent", 0) >= 95.0 for case in benchmark.get("cases", [])),
        "each gold benchmark case should individually meet the 95% threshold.",
    )
    score_fields = ("modeling_accuracy_percent", "coverage_percent", "test_accuracy_percent", "overall_percent")
    assert_true(
        all((case.get("scores") or {}).get(field, 0) >= 95.0 for case in benchmark.get("cases", []) for field in score_fields),
        "each gold benchmark case should individually meet the 95% threshold for every score dimension.",
    )


def run_qa_metrics_definition_quality_fixture(script_dir: Path, tmp_path: Path) -> None:
    scaffold_spec = importlib.util.spec_from_file_location("scaffold_requirement", script_dir / "scaffold_requirement.py")
    assert_true(scaffold_spec is not None and scaffold_spec.loader is not None, "scaffold module should be importable for qa metrics checks.")
    scaffold_module = importlib.util.module_from_spec(scaffold_spec)
    scaffold_spec.loader.exec_module(scaffold_module)
    tests = [
        {
            "id": "T1",
            "requirement_ids": ["R1"],
            "type": "api",
            "steps": ["Call GET /api/orders with a safe test tenant."],
            "expected": "Orders API returns 200.",
            "required_evidence": ["api_response"],
            "status": "Planned",
        },
        {
            "id": "T2",
            "requirement_ids": ["R1"],
            "type": "api",
            "expected": "Orders API returns order_id.",
            "required_evidence": ["response body"],
            "status": "Planned",
        },
        {
            "id": "T3",
            "requirement_ids": ["R1"],
            "type": "persistence",
            "steps": ["Read order status from a project-approved helper."],
            "expected": "Order persists completed status.",
            "status": "Planned",
        },
    ]
    metrics = scaffold_module.build_qa_metrics(
        [{"id": "R1", "text": "Orders API response and persistence must be verified.", "test_ids": ["T1", "T2", "T3"]}],
        tests,
        [{"action": "api", "testIds": ["T1"], "requirementIds": ["R1"]}],
        [],
        {
            "actors": [{"name": "authenticated user"}],
            "entities": [{"name": "order"}],
            "workflows": [{"label": "order lookup"}],
            "state_transitions": [],
            "business_rules": [],
            "agent_team_contract": {"qa_agent": {"consumes": ["test-matrix.json"]}},
            "entry_points": [],
            "api_paths": ["/api/orders"],
        },
        {
            "summary": {"evidence_layer_counts": {"api_response": 1}},
            "requirements": [
                {
                    "requirement_id": "R1",
                    "oracle_tests": ["Verify API response and persistence evidence."],
                    "required_evidence_layers": ["api_response", "persistence"],
                    "pass_rule": "Pass only with direct API and persistence evidence.",
                }
            ],
        },
    )
    quality_inputs = metrics.get("quality_inputs") or {}
    quality_scores = metrics.get("quality_scores") or {}
    assert_true(quality_inputs.get("complete_test_definition_count") == 1, "qa metrics should only count tests with steps and required_evidence as complete definitions.")
    assert_true(quality_scores.get("test_definition_quality_percent") == 33.3, "qa metrics should penalize missing steps or missing required evidence in test-definition quality.")




def run_stale_scaffold_summary_refresh_fixture(script_dir: Path, tmp_path: Path) -> None:
    stale_dir = tmp_path / "stale-scaffold-summary-refresh"
    stale_dir.mkdir(parents=True, exist_ok=True)
    (stale_dir / "requirement.md").write_text("- Current requirement needs a read-only helper.\n", encoding="utf-8")
    write_json(
        stale_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1",
                    "text": "Current requirement needs a read-only helper.",
                    "test_ids": ["T1"],
                    "status": "Blocked",
                    "notes": "Read-only helper is not configured.",
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "persistence",
                    "expected": "Read-only helper verifies current requirement.",
                    "status": "Blocked",
                    "notes": "Read-only helper is not configured.",
                }
            ],
        },
    )
    write_json(
        stale_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(stale_dir),
            "scenarios": [],
        },
    )
    write_json(
        stale_dir / "scaffold-summary.json",
        {
            "schema_version": 1,
            "status": "scaffolded",
            "coverage_gaps": [
                "R4: stale click-to-response probe needs a UI entry path.",
                "R24: stale persistence helper is missing.",
            ],
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "refresh_semantic_artifacts.py"),
            "--run-dir",
            str(stale_dir),
        ],
        cwd=stale_dir,
    )
    summary = load_json(stale_dir / "semantic-artifacts-summary.json")
    closeout = load_json(stale_dir / "closeout-candidates.json")
    candidate_text = "\n".join(str(item.get("text")) for item in closeout.get("qa_process_improvement_candidates", []) if isinstance(item, dict))
    assert_true("R4:" not in candidate_text and "R24:" not in candidate_text, "stale scaffold-summary gaps must not pollute refreshed closeout candidates.")
    assert_true("T1:" in candidate_text, "refresh should rebuild coverage gaps from the current matrix when scaffold-summary is stale.")
    assert_true(summary.get("summary", {}).get("coverage_gap_count") == 1, "semantic summary should count only current matrix-derived gaps.")
    assert_true(any(item.get("name") == "scaffold-summary" for item in summary.get("warnings", [])), "semantic summary should disclose that stale scaffold-summary gaps were ignored.")


def run_analytics_semantic_layer_filter_fixture(script_dir: Path, tmp_path: Path) -> None:
    analytics_dir = tmp_path / "analytics-semantic-layer-filter"
    analytics_dir.mkdir(parents=True, exist_ok=True)
    (analytics_dir / "requirement.md").write_text(
        "\n".join(
            [
                "# Analytics semantic layer fixture",
                "- Shopper opens /checkout and POST /api/v1/checkout returns order_id=ord_ana_123, transaction_id=tx_ana_123, status=paid.",
                "- The browser sends POST /api/v1/analytics/events with event_name=checkout_completed, event_id=evt_ana_123, schema_version=analytics_checkout_v5, consent_version=consent_v3, session_id=sess_ana_123, user_pseudonym_id=pseudo_ana_123, attribution_id=attr_ana_123, campaign_id=camp_qa_123, experiment_id=exp_checkout_2026, variant=treatment_b, dedupe_key=checkout_evt_ana_123, event_time=2026-07-01T12:00:00Z, and qa_marker.",
                "- The analytics request, stored analytics_event row, conversion row, logs, and report artifacts must not leak raw email, phone, shipping_address, card_last4, access_token, or cookie values; only user_pseudonym_id may identify the shopper.",
                "- If POST /api/v1/analytics/events returns 503, the analytics queue records retry_count=1, next_retry_at=2026-07-01T12:05:00Z, backoff_schedule=exponential, queue_status=pending_retry, and must not mark attribution_credit or experiment_exposure as committed until retry succeeds.",
            ]
        ),
        encoding="utf-8",
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(analytics_dir / "requirement.md"),
            "--run-dir",
            str(analytics_dir),
            "--base-url",
            "http://127.0.0.1:9527",
            "--entry-path",
            "/checkout",
        ],
        cwd=analytics_dir,
    )
    business_model = load_json(analytics_dir / "business-model.json")
    oracle_model = load_json(analytics_dir / "oracle-model.json")
    layers: set[str] = set()
    for workflow in business_model.get("workflows", []):
        if isinstance(workflow, dict):
            layers.update(str(layer) for layer in workflow.get("evidence_layers", []))
    for item in oracle_model.get("requirements", []):
        if isinstance(item, dict):
            layers.update(str(layer) for layer in item.get("required_evidence_layers", []))
    forbidden_layers = {
        "privacy_export",
        "export_artifact",
        "erasure_request",
        "legal_hold",
        "search_index_removal",
        "dead_letter",
        "worker_log",
        "background_worker",
        "artifact_generation",
        "offline_sync",
    }
    assert_true(not (layers & forbidden_layers), f"analytics semantic layers should not include cross-domain lifecycle/background layers: {sorted(layers & forbidden_layers)}")
    for required_layer in ("analytics", "analytics_event", "pii_redaction", "forbidden text absence", "retry_count", "queue_status"):
        assert_true(required_layer in layers, f"analytics semantic filtering must preserve required layer {required_layer}.")


def run_adapter_probe_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "adapter-probe-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    context_path = input_dir / "adapter-context.json"
    plan_path = input_dir / "test-plan.json"
    matrix_path = input_dir / "test-matrix.json"
    out_path = input_dir / "nested" / "adapter-probes.json"
    context_path.write_text("[]", encoding="utf-8")
    plan_path.mkdir()
    matrix_path.write_text("{not-json", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "synthesize_adapter_probes.py"),
            "--run-dir",
            str(input_dir),
            "--adapter-context",
            str(context_path),
            "--plan",
            str(plan_path),
            "--matrix",
            str(matrix_path),
            "--out",
            str(out_path),
            "--apply",
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "synthesize_adapter_probes should exit non-zero for unreadable input artifacts.")
    assert_true(out_path.exists(), "synthesize_adapter_probes should write adapter-probes.json even when inputs are unreadable.")
    report = load_json(out_path)
    input_errors = {item.get("name"): item.get("error") for item in report.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(input_errors.get("adapter_context") == "json_root_not_object", "synthesize_adapter_probes should classify non-object adapter contexts.")
    assert_true(input_errors.get("plan") == "path_is_directory", "synthesize_adapter_probes should classify directory-shaped plans.")
    assert_true(str(input_errors.get("matrix", "")).startswith("invalid_json"), "synthesize_adapter_probes should classify malformed matrices.")
    assert_true(report.get("summary", {}).get("input_artifact_error_count") == 3, "adapter-probes summary should count unreadable inputs.")
    assert_true(report.get("proposed_step_ids") == [] and report.get("added_step_ids") == [], "bad adapter-probe inputs should not synthesize or apply steps.")
    assert_true("Traceback" not in proc.stderr, "synthesize_adapter_probes should report bad inputs without a Python traceback.")


def run_preflight_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "preflight-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    context_path = input_dir / "adapter-context.json"
    plan_path = input_dir / "test-plan.json"
    out_path = input_dir / "nested" / "service-preflight.json"
    context_path.write_text("[]", encoding="utf-8")
    plan_path.mkdir()

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "preflight_runtime.py"),
            "--run-dir",
            str(input_dir),
            "--adapter-context",
            str(context_path),
            "--plan",
            str(plan_path),
            "--out",
            str(out_path),
            "--fail-on-blockers",
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "preflight_runtime should exit non-zero for unreadable input artifacts.")
    assert_true(out_path.exists(), "preflight_runtime should write service-preflight.json even when inputs are unreadable.")
    report = load_json(out_path)
    input_errors = {item.get("name"): item.get("error") for item in report.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(report.get("runnable") is False, "bad preflight inputs must not be runnable.")
    assert_true(input_errors.get("adapter_context") == "json_root_not_object", "preflight_runtime should classify non-object adapter contexts.")
    assert_true(input_errors.get("plan") == "path_is_directory", "preflight_runtime should classify directory-shaped plans.")
    assert_true(report.get("start_plan") == [], "bad preflight inputs should not synthesize a service start plan.")
    assert_true("Traceback" not in proc.stderr, "preflight_runtime should report bad inputs without a Python traceback.")


def run_preflight_missing_required_service_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "preflight-missing-required-service"
    input_dir.mkdir(parents=True, exist_ok=True)
    context_path = input_dir / "adapter-context.json"
    plan_path = input_dir / "test-plan.json"
    out_path = input_dir / "service-preflight.json"
    write_json(
        context_path,
        {
            "schema_version": 1,
            "adapter": "fixture",
            "project_root": str(input_dir),
            "base_url": "http://127.0.0.1:65527",
            "environment_boundary": {
                "runtime_mode": "test",
                "data_boundary_status": "fixture data only; no production data",
            },
            "services": [],
        },
    )
    write_json(
        plan_path,
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:65527",
            "artifactDir": str(input_dir),
            "scenarios": [],
        },
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "preflight_runtime.py"),
            "--run-dir",
            str(input_dir),
            "--adapter-context",
            str(context_path),
            "--plan",
            str(plan_path),
            "--out",
            str(out_path),
            "--required-service",
            "missing-api",
            "--fail-on-blockers",
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "preflight_runtime should block when an explicit required service id is absent from adapter context.")
    report = load_json(out_path)
    blockers = {(item.get("service"), item.get("reason")) for item in report.get("blockers", []) if isinstance(item, dict)}
    assert_true(report.get("runnable") is False, "missing explicit required services must not be runnable.")
    assert_true(("missing-api", "required service is not present in adapter context") in blockers, "preflight should name the missing required service id.")
    assert_true(report.get("start_plan") == [], "missing service definitions should not synthesize a start plan.")
    assert_true("Traceback" not in proc.stderr, "missing required services should report without a Python traceback.")


def run_generic_service_id_and_preflight_dependency_fixture(script_dir: Path, tmp_path: Path) -> None:
    fixture_dir = tmp_path / "generic-service-id-preflight"
    project_root = fixture_dir / "project"
    run_dir = fixture_dir / "run"
    project_root.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)
    (project_root / "package.json").write_text(
        json.dumps({"name": "fixture-node", "scripts": {"dev": "vite --host 127.0.0.1", "test": "vitest run"}}, indent=2),
        encoding="utf-8",
    )
    (project_root / "pyproject.toml").write_text("[project]\nname = \"fixture-python\"\nversion = \"0.1.0\"\n", encoding="utf-8")
    write_json(
        run_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "",
            "preflight": {
                "requiredPaths": [
                    {
                        "path": "tests/fixtures/db_seed.json",
                        "type": "file",
                        "reason": "DB fixture required for persistence checks.",
                    }
                ]
            },
            "scenarios": [],
        },
    )

    run_cmd(
        [
            sys.executable,
            str(script_dir / "discover_project_context.py"),
            "--project-root",
            str(project_root),
            "--run-dir",
            str(run_dir),
            "--runtime-mode",
            "test",
            "--data-boundary-status",
            "synthetic fixture data; no production data",
            "--no-http-probe",
        ],
        cwd=fixture_dir,
    )
    context = load_json(run_dir / "adapter-context.json")
    service_ids = {service.get("id") for service in context.get("services", []) if isinstance(service, dict)}
    assert_true("node-app" in service_ids, "root package.json should get a stable node-app service id instead of '.'.")
    assert_true("python-service" in service_ids, "root pyproject.toml should get a stable python-service id instead of colliding with node-app.")
    assert_true("." not in service_ids, "generic service ids should not use '.' for root services.")

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "preflight_runtime.py"),
            "--run-dir",
            str(run_dir),
            "--project-root",
            str(project_root),
            "--required-service",
            "node-app",
            "--allow-stopped-services",
            "--fail-on-blockers",
        ],
        cwd=fixture_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "missing local dependencies and fixture paths should block runtime preflight.")
    report = load_json(run_dir / "service-preflight.json")
    blocker_reasons = {item.get("reason") for item in report.get("blockers", []) if isinstance(item, dict)}
    assert_true("node dependencies are missing" in blocker_reasons, "preflight should report missing node_modules for required npm services.")
    assert_true("required plan path is missing" in blocker_reasons, "preflight should report missing plan-declared fixture/config paths.")
    assert_true(report.get("runnable") is False, "missing local dependencies should make preflight non-runnable.")
    assert_true("Traceback" not in proc.stderr, "preflight dependency blockers should report without a Python traceback.")


def run_preflight_command_prerequisite_fixture(script_dir: Path, tmp_path: Path) -> None:
    prereq_dir = tmp_path / "preflight-command-prerequisites"
    prereq_dir.mkdir(parents=True, exist_ok=True)
    (prereq_dir / "package.json").write_text(
        json.dumps({"name": "preflight-command-prereq", "scripts": {"lint": "eslint ."}}, indent=2),
        encoding="utf-8",
    )
    write_json(
        prereq_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "",
            "scenarios": [
                {
                    "id": "command-prerequisites",
                    "steps": [
                        {
                            "action": "command",
                            "id": "missing-cwd",
                            "command": [sys.executable, "-c", "print('ok')"],
                            "cwd": "missing-subdir",
                            "evidenceType": "command",
                            "proves": "Command runs from the planned cwd.",
                        },
                        {
                            "action": "command",
                            "id": "missing-mypy-config",
                            "command": ["mypy", "--config-file", "missing-mypy.ini", "src"],
                            "evidenceType": "static_analysis",
                            "proves": "Mypy runs with the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-python-module-mypy-config",
                            "command": [sys.executable, "-m", "mypy", "--config-file", "missing-module-mypy.ini", "src"],
                            "evidenceType": "static_analysis",
                            "proves": "Python module mypy runs with the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-uv-run-mypy-config",
                            "command": ["uv", "run", "mypy", "--config-file", "missing-uv-mypy.ini", "src"],
                            "evidenceType": "static_analysis",
                            "proves": "uv run mypy uses the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-poetry-run-mypy-config",
                            "command": ["poetry", "run", "mypy", "--config-file", "missing-poetry-mypy.ini", "src"],
                            "evidenceType": "static_analysis",
                            "proves": "poetry run mypy uses the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-env-python-module-mypy-config",
                            "command": "PYTHONPATH=src python -m mypy --config-file missing-env-mypy.ini src",
                            "evidenceType": "static_analysis",
                            "proves": "Environment-prefixed python module mypy uses the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-env-command-python-module-mypy-config",
                            "command": "env PYTHONPATH=src python -m mypy --config-file missing-env-command-mypy.ini src",
                            "evidenceType": "static_analysis",
                            "proves": "env-command-prefixed python module mypy uses the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-env-unset-python-module-mypy-config",
                            "command": "env -u NODE_OPTIONS python -m mypy --config-file missing-env-unset-mypy.ini src",
                            "evidenceType": "static_analysis",
                            "proves": "env-unset-prefixed python module mypy uses the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-cross-env-python-module-mypy-config",
                            "command": "cross-env PYTHONPATH=src python -m mypy --config-file missing-cross-env-mypy.ini src",
                            "evidenceType": "static_analysis",
                            "proves": "cross-env-prefixed python module mypy uses the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-npx-cross-env-python-module-mypy-config",
                            "command": "npx cross-env PYTHONPATH=src python -m mypy --config-file missing-npx-cross-env-mypy.ini src",
                            "evidenceType": "static_analysis",
                            "proves": "npx cross-env-prefixed python module mypy uses the project configuration.",
                        },
                        {
                            "action": "command",
                            "id": "missing-fixture",
                            "command": [sys.executable, "-c", "print('ok')"],
                            "requiredFiles": ["tests/fixtures/db_seed.json"],
                            "evidenceType": "persistence",
                            "proves": "Persistence command has the DB fixture it needs.",
                        },
                        {
                            "action": "command",
                            "id": "missing-executable",
                            "command": ["definitely-missing-aqa-command", "--version"],
                            "evidenceType": "command",
                            "proves": "The planned command executable is installed before execution.",
                        },
                        {
                            "action": "command",
                            "id": "missing-npm-test-script-and-node-modules",
                            "command": ["npm", "run", "test"],
                            "evidenceType": "command",
                            "proves": "The planned npm validation command has its script and local dependencies installed before execution.",
                        },
                    ],
                }
            ],
        },
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "preflight_runtime.py"),
            "--run-dir",
            str(prereq_dir),
            "--project-root",
            str(prereq_dir),
            "--fail-on-blockers",
        ],
        cwd=prereq_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "preflight should block command cwd/config/fixture prerequisites before execution.")
    report = load_json(prereq_dir / "service-preflight.json")
    blocker_reasons = "\n".join(str(item.get("reason")) for item in report.get("blockers", []) if isinstance(item, dict))
    assert_true("command cwd path is missing" in blocker_reasons, "preflight should report missing command cwd.")
    assert_true("mypy config file is missing" in blocker_reasons, "preflight should report missing mypy config.")
    assert_true(blocker_reasons.count("mypy config file is missing") >= 9, "preflight should report missing mypy configs for direct, python -m mypy, wrapper-run, environment-prefixed, env-command-prefixed, env-unset-prefixed, direct cross-env, and package-runner cross-env-prefixed mypy commands.")
    assert_true("required command path is missing" in blocker_reasons, "preflight should report missing command fixture paths.")
    assert_true("command executable is missing" in blocker_reasons, "preflight should report missing command executables.")
    assert_true("npm script is missing" in blocker_reasons, "preflight should report missing npm scripts for planned npm command steps.")
    assert_true("node dependencies are missing" in blocker_reasons, "preflight should report missing node_modules for planned npm command steps.")
    assert_true(
        not any(item.get("executable") == "PYTHONPATH=src" for item in report.get("blockers", []) if isinstance(item, dict)),
        "preflight should not treat leading environment assignments as missing command executables.",
    )
    assert_true(report.get("runnable") is False, "missing command prerequisites should make preflight non-runnable.")
    assert_true("Traceback" not in proc.stderr, "preflight command prerequisite blockers should report without a Python traceback.")

    workspace_dir = tmp_path / "preflight-package-manager-cwd"
    workspace_app_dir = workspace_dir / "apps" / "web"
    workspace_app_dir.mkdir(parents=True, exist_ok=True)
    (workspace_dir / "node_modules").mkdir()
    (workspace_dir / "package.json").write_text(
        json.dumps({"name": "workspace-root", "scripts": {"test": "echo root test"}, "workspaces": ["apps/*"]}, indent=2),
        encoding="utf-8",
    )
    (workspace_app_dir / "package.json").write_text(
        json.dumps({"name": "web", "scripts": {"lint": "echo web lint"}}, indent=2),
        encoding="utf-8",
    )
    write_json(
        workspace_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "",
            "scenarios": [
                {
                    "id": "package-manager-cwd-prerequisites",
                    "steps": [
                        {
                            "action": "command",
                            "id": "missing-npm-prefix-test-script",
                            "command": ["npm", "--prefix", "apps/web", "run", "test"],
                            "evidenceType": "command",
                            "proves": "npm --prefix checks the package script in the target package directory.",
                        },
                        {
                            "action": "command",
                            "id": "missing-pnpm-dir-test-script",
                            "command": ["pnpm", "--dir", "apps/web", "test"],
                            "evidenceType": "command",
                            "proves": "pnpm --dir checks the package script in the target package directory.",
                        },
                        {
                            "action": "command",
                            "id": "missing-yarn-cwd-test-script",
                            "command": ["yarn", "--cwd", "apps/web", "test"],
                            "evidenceType": "command",
                            "proves": "yarn --cwd checks the package script in the target package directory.",
                        },
                        {
                            "action": "command",
                            "id": "missing-corepack-pnpm-dir-test-script",
                            "command": ["corepack", "pnpm", "--dir", "apps/web", "test"],
                            "evidenceType": "command",
                            "proves": "corepack pnpm --dir checks the package script in the target package directory.",
                        },
                        {
                            "action": "command",
                            "id": "missing-corepack-yarn-cwd-test-script",
                            "command": ["corepack", "yarn", "--cwd", "apps/web", "test"],
                            "evidenceType": "command",
                            "proves": "corepack yarn --cwd checks the package script in the target package directory.",
                        },
                    ],
                }
            ],
        },
    )
    workspace_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "preflight_runtime.py"),
            "--run-dir",
            str(workspace_dir),
            "--project-root",
            str(workspace_dir),
            "--fail-on-blockers",
        ],
        cwd=workspace_dir,
        text=True,
        capture_output=True,
    )
    assert_true(workspace_proc.returncode != 0, "preflight should block missing package scripts in package-manager target directories.")
    workspace_report = load_json(workspace_dir / "service-preflight.json")
    missing_script_locations = {
        item.get("location")
        for item in workspace_report.get("blockers", [])
        if isinstance(item, dict) and item.get("reason") == "npm script is missing"
    }
    assert_true(
        {
            "package-manager-cwd-prerequisites.missing-npm-prefix-test-script",
            "package-manager-cwd-prerequisites.missing-pnpm-dir-test-script",
            "package-manager-cwd-prerequisites.missing-yarn-cwd-test-script",
            "package-manager-cwd-prerequisites.missing-corepack-pnpm-dir-test-script",
            "package-manager-cwd-prerequisites.missing-corepack-yarn-cwd-test-script",
        }.issubset(missing_script_locations),
        "preflight should resolve npm --prefix, pnpm --dir, yarn --cwd, and corepack-wrapped package-manager cwd options before checking package scripts.",
    )

    corepack_dir = tmp_path / "preflight-corepack-executable"
    corepack_app_dir = corepack_dir / "apps" / "web"
    corepack_bin_dir = corepack_dir / "bin"
    corepack_app_dir.mkdir(parents=True, exist_ok=True)
    corepack_bin_dir.mkdir(parents=True, exist_ok=True)
    (corepack_dir / "node_modules").mkdir()
    fake_corepack = corepack_bin_dir / "corepack"
    fake_corepack.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_corepack.chmod(0o755)
    (corepack_dir / "package.json").write_text(
        json.dumps({"name": "workspace-root", "workspaces": ["apps/*"]}, indent=2),
        encoding="utf-8",
    )
    (corepack_app_dir / "package.json").write_text(
        json.dumps({"name": "web", "scripts": {"test": "echo web test"}}, indent=2),
        encoding="utf-8",
    )
    write_json(
        corepack_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "",
            "scenarios": [
                {
                    "id": "corepack-executable-prerequisites",
                    "steps": [
                        {
                            "action": "command",
                            "id": "corepack-yarn-cwd-existing-script",
                            "command": ["corepack", "yarn", "--cwd", "apps/web", "test"],
                            "evidenceType": "command",
                            "proves": "corepack is the executable while yarn is the package-manager argument.",
                        },
                    ],
                }
            ],
        },
    )
    corepack_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "preflight_runtime.py"),
            "--run-dir",
            str(corepack_dir),
            "--project-root",
            str(corepack_dir),
            "--fail-on-blockers",
        ],
        cwd=corepack_dir,
        env={**os.environ, "PATH": str(corepack_bin_dir)},
        text=True,
        capture_output=True,
    )
    corepack_report = load_json(corepack_dir / "service-preflight.json")
    assert_true(corepack_proc.returncode == 0, "preflight should not block corepack-wrapped package-manager commands when corepack exists and scripts/dependencies are present.")
    assert_true(
        not any(item.get("executable") == "yarn" for item in corepack_report.get("blockers", []) if isinstance(item, dict)),
        "preflight should check the corepack executable, not require a direct yarn executable for corepack yarn commands.",
    )

    npx_wrapper_dir = tmp_path / "preflight-npx-wrapper-executable"
    npx_wrapper_bin_dir = npx_wrapper_dir / "bin"
    npx_wrapper_bin_dir.mkdir(parents=True, exist_ok=True)
    fake_python = npx_wrapper_bin_dir / "python"
    fake_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_python.chmod(0o755)
    (npx_wrapper_dir / "package.json").write_text(
        json.dumps({"name": "npx-wrapper-fixture", "scripts": {}}, indent=2),
        encoding="utf-8",
    )
    write_json(
        npx_wrapper_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "",
            "scenarios": [
                {
                    "id": "npx-wrapper-executable-prerequisites",
                    "steps": [
                        {
                            "action": "command",
                            "id": "missing-npx-cross-env-python",
                            "command": ["npx", "cross-env", "PYTHONPATH=src", "python", "-c", "print(1)"],
                            "evidenceType": "command",
                            "proves": "npx is the executable while python is the nested cross-env command.",
                        },
                    ],
                }
            ],
        },
    )
    npx_wrapper_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "preflight_runtime.py"),
            "--run-dir",
            str(npx_wrapper_dir),
            "--project-root",
            str(npx_wrapper_dir),
            "--fail-on-blockers",
        ],
        cwd=npx_wrapper_dir,
        env={**os.environ, "PATH": str(npx_wrapper_bin_dir)},
        text=True,
        capture_output=True,
    )
    npx_wrapper_report = load_json(npx_wrapper_dir / "service-preflight.json")
    assert_true(npx_wrapper_proc.returncode != 0, "preflight should block when an npx-wrapped validation command is missing npx.")
    assert_true(
        any(item.get("executable") == "npx" for item in npx_wrapper_report.get("blockers", []) if isinstance(item, dict)),
        "preflight should check the npx executable before unwrapping npx cross-env commands for semantic prerequisite checks.",
    )

    npx_nested_dir = tmp_path / "preflight-npx-wrapper-nested-executable"
    npx_nested_bin_dir = npx_nested_dir / "bin"
    npx_nested_bin_dir.mkdir(parents=True, exist_ok=True)
    fake_npx = npx_nested_bin_dir / "npx"
    fake_npx.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_npx.chmod(0o755)
    (npx_nested_dir / "package.json").write_text(
        json.dumps({"name": "npx-nested-fixture", "scripts": {}}, indent=2),
        encoding="utf-8",
    )
    write_json(
        npx_nested_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "",
            "scenarios": [
                {
                    "id": "npx-wrapper-nested-executable-prerequisites",
                    "steps": [
                        {
                            "action": "command",
                            "id": "missing-npx-cross-env-nested-python",
                            "command": ["npx", "cross-env", "PYTHONPATH=src", "python", "-c", "print(1)"],
                            "evidenceType": "command",
                            "proves": "npx and the nested cross-env command executable are both available.",
                        },
                    ],
                }
            ],
        },
    )
    npx_nested_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "preflight_runtime.py"),
            "--run-dir",
            str(npx_nested_dir),
            "--project-root",
            str(npx_nested_dir),
            "--fail-on-blockers",
        ],
        cwd=npx_nested_dir,
        env={**os.environ, "PATH": str(npx_nested_bin_dir)},
        text=True,
        capture_output=True,
    )
    npx_nested_report = load_json(npx_nested_dir / "service-preflight.json")
    assert_true(npx_nested_proc.returncode != 0, "preflight should block when an npx cross-env command has a missing nested executable.")
    assert_true(
        any(item.get("executable") == "python" for item in npx_nested_report.get("blockers", []) if isinstance(item, dict)),
        "preflight should check the nested executable after npx cross-env once the npx wrapper itself exists.",
    )


def run_command_project_root_cwd_fixture(script_dir: Path, tmp_path: Path) -> None:
    fixture_dir = tmp_path / "command-project-root-cwd"
    project_root = fixture_dir / "project"
    run_dir = fixture_dir / "run"
    project_root.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)
    (project_root / "project-marker.txt").write_text("project-root-marker", encoding="utf-8")
    (run_dir / "requirement.md").write_text("- Code PR command validation runs from the project checkout root by default.\n", encoding="utf-8")
    write_json(
        run_dir / "adapter-context.json",
        {
            "schema_version": 1,
            "adapter": "fixture",
            "project_root": str(project_root),
            "base_url": "",
            "environment_boundary": {
                "runtime_mode": "test",
                "data_boundary_status": "synthetic fixture data; no production data",
            },
        },
    )
    write_json(
        run_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-command",
                    "source": "fixture",
                    "text": "Code PR command validation runs from the project checkout root by default.",
                    "test_ids": ["T-command"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-command",
                    "requirement_ids": ["R-command"],
                    "type": "code_pr",
                    "steps": ["Run a project-root-relative command without an explicit cwd."],
                    "expected": "The command can read project-root-relative fixture files and exits successfully.",
                    "required_evidence": ["command stdout JSON", "project root cwd"],
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        run_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "",
            "artifactDir": str(run_dir),
            "scenarios": [
                {
                    "id": "command-project-root",
                    "steps": [
                        {
                            "action": "command",
                            "id": "T-command",
                            "testIds": ["T-command"],
                            "requirementIds": ["R-command"],
                            "command": [
                                sys.executable,
                                "-c",
                                "import json, pathlib; print(json.dumps({'marker': pathlib.Path('project-marker.txt').read_text().strip(), 'cwd': pathlib.Path.cwd().name}))",
                            ],
                            "requiredFiles": ["project-marker.txt"],
                            "expectStdoutJson": {"marker": "project-root-marker", "cwd": "project"},
                            "captureStdout": True,
                            "evidenceType": "code_pr",
                            "proves": "Default command cwd is the project checkout root when --project-root is supplied.",
                        }
                    ],
                }
            ],
        },
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(run_dir),
            "--project-root",
            str(project_root),
            "--preflight-runtime",
            "--allow-unsafe-command",
            "--runtime-mode",
            "test",
            "--data-boundary-status",
            "synthetic fixture data; no production data",
            "--skip-report",
        ],
        cwd=fixture_dir,
        text=True,
        capture_output=True,
    )
    assert_true(
        proc.returncode == 0,
        "run_qa_cycle should execute default-cwd command probes from --project-root, not the artifact run dir.\n"
        + f"stdout={proc.stdout[-2000:]}\nstderr={proc.stderr[-2000:]}",
    )
    preflight = load_json(run_dir / "service-preflight.json")
    assert_true(preflight.get("runnable") is True and not preflight.get("blockers"), "project-root-relative command prerequisites should not block preflight.")
    verdict = load_json(run_dir / "qa-verdict.json")
    ledger = load_json(run_dir / "evidence-ledger.json")
    evidence = next((item for item in ledger.get("evidence", []) if item.get("type") == "code_pr"), {})
    assert_true(verdict.get("can_claim_pass") is True, "project-root command fixture should produce a pass verdict.")
    assert_true(evidence.get("checked_stdout_json", {}).get("marker") == "project-root-marker", "ledger should preserve project-root stdout JSON evidence.")


def run_service_runtime_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "service-runtime-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    preflight_path = input_dir / "service-preflight.json"
    runtime_path = input_dir / "service-runtime.json"
    start_out = input_dir / "nested" / "service-runtime.json"
    stop_out = input_dir / "nested" / "service-runtime-stop.json"
    preflight_path.write_text("[]", encoding="utf-8")
    runtime_path.mkdir()

    start_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "service_runtime.py"),
            "--run-dir",
            str(input_dir),
            "--preflight",
            str(preflight_path),
            "--out",
            str(start_out),
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(start_proc.returncode != 0, "service_runtime dry-run should exit non-zero for unreadable preflight artifacts.")
    assert_true(start_out.exists(), "service_runtime should write service-runtime.json even when preflight is unreadable.")
    start_report = load_json(start_out)
    start_errors = {item.get("name"): item.get("error") for item in start_report.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(start_errors.get("preflight") == "json_root_not_object", "service_runtime should classify non-object preflight artifacts.")
    assert_true(start_report.get("summary", {}).get("started_count") == 0, "bad preflight input should not start services.")
    assert_true("Traceback" not in start_proc.stderr, "service_runtime dry-run should report bad inputs without a Python traceback.")

    stop_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "service_runtime.py"),
            "--run-dir",
            str(input_dir),
            "--runtime",
            str(runtime_path),
            "--out",
            str(stop_out),
            "--stop",
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(stop_proc.returncode != 0, "service_runtime stop should exit non-zero for unreadable runtime artifacts.")
    assert_true(stop_out.exists(), "service_runtime should write service-runtime-stop.json even when runtime input is unreadable.")
    stop_report = load_json(stop_out)
    stop_errors = {item.get("name"): item.get("error") for item in stop_report.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(stop_errors.get("runtime") == "path_is_directory", "service_runtime should classify directory-shaped runtime artifacts.")
    assert_true(stop_report.get("summary", {}).get("stopped_count") == 0, "bad runtime input should not stop services.")
    assert_true("Traceback" not in stop_proc.stderr, "service_runtime stop should report bad inputs without a Python traceback.")


def run_discover_project_context_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "discover-context-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    missing_root = input_dir / "missing-project-root"
    out_path = input_dir / "nested" / "adapter-context.json"

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "discover_project_context.py"),
            "--project-root",
            str(missing_root),
            "--out",
            str(out_path),
            "--no-http-probe",
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "discover_project_context should exit non-zero for unreadable project roots.")
    assert_true(out_path.exists(), "discover_project_context should write adapter-context.json even when project-root is unreadable.")
    context = load_json(out_path)
    input_errors = {item.get("name"): item.get("error") for item in context.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(input_errors.get("project_root") == "missing", "discover_project_context should classify missing project roots.")
    assert_true(context.get("project_root_status", {}).get("readable") is False, "adapter context should mark unreadable project roots.")
    assert_true(context.get("services") == [], "bad project roots should not synthesize service candidates.")
    assert_true("Traceback" not in proc.stderr, "discover_project_context should report bad project roots without a Python traceback.")


def run_preflight_project_root_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "preflight-project-root-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    file_root = input_dir / "not-a-project-root.txt"
    file_root.write_text("not a directory\n", encoding="utf-8")
    out_path = input_dir / "nested" / "service-preflight.json"

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "preflight_runtime.py"),
            "--run-dir",
            str(input_dir),
            "--project-root",
            str(file_root),
            "--refresh-context",
            "--no-http-probe",
            "--out",
            str(out_path),
            "--fail-on-blockers",
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "preflight_runtime should exit non-zero for unreadable discovered project roots.")
    assert_true(out_path.exists(), "preflight_runtime should write service-preflight.json for unreadable project roots.")
    report = load_json(out_path)
    input_errors = {item.get("name"): item.get("error") for item in report.get("input_artifact_errors", []) if isinstance(item, dict)}
    blocker_errors = {item.get("artifact"): item.get("error") for item in report.get("blockers", []) if isinstance(item, dict)}
    assert_true(report.get("runnable") is False, "preflight with unreadable project root must not be runnable.")
    assert_true(input_errors.get("project_root") == "path_is_not_directory", "preflight should preserve project-root input errors from discovery.")
    assert_true(blocker_errors.get("project_root") == "path_is_not_directory", "preflight blockers should name the project-root error.")
    assert_true(report.get("start_plan") == [], "bad project roots should not synthesize service start plans.")
    assert_true("Traceback" not in proc.stderr, "preflight_runtime should report bad discovered project roots without a Python traceback.")


def run_audit_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "audit-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = input_dir / "evidence-ledger.json"
    matrix_path = input_dir / "test-matrix.json"
    results_path = input_dir / "results.json"
    summary_path = input_dir / "nested" / "audit-summary.json"
    ledger_path.write_text("[]", encoding="utf-8")
    matrix_path.mkdir()
    results_path.write_text("{not-json", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_evidence.py"),
            "--ledger",
            str(ledger_path),
            "--matrix",
            str(matrix_path),
            "--results",
            str(results_path),
            "--summary",
            str(summary_path),
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "audit_evidence should exit non-zero for unreadable input artifacts.")
    assert_true(summary_path.exists(), "audit_evidence should write audit-summary.json even when inputs are unreadable.")
    summary = load_json(summary_path)
    input_errors = {item.get("name"): item.get("error") for item in summary.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(summary.get("passed") is False, "bad audit_evidence inputs must not pass.")
    assert_true(input_errors.get("ledger") == "json_root_not_object", "audit_evidence should classify non-object ledgers.")
    assert_true(input_errors.get("matrix") == "path_is_directory", "audit_evidence should classify directory-shaped matrices.")
    assert_true(str(input_errors.get("results", "")).startswith("invalid_json"), "audit_evidence should classify malformed results JSON.")
    assert_true(summary.get("requirement_count") == 0 and summary.get("evidence_count") == 0, "bad audit_evidence inputs should not synthesize evidence counts.")
    assert_true(summary.get("passed_evidence_current_run_checked") is False, "bad audit_evidence inputs should not claim current-run evidence was checked.")
    assert_true("Traceback" not in proc.stderr, "audit_evidence should report bad inputs without a Python traceback.")


def run_defect_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "defect-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = input_dir / "evidence-ledger.json"
    matrix_path = input_dir / "test-matrix.json"
    results_path = input_dir / "results.json"
    defects_path = input_dir / "nested" / "defects.json"
    ledger_path.write_text("[]", encoding="utf-8")
    matrix_path.mkdir()
    results_path.write_text("{not-json", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "generate_defects.py"),
            "--ledger",
            str(ledger_path),
            "--results",
            str(results_path),
            "--matrix",
            str(matrix_path),
            "--out",
            str(defects_path),
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "generate_defects should exit non-zero for unreadable input artifacts.")
    assert_true(defects_path.exists(), "generate_defects should write defects.json even when inputs are unreadable.")
    defects = load_json(defects_path)
    input_errors = {item.get("name"): item.get("error") for item in defects.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(defects.get("summary", {}).get("finding_count") == 0, "bad defect inputs should not synthesize findings.")
    assert_true(input_errors.get("ledger") == "json_root_not_object", "generate_defects should classify non-object ledgers.")
    assert_true(input_errors.get("matrix") == "path_is_directory", "generate_defects should classify directory-shaped matrices.")
    assert_true(str(input_errors.get("results", "")).startswith("invalid_json"), "generate_defects should classify malformed results JSON.")
    assert_true(defects.get("summary", {}).get("input_artifact_error_count") == 3, "defects summary should count unreadable inputs.")
    assert_true("Traceback" not in proc.stderr, "generate_defects should report bad inputs without a Python traceback.")


def run_next_probe_generation_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "next-probe-generation-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    defects_path = input_dir / "defects.json"
    results_path = input_dir / "results.json"
    ledger_path = input_dir / "evidence-ledger.json"
    next_path = input_dir / "nested" / "next-probes.json"
    defects_path.write_text("[]", encoding="utf-8")
    results_path.mkdir()
    ledger_path.write_text("{not-json", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "generate_next_probes.py"),
            "--defects",
            str(defects_path),
            "--results",
            str(results_path),
            "--ledger",
            str(ledger_path),
            "--out",
            str(next_path),
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "generate_next_probes should exit non-zero for unreadable input artifacts.")
    assert_true(next_path.exists(), "generate_next_probes should write next-probes.json even when inputs are unreadable.")
    next_probes = load_json(next_path)
    input_errors = {item.get("name"): item.get("error") for item in next_probes.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(next_probes.get("summary", {}).get("recommendation_count") == 0, "bad next-probe inputs should not synthesize recommendations.")
    assert_true(input_errors.get("defects") == "json_root_not_object", "generate_next_probes should classify non-object defects.")
    assert_true(input_errors.get("results") == "path_is_directory", "generate_next_probes should classify directory-shaped results.")
    assert_true(str(input_errors.get("ledger", "")).startswith("invalid_json"), "generate_next_probes should classify malformed ledgers.")
    assert_true(next_probes.get("summary", {}).get("input_artifact_error_count") == 3, "next-probes summary should count unreadable inputs.")
    assert_true("Traceback" not in proc.stderr, "generate_next_probes should report bad inputs without a Python traceback.")


def run_ledger_input_error_fixture(script_dir: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "ledger-input-errors"
    input_dir.mkdir(parents=True, exist_ok=True)
    matrix_path = input_dir / "test-matrix.json"
    results_path = input_dir / "results.json"
    ledger_path = input_dir / "nested" / "evidence-ledger.json"
    matrix_path.write_text("[]", encoding="utf-8")
    results_path.write_text("{not-json", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "ledger_from_probe.py"),
            "--matrix",
            str(matrix_path),
            "--results",
            str(results_path),
            "--out",
            str(ledger_path),
        ],
        cwd=input_dir,
        text=True,
        capture_output=True,
    )
    assert_true(proc.returncode != 0, "ledger_from_probe should exit non-zero for unreadable input artifacts.")
    assert_true(ledger_path.exists(), "ledger_from_probe should write evidence-ledger.json even when inputs are unreadable.")
    ledger = load_json(ledger_path)
    input_errors = {item.get("name"): item.get("error") for item in ledger.get("input_artifact_errors", []) if isinstance(item, dict)}
    assert_true(ledger.get("requirements") == [] and ledger.get("tests") == [] and ledger.get("evidence") == [], "bad ledger inputs should not synthesize evidence.")
    assert_true(input_errors.get("matrix") == "json_root_not_object", "ledger_from_probe should classify non-object matrices.")
    assert_true(str(input_errors.get("results", "")).startswith("invalid_json"), "ledger_from_probe should classify malformed results JSON.")
    assert_true(ledger.get("runtime_summary", {}).get("input_artifact_error_count") == 2, "ledger runtime summary should count unreadable inputs.")
    assert_true("Traceback" not in proc.stderr, "ledger_from_probe should report bad inputs without a Python traceback.")


def run_audit_failure_handoff_fixture(script_dir: Path, tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit-failure-handoff"
    audit_dir.mkdir(parents=True, exist_ok=True)
    (audit_dir / "requirement.md").write_text("- A visible result must be backed by a current screenshot artifact.\n", encoding="utf-8")
    write_json(
        audit_dir / "adapter-context.json",
        {
            "schema_version": 1,
            "adapter": "fixture",
            "environment_boundary": {
                "runtime_mode": "test",
                "data_boundary_status": "synthetic screenshot fixture data; no production data",
            },
        },
    )
    write_json(
        audit_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-shot",
                    "source": "fixture",
                    "text": "A visible result must be backed by a current screenshot artifact.",
                    "test_ids": ["T-shot"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-shot",
                    "requirement_ids": ["R-shot"],
                    "type": "ui",
                    "expected": "The screenshot artifact exists and is readable.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        audit_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(audit_dir),
            "scenarios": [
                {
                    "id": "shot-proof",
                    "steps": [
                        {
                            "action": "screenshot",
                            "id": "shot-proof-step",
                            "testIds": ["T-shot"],
                            "requirementIds": ["R-shot"],
                            "evidenceType": "screenshot",
                            "proves": "A visible result is captured in a screenshot artifact.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        audit_dir / "results.json",
        {
            "schemaVersion": 2,
            "artifactDir": str(audit_dir),
            "status": "passed",
            "startedAt": "2026-06-15T00:00:00+00:00",
            "finishedAt": "2026-06-15T00:00:01+00:00",
            "scenarios": [
                {
                    "id": "shot-proof",
                    "steps": [
                        {
                            "stepId": "shot-proof-step",
                            "action": "screenshot",
                            "status": "passed",
                            "screenshot": "screenshots/missing.png",
                            "testIds": ["T-shot"],
                            "requirementIds": ["R-shot"],
                            "evidenceType": "screenshot",
                            "proves": "A visible result is captured in a screenshot artifact.",
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    cycle_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(audit_dir),
            "--skip-probe",
            "--skip-report",
        ],
        cwd=audit_dir,
        text=True,
        capture_output=True,
    )
    assert_true(cycle_proc.returncode != 0, "audit failure cycle should exit non-zero.")
    cycle_summary = load_json(audit_dir / "qa-run-summary.json")
    cycle_verdict = load_json(audit_dir / "qa-verdict.json")
    cycle_codes = {reason.get("code") for reason in cycle_verdict.get("reasons", [])}
    audit_summary = load_json(audit_dir / "audit-summary.json")
    assert_true(audit_summary.get("passed") is False, "fixture audit should fail before verdict handoff.")
    assert_true(cycle_summary.get("status") == "inconclusive", "audit failure summary should use the structured verdict status.")
    assert_true(cycle_verdict.get("verdict") == "inconclusive", "audit failure handoff verdict should be inconclusive.")
    assert_true(cycle_verdict.get("can_claim_pass") is False, "audit failure handoff must not allow pass.")
    assert_true("audit_failed" in cycle_codes, "audit failure handoff should include audit_failed.")
    assert_true(cycle_summary.get("verdict", {}).get("verdict") == "inconclusive", "cycle summary should embed the audit failure verdict.")

    loop_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "qa_agent_loop.py"),
            "--run-dir",
            str(audit_dir),
            "--skip-probe",
            "--skip-report",
            "--max-iterations",
            "1",
        ],
        cwd=audit_dir,
        text=True,
        capture_output=True,
    )
    assert_true(loop_proc.returncode != 0, "agent loop should stay non-zero for audit failure handoff.")
    agent_summary = load_json(audit_dir / "qa-agent-summary.json")
    assert_true(agent_summary.get("status") == "inconclusive", "agent loop should preserve audit failure verdict status.")
    assert_true(agent_summary.get("stop_reason") == "cycle_stopped_with_verdict", "agent loop should distinguish audit verdict handoff from generic failure.")
    assert_true((agent_summary.get("next_action") or {}).get("action") == "repair_evidence_pipeline", "audit failure should request evidence-pipeline repair.")


def run_helper_failure_handoff_fixture(script_dir: Path, tmp_path: Path) -> None:
    helper_dir = tmp_path / "helper-failure-handoff"
    helper_dir.mkdir(parents=True, exist_ok=True)
    (helper_dir / "requirement.md").write_text("- A visible result must be backed by a current screenshot artifact.\n", encoding="utf-8")
    write_json(
        helper_dir / "adapter-context.json",
        {
            "schema_version": 1,
            "adapter": "fixture",
            "environment_boundary": {
                "runtime_mode": "test",
                "data_boundary_status": "synthetic screenshot fixture data; no production data",
            },
        },
    )
    (helper_dir / "screenshots").mkdir(parents=True, exist_ok=True)
    (helper_dir / "screenshots" / "actual.png").write_bytes(VALID_PNG_1X1)
    write_json(
        helper_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-shot",
                    "source": "fixture",
                    "text": "A visible result must be backed by a current screenshot artifact.",
                    "test_ids": ["T-shot"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-shot",
                    "requirement_ids": ["R-shot"],
                    "type": "ui",
                    "expected": "The screenshot artifact exists and is readable.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        helper_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(helper_dir),
            "scenarios": [
                {
                    "id": "shot-proof",
                    "steps": [
                        {
                            "action": "screenshot",
                            "id": "shot-proof-step",
                            "testIds": ["T-shot"],
                            "requirementIds": ["R-shot"],
                            "evidenceType": "screenshot",
                            "proves": "A visible result is captured in a screenshot artifact.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        helper_dir / "results.json",
        {
            "schemaVersion": 2,
            "artifactDir": str(helper_dir),
            "status": "passed",
            "startedAt": "2000-01-01T00:00:00+00:00",
            "finishedAt": "2000-01-01T00:00:01+00:00",
            "scenarios": [
                {
                    "id": "shot-proof",
                    "steps": [
                        {
                            "stepId": "shot-proof-step",
                            "action": "screenshot",
                            "status": "passed",
                            "screenshot": "screenshots/actual.png",
                            "testIds": ["T-shot"],
                            "requirementIds": ["R-shot"],
                            "evidenceType": "screenshot",
                            "proves": "A visible result is captured in a screenshot artifact.",
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    (helper_dir / "defects.json").mkdir()
    cycle_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(helper_dir),
            "--skip-probe",
            "--skip-report",
        ],
        cwd=helper_dir,
        text=True,
        capture_output=True,
    )
    assert_true(cycle_proc.returncode != 0, "helper failure cycle should exit non-zero.")
    cycle_summary = load_json(helper_dir / "qa-run-summary.json")
    cycle_error = load_json(helper_dir / "qa-cycle-error.json")
    cycle_verdict = load_json(helper_dir / "qa-verdict.json")
    cycle_codes = {reason.get("code") for reason in cycle_verdict.get("reasons", [])}
    assert_true(cycle_error.get("phase") == "generate_defects", "cycle error should name the failed helper phase.")
    assert_true(cycle_summary.get("status") == "inconclusive", "helper failure summary should use the structured verdict status.")
    assert_true(cycle_verdict.get("verdict") == "inconclusive", "helper failure handoff verdict should be inconclusive.")
    assert_true(cycle_verdict.get("can_claim_pass") is False, "helper failure handoff must not allow pass.")
    assert_true("cycle_helper_failed" in cycle_codes, "helper failure handoff should include cycle_helper_failed.")
    assert_true(cycle_verdict.get("gates", {}).get("cycle_completed") is False, "helper failure verdict should mark the cycle incomplete.")

    loop_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "qa_agent_loop.py"),
            "--run-dir",
            str(helper_dir),
            "--skip-probe",
            "--skip-report",
            "--max-iterations",
            "1",
        ],
        cwd=helper_dir,
        text=True,
        capture_output=True,
    )
    assert_true(loop_proc.returncode != 0, "agent loop should stay non-zero for helper failure handoff.")
    agent_summary = load_json(helper_dir / "qa-agent-summary.json")
    assert_true(agent_summary.get("status") == "inconclusive", "agent loop should preserve helper failure verdict status.")
    assert_true(agent_summary.get("stop_reason") == "cycle_stopped_with_verdict", "agent loop should distinguish helper verdict handoff from generic failure.")
    assert_true((agent_summary.get("next_action") or {}).get("action") == "repair_evidence_pipeline", "helper failure should request evidence-pipeline repair.")


def copy_script_runtime(script_dir: Path, target_dir: Path) -> None:
    """复制兼容脚本及其内部包，供故障注入夹具隔离修改。"""
    target_dir.mkdir(parents=True, exist_ok=True)
    for source in script_dir.iterdir():
        if source.is_file() and source.suffix in {".py", ".mjs"}:
            shutil.copy2(source, target_dir / source.name)
    for package_name in ("qa_core", "qa_scaffold"):
        shutil.copytree(script_dir / package_name, target_dir / package_name, dirs_exist_ok=True)
    shutil.copytree(script_dir.parent / "references" / "schemas", target_dir.parent / "references" / "schemas", dirs_exist_ok=True)


def run_helper_output_unreadable_fixture(script_dir: Path, tmp_path: Path) -> None:
    shim_dir = tmp_path / "helper-output-unreadable-shim"
    copy_script_runtime(script_dir, shim_dir)

    preflight_shim_dir = tmp_path / "helper-output-missing-preflight-shim"
    copy_script_runtime(script_dir, preflight_shim_dir)
    (preflight_shim_dir / "preflight_runtime.py").write_text(
        """#!/usr/bin/env python3
raise SystemExit(0)
""",
        encoding="utf-8",
    )
    (shim_dir / "generate_defects.py").write_text(
        """#!/usr/bin/env python3
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--ledger")
parser.add_argument("--results")
parser.add_argument("--matrix")
parser.add_argument("--out", required=True)
args = parser.parse_args()
Path(args.out).write_text("{not-json", encoding="utf-8")
print(args.out)
raise SystemExit(0)
""",
        encoding="utf-8",
    )

    missing_preflight_dir = tmp_path / "helper-output-missing-preflight"
    missing_preflight_dir.mkdir(parents=True, exist_ok=True)
    write_valid_skip_probe_plan(missing_preflight_dir)
    preflight_proc = subprocess.run(
        [
            sys.executable,
            str(preflight_shim_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(missing_preflight_dir),
            "--preflight-runtime",
            "--skip-probe",
            "--skip-report",
        ],
        cwd=missing_preflight_dir,
        text=True,
        capture_output=True,
    )
    assert_true(preflight_proc.returncode != 0, "cycle should exit non-zero when preflight exits zero without service-preflight.json.")
    assert_true("Traceback" not in preflight_proc.stderr, "missing preflight output should not crash run_qa_cycle with a traceback.")
    preflight_error = load_json(missing_preflight_dir / "qa-cycle-error.json")
    preflight_verdict = load_json(missing_preflight_dir / "qa-verdict.json")
    preflight_codes = {reason.get("code") for reason in preflight_verdict.get("reasons", [])}
    assert_true(preflight_error.get("code") == "helper_output_unreadable", "missing preflight output should be classified as unreadable helper output.")
    assert_true(preflight_error.get("phase") == "preflight_runtime", "missing preflight output should name the preflight phase.")
    assert_true("missing_output" in str(preflight_error.get("message")), "missing preflight output should preserve the missing_output load error.")
    assert_true("helper_output_unreadable" in preflight_codes, "preflight verdict should include helper_output_unreadable.")

    case_dir = tmp_path / "helper-output-unreadable"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "screenshots").mkdir(parents=True, exist_ok=True)
    (case_dir / "screenshots" / "actual.png").write_bytes(VALID_PNG_1X1)
    write_json(
        case_dir / "test-matrix.json",
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R-output",
                    "source": "fixture",
                    "text": "A helper that exits zero must still produce readable JSON.",
                    "test_ids": ["T-output"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T-output",
                    "requirement_ids": ["R-output"],
                    "type": "ui",
                    "expected": "The screenshot artifact exists and is readable.",
                    "status": "Untested",
                }
            ],
        },
    )
    write_json(
        case_dir / "test-plan.json",
        {
            "schemaVersion": 2,
            "baseUrl": "http://127.0.0.1:9527",
            "artifactDir": str(case_dir),
            "scenarios": [
                {
                    "id": "output-proof",
                    "steps": [
                        {
                            "action": "screenshot",
                            "id": "output-proof-step",
                            "testIds": ["T-output"],
                            "requirementIds": ["R-output"],
                            "evidenceType": "screenshot",
                            "proves": "A visible result is captured in a screenshot artifact.",
                        }
                    ],
                }
            ],
        },
    )
    write_json(
        case_dir / "results.json",
        {
            "schemaVersion": 2,
            "artifactDir": str(case_dir),
            "status": "passed",
            "startedAt": "2000-01-01T00:00:00+00:00",
            "finishedAt": "2000-01-01T00:00:01+00:00",
            "scenarios": [
                {
                    "id": "output-proof",
                    "steps": [
                        {
                            "stepId": "output-proof-step",
                            "action": "screenshot",
                            "status": "passed",
                            "screenshot": "screenshots/actual.png",
                            "testIds": ["T-output"],
                            "requirementIds": ["R-output"],
                            "evidenceType": "screenshot",
                            "proves": "A visible result is captured in a screenshot artifact.",
                        }
                    ],
                }
            ],
            "console": [],
            "failedResponses": [],
            "requestFailures": [],
        },
    )
    cycle_proc = subprocess.run(
        [
            sys.executable,
            str(shim_dir / "run_qa_cycle.py"),
            "--run-dir",
            str(case_dir),
            "--skip-probe",
            "--skip-report",
        ],
        cwd=case_dir,
        text=True,
        capture_output=True,
    )
    assert_true(cycle_proc.returncode != 0, "cycle should exit non-zero when a zero-exit helper writes unreadable JSON.")
    assert_true("Traceback" not in cycle_proc.stderr, "unreadable helper output should not crash run_qa_cycle with a traceback.")
    cycle_summary = load_json(case_dir / "qa-run-summary.json")
    cycle_error = load_json(case_dir / "qa-cycle-error.json")
    cycle_verdict = load_json(case_dir / "qa-verdict.json")
    cycle_codes = {reason.get("code") for reason in cycle_verdict.get("reasons", [])}
    assert_true(cycle_error.get("code") == "helper_output_unreadable", "cycle error should classify zero-exit unreadable helper output.")
    assert_true(cycle_error.get("phase") == "generate_defects", "cycle error should name the helper phase with unreadable output.")
    assert_true("invalid_json" in str(cycle_error.get("message")), "cycle error should preserve the JSON load error.")
    assert_true(cycle_verdict.get("can_claim_pass") is False, "unreadable helper output must block pass claims.")
    assert_true("helper_output_unreadable" in cycle_codes, "verdict should include helper_output_unreadable.")
    assert_true(cycle_summary.get("cycle_error", {}).get("code") == "helper_output_unreadable", "cycle summary should embed the unreadable helper output error.")
