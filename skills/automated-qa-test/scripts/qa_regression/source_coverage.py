"""需求源切分、覆盖放行与 verdict 门回归夹具。"""

import subprocess
import sys
from pathlib import Path
from typing import Callable

from .support import assert_true, load_json, run_cmd, write_json


def _verify_unmapped_allow_gate(script_dir: Path, tmp_path: Path) -> tuple[Path, Path]:
    gate_dir = tmp_path / "unmapped-source-allow-gate"
    gate_dir.mkdir(parents=True, exist_ok=True)
    requirement_path = gate_dir / "requirement.md"
    matrix_path = gate_dir / "test-matrix.json"
    coverage_path = gate_dir / "requirement-coverage.json"
    requirement_path.write_text(
        "\n".join([
            "- Users can open /settings.",
            "- The Save button persists the edited setting.",
            "- Non-admin users cannot save restricted settings.",
        ]),
        encoding="utf-8",
    )
    write_json(
        matrix_path,
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1",
                    "text": "Users can open /settings.",
                    "test_ids": ["T1"],
                    "status": "Passed",
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "ui",
                    "expected": "Users can open /settings.",
                    "status": "Passed",
                }
            ],
        },
    )
    coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(requirement_path),
            "--matrix",
            str(matrix_path),
            "--out",
            str(coverage_path),
            "--allow-unmapped-source",
        ],
        cwd=gate_dir,
        text=True,
        capture_output=True,
    )
    assert_true(coverage_proc.returncode == 0, "--allow-unmapped-source should allow execution handoff without returning a hard failure.")
    coverage = load_json(coverage_path)
    assert_true(coverage.get("passed") is False, "coverage passed must mean complete source coverage even when unmapped source is allowed.")
    assert_true(coverage.get("allow_unmapped_source") is True, "coverage artifact should record that unmapped source was only allowed for continuation.")
    assert_true(coverage.get("execution_allowed") is True, "coverage artifact should distinguish execution allowance from pass semantics.")
    assert_true(coverage.get("uncovered_count") == 2, "coverage artifact should preserve the real uncovered source count.")
    return gate_dir, coverage_path

def _verify_paragraph_and_command_units(script_dir: Path, tmp_path: Path) -> None:
    paragraph_dir = tmp_path / "paragraph-source-coverage"
    paragraph_dir.mkdir(parents=True, exist_ok=True)
    paragraph_requirement_path = paragraph_dir / "requirement.md"
    paragraph_matrix_path = paragraph_dir / "test-matrix.json"
    paragraph_coverage_path = paragraph_dir / "requirement-coverage.json"
    paragraph_requirement_path.write_text(
        "POST /api/orders returns 201 and response includes order_id and persists order_123 in the database.",
        encoding="utf-8",
    )
    write_json(
        paragraph_matrix_path,
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "paragraph 1",
                    "text": "POST /api/orders returns 201 and response includes order_id and persists order_123 in the database.",
                    "test_ids": ["T1", "T2"],
                    "status": "Blocked",
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "api",
                    "steps": ["Identify a safe read-only endpoint or reversible test data."],
                    "expected": "POST /api/orders returns 201 and response includes order_id.",
                    "required_evidence": ["api_response", "response body"],
                    "status": "Blocked",
                },
                {
                    "id": "T2",
                    "requirement_ids": ["R1"],
                    "type": "persistence",
                    "steps": ["Provide a read-only persistence helper."],
                    "expected": "order_123 is persisted in the database.",
                    "required_evidence": ["persistence"],
                    "status": "Blocked",
                },
            ],
        },
    )
    paragraph_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(paragraph_requirement_path),
            "--matrix",
            str(paragraph_matrix_path),
            "--out",
            str(paragraph_coverage_path),
        ],
        cwd=paragraph_dir,
        text=True,
        capture_output=True,
    )
    assert_true(paragraph_coverage_proc.returncode == 0, "paragraph behavior clauses should be covered when the matrix maps the full source behavior.")
    paragraph_coverage = load_json(paragraph_coverage_path)
    assert_true(paragraph_coverage.get("requirement_unit_count") == 3, "paragraph source coverage should split API status, response body, and persistence clauses.")
    assert_true(paragraph_coverage.get("covered_count") == 3, "paragraph clause coverage should count each mapped behavior point.")
    assert_true(paragraph_coverage.get("uncovered_count") == 0, "paragraph clause coverage should not leave mapped behavior points uncovered.")

    templated_dir = tmp_path / "templated-source-coverage"
    templated_dir.mkdir(parents=True, exist_ok=True)
    templated_requirement_path = templated_dir / "requirement.md"
    templated_matrix_path = templated_dir / "test-matrix.json"
    templated_coverage_path = templated_dir / "requirement-coverage.json"
    templated_requirement_path.write_text(
        "\n".join(
            [f"- Requirement behavior {index}: user-visible rule {index} must be verified with current-run evidence." for index in range(1, 32)]
        ),
        encoding="utf-8",
    )
    write_json(
        templated_matrix_path,
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1",
                    "text": "Requirement behavior 1: user-visible rule 1 must be verified with current-run evidence.",
                    "test_ids": ["T1"],
                    "status": "Untested",
                },
                {
                    "id": "R2",
                    "source": "line 2",
                    "text": "Requirement behavior 2: user-visible rule 2 must be verified with current-run evidence.",
                    "test_ids": ["T2"],
                    "status": "Untested",
                },
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "logic",
                    "expected": "Rule 1 is verified.",
                    "status": "Untested",
                },
                {
                    "id": "T2",
                    "requirement_ids": ["R2"],
                    "type": "logic",
                    "expected": "Rule 2 is verified.",
                    "status": "Untested",
                },
            ],
        },
    )
    templated_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(templated_requirement_path),
            "--matrix",
            str(templated_matrix_path),
            "--out",
            str(templated_coverage_path),
        ],
        cwd=templated_dir,
        text=True,
        capture_output=True,
    )
    assert_true(templated_coverage_proc.returncode != 0, "templated source lines with different rule ids must not pass from generic token overlap.")
    templated_coverage = load_json(templated_coverage_path)
    assert_true(templated_coverage.get("covered_count") == 2, "coverage should only count the two explicitly mapped templated source lines.")
    assert_true(templated_coverage.get("uncovered_count") == 29, "coverage should preserve the unmapped templated source lines instead of overmatching shared wording.")

    multi_command_dir = tmp_path / "multi-command-source-coverage"
    multi_command_dir.mkdir(parents=True, exist_ok=True)
    multi_command_requirement_path = multi_command_dir / "requirement.md"
    multi_command_matrix_path = multi_command_dir / "test-matrix.json"
    multi_command_coverage_path = multi_command_dir / "requirement-coverage.json"
    multi_command_requirement_path.write_text(
        "- Validation must run `python -m pytest tests/worker/test_job.py` and `python -m ruff check services/worker.py` before merge.",
        encoding="utf-8",
    )
    write_json(
        multi_command_matrix_path,
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1",
                    "text": "Validation command `python -m pytest tests/worker/test_job.py` passes before merge.",
                    "test_ids": ["T1"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "code_pr",
                    "expected": "pytest validation passes.",
                    "status": "Untested",
                }
            ],
        },
    )
    multi_command_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(multi_command_requirement_path),
            "--matrix",
            str(multi_command_matrix_path),
            "--out",
            str(multi_command_coverage_path),
        ],
        cwd=multi_command_dir,
        text=True,
        capture_output=True,
    )
    assert_true(multi_command_coverage_proc.returncode != 0, "a source line with two commands must not be covered when only one command is mapped.")
    multi_command_coverage = load_json(multi_command_coverage_path)
    assert_true(multi_command_coverage.get("covered_count") == 0, "partial command coverage must not increment covered_count for the source unit.")
    assert_true(multi_command_coverage.get("uncovered_count") == 1, "partial command coverage should keep the source unit uncovered.")
    assert_true(
        "python -m ruff check services/worker.py" in "\n".join(multi_command_coverage.get("errors", [])),
        "coverage errors should name the missing command from the source unit.",
    )

    mixed_backtick_bare_command_dir = tmp_path / "mixed-backtick-bare-command-source-coverage"
    mixed_backtick_bare_command_dir.mkdir(parents=True, exist_ok=True)
    mixed_backtick_bare_command_requirement_path = mixed_backtick_bare_command_dir / "requirement.md"
    mixed_backtick_bare_command_matrix_path = mixed_backtick_bare_command_dir / "test-matrix.json"
    mixed_backtick_bare_command_coverage_path = mixed_backtick_bare_command_dir / "requirement-coverage.json"
    mixed_backtick_bare_command_requirement_path.write_text(
        "- Validation must run `python -m pytest tests/worker/test_job.py` and npm test -- worker before merge.",
        encoding="utf-8",
    )
    write_json(
        mixed_backtick_bare_command_matrix_path,
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1",
                    "text": "Validation command `python -m pytest tests/worker/test_job.py` passes before merge.",
                    "test_ids": ["T1"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "code_pr",
                    "expected": "pytest validation passes.",
                    "status": "Untested",
                }
            ],
        },
    )
    mixed_backtick_bare_command_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(mixed_backtick_bare_command_requirement_path),
            "--matrix",
            str(mixed_backtick_bare_command_matrix_path),
            "--out",
            str(mixed_backtick_bare_command_coverage_path),
        ],
        cwd=mixed_backtick_bare_command_dir,
        text=True,
        capture_output=True,
    )
    assert_true(mixed_backtick_bare_command_coverage_proc.returncode != 0, "mixed backticked/bare command source lines must not pass when the bare command is unmapped.")
    mixed_backtick_bare_command_coverage = load_json(mixed_backtick_bare_command_coverage_path)
    assert_true(
        "npm test -- worker" in "\n".join(mixed_backtick_bare_command_coverage.get("errors", [])),
        "coverage errors should name a missing bare command even when another command is backticked.",
    )

    contextual_command_dir = tmp_path / "contextual-command-source-coverage"
    contextual_command_dir.mkdir(parents=True, exist_ok=True)
    contextual_command_requirement_path = contextual_command_dir / "requirement.md"
    contextual_command_matrix_path = contextual_command_dir / "test-matrix.json"
    contextual_command_coverage_path = contextual_command_dir / "requirement-coverage.json"
    contextual_command_requirement_path.write_text(
        "- Validation: CI=1 pnpm test -- dashboard and cd apps/web && npm run test:e2e before merge.",
        encoding="utf-8",
    )
    write_json(
        contextual_command_matrix_path,
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1",
                    "text": "Validation command pnpm test -- dashboard passes before merge.",
                    "test_ids": ["T1"],
                    "status": "Untested",
                },
                {
                    "id": "R2",
                    "source": "line 1",
                    "text": "Validation command npm run test:e2e passes before merge.",
                    "test_ids": ["T2"],
                    "status": "Untested",
                },
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "code_pr",
                    "expected": "pnpm validation passes.",
                    "status": "Untested",
                },
                {
                    "id": "T2",
                    "requirement_ids": ["R2"],
                    "type": "code_pr",
                    "expected": "npm validation passes.",
                    "status": "Untested",
                },
            ],
        },
    )
    contextual_command_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(contextual_command_requirement_path),
            "--matrix",
            str(contextual_command_matrix_path),
            "--out",
            str(contextual_command_coverage_path),
        ],
        cwd=contextual_command_dir,
        text=True,
        capture_output=True,
    )
    assert_true(contextual_command_coverage_proc.returncode != 0, "env/cd command context from source must not be covered by bare command matrix rows.")
    contextual_command_coverage = load_json(contextual_command_coverage_path)
    contextual_command_errors = "\n".join(contextual_command_coverage.get("errors", []))
    assert_true("ci=1 pnpm test -- dashboard" in contextual_command_errors, "coverage errors should preserve missing env-prefixed command context.")
    assert_true("cd apps/web && npm run test:e2e" in contextual_command_errors, "coverage errors should preserve missing cd-prefixed command context.")

    dot_command_dir = tmp_path / "dot-command-source-coverage"
    dot_command_dir.mkdir(parents=True, exist_ok=True)
    dot_command_requirement_path = dot_command_dir / "requirement.md"
    dot_command_matrix_path = dot_command_dir / "test-matrix.json"
    dot_command_coverage_path = dot_command_dir / "requirement-coverage.json"
    dot_command_requirement_path.write_text(
        "- Validation must run `ruff check .` before merge.",
        encoding="utf-8",
    )
    write_json(
        dot_command_matrix_path,
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1",
                    "text": "Validation command `ruff check .` passes before merge.",
                    "test_ids": ["T1"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "code_pr",
                    "expected": "ruff validation passes.",
                    "status": "Untested",
                }
            ],
        },
    )
    dot_command_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(dot_command_requirement_path),
            "--matrix",
            str(dot_command_matrix_path),
            "--out",
            str(dot_command_coverage_path),
        ],
        cwd=dot_command_dir,
        text=True,
        capture_output=True,
    )
    assert_true(dot_command_coverage_proc.returncode == 0, "command coverage should map `ruff check .` exactly.")
    dot_command_coverage = load_json(dot_command_coverage_path)
    dot_command_item = dot_command_coverage.get("coverage", [{}])[0]
    assert_true("ruff check ." in dot_command_item.get("required_commands", []), "coverage should preserve `.` as a command argument, not strip it as punctuation.")
    assert_true("ruff check ." in dot_command_item.get("matched_commands", []), "coverage should match the full `ruff check .` command.")

def _verify_behavior_and_response_clauses(script_dir: Path, tmp_path: Path) -> None:
    multi_behavior_dir = tmp_path / "multi-behavior-source-coverage"
    multi_behavior_dir.mkdir(parents=True, exist_ok=True)
    multi_behavior_requirement_path = multi_behavior_dir / "requirement.md"
    multi_behavior_matrix_path = multi_behavior_dir / "test-matrix.json"
    multi_behavior_coverage_path = multi_behavior_dir / "requirement-coverage.json"
    multi_behavior_requirement_path.write_text(
        "- Saving profile posts to /api/profile, persists profile_123 in the database, and shows a Success toast.",
        encoding="utf-8",
    )
    write_json(
        multi_behavior_matrix_path,
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1",
                    "text": "Saving profile posts to /api/profile and returns 200.",
                    "test_ids": ["T1"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "api",
                    "expected": "POST /api/profile returns 200.",
                    "status": "Untested",
                }
            ],
        },
    )
    multi_behavior_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(multi_behavior_requirement_path),
            "--matrix",
            str(multi_behavior_matrix_path),
            "--out",
            str(multi_behavior_coverage_path),
        ],
        cwd=multi_behavior_dir,
        text=True,
        capture_output=True,
    )
    assert_true(multi_behavior_coverage_proc.returncode != 0, "a source bullet with API, persistence, and UI behavior must not be covered by only the API row.")
    multi_behavior_coverage = load_json(multi_behavior_coverage_path)
    assert_true(multi_behavior_coverage.get("requirement_unit_count") == 3, "coverage should split a compound source bullet into behavior clauses.")
    assert_true(multi_behavior_coverage.get("covered_count") == 1, "only the API behavior clause should be covered.")
    assert_true(multi_behavior_coverage.get("uncovered_count") == 2, "persistence and toast behavior clauses should remain uncovered.")
    multi_behavior_errors = "\n".join(multi_behavior_coverage.get("errors", []))
    assert_true("persists profile_123" in multi_behavior_errors, "coverage errors should name the uncovered persistence behavior.")
    assert_true("shows a Success toast" in multi_behavior_errors, "coverage errors should name the uncovered toast behavior.")

    cn_multi_behavior_dir = tmp_path / "cn-multi-behavior-source-coverage"
    cn_multi_behavior_dir.mkdir(parents=True, exist_ok=True)
    cn_multi_behavior_requirement_path = cn_multi_behavior_dir / "requirement.md"
    cn_multi_behavior_matrix_path = cn_multi_behavior_dir / "test-matrix.json"
    cn_multi_behavior_coverage_path = cn_multi_behavior_dir / "requirement-coverage.json"
    cn_multi_behavior_requirement_path.write_text(
        "- 保存资料时必须 POST /api/profile，持久化 profile_123 到数据库，并显示成功 toast。",
        encoding="utf-8",
    )
    write_json(
        cn_multi_behavior_matrix_path,
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1",
                    "text": "保存资料时必须 POST /api/profile 并返回 200。",
                    "test_ids": ["T1"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "api",
                    "expected": "POST /api/profile returns 200.",
                    "status": "Untested",
                }
            ],
        },
    )
    cn_multi_behavior_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(cn_multi_behavior_requirement_path),
            "--matrix",
            str(cn_multi_behavior_matrix_path),
            "--out",
            str(cn_multi_behavior_coverage_path),
        ],
        cwd=cn_multi_behavior_dir,
        text=True,
        capture_output=True,
    )
    assert_true(cn_multi_behavior_coverage_proc.returncode != 0, "Chinese compound bullets must not be covered by only the API row.")
    cn_multi_behavior_coverage = load_json(cn_multi_behavior_coverage_path)
    assert_true(cn_multi_behavior_coverage.get("requirement_unit_count") == 3, "Chinese coverage should split API, persistence, and toast clauses.")
    assert_true(cn_multi_behavior_coverage.get("covered_count") == 1, "only the Chinese API behavior clause should be covered.")
    assert_true(cn_multi_behavior_coverage.get("uncovered_count") == 2, "Chinese persistence and toast clauses should remain uncovered.")
    cn_multi_behavior_errors = "\n".join(cn_multi_behavior_coverage.get("errors", []))
    assert_true("持久化 profile_123" in cn_multi_behavior_errors, "coverage errors should name the uncovered Chinese persistence behavior.")
    assert_true("显示成功 toast" in cn_multi_behavior_errors, "coverage errors should name the uncovered Chinese toast behavior.")

    response_clause_dir = tmp_path / "response-clause-source-coverage"
    response_clause_dir.mkdir(parents=True, exist_ok=True)
    response_clause_requirement_path = response_clause_dir / "requirement.md"
    response_clause_matrix_path = response_clause_dir / "test-matrix.json"
    response_clause_coverage_path = response_clause_dir / "requirement-coverage.json"
    response_clause_requirement_path.write_text(
        "- POST /api/orders returns 201, response includes order_id, and persists order_123 in the database.",
        encoding="utf-8",
    )
    write_json(
        response_clause_matrix_path,
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1",
                    "text": "POST /api/orders returns 201.",
                    "test_ids": ["T1"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "api",
                    "expected": "POST /api/orders returns 201.",
                    "status": "Untested",
                }
            ],
        },
    )
    response_clause_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(response_clause_requirement_path),
            "--matrix",
            str(response_clause_matrix_path),
            "--out",
            str(response_clause_coverage_path),
        ],
        cwd=response_clause_dir,
        text=True,
        capture_output=True,
    )
    assert_true(response_clause_coverage_proc.returncode != 0, "response field and persistence clauses must not be covered by only the status-code row.")
    response_clause_coverage = load_json(response_clause_coverage_path)
    assert_true(response_clause_coverage.get("requirement_unit_count") == 3, "coverage should split response-field clauses from status and persistence clauses.")
    assert_true(response_clause_coverage.get("covered_count") == 1, "only the status-code clause should be covered.")
    assert_true(response_clause_coverage.get("uncovered_count") == 2, "response-field and persistence clauses should remain uncovered.")
    response_clause_errors = "\n".join(response_clause_coverage.get("errors", []))
    assert_true("response includes order_id" in response_clause_errors, "coverage errors should name the uncovered response-field behavior.")
    assert_true("persists order_123" in response_clause_errors, "coverage errors should name the uncovered order persistence behavior.")

    and_response_clause_dir = tmp_path / "and-response-clause-source-coverage"
    and_response_clause_dir.mkdir(parents=True, exist_ok=True)
    and_response_clause_requirement_path = and_response_clause_dir / "requirement.md"
    and_response_clause_matrix_path = and_response_clause_dir / "test-matrix.json"
    and_response_clause_coverage_path = and_response_clause_dir / "requirement-coverage.json"
    and_response_clause_requirement_path.write_text(
        "- POST /api/orders returns 201 and response includes order_id and persists order_123 in the database.",
        encoding="utf-8",
    )
    write_json(
        and_response_clause_matrix_path,
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1",
                    "text": "POST /api/orders returns 201.",
                    "test_ids": ["T1"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "api",
                    "expected": "POST /api/orders returns 201.",
                    "status": "Untested",
                }
            ],
        },
    )
    and_response_clause_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(and_response_clause_requirement_path),
            "--matrix",
            str(and_response_clause_matrix_path),
            "--out",
            str(and_response_clause_coverage_path),
        ],
        cwd=and_response_clause_dir,
        text=True,
        capture_output=True,
    )
    assert_true(and_response_clause_coverage_proc.returncode != 0, "unpunctuated and-linked response and persistence clauses must not be covered by only the status-code row.")
    and_response_clause_coverage = load_json(and_response_clause_coverage_path)
    assert_true(and_response_clause_coverage.get("requirement_unit_count") == 3, "coverage should split and-linked response-field clauses from status and persistence clauses.")
    assert_true(and_response_clause_coverage.get("covered_count") == 1, "only the and-linked status-code clause should be covered.")
    assert_true(and_response_clause_coverage.get("uncovered_count") == 2, "and-linked response-field and persistence clauses should remain uncovered.")
    and_response_clause_errors = "\n".join(and_response_clause_coverage.get("errors", []))
    assert_true("response includes order_id" in and_response_clause_errors, "coverage errors should name the uncovered and-linked response-field behavior.")
    assert_true("persists order_123" in and_response_clause_errors, "coverage errors should name the uncovered and-linked persistence behavior.")

    method_semicolon_clause_dir = tmp_path / "method-semicolon-clause-source-coverage"
    method_semicolon_clause_dir.mkdir(parents=True, exist_ok=True)
    method_semicolon_clause_requirement_path = method_semicolon_clause_dir / "requirement.md"
    method_semicolon_clause_matrix_path = method_semicolon_clause_dir / "test-matrix.json"
    method_semicolon_clause_coverage_path = method_semicolon_clause_dir / "requirement-coverage.json"
    method_semicolon_requirement_text = (
        "- Admin opens /orders and clicks Approve; POST /api/orders/{id}/approve returns 200 "
        "and writes audit_log row; viewer cannot approve and must see 403."
    )
    method_semicolon_clause_requirement_path.write_text(method_semicolon_requirement_text, encoding="utf-8")
    write_json(
        method_semicolon_clause_matrix_path,
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1 clause 1",
                    "text": "Admin opens /orders and clicks Approve.",
                    "test_ids": ["T1"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "ui",
                    "expected": "Admin opens /orders and clicks Approve.",
                    "status": "Untested",
                }
            ],
        },
    )
    method_semicolon_clause_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(method_semicolon_clause_requirement_path),
            "--matrix",
            str(method_semicolon_clause_matrix_path),
            "--out",
            str(method_semicolon_clause_coverage_path),
        ],
        cwd=method_semicolon_clause_dir,
        text=True,
        capture_output=True,
    )
    assert_true(method_semicolon_clause_coverage_proc.returncode != 0, "API-method semicolon clauses must not collapse into one covered source unit.")
    method_semicolon_clause_coverage = load_json(method_semicolon_clause_coverage_path)
    assert_true(method_semicolon_clause_coverage.get("requirement_unit_count") == 4, "coverage should split UI, API response, persistence, and denied-viewer clauses.")
    assert_true(method_semicolon_clause_coverage.get("covered_count") == 1, "only the UI clause should be covered by the partial matrix.")
    assert_true(method_semicolon_clause_coverage.get("uncovered_count") == 3, "API response, persistence, and permission clauses should remain uncovered.")
    method_semicolon_errors = "\n".join(method_semicolon_clause_coverage.get("errors", []))
    assert_true("POST /api/orders/{id}/approve returns 200" in method_semicolon_errors, "coverage errors should name the uncovered API-method clause.")
    assert_true("writes audit_log row" in method_semicolon_errors, "coverage errors should name the uncovered persistence clause.")
    assert_true("viewer cannot approve" in method_semicolon_errors, "coverage errors should name the uncovered permission clause.")

    method_semicolon_scaffold_dir = tmp_path / "method-semicolon-clause-scaffold"
    method_semicolon_scaffold_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(method_semicolon_clause_requirement_path),
            "--run-dir",
            str(method_semicolon_scaffold_dir),
            "--base-url",
            "http://127.0.0.1:3000",
        ],
        cwd=method_semicolon_clause_dir,
        text=True,
        capture_output=True,
    )
    assert_true(method_semicolon_scaffold_proc.returncode == 0, "scaffold should handle API-method semicolon clauses.")
    method_semicolon_scaffold_matrix = load_json(method_semicolon_scaffold_dir / "test-matrix.json")
    method_semicolon_scaffold_reqs = method_semicolon_scaffold_matrix.get("requirements", [])
    assert_true(len(method_semicolon_scaffold_reqs) == 4, "scaffold should model each API-method semicolon clause separately.")
    method_semicolon_scaffold_text = "\n".join(str(req.get("text", "")) for req in method_semicolon_scaffold_reqs)
    assert_true("POST /api/orders/{id}/approve returns 200" in method_semicolon_scaffold_text, "scaffold matrix should contain the API-method clause.")
    assert_true("writes audit_log row" in method_semicolon_scaffold_text, "scaffold matrix should contain the persistence clause.")
    assert_true("viewer cannot approve" in method_semicolon_scaffold_text, "scaffold matrix should contain the permission clause.")
    method_semicolon_scaffold_coverage_path = method_semicolon_scaffold_dir / "requirement-coverage.json"
    method_semicolon_scaffold_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(method_semicolon_scaffold_dir / "requirement.md"),
            "--matrix",
            str(method_semicolon_scaffold_dir / "test-matrix.json"),
            "--out",
            str(method_semicolon_scaffold_coverage_path),
        ],
        cwd=method_semicolon_scaffold_dir,
        text=True,
        capture_output=True,
    )
    assert_true(method_semicolon_scaffold_coverage_proc.returncode == 0, "scaffolded API-method semicolon clauses should pass source coverage.")
    method_semicolon_scaffold_coverage = load_json(method_semicolon_scaffold_coverage_path)
    assert_true(method_semicolon_scaffold_coverage.get("requirement_unit_count") == 4, "scaffolded API-method semicolon coverage should audit four source units.")
    assert_true(method_semicolon_scaffold_coverage.get("covered_count") == 4, "scaffolded API-method semicolon coverage should cover all four source units.")
    assert_true(method_semicolon_scaffold_coverage.get("uncovered_count") == 0, "scaffolded API-method semicolon coverage should not leave source units uncovered.")

    cn_response_clause_dir = tmp_path / "cn-response-clause-source-coverage"
    cn_response_clause_dir.mkdir(parents=True, exist_ok=True)
    cn_response_clause_requirement_path = cn_response_clause_dir / "requirement.md"
    cn_response_clause_matrix_path = cn_response_clause_dir / "test-matrix.json"
    cn_response_clause_coverage_path = cn_response_clause_dir / "requirement-coverage.json"
    cn_response_clause_requirement_path.write_text(
        "- 提交订单时 POST /api/orders 返回 201，响应包含 order_id，并写入订单库。",
        encoding="utf-8",
    )
    write_json(
        cn_response_clause_matrix_path,
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1",
                    "text": "提交订单时 POST /api/orders 返回 201。",
                    "test_ids": ["T1"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "api",
                    "expected": "POST /api/orders returns 201.",
                    "status": "Untested",
                }
            ],
        },
    )
    cn_response_clause_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(cn_response_clause_requirement_path),
            "--matrix",
            str(cn_response_clause_matrix_path),
            "--out",
            str(cn_response_clause_coverage_path),
        ],
        cwd=cn_response_clause_dir,
        text=True,
        capture_output=True,
    )
    assert_true(cn_response_clause_coverage_proc.returncode != 0, "Chinese response field and persistence clauses must not be covered by only the status-code row.")
    cn_response_clause_coverage = load_json(cn_response_clause_coverage_path)
    assert_true(cn_response_clause_coverage.get("requirement_unit_count") == 3, "Chinese coverage should split response-field clauses from status and persistence clauses.")
    assert_true(cn_response_clause_coverage.get("covered_count") == 1, "only the Chinese status-code clause should be covered.")
    assert_true(cn_response_clause_coverage.get("uncovered_count") == 2, "Chinese response-field and persistence clauses should remain uncovered.")
    cn_response_clause_errors = "\n".join(cn_response_clause_coverage.get("errors", []))
    assert_true("响应包含 order_id" in cn_response_clause_errors, "coverage errors should name the uncovered Chinese response-field behavior.")
    assert_true("写入订单库" in cn_response_clause_errors, "coverage errors should name the uncovered Chinese persistence behavior.")

    cn_joined_response_clause_dir = tmp_path / "cn-joined-response-clause-source-coverage"
    cn_joined_response_clause_dir.mkdir(parents=True, exist_ok=True)
    cn_joined_response_clause_requirement_path = cn_joined_response_clause_dir / "requirement.md"
    cn_joined_response_clause_matrix_path = cn_joined_response_clause_dir / "test-matrix.json"
    cn_joined_response_clause_coverage_path = cn_joined_response_clause_dir / "requirement-coverage.json"
    cn_joined_response_clause_requirement_path.write_text(
        "- 提交订单时 POST /api/orders 返回 201并响应包含 order_id并写入订单库。",
        encoding="utf-8",
    )
    write_json(
        cn_joined_response_clause_matrix_path,
        {
            "schemaVersion": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1",
                    "text": "提交订单时 POST /api/orders 返回 201。",
                    "test_ids": ["T1"],
                    "status": "Untested",
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "api",
                    "expected": "POST /api/orders returns 201.",
                    "status": "Untested",
                }
            ],
        },
    )
    cn_joined_response_clause_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(cn_joined_response_clause_requirement_path),
            "--matrix",
            str(cn_joined_response_clause_matrix_path),
            "--out",
            str(cn_joined_response_clause_coverage_path),
        ],
        cwd=cn_joined_response_clause_dir,
        text=True,
        capture_output=True,
    )
    assert_true(cn_joined_response_clause_coverage_proc.returncode != 0, "Chinese joined response and persistence clauses must not be covered by only the status-code row.")
    cn_joined_response_clause_coverage = load_json(cn_joined_response_clause_coverage_path)
    assert_true(cn_joined_response_clause_coverage.get("requirement_unit_count") == 3, "Chinese coverage should split joined response-field clauses from status and persistence clauses.")
    assert_true(cn_joined_response_clause_coverage.get("covered_count") == 1, "only the Chinese joined status-code clause should be covered.")
    assert_true(cn_joined_response_clause_coverage.get("uncovered_count") == 2, "Chinese joined response-field and persistence clauses should remain uncovered.")
    cn_joined_response_clause_errors = "\n".join(cn_joined_response_clause_coverage.get("errors", []))
    assert_true("响应包含 order_id" in cn_joined_response_clause_errors, "coverage errors should name the uncovered Chinese joined response-field behavior.")
    assert_true("写入订单库" in cn_joined_response_clause_errors, "coverage errors should name the uncovered Chinese joined persistence behavior.")

def _verify_long_requirement_sources(script_dir: Path, tmp_path: Path) -> None:
    long_dir = tmp_path / "long-source-coverage"
    long_dir.mkdir(parents=True, exist_ok=True)
    long_requirement_path = long_dir / "requirement.md"
    long_matrix_path = long_dir / "test-matrix.json"
    long_coverage_path = long_dir / "requirement-coverage.json"
    long_capped_coverage_path = long_dir / "requirement-coverage-capped.json"
    long_requirement_lines = [
        f"- Requirement item {index:03d} must be covered by test T{index:03d}."
        for index in range(1, 86)
    ]
    long_requirement_path.write_text("\n".join(long_requirement_lines), encoding="utf-8")
    long_requirements = []
    long_tests = []
    for index in range(1, 81):
        req_id = f"R{index:03d}"
        test_id = f"T{index:03d}"
        text = f"Requirement item {index:03d} must be covered by test T{index:03d}."
        long_requirements.append({
            "id": req_id,
            "source": f"line {index}",
            "text": text,
            "test_ids": [test_id],
            "status": "Passed",
        })
        long_tests.append({
            "id": test_id,
            "requirement_ids": [req_id],
            "type": "logic",
            "expected": text,
            "status": "Passed",
        })
    write_json(
        long_matrix_path,
        {"schemaVersion": 2, "requirements": long_requirements, "tests": long_tests},
    )
    long_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(long_requirement_path),
            "--matrix",
            str(long_matrix_path),
            "--out",
            str(long_coverage_path),
        ],
        cwd=long_dir,
        text=True,
        capture_output=True,
    )
    assert_true(long_coverage_proc.returncode != 0, "coverage audit must fail when long requirement sources have unmapped trailing units.")
    long_coverage = load_json(long_coverage_path)
    assert_true(long_coverage.get("requirement_unit_count") == 85, "default coverage audit should inspect all 85 source units, not silently cap at 80.")
    assert_true(long_coverage.get("source_unit_total_count") == 85, "coverage artifact should expose the full source unit count.")
    assert_true(long_coverage.get("source_unit_omitted_count") == 0, "default coverage audit should not omit source units.")
    assert_true(long_coverage.get("covered_count") == 80, "first 80 long source units should be covered by the matrix.")
    assert_true(long_coverage.get("uncovered_count") == 5, "trailing long source units should remain uncovered instead of disappearing.")
    assert_true(long_coverage.get("passed") is False, "long source coverage must not pass while trailing units are unmapped.")
    long_errors = "\n".join(long_coverage.get("errors", []))
    assert_true("S81 (line 81)" in long_errors, "coverage errors should name the first omitted-by-old-cap trailing requirement.")

    long_capped_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(long_requirement_path),
            "--matrix",
            str(long_matrix_path),
            "--out",
            str(long_capped_coverage_path),
            "--max-units",
            "80",
            "--allow-unmapped-source",
        ],
        cwd=long_dir,
        text=True,
        capture_output=True,
    )
    assert_true(long_capped_proc.returncode == 0, "--allow-unmapped-source should allow capped coverage handoff without claiming pass.")
    long_capped_coverage = load_json(long_capped_coverage_path)
    assert_true(long_capped_coverage.get("source_units_truncated") is True, "explicitly capped coverage should disclose truncation.")
    assert_true(long_capped_coverage.get("source_unit_total_count") == 85, "explicitly capped coverage should preserve the total source unit count.")
    assert_true(long_capped_coverage.get("source_unit_omitted_count") == 5, "explicitly capped coverage should preserve the omitted source unit count.")
    assert_true(long_capped_coverage.get("passed") is False, "explicitly capped coverage must not pass when source units were omitted.")
    assert_true(long_capped_coverage.get("execution_allowed") is True, "allow-unmapped-source should only allow continuation for capped coverage.")
    capped_messages = "\n".join(long_capped_coverage.get("warnings", []) + long_capped_coverage.get("errors", []))
    assert_true("--max-units=80" in capped_messages, "capped coverage artifact should explain the max-units truncation.")

    long_scaffold_dir = tmp_path / "long-source-scaffold"
    long_scaffold_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "scaffold_requirement.py"),
            "--requirement-file",
            str(long_requirement_path),
            "--run-dir",
            str(long_scaffold_dir),
            "--base-url",
            "http://127.0.0.1:3000",
        ],
        cwd=long_dir,
        text=True,
        capture_output=True,
    )
    assert_true(long_scaffold_proc.returncode == 0, "scaffold should generate artifacts for long explicit requirement lists.")
    long_scaffold_matrix = load_json(long_scaffold_dir / "test-matrix.json")
    long_scaffold_summary = load_json(long_scaffold_dir / "scaffold-summary.json")
    long_scaffold_requirements = long_scaffold_matrix.get("requirements", [])
    assert_true(len(long_scaffold_requirements) == 85, "scaffold should model every explicit long requirement source unit, not only the first 24.")
    assert_true(long_scaffold_summary.get("requirement_count") == 85, "scaffold summary should report all explicit long requirement source units.")
    assert_true(
        any("line 85" in req.get("source", "") and "Requirement item 085" in req.get("text", "") for req in long_scaffold_requirements),
        "scaffold matrix should include the trailing long requirement source unit.",
    )
    long_scaffold_coverage_path = long_scaffold_dir / "requirement-coverage.json"
    long_scaffold_coverage_proc = subprocess.run(
        [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(long_scaffold_dir / "requirement.md"),
            "--matrix",
            str(long_scaffold_dir / "test-matrix.json"),
            "--out",
            str(long_scaffold_coverage_path),
        ],
        cwd=long_scaffold_dir,
        text=True,
        capture_output=True,
    )
    assert_true(long_scaffold_coverage_proc.returncode == 0, "coverage audit should pass for a scaffold that models every explicit long source unit.")
    long_scaffold_coverage = load_json(long_scaffold_coverage_path)
    assert_true(long_scaffold_coverage.get("requirement_unit_count") == 85, "scaffolded long source coverage should audit all 85 units.")
    assert_true(long_scaffold_coverage.get("covered_count") == 85, "scaffolded long source coverage should cover all 85 units.")
    assert_true(long_scaffold_coverage.get("uncovered_count") == 0, "scaffolded long source coverage should not leave trailing units uncovered.")
    assert_true(long_scaffold_coverage.get("passed") is True, "scaffolded long source coverage should pass once every unit is modeled.")

def _verify_unmapped_verdict_gate(
    script_dir: Path,
    tmp_path: Path,
    gate_dir: Path,
    coverage_path: Path,
) -> None:
    write_json(
        gate_dir / "evidence-ledger.json",
        {
            "schema_version": 2,
            "requirements": [
                {
                    "id": "R1",
                    "source": "line 1",
                    "text": "Users can open /settings.",
                    "test_ids": ["T1"],
                    "status": "Passed",
                    "evidence_ids": ["E1"],
                }
            ],
            "tests": [
                {
                    "id": "T1",
                    "requirement_ids": ["R1"],
                    "type": "ui",
                    "expected": "Users can open /settings.",
                    "status": "Passed",
                    "evidence_ids": ["E1"],
                }
            ],
            "evidence": [
                {
                    "id": "E1",
                    "type": "ui_assertion",
                    "value": "settings opened",
                    "current_run": True,
                    "assertions": ["Settings opened."],
                    "proves": "Settings opened.",
                }
            ],
        },
    )
    write_json(
        gate_dir / "audit-summary.json",
        {
            "schema_version": 1,
            "passed": True,
            "errors": [],
            "warnings": [],
            "status_counts": {"Passed": 1, "Failed": 0, "Blocked": 0, "Untested": 0, "Inconclusive": 0},
        },
    )
    run_cmd(
        [
            sys.executable,
            str(script_dir / "generate_verdict.py"),
            "--ledger",
            str(gate_dir / "evidence-ledger.json"),
            "--audit-summary",
            str(gate_dir / "audit-summary.json"),
            "--requirement-coverage",
            str(coverage_path),
            "--out",
            str(gate_dir / "qa-verdict.json"),
        ],
        cwd=gate_dir,
    )
    verdict = load_json(gate_dir / "qa-verdict.json")
    reason_codes = {reason.get("code") for reason in verdict.get("reasons", []) if isinstance(reason, dict)}
    assert_true(verdict.get("gates", {}).get("requirement_source_covered") is False, "verdict gate must stay false when source units remain unmapped.")
    assert_true("requirement_source_unmapped" in reason_codes, "verdict must preserve unmapped-source as a pass-blocking reason.")
    assert_true(verdict.get("can_claim_pass") is False, "unmapped source must still block final pass claims.")

_SOURCE_COVERAGE_FAMILIES: tuple[Callable[[Path, Path], None], ...] = (
    _verify_paragraph_and_command_units,
    _verify_behavior_and_response_clauses,
    _verify_long_requirement_sources,
)

def run_unmapped_source_allow_gate_fixture(
    script_dir: Path,
    tmp_path: Path,
) -> None:
    """按协议族验证需求源覆盖，并保留原公开夹具入口。"""
    gate_dir, coverage_path = _verify_unmapped_allow_gate(script_dir, tmp_path)
    for family in _SOURCE_COVERAGE_FAMILIES:
        try:
            family(script_dir, tmp_path)
        except AssertionError as exc:
            raise AssertionError(f"{family.__name__}: {exc}") from exc
    _verify_unmapped_verdict_gate(
        script_dir,
        tmp_path,
        gate_dir,
        coverage_path,
    )
