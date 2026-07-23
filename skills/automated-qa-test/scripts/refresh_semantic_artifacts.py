#!/usr/bin/env python3
import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from qa_common import atomic_write_json
from scaffold_artifacts import source_binding, try_read_text, write_semantic_artifacts
from scaffold_requirement import (
    build_business_model,
    build_closeout_candidates,
    build_oracle_model,
    build_qa_metrics,
)


def try_load_json(path: Path) -> tuple[dict[str, Any], str | None]:
    if not path.exists():
        return {}, "missing"
    if path.is_dir():
        return {}, "path_is_directory"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {}, f"invalid_json: {exc.msg}"
    except OSError as exc:
        return {}, f"read_error: {exc}"
    if not isinstance(value, dict):
        return {}, "json_root_not_object"
    return value, None


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def plan_steps(plan: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for scenario in as_list(plan.get("scenarios")):
        if not isinstance(scenario, dict):
            continue
        for step in as_list(scenario.get("steps")):
            if isinstance(step, dict):
                steps.append(step)
    return steps


def binding_sha(summary: dict[str, Any], name: str) -> str | None:
    bindings = summary.get("source_bindings") if isinstance(summary.get("source_bindings"), dict) else {}
    binding = bindings.get(name) if isinstance(bindings.get(name), dict) else {}
    value = binding.get("sha256")
    return value if isinstance(value, str) and value else None


def scaffold_summary_current(summary: dict[str, Any], matrix_path: Path, plan_path: Path) -> bool:
    return (
        binding_sha(summary, "matrix") == source_binding(matrix_path, "test_matrix").get("sha256")
        and binding_sha(summary, "plan") == source_binding(plan_path, "test_plan").get("sha256")
    )


def coverage_gaps(run_dir: Path, matrix: dict[str, Any], matrix_path: Path, plan_path: Path, warnings: list[dict[str, str]]) -> list[str]:
    summary, load_error = try_load_json(run_dir / "scaffold-summary.json")
    if not load_error:
        gaps = summary.get("coverage_gaps")
        if isinstance(gaps, list):
            if scaffold_summary_current(summary, matrix_path, plan_path):
                return [str(gap) for gap in gaps if str(gap).strip()]
            if any(str(gap).strip() for gap in gaps):
                warnings.append({
                    "name": "scaffold-summary",
                    "path": str(run_dir / "scaffold-summary.json"),
                    "warning": "stale_or_unbound_coverage_gaps_ignored",
                })
    gaps: list[str] = []
    for test in as_list(matrix.get("tests")):
        if not isinstance(test, dict) or test.get("status") != "Blocked":
            continue
        test_id = str(test.get("id") or "unknown")
        notes = str(test.get("notes") or "blocked test lacks executable evidence inputs")
        gaps.append(f"{test_id}: {notes}")
    return gaps


def write_summary(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_json(path, payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh semantic planning artifacts from the current requirement, matrix, and plan.")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--requirement")
    parser.add_argument("--matrix")
    parser.add_argument("--plan")
    parser.add_argument("--out-summary")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    requirement_path = Path(args.requirement).expanduser().resolve() if args.requirement else run_dir / "requirement.md"
    matrix_path = Path(args.matrix).expanduser().resolve() if args.matrix else run_dir / "test-matrix.json"
    plan_path = Path(args.plan).expanduser().resolve() if args.plan else run_dir / "test-plan.json"
    summary_path = Path(args.out_summary).expanduser().resolve() if args.out_summary else run_dir / "semantic-artifacts-summary.json"

    input_errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    requirement_text, requirement_error = try_read_text(requirement_path)
    if requirement_error:
        warnings.append({"name": "requirement", "path": str(requirement_path), "warning": requirement_error})
        requirement_text = ""
    matrix, matrix_error = try_load_json(matrix_path)
    if matrix_error:
        input_errors.append({"name": "matrix", "path": str(matrix_path), "error": matrix_error})
    plan, plan_error = try_load_json(plan_path)
    if plan_error:
        input_errors.append({"name": "plan", "path": str(plan_path), "error": plan_error})

    if input_errors:
        write_summary(summary_path, {
            "schema_version": 1,
            "status": "blocked",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "input_artifact_errors": input_errors,
            "warnings": warnings,
        })
        print(summary_path)
        return 1

    requirements = [item for item in as_list(matrix.get("requirements")) if isinstance(item, dict)]
    tests = [item for item in as_list(matrix.get("tests")) if isinstance(item, dict)]
    steps = plan_steps(plan)
    gaps = coverage_gaps(run_dir, matrix, matrix_path, plan_path, warnings)

    business_model = build_business_model(requirement_text or "", requirements, tests, gaps)
    oracle_model = build_oracle_model(requirements, tests)
    qa_metrics = build_qa_metrics(requirements, tests, steps, gaps, business_model, oracle_model)
    closeout_candidates = build_closeout_candidates(business_model, oracle_model, gaps)
    artifacts = {
        "business_model": business_model,
        "oracle_model": oracle_model,
        "qa_metrics": qa_metrics,
        "closeout_candidates": closeout_candidates,
    }
    write_semantic_artifacts(run_dir, artifacts)

    write_summary(summary_path, {
        "schema_version": 1,
        "status": "refreshed",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_bindings": {
            "requirement": source_binding(requirement_path, "requirement_source"),
            "matrix": source_binding(matrix_path, "test_matrix"),
            "plan": source_binding(plan_path, "test_plan"),
            "business_model": source_binding(run_dir / "business-model.json", "business_planning_context"),
            "oracle_model": source_binding(run_dir / "oracle-model.json", "oracle_contract_context"),
            "qa_metrics": source_binding(run_dir / "qa-metrics.json", "qa_planning_metrics"),
            "closeout_candidates": source_binding(run_dir / "closeout-candidates.json", "human_confirmed_closeout_candidates"),
        },
        "summary": {
            "requirement_count": len(requirements),
            "test_count": len(tests),
            "planned_step_count": len(steps),
            "coverage_gap_count": len(gaps),
            "business_model": business_model.get("summary", {}),
            "oracle_model": oracle_model.get("summary", {}),
            "qa_metrics": qa_metrics.get("summary", {}),
        },
        "input_artifact_errors": [],
        "warnings": warnings,
    })
    print(summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
