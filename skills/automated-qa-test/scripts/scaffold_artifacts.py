#!/usr/bin/env python3
from pathlib import Path
from typing import Any

from qa_common import atomic_write_json, file_sha256

SEMANTIC_ARTIFACTS_NOT_EVIDENCE = "Planning/oracle/metrics handoff only; not current-run proof."


def try_read_text(path: Path) -> tuple[str | None, str | None]:
    if not path.exists():
        return None, "missing"
    if path.is_dir():
        return None, "path_is_directory"
    try:
        return path.read_text(encoding="utf-8"), None
    except OSError as exc:
        return None, f"read_error: {exc}"


def source_binding(path: Path, role: str) -> dict[str, Any]:
    return {
        "role": role,
        "path": str(path),
        "exists": path.exists() and not path.is_dir(),
        "sha256": file_sha256(path),
        "size_bytes": path.stat().st_size if path.exists() and not path.is_dir() else None,
    }


def attach_semantic_integrity(
    artifact: dict[str, Any],
    *,
    role: str,
    bindings: dict[str, dict[str, Any]],
) -> None:
    artifact["artifact_role"] = role
    artifact["not_evidence"] = True
    artifact["integrity_note"] = SEMANTIC_ARTIFACTS_NOT_EVIDENCE
    artifact["source_bindings"] = bindings


def write_semantic_artifacts(run_dir: Path, artifacts: dict[str, Any]) -> None:
    requirement_path = run_dir / "requirement.md"
    matrix_path = run_dir / "test-matrix.json"
    plan_path = run_dir / "test-plan.json"
    base_bindings = {
        "requirement": source_binding(requirement_path, "requirement_source"),
        "matrix": source_binding(matrix_path, "test_matrix"),
        "plan": source_binding(plan_path, "test_plan"),
    }

    business_model = artifacts["business_model"]
    attach_semantic_integrity(business_model, role="business_planning_context", bindings=dict(base_bindings))
    atomic_write_json(run_dir / "business-model.json", business_model)

    oracle_model = artifacts["oracle_model"]
    oracle_bindings = dict(base_bindings)
    oracle_bindings["business_model"] = source_binding(run_dir / "business-model.json", "business_planning_context")
    attach_semantic_integrity(oracle_model, role="oracle_contract_context", bindings=oracle_bindings)
    atomic_write_json(run_dir / "oracle-model.json", oracle_model)

    qa_metrics = artifacts["qa_metrics"]
    metrics_bindings = dict(oracle_bindings)
    metrics_bindings["oracle_model"] = source_binding(run_dir / "oracle-model.json", "oracle_contract_context")
    attach_semantic_integrity(qa_metrics, role="qa_planning_metrics", bindings=metrics_bindings)
    atomic_write_json(run_dir / "qa-metrics.json", qa_metrics)

    closeout_candidates = artifacts["closeout_candidates"]
    closeout_bindings = dict(metrics_bindings)
    closeout_bindings["qa_metrics"] = source_binding(run_dir / "qa-metrics.json", "qa_planning_metrics")
    attach_semantic_integrity(closeout_candidates, role="human_confirmed_closeout_candidates", bindings=closeout_bindings)
    atomic_write_json(run_dir / "closeout-candidates.json", closeout_candidates)


def attach_scaffold_summary_bindings(run_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    summary["source_bindings"] = {
        "requirement": source_binding(run_dir / "requirement.md", "requirement_source"),
        "matrix": source_binding(run_dir / "test-matrix.json", "test_matrix"),
        "plan": source_binding(run_dir / "test-plan.json", "test_plan"),
    }
    return summary


def load_text(path: str | None, inline: str | None) -> tuple[str, list[dict[str, str]]]:
    parts: list[str] = []
    input_errors: list[dict[str, str]] = []
    if path:
        source_path = Path(path).expanduser()
        text, read_error = try_read_text(source_path)
        if read_error:
            input_errors.append({"name": "requirement", "path": str(source_path), "error": read_error})
        elif text is not None:
            parts.append(text)
    if inline:
        parts.append(inline)
    return "\n\n".join(part.strip() for part in parts if part and part.strip()), input_errors
