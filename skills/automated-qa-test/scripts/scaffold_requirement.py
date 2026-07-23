#!/usr/bin/env python3

"""兼容原有脚手架 CLI 与 Python 导入入口。"""

import argparse
from pathlib import Path

from qa_common import atomic_write_json, atomic_write_text
from qa_scaffold import (
    build_business_model,
    build_closeout_candidates,
    build_oracle_model,
    build_qa_metrics,
    has_secret_exposure_command,
    input_error_artifacts,
    scaffold,
    split_shell_script_parts,
)
from scaffold_artifacts import attach_scaffold_summary_bindings, load_text, try_read_text, write_semantic_artifacts

__all__ = [
    "build_business_model",
    "build_closeout_candidates",
    "build_oracle_model",
    "build_qa_metrics",
    "has_secret_exposure_command",
    "input_error_artifacts",
    "scaffold",
    "split_shell_script_parts",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Scaffold a QA charter, matrix, and probe plan from requirement text.")
    parser.add_argument("--requirement-file")
    parser.add_argument("--requirement-text")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument("--entry-path", help="Optional user-facing entry path to use when requirements mention UI but no route.")
    parser.add_argument("--persistence-command", help="Project-approved read-only persistence/log helper command.")
    parser.add_argument("--allow-live-stream", action="store_true", help="Allow scaffolded WebSocket probes when a stream endpoint is present.")
    parser.add_argument("--allow-mutating-api", action="store_true", help="Allow mutating API methods in generated probes. Use only with safe test data.")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "screenshots").mkdir(exist_ok=True)
    (run_dir / "evidence").mkdir(exist_ok=True)
    requirement, input_errors = load_text(args.requirement_file, args.requirement_text)
    if not requirement and (run_dir / "requirement.md").exists():
        existing_requirement, existing_error = try_read_text(run_dir / "requirement.md")
        if existing_error:
            input_errors.append({"name": "requirement", "path": str(run_dir / "requirement.md"), "error": existing_error})
        else:
            requirement = existing_requirement or ""
    atomic_write_text(run_dir / "requirement.md", requirement or "Requirement source was not provided.\n")

    if input_errors:
        artifacts = input_error_artifacts(args.base_url, run_dir, input_errors)
    else:
        artifacts = scaffold(
            requirement=requirement,
            base_url=args.base_url,
            artifact_dir=run_dir,
            entry_path=args.entry_path,
            persistence_command=args.persistence_command,
            allow_live_stream=args.allow_live_stream,
            allow_mutating_api=args.allow_mutating_api,
        )
    atomic_write_text(run_dir / "test-charter.md", artifacts["charter"])
    atomic_write_json(run_dir / "test-matrix.json", artifacts["matrix"])
    atomic_write_json(run_dir / "test-plan.json", artifacts["plan"])
    attach_scaffold_summary_bindings(run_dir, artifacts["summary"])
    atomic_write_json(run_dir / "scaffold-summary.json", artifacts["summary"])
    write_semantic_artifacts(run_dir, artifacts)
    print(run_dir)
    return 1 if input_errors else 0

if __name__ == "__main__":
    raise SystemExit(main())
