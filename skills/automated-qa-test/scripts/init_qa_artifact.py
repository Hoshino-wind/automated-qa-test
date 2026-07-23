#!/usr/bin/env python3
import argparse
import re
import tempfile
from datetime import datetime
from pathlib import Path

from discover_project_context import discover_context
from qa_common import atomic_write_json, atomic_write_text
from scaffold_artifacts import attach_scaffold_summary_bindings, try_read_text, write_semantic_artifacts
from scaffold_requirement import input_error_artifacts, scaffold


def slugify(text: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "-", text.strip().lower()).strip("-")
    return value[:48] or "requirement-qa"


def load_requirement(args: argparse.Namespace) -> tuple[str, list[dict[str, str]]]:
    parts = []
    input_errors: list[dict[str, str]] = []
    if args.requirement_file:
        source_path = Path(args.requirement_file).expanduser()
        text, read_error = try_read_text(source_path)
        if read_error:
            input_errors.append({"name": "requirement", "path": str(source_path), "error": read_error})
        elif text is not None:
            parts.append(text)
    if args.requirement_text:
        parts.append(args.requirement_text)
    return "\n\n".join(p.strip() for p in parts if p.strip()), input_errors


def seed_ledger_from_matrix(matrix: dict) -> dict:
    return {
        "schema_version": 2,
        "requirements": [{
            "id": item.get("id"),
            "source": item.get("source", "requirement.md"),
            "text": item.get("text", ""),
            "test_ids": item.get("test_ids", []),
            "status": item.get("status", "Untested"),
            "evidence_ids": [],
            "notes": "Initial scaffold entry. Execute probes before final reporting.",
        } for item in matrix.get("requirements", [])],
        "tests": [{
            "id": item.get("id"),
            "requirement_ids": item.get("requirement_ids", []),
            "type": item.get("type", "probe"),
            "expected": item.get("expected", ""),
            "status": item.get("status", "Untested"),
            "evidence_ids": [],
            "notes": "Initial scaffold entry. Execute probes before final reporting.",
        } for item in matrix.get("tests", [])],
        "evidence": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a requirement-driven QA artifact folder.")
    parser.add_argument("--requirement-file", help="Path to requirement, issue, or PR notes.")
    parser.add_argument("--requirement-text", help="Inline requirement text.")
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    parser.add_argument("--entry-path", help="Optional user-facing entry path for UI requirements without a route.")
    parser.add_argument("--persistence-command", help="Project-approved read-only persistence/log helper command.")
    parser.add_argument("--allow-live-stream", action="store_true", help="Allow scaffolded WebSocket probes when a stream endpoint is present.")
    parser.add_argument("--allow-mutating-api", action="store_true", help="Allow mutating API methods in generated probes. Use only with safe test data.")
    parser.add_argument("--project-root", default=".", help="Project checkout to inspect for adapter/environment context.")
    parser.add_argument("--runtime-mode", help="Declared runtime mode for adapter-context.json, such as local, test, staging, production, or ci.")
    parser.add_argument("--data-boundary-status", help="Declared data boundary for adapter-context.json, such as local seed data, test database, staging data, or production read-only.")
    parser.add_argument("--skip-adapter-context", action="store_true", help="Do not generate adapter-context.json.")
    parser.add_argument("--no-http-probe", action="store_true", help="Skip HTTP probes while generating adapter context.")
    parser.add_argument("--out-dir", default=str(Path(tempfile.gettempdir()) / "automated-qa-test"))
    parser.add_argument("--slug", help="Readable run slug.")
    args = parser.parse_args()

    requirement, requirement_input_errors = load_requirement(args)
    initialization_errors = list(requirement_input_errors)
    title_seed = args.slug or (requirement.splitlines()[0] if requirement else Path(args.requirement_file).stem if args.requirement_file else "requirement qa")
    run_id = f"{datetime.now().strftime('%Y-%m-%dT%H-%M-%S')}-{slugify(title_seed)}"
    run_dir = Path(args.out_dir).expanduser() / run_id
    screenshots = run_dir / "screenshots"
    evidence = run_dir / "evidence"
    screenshots.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)

    adapter_context = None
    if not args.skip_adapter_context and not requirement_input_errors:
        adapter_context = discover_context(
            project_root=Path(args.project_root),
            base_url=args.base_url,
            probe_http=not args.no_http_probe,
            runtime_mode=args.runtime_mode,
            data_boundary_status=args.data_boundary_status,
        )
        atomic_write_json(run_dir / "adapter-context.json", adapter_context)
        initialization_errors.extend(
            item for item in adapter_context.get("input_artifact_errors", [])
            if isinstance(item, dict)
        )

    atomic_write_text(run_dir / "requirement.md", requirement or "Requirement source was not provided.\n")
    if requirement_input_errors:
        artifacts = input_error_artifacts(args.base_url, run_dir, requirement_input_errors)
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
    if initialization_errors:
        artifacts["summary"]["status"] = "blocked"
        artifacts["summary"]["input_artifact_errors"] = initialization_errors
        artifacts["summary"].setdefault("coverage_gaps", []).extend(
            f"{item.get('name')} input is unreadable: {item.get('error')} ({item.get('path')})"
            for item in initialization_errors
            if isinstance(item, dict)
        )
        atomic_write_json(run_dir / "qa-initialization-error.json", {
            "schema_version": 1,
            "status": "blocked",
            "run_dir": str(run_dir),
            "input_artifact_errors": initialization_errors,
        })
    if adapter_context:
        artifacts["plan"].setdefault("metadata", {})["adapterContext"] = "adapter-context.json"
        artifacts["plan"]["metadata"]["adapter"] = adapter_context.get("adapter")
        artifacts["summary"]["adapter"] = adapter_context.get("adapter")
        artifacts["summary"]["adapter_context"] = "adapter-context.json"
    atomic_write_text(run_dir / "test-charter.md", artifacts["charter"])
    atomic_write_json(run_dir / "test-plan.json", artifacts["plan"])
    atomic_write_json(run_dir / "test-matrix.json", artifacts["matrix"])
    attach_scaffold_summary_bindings(run_dir, artifacts["summary"])
    atomic_write_json(run_dir / "scaffold-summary.json", artifacts["summary"])
    write_semantic_artifacts(run_dir, artifacts)
    atomic_write_json(run_dir / "evidence-ledger.json", seed_ledger_from_matrix(artifacts["matrix"]))

    print(run_dir)
    return 1 if initialization_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
