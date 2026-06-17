#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def try_load_json(path: Path) -> tuple[dict[str, Any], str | None]:
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


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def run_command(args: list[str], cwd: Path | None = None) -> dict[str, Any]:
    started_at = datetime.now().isoformat(timespec="seconds")
    proc = subprocess.run(args, cwd=str(cwd) if cwd else None, text=True, capture_output=True, env=os.environ.copy())
    return {
        "command": args,
        "cwd": str(cwd) if cwd else None,
        "started_at": started_at,
        "finished_at": datetime.now().isoformat(timespec="seconds"),
        "exit_code": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
    }


def add_step(summary: dict[str, Any], name: str, result: dict[str, Any]) -> None:
    item = {"name": name, **result}
    summary.setdefault("steps", []).append(item)


def discover_results_path(stdout: str) -> Path | None:
    for line in reversed((stdout or "").splitlines()):
        candidate = Path(line.strip()).expanduser()
        if candidate.name == "results.json" and candidate.exists():
            return candidate.resolve()
    return None


def make_skipped_results(plan_path: Path, run_dir: Path, reason: str) -> dict[str, Any]:
    plan = load_json(plan_path)
    now = datetime.now().isoformat(timespec="seconds")
    return {
        "schemaVersion": plan.get("schemaVersion", 2),
        "status": "skipped",
        "reason": reason,
        "artifactDir": str(run_dir),
        "startedAt": now,
        "finishedAt": now,
        "baseUrl": plan.get("baseUrl"),
        "scenarios": [
            {
                "id": scenario.get("id", f"scenario-{index}"),
                "title": scenario.get("title", ""),
                "status": "skipped",
                "steps": [],
            }
            for index, scenario in enumerate(plan.get("scenarios", []), 1)
        ],
        "console": [],
        "failedResponses": [],
        "requestFailures": [],
    }


def fail(summary: dict[str, Any], message: str, out_path: Path, *, status: str = "failed") -> int:
    summary["status"] = status
    summary["error"] = message
    summary["finished_at"] = datetime.now().isoformat(timespec="seconds")
    write_json(out_path, summary)
    print(out_path)
    print(message, file=sys.stderr)
    return 1


def clear_stale_terminal_outputs(summary: dict[str, Any], artifacts: list[tuple[str, Path]]) -> None:
    cleared: list[dict[str, str]] = []
    for name, path in artifacts:
        if not path.exists():
            continue
        artifact_kind = "directory" if path.is_dir() and not path.is_symlink() else "file"
        if artifact_kind == "directory":
            shutil.rmtree(path)
        else:
            path.unlink()
        cleared.append({"name": name, "path": str(path), "kind": artifact_kind})
    if cleared:
        summary["cleared_stale_outputs"] = cleared


def apply_environment_boundary_args(context_path: Path, runtime_mode: str | None, data_boundary_status: str | None) -> str | None:
    if not (runtime_mode or data_boundary_status) or not context_path.exists():
        return None
    context, load_error = try_load_json(context_path)
    if load_error:
        return load_error
    boundary = context.setdefault("environment_boundary", {})
    if runtime_mode:
        boundary["runtime_mode"] = runtime_mode
    if data_boundary_status:
        boundary["data_boundary_status"] = data_boundary_status
    write_json(context_path, context)
    return None


def is_runtime_disposition_only_audit_failure(audit_summary: dict[str, Any]) -> bool:
    errors = audit_summary.get("errors") if isinstance(audit_summary, dict) else []
    if not isinstance(errors, list) or not errors:
        return False
    return all("Missing runtime disposition" in str(error) for error in errors)


def is_current_artifact(path: Path, current_artifacts: set[Path]) -> bool:
    return path.exists() and path.resolve() in current_artifacts


def read_current_json_artifact(path: Path, current_artifacts: set[Path]) -> tuple[dict[str, Any], str | None]:
    if not path.exists():
        return {}, "missing_output"
    current_artifacts.add(path.resolve())
    return try_load_json(path)


def write_cycle_error(
    path: Path,
    *,
    code: str,
    phase: str,
    message: str,
    result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "code": code,
        "phase": phase,
        "message": message,
    }
    if result:
        payload["result"] = {
            key: result.get(key)
            for key in ("command", "cwd", "started_at", "finished_at", "exit_code", "stdout", "stderr")
            if key in result
        }
    write_json(path, payload)
    return payload


def write_minimal_error_verdict(verdict_path: Path, cycle_error_path: Path, *, code: str, phase: str, message: str) -> dict[str, Any]:
    verdict = {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "verdict": "inconclusive",
        "can_claim_pass": False,
        "statement": "Do not claim pass: the QA cycle could not produce a complete final verdict.",
        "status_counts": {status: 0 for status in ("Passed", "Failed", "Blocked", "Untested", "Inconclusive")},
        "runtime_issue_counts": {"console_errors": 0, "failed_responses": 0, "request_failures": 0, "total": 0},
        "gates": {
            "ledger_present": False,
            "audit_passed": False,
            "cycle_completed": False,
        },
        "reasons": [
            {
                "code": code,
                "category": "tooling",
                "severity": "gap",
                "message": f"QA cycle helper failed during {phase}: {message}",
                "refs": ["qa-cycle-error.json", str(cycle_error_path), str(phase)],
            }
        ],
        "inputs": {"cycle_error": str(cycle_error_path)},
    }
    write_json(verdict_path, verdict)
    return verdict


def generate_verdict_handoff(
    summary: dict[str, Any],
    *,
    script_dir: Path,
    run_dir: Path,
    ledger_path: Path,
    audit_summary_path: Path,
    results_path: Path,
    service_preflight_path: Path,
    service_runtime_path: Path,
    plan_audit_summary_path: Path,
    defects_path: Path,
    requirement_coverage_path: Path,
    adapter_context_path: Path,
    adapter_probes_path: Path,
    cycle_error_path: Path,
    verdict_path: Path,
    require_environment_boundary: bool,
    current_artifacts: set[Path],
) -> None:
    verdict_cmd = [
        sys.executable,
        str(script_dir / "generate_verdict.py"),
        "--out",
        str(verdict_path),
    ]
    omitted_stale: list[dict[str, str]] = []

    def add_current(flag: str, path: Path, *, allow_existing_input: bool = False) -> None:
        if allow_existing_input and path.exists():
            _, load_error = try_load_json(path)
            if load_error:
                omitted_stale.append({"flag": flag, "path": str(path), "reason": f"unreadable_input:{load_error}"})
                return
            verdict_cmd.extend([flag, str(path)])
            return
        if is_current_artifact(path, current_artifacts):
            verdict_cmd.extend([flag, str(path)])
            return
        if path.exists():
            omitted_stale.append({"flag": flag, "path": str(path), "reason": "not_produced_in_current_cycle"})

    add_current("--ledger", ledger_path)
    add_current("--audit-summary", audit_summary_path)
    optional_artifacts = [
        ("--results", results_path, False),
        ("--service-preflight", service_preflight_path, False),
        ("--service-runtime", service_runtime_path, False),
        ("--plan-audit-summary", plan_audit_summary_path, False),
        ("--defects", defects_path, False),
        ("--requirement-coverage", requirement_coverage_path, False),
        ("--adapter-context", adapter_context_path, True),
        ("--adapter-probes", adapter_probes_path, False),
        ("--cycle-error", cycle_error_path, False),
    ]
    for flag, path, allow_existing_input in optional_artifacts:
        add_current(flag, path, allow_existing_input=allow_existing_input)
    if omitted_stale:
        summary.setdefault("omitted_stale_handoff_artifacts", []).extend(omitted_stale)
    if require_environment_boundary:
        verdict_cmd.append("--require-environment-boundary")
    verdict_result = run_command(verdict_cmd, cwd=run_dir)
    add_step(summary, "generate_verdict_handoff", verdict_result)
    summary.setdefault("paths", {})["verdict"] = str(verdict_path) if verdict_path.exists() else None
    if verdict_path.exists():
        current_artifacts.add(verdict_path.resolve())
        verdict, load_error = try_load_json(verdict_path)
        if load_error:
            summary["verdict_load_error"] = {"path": str(verdict_path), "error": load_error}
        else:
            summary["verdict"] = verdict


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a complete QA probe cycle: validate plan, execute probe, build ledger, audit evidence, and generate report.")
    parser.add_argument("--run-dir", required=True, help="QA artifact directory containing test-plan.json and test-matrix.json")
    parser.add_argument("--plan", help="Defaults to <run-dir>/test-plan.json")
    parser.add_argument("--matrix", help="Defaults to <run-dir>/test-matrix.json")
    parser.add_argument("--requirement", help="Defaults to <run-dir>/requirement.md when present")
    parser.add_argument("--results", help="Defaults to <run-dir>/results.json")
    parser.add_argument("--ledger", help="Defaults to <run-dir>/evidence-ledger.json")
    parser.add_argument("--audit-summary", help="Defaults to <run-dir>/audit-summary.json")
    parser.add_argument("--requirement-coverage", help="Defaults to <run-dir>/requirement-coverage.json")
    parser.add_argument("--plan-audit-summary", help="Defaults to <run-dir>/plan-audit-summary.json")
    parser.add_argument("--adapter-context", help="Defaults to <run-dir>/adapter-context.json when present")
    parser.add_argument("--runtime-mode", help="Declared runtime mode to write into adapter-context.json, such as local, test, staging, production, or ci.")
    parser.add_argument("--data-boundary-status", help="Declared data boundary to write into adapter-context.json.")
    parser.add_argument("--adapter-probes", help="Defaults to <run-dir>/adapter-probes.json when present")
    parser.add_argument("--service-preflight", help="Defaults to <run-dir>/service-preflight.json when present")
    parser.add_argument("--service-runtime", help="Defaults to <run-dir>/service-runtime.json when service startup is used")
    parser.add_argument("--defects", help="Defaults to <run-dir>/defects.json")
    parser.add_argument("--next-probes", help="Defaults to <run-dir>/next-probes.json")
    parser.add_argument("--next-probe-application", help="Defaults to <run-dir>/next-probe-application.json")
    parser.add_argument("--business-model", help="Defaults to <run-dir>/business-model.json when present")
    parser.add_argument("--oracle-model", help="Defaults to <run-dir>/oracle-model.json when present")
    parser.add_argument("--qa-metrics", help="Defaults to <run-dir>/qa-metrics.json when present")
    parser.add_argument("--closeout-candidates", help="Defaults to <run-dir>/closeout-candidates.json when present")
    parser.add_argument("--semantic-artifacts-summary", help="Defaults to <run-dir>/semantic-artifacts-summary.json")
    parser.add_argument("--cycle-error", help="Defaults to <run-dir>/qa-cycle-error.json")
    parser.add_argument("--verdict", help="Defaults to <run-dir>/qa-verdict.json")
    parser.add_argument("--report", help="Defaults to <run-dir>/report.md")
    parser.add_argument("--summary", help="Defaults to <run-dir>/qa-run-summary.json")
    parser.add_argument("--node-bin", default="node")
    parser.add_argument("--strict-runtime", action="store_true")
    parser.add_argument("--require-environment-boundary", action="store_true", help="Require adapter-context.json with confirmed runtime/data boundary before final pass can be claimed.")
    parser.add_argument("--allow-unsafe-command", action="store_true")
    parser.add_argument("--skip-requirement-coverage", action="store_true", help="Skip requirement.md to test-matrix.json source coverage audit.")
    parser.add_argument("--allow-unmapped-requirement-source", action="store_true", help="Write requirement coverage warnings instead of failing for unmapped source units.")
    parser.add_argument("--preflight-runtime", action="store_true", help="Check required services/tooling before validation and execution.")
    parser.add_argument("--start-missing-services", action="store_true", help="Start missing required services from service-preflight.json start_plan after an initial preflight.")
    parser.add_argument("--service-start-timeout", type=float, default=60.0, help="Seconds to wait for each started service port.")
    parser.add_argument("--service-start-no-wait", action="store_true", help="Start missing services but do not wait for port readiness.")
    parser.add_argument("--allow-preflight-blockers", action="store_true", help="Continue even when service-preflight.json contains blockers.")
    parser.add_argument("--refresh-adapter-context", action="store_true", help="Re-probe adapter context during runtime preflight.")
    parser.add_argument("--synthesize-adapter-probes", action="store_true", help="Apply adapter-aware probes before plan validation.")
    parser.add_argument("--apply-next-probes", action="store_true", help="Apply existing safe next-probes.json recommendations before plan validation.")
    parser.add_argument("--allow-live-stream", action="store_true", help="Forwarded to synthesize_adapter_probes.py when enabled.")
    parser.add_argument("--allow-stopped-service", action="store_true", help="Forwarded to synthesize_adapter_probes.py when enabled.")
    parser.add_argument("--agent-id", help="Forwarded to synthesize_adapter_probes.py.")
    parser.add_argument("--user-id", help="Forwarded to synthesize_adapter_probes.py.")
    parser.add_argument("--marker", help="Forwarded to synthesize_adapter_probes.py.")
    parser.add_argument("--question", help="Forwarded to synthesize_adapter_probes.py.")
    parser.add_argument("--ws-path", help="Forwarded to synthesize_adapter_probes.py.")
    parser.add_argument("--session-detail-path", help="Forwarded to synthesize_adapter_probes.py.")
    parser.add_argument("--persistence-command", help="Forwarded to synthesize_adapter_probes.py. Must be read-only.")
    parser.add_argument("--allow-mutating-api-next-probes", action="store_true", help="Forwarded to apply_next_probes.py for explicitly safe test data only.")
    parser.add_argument("--project-root", help="Forwarded to preflight_runtime.py.")
    parser.add_argument("--required-service", action="append", help="Forwarded to preflight_runtime.py. May be repeated.")
    parser.add_argument("--skip-probe", action="store_true", help="Use an existing results.json, or write an explicit skipped-results stub when it is missing.")
    parser.add_argument("--skip-report", action="store_true")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    run_dir = Path(args.run_dir).expanduser().resolve()
    plan_path = Path(args.plan).expanduser().resolve() if args.plan else run_dir / "test-plan.json"
    matrix_path = Path(args.matrix).expanduser().resolve() if args.matrix else run_dir / "test-matrix.json"
    requirement_path = Path(args.requirement).expanduser().resolve() if args.requirement else run_dir / "requirement.md"
    results_path = Path(args.results).expanduser().resolve() if args.results else run_dir / "results.json"
    ledger_path = Path(args.ledger).expanduser().resolve() if args.ledger else run_dir / "evidence-ledger.json"
    audit_summary_path = Path(args.audit_summary).expanduser().resolve() if args.audit_summary else run_dir / "audit-summary.json"
    requirement_coverage_path = Path(args.requirement_coverage).expanduser().resolve() if args.requirement_coverage else run_dir / "requirement-coverage.json"
    plan_audit_summary_path = Path(args.plan_audit_summary).expanduser().resolve() if args.plan_audit_summary else run_dir / "plan-audit-summary.json"
    adapter_context_path = Path(args.adapter_context).expanduser().resolve() if args.adapter_context else run_dir / "adapter-context.json"
    adapter_probes_path = Path(args.adapter_probes).expanduser().resolve() if args.adapter_probes else run_dir / "adapter-probes.json"
    service_preflight_path = Path(args.service_preflight).expanduser().resolve() if args.service_preflight else run_dir / "service-preflight.json"
    service_runtime_path = Path(args.service_runtime).expanduser().resolve() if args.service_runtime else run_dir / "service-runtime.json"
    defects_path = Path(args.defects).expanduser().resolve() if args.defects else run_dir / "defects.json"
    next_probes_path = Path(args.next_probes).expanduser().resolve() if args.next_probes else run_dir / "next-probes.json"
    next_probe_application_path = Path(args.next_probe_application).expanduser().resolve() if args.next_probe_application else run_dir / "next-probe-application.json"
    business_model_path = Path(args.business_model).expanduser().resolve() if args.business_model else run_dir / "business-model.json"
    oracle_model_path = Path(args.oracle_model).expanduser().resolve() if args.oracle_model else run_dir / "oracle-model.json"
    qa_metrics_path = Path(args.qa_metrics).expanduser().resolve() if args.qa_metrics else run_dir / "qa-metrics.json"
    closeout_candidates_path = Path(args.closeout_candidates).expanduser().resolve() if args.closeout_candidates else run_dir / "closeout-candidates.json"
    semantic_artifacts_summary_path = Path(args.semantic_artifacts_summary).expanduser().resolve() if args.semantic_artifacts_summary else run_dir / "semantic-artifacts-summary.json"
    cycle_error_path = Path(args.cycle_error).expanduser().resolve() if args.cycle_error else run_dir / "qa-cycle-error.json"
    verdict_path = Path(args.verdict).expanduser().resolve() if args.verdict else run_dir / "qa-verdict.json"
    report_path = Path(args.report).expanduser().resolve() if args.report else run_dir / "report.md"
    summary_path = Path(args.summary).expanduser().resolve() if args.summary else run_dir / "qa-run-summary.json"
    run_dir.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {
        "schema_version": 1,
        "status": "running",
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "run_dir": str(run_dir),
        "paths": {
            "plan": str(plan_path),
            "matrix": str(matrix_path),
            "requirement": str(requirement_path) if requirement_path.exists() else None,
            "results": str(results_path),
            "ledger": str(ledger_path),
            "requirement_coverage": str(requirement_coverage_path),
            "defects": str(defects_path),
            "next_probes": str(next_probes_path),
            "next_probe_application": str(next_probe_application_path) if next_probe_application_path.exists() else None,
            "business_model": str(business_model_path) if business_model_path.exists() else None,
            "oracle_model": str(oracle_model_path) if oracle_model_path.exists() else None,
            "qa_metrics": str(qa_metrics_path) if qa_metrics_path.exists() else None,
            "closeout_candidates": str(closeout_candidates_path) if closeout_candidates_path.exists() else None,
            "semantic_artifacts_summary": str(semantic_artifacts_summary_path) if semantic_artifacts_summary_path.exists() else None,
            "cycle_error": str(cycle_error_path),
            "verdict": str(verdict_path),
            "adapter_context": str(adapter_context_path) if adapter_context_path.exists() else None,
            "adapter_probes": str(adapter_probes_path) if adapter_probes_path.exists() else None,
            "service_preflight": str(service_preflight_path) if service_preflight_path.exists() else None,
            "service_runtime": str(service_runtime_path) if service_runtime_path.exists() else None,
            "plan_audit_summary": str(plan_audit_summary_path),
            "audit_summary": str(audit_summary_path),
            "report": str(report_path) if not args.skip_report else None,
        },
        "steps": [],
    }
    clear_stale_terminal_outputs(summary, [("verdict", verdict_path), ("report", report_path), ("cycle_error", cycle_error_path)])
    write_json(summary_path, summary)
    current_artifacts: set[Path] = {summary_path.resolve()}

    def fail_with_cycle_handoff(message: str, *, phase: str, result: dict[str, Any] | None = None, code: str = "cycle_helper_failed") -> int:
        cycle_error = write_cycle_error(cycle_error_path, code=code, phase=phase, message=message, result=result)
        summary["cycle_error"] = cycle_error
        summary.setdefault("paths", {})["cycle_error"] = str(cycle_error_path)
        current_artifacts.add(cycle_error_path.resolve())
        generate_verdict_handoff(
            summary,
            script_dir=script_dir,
            run_dir=run_dir,
            ledger_path=ledger_path,
            audit_summary_path=audit_summary_path,
            results_path=results_path,
            service_preflight_path=service_preflight_path,
            service_runtime_path=service_runtime_path,
            plan_audit_summary_path=plan_audit_summary_path,
            defects_path=defects_path,
            requirement_coverage_path=requirement_coverage_path,
            adapter_context_path=adapter_context_path,
            adapter_probes_path=adapter_probes_path,
            cycle_error_path=cycle_error_path,
            verdict_path=verdict_path,
            require_environment_boundary=args.require_environment_boundary,
            current_artifacts=current_artifacts,
        )
        if not summary.get("verdict"):
            summary["verdict"] = write_minimal_error_verdict(
                verdict_path,
                cycle_error_path,
                code=code,
                phase=phase,
                message=message,
            )
            current_artifacts.add(verdict_path.resolve())
        status = (summary.get("verdict") or {}).get("verdict") or "inconclusive"
        return fail(summary, message, summary_path, status=status)

    if adapter_context_path.exists():
        _, adapter_context_load_error = try_load_json(adapter_context_path)
        if adapter_context_load_error:
            return fail_with_cycle_handoff(
                f"Invalid adapter context: {adapter_context_path} ({adapter_context_load_error}).",
                phase="adapter_context",
                code="invalid_adapter_context",
            )
    boundary_apply_error = apply_environment_boundary_args(adapter_context_path, args.runtime_mode, args.data_boundary_status)
    if boundary_apply_error:
        return fail_with_cycle_handoff(
            f"Invalid adapter context while applying environment boundary: {adapter_context_path} ({boundary_apply_error}).",
            phase="adapter_context",
            code="invalid_adapter_context",
        )
    if adapter_context_path.exists() and (args.runtime_mode or args.data_boundary_status):
        current_artifacts.add(adapter_context_path.resolve())

    for required_path, label in ((plan_path, "test plan"), (matrix_path, "test matrix")):
        if not required_path.exists():
            return fail_with_cycle_handoff(
                f"Missing {label}: {required_path}",
                phase="required_artifacts",
                code="missing_required_qa_artifact",
            )
        _, load_error = try_load_json(required_path)
        if load_error:
            return fail_with_cycle_handoff(
                f"Invalid {label}: {required_path} ({load_error}).",
                phase="required_artifacts",
                code="invalid_required_qa_artifact",
            )

    if requirement_path.exists() and not args.skip_requirement_coverage:
        coverage_cmd = [
            sys.executable,
            str(script_dir / "audit_requirement_coverage.py"),
            "--requirement",
            str(requirement_path),
            "--matrix",
            str(matrix_path),
            "--out",
            str(requirement_coverage_path),
        ]
        if args.allow_unmapped_requirement_source:
            coverage_cmd.append("--allow-unmapped-source")
        coverage_result = run_command(coverage_cmd, cwd=run_dir)
        add_step(summary, "audit_requirement_coverage", coverage_result)
        if requirement_coverage_path.exists() or coverage_result["exit_code"] == 0:
            requirement_coverage, coverage_load_error = read_current_json_artifact(requirement_coverage_path, current_artifacts)
            if coverage_load_error:
                return fail_with_cycle_handoff(
                    f"Requirement coverage artifact is unreadable after audit_requirement_coverage.py: {requirement_coverage_path} ({coverage_load_error}).",
                    phase="audit_requirement_coverage",
                    code="helper_output_unreadable",
                    result=coverage_result,
                )
            summary["requirement_coverage"] = requirement_coverage
        if coverage_result["exit_code"] != 0:
            generate_verdict_handoff(
                summary,
                script_dir=script_dir,
                run_dir=run_dir,
                ledger_path=ledger_path,
                audit_summary_path=audit_summary_path,
                results_path=results_path,
                service_preflight_path=service_preflight_path,
                service_runtime_path=service_runtime_path,
                plan_audit_summary_path=plan_audit_summary_path,
                defects_path=defects_path,
                requirement_coverage_path=requirement_coverage_path,
                adapter_context_path=adapter_context_path,
                adapter_probes_path=adapter_probes_path,
                cycle_error_path=cycle_error_path,
                verdict_path=verdict_path,
                require_environment_boundary=args.require_environment_boundary,
                current_artifacts=current_artifacts,
            )
            return fail(summary, "Requirement source coverage audit failed; map every requirement.md behavior point before executing probes.", summary_path, status="blocked")
    elif not requirement_path.exists():
        add_step(summary, "audit_requirement_coverage", {"skipped": True, "reason": "requirement file is missing", "exit_code": 0})
    else:
        add_step(summary, "audit_requirement_coverage", {"skipped": True, "reason": "--skip-requirement-coverage", "exit_code": 0})

    def build_preflight_cmd(*, fail_on_blockers: bool, refresh_context: bool) -> list[str]:
        cmd = [
            sys.executable,
            str(script_dir / "preflight_runtime.py"),
            "--run-dir",
            str(run_dir),
            "--plan",
            str(plan_path),
            "--out",
            str(service_preflight_path),
        ]
        if adapter_context_path.exists():
            cmd.extend(["--adapter-context", str(adapter_context_path)])
        if args.project_root:
            cmd.extend(["--project-root", args.project_root])
        if args.runtime_mode:
            cmd.extend(["--runtime-mode", args.runtime_mode])
        if args.data_boundary_status:
            cmd.extend(["--data-boundary-status", args.data_boundary_status])
        if refresh_context:
            cmd.append("--refresh-context")
        if args.allow_stopped_service:
            cmd.append("--allow-stopped-services")
        if fail_on_blockers:
            cmd.append("--fail-on-blockers")
        for service_id in args.required_service or []:
            cmd.extend(["--required-service", service_id])
        return cmd

    if args.preflight_runtime:
        preflight_cmd = build_preflight_cmd(
            fail_on_blockers=not args.allow_preflight_blockers and not args.start_missing_services,
            refresh_context=args.refresh_adapter_context,
        )
        preflight_result = run_command(preflight_cmd, cwd=run_dir)
        add_step(summary, "preflight_runtime", preflight_result)
        summary["paths"]["service_preflight"] = str(service_preflight_path) if service_preflight_path.exists() else None
        if service_preflight_path.exists():
            current_artifacts.add(service_preflight_path.resolve())
        if preflight_result["exit_code"] != 0:
            generate_verdict_handoff(
                summary,
                script_dir=script_dir,
                run_dir=run_dir,
                ledger_path=ledger_path,
                audit_summary_path=audit_summary_path,
                results_path=results_path,
                service_preflight_path=service_preflight_path,
                service_runtime_path=service_runtime_path,
                plan_audit_summary_path=plan_audit_summary_path,
                defects_path=defects_path,
                requirement_coverage_path=requirement_coverage_path,
                adapter_context_path=adapter_context_path,
                adapter_probes_path=adapter_probes_path,
                cycle_error_path=cycle_error_path,
                verdict_path=verdict_path,
                require_environment_boundary=args.require_environment_boundary,
                current_artifacts=current_artifacts,
            )
            return fail(summary, "Runtime preflight found blockers; inspect service-preflight.json before executing probes.", summary_path, status="blocked")
        preflight_report, preflight_load_error = read_current_json_artifact(service_preflight_path, current_artifacts)
        if preflight_load_error:
            return fail_with_cycle_handoff(
                f"Service preflight artifact is unreadable after preflight_runtime.py: {service_preflight_path} ({preflight_load_error}).",
                phase="preflight_runtime",
                code="helper_output_unreadable",
                result=preflight_result,
            )
        if args.start_missing_services and preflight_report.get("blockers"):
            runtime_cmd = [
                sys.executable,
                str(script_dir / "service_runtime.py"),
                "--run-dir",
                str(run_dir),
                "--preflight",
                str(service_preflight_path),
                "--out",
                str(service_runtime_path),
                "--start",
                "--wait-timeout",
                str(args.service_start_timeout),
            ]
            if args.service_start_no_wait:
                runtime_cmd.append("--no-wait")
            runtime_result = run_command(runtime_cmd, cwd=run_dir)
            add_step(summary, "service_runtime_start", runtime_result)
            summary["paths"]["service_runtime"] = str(service_runtime_path) if service_runtime_path.exists() else None
            if runtime_result["exit_code"] != 0:
                generate_verdict_handoff(
                    summary,
                    script_dir=script_dir,
                    run_dir=run_dir,
                    ledger_path=ledger_path,
                    audit_summary_path=audit_summary_path,
                    results_path=results_path,
                    service_preflight_path=service_preflight_path,
                    service_runtime_path=service_runtime_path,
                    plan_audit_summary_path=plan_audit_summary_path,
                    defects_path=defects_path,
                    requirement_coverage_path=requirement_coverage_path,
                    adapter_context_path=adapter_context_path,
                    adapter_probes_path=adapter_probes_path,
                    cycle_error_path=cycle_error_path,
                    verdict_path=verdict_path,
                    require_environment_boundary=args.require_environment_boundary,
                    current_artifacts=current_artifacts,
                )
                return fail(summary, "Service runtime startup failed; inspect service-runtime.json and service logs before executing probes.", summary_path, status="blocked")
            _, service_runtime_load_error = read_current_json_artifact(service_runtime_path, current_artifacts)
            if service_runtime_load_error:
                return fail_with_cycle_handoff(
                    f"Service runtime artifact is unreadable after service_runtime.py: {service_runtime_path} ({service_runtime_load_error}).",
                    phase="service_runtime_start",
                    code="helper_output_unreadable",
                    result=runtime_result,
                )
            preflight_after_start_cmd = build_preflight_cmd(
                fail_on_blockers=not args.allow_preflight_blockers,
                refresh_context=True,
            )
            preflight_after_start_result = run_command(preflight_after_start_cmd, cwd=run_dir)
            add_step(summary, "preflight_runtime_after_start", preflight_after_start_result)
            summary["paths"]["service_preflight"] = str(service_preflight_path) if service_preflight_path.exists() else None
            if preflight_after_start_result["exit_code"] != 0:
                generate_verdict_handoff(
                    summary,
                    script_dir=script_dir,
                    run_dir=run_dir,
                    ledger_path=ledger_path,
                    audit_summary_path=audit_summary_path,
                    results_path=results_path,
                    service_preflight_path=service_preflight_path,
                    service_runtime_path=service_runtime_path,
                    plan_audit_summary_path=plan_audit_summary_path,
                    defects_path=defects_path,
                    requirement_coverage_path=requirement_coverage_path,
                    adapter_context_path=adapter_context_path,
                    adapter_probes_path=adapter_probes_path,
                    cycle_error_path=cycle_error_path,
                    verdict_path=verdict_path,
                    require_environment_boundary=args.require_environment_boundary,
                    current_artifacts=current_artifacts,
                )
                return fail(summary, "Runtime preflight still has blockers after service startup; inspect service-preflight.json.", summary_path, status="blocked")
            _, preflight_after_start_load_error = read_current_json_artifact(service_preflight_path, current_artifacts)
            if preflight_after_start_load_error:
                return fail_with_cycle_handoff(
                    f"Service preflight artifact is unreadable after post-start preflight_runtime.py: {service_preflight_path} ({preflight_after_start_load_error}).",
                    phase="preflight_runtime_after_start",
                    code="helper_output_unreadable",
                    result=preflight_after_start_result,
                )

    if args.synthesize_adapter_probes:
        synth_cmd = [
            sys.executable,
            str(script_dir / "synthesize_adapter_probes.py"),
            "--run-dir",
            str(run_dir),
            "--plan",
            str(plan_path),
            "--matrix",
            str(matrix_path),
            "--out",
            str(adapter_probes_path),
            "--apply",
        ]
        if adapter_context_path.exists():
            synth_cmd.extend(["--adapter-context", str(adapter_context_path)])
        for flag_name, enabled in (
            ("--allow-live-stream", args.allow_live_stream),
            ("--allow-stopped-service", args.allow_stopped_service),
        ):
            if enabled:
                synth_cmd.append(flag_name)
        for flag_name, value in (
            ("--agent-id", args.agent_id),
            ("--user-id", args.user_id),
            ("--marker", args.marker),
            ("--question", args.question),
            ("--ws-path", args.ws_path),
            ("--session-detail-path", args.session_detail_path),
            ("--persistence-command", args.persistence_command),
        ):
            if value:
                synth_cmd.extend([flag_name, value])
        synth_result = run_command(synth_cmd, cwd=run_dir)
        add_step(summary, "synthesize_adapter_probes", synth_result)
        summary["paths"]["adapter_probes"] = str(adapter_probes_path) if adapter_probes_path.exists() else None
        if synth_result["exit_code"] != 0:
            return fail_with_cycle_handoff("Adapter probe synthesis failed.", phase="synthesize_adapter_probes", result=synth_result)
        _, adapter_probes_load_error = read_current_json_artifact(adapter_probes_path, current_artifacts)
        if adapter_probes_load_error:
            return fail_with_cycle_handoff(
                f"Adapter probes artifact is unreadable after synthesize_adapter_probes.py: {adapter_probes_path} ({adapter_probes_load_error}).",
                phase="synthesize_adapter_probes",
                code="helper_output_unreadable",
                result=synth_result,
            )

    if args.apply_next_probes:
        if not next_probes_path.exists():
            add_step(summary, "apply_next_probes", {"skipped": True, "exit_code": 0, "reason": f"Missing next-probes.json: {next_probes_path}"})
        else:
            apply_next_cmd = [
                sys.executable,
                str(script_dir / "apply_next_probes.py"),
                "--run-dir",
                str(run_dir),
                "--plan",
                str(plan_path),
                "--matrix",
                str(matrix_path),
                "--next-probes",
                str(next_probes_path),
                "--out",
                str(next_probe_application_path),
                "--apply",
            ]
            if ledger_path.exists():
                apply_next_cmd.extend(["--ledger", str(ledger_path)])
            if defects_path.exists():
                apply_next_cmd.extend(["--defects", str(defects_path)])
            if args.allow_live_stream:
                apply_next_cmd.append("--allow-live-stream")
            if args.allow_unsafe_command:
                apply_next_cmd.append("--allow-command-probes")
            if args.allow_mutating_api_next_probes:
                apply_next_cmd.append("--allow-mutating-api")
            apply_next_result = run_command(apply_next_cmd, cwd=run_dir)
            add_step(summary, "apply_next_probes", apply_next_result)
            summary["paths"]["next_probe_application"] = str(next_probe_application_path) if next_probe_application_path.exists() else None
            if apply_next_result["exit_code"] != 0:
                return fail_with_cycle_handoff("Next-probe application failed.", phase="apply_next_probes", result=apply_next_result)
            _, next_probe_application_load_error = read_current_json_artifact(next_probe_application_path, current_artifacts)
            if next_probe_application_load_error:
                return fail_with_cycle_handoff(
                    f"Next-probe application artifact is unreadable after apply_next_probes.py: {next_probe_application_path} ({next_probe_application_load_error}).",
                    phase="apply_next_probes",
                    code="helper_output_unreadable",
                    result=apply_next_result,
                )

    semantic_cmd = [
        sys.executable,
        str(script_dir / "refresh_semantic_artifacts.py"),
        "--run-dir",
        str(run_dir),
        "--requirement",
        str(requirement_path),
        "--matrix",
        str(matrix_path),
        "--plan",
        str(plan_path),
        "--out-summary",
        str(semantic_artifacts_summary_path),
    ]
    semantic_result = run_command(semantic_cmd, cwd=run_dir)
    add_step(summary, "refresh_semantic_artifacts", semantic_result)
    summary["paths"]["business_model"] = str(business_model_path) if business_model_path.exists() else None
    summary["paths"]["oracle_model"] = str(oracle_model_path) if oracle_model_path.exists() else None
    summary["paths"]["qa_metrics"] = str(qa_metrics_path) if qa_metrics_path.exists() else None
    summary["paths"]["closeout_candidates"] = str(closeout_candidates_path) if closeout_candidates_path.exists() else None
    summary["paths"]["semantic_artifacts_summary"] = str(semantic_artifacts_summary_path) if semantic_artifacts_summary_path.exists() else None
    if semantic_result["exit_code"] != 0:
        return fail_with_cycle_handoff("Semantic artifact refresh failed.", phase="refresh_semantic_artifacts", result=semantic_result)
    for semantic_path in (business_model_path, oracle_model_path, qa_metrics_path, closeout_candidates_path, semantic_artifacts_summary_path):
        if semantic_path.exists():
            current_artifacts.add(semantic_path.resolve())

    validate_cmd = [
        sys.executable,
        str(script_dir / "validate_plan.py"),
        "--plan",
        str(plan_path),
        "--matrix",
        str(matrix_path),
        "--summary",
        str(plan_audit_summary_path),
    ]
    if args.allow_unsafe_command:
        validate_cmd.append("--allow-unsafe-command")
    validate_result = run_command(validate_cmd, cwd=run_dir)
    add_step(summary, "validate_plan", validate_result)
    if plan_audit_summary_path.exists() or validate_result["exit_code"] == 0:
        plan_audit_summary, plan_audit_load_error = read_current_json_artifact(plan_audit_summary_path, current_artifacts)
        if plan_audit_load_error:
            return fail_with_cycle_handoff(
                f"Plan audit artifact is unreadable after validate_plan.py: {plan_audit_summary_path} ({plan_audit_load_error}).",
                phase="validate_plan",
                code="helper_output_unreadable",
                result=validate_result,
            )
    if validate_result["exit_code"] != 0:
        generate_verdict_handoff(
            summary,
            script_dir=script_dir,
            run_dir=run_dir,
            ledger_path=ledger_path,
            audit_summary_path=audit_summary_path,
            results_path=results_path,
            service_preflight_path=service_preflight_path,
            service_runtime_path=service_runtime_path,
            plan_audit_summary_path=plan_audit_summary_path,
            defects_path=defects_path,
            requirement_coverage_path=requirement_coverage_path,
            adapter_context_path=adapter_context_path,
            adapter_probes_path=adapter_probes_path,
            cycle_error_path=cycle_error_path,
            verdict_path=verdict_path,
            require_environment_boundary=args.require_environment_boundary,
            current_artifacts=current_artifacts,
        )
        return fail(summary, "Plan validation failed; fix plan/matrix before executing probes.", summary_path, status="blocked")

    if args.skip_probe:
        existing_results: dict[str, Any] = {}
        if results_path.exists():
            existing_results, results_load_error = try_load_json(results_path)
            if results_load_error:
                return fail_with_cycle_handoff(
                    f"Existing results artifact is unreadable while --skip-probe was set: {results_path} ({results_load_error}).",
                    phase="probe",
                    code="skip_probe_results_unreadable",
                )
        if not results_path.exists() or existing_results.get("status") == "skipped":
            write_json(results_path, make_skipped_results(plan_path, run_dir, "--skip-probe was set and no existing results.json was present."))
        add_step(summary, "probe", {"skipped": True, "exit_code": 0, "results": str(results_path)})
        if results_path.exists():
            current_artifacts.add(results_path.resolve())
    else:
        probe_result = run_command([args.node_bin, str(script_dir / "playwright_probe.mjs"), "--plan", str(plan_path)], cwd=run_dir)
        add_step(summary, "probe", probe_result)
        if probe_result["exit_code"] != 0:
            return fail_with_cycle_handoff("Probe runner failed before producing a usable result.", phase="probe", result=probe_result)
        if not results_path.exists():
            discovered = discover_results_path(probe_result.get("stdout", ""))
            if discovered:
                results_path = discovered
                summary["paths"]["results"] = str(results_path)
        if not results_path.exists():
            return fail_with_cycle_handoff(f"Probe runner completed but results file is missing: {results_path}", phase="probe", result=probe_result, code="probe_results_missing")
        _, results_load_error = read_current_json_artifact(results_path, current_artifacts)
        if results_load_error:
            return fail_with_cycle_handoff(
                f"Probe results artifact is unreadable after playwright_probe.mjs: {results_path} ({results_load_error}).",
                phase="probe",
                code="helper_output_unreadable",
                result=probe_result,
            )

    ledger_result = run_command(
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
        cwd=run_dir,
    )
    add_step(summary, "ledger_from_probe", ledger_result)
    if ledger_result["exit_code"] != 0:
        return fail_with_cycle_handoff("Ledger generation failed.", phase="ledger_from_probe", result=ledger_result)
    _, ledger_load_error = read_current_json_artifact(ledger_path, current_artifacts)
    if ledger_load_error:
        return fail_with_cycle_handoff(
            f"Evidence ledger artifact is unreadable after ledger_from_probe.py: {ledger_path} ({ledger_load_error}).",
            phase="ledger_from_probe",
            code="helper_output_unreadable",
            result=ledger_result,
        )

    audit_cmd = [
        sys.executable,
        str(script_dir / "audit_evidence.py"),
        "--matrix",
        str(matrix_path),
        "--results",
        str(results_path),
        "--ledger",
        str(ledger_path),
        "--summary",
        str(audit_summary_path),
    ]
    if args.strict_runtime:
        audit_cmd.append("--strict-runtime")
    audit_result = run_command(audit_cmd, cwd=run_dir)
    add_step(summary, "audit_evidence", audit_result)
    if audit_summary_path.exists() or audit_result["exit_code"] == 0:
        audit_summary, audit_load_error = read_current_json_artifact(audit_summary_path, current_artifacts)
        if audit_load_error:
            return fail_with_cycle_handoff(
                f"Audit summary artifact is unreadable after audit_evidence.py: {audit_summary_path} ({audit_load_error}).",
                phase="audit_evidence",
                code="helper_output_unreadable",
                result=audit_result,
            )
        summary["audit"] = audit_summary
    if audit_result["exit_code"] != 0:
        audit_summary = summary.get("audit") or {}
        if args.strict_runtime and is_runtime_disposition_only_audit_failure(audit_summary):
            summary["runtime_disposition_audit_failed"] = True
            add_step(summary, "audit_runtime_disposition_handoff", {
                "exit_code": 0,
                "reason": "Continuing after strict runtime disposition failure so defects, next probes, verdict, and report can be generated.",
            })
        else:
            generate_verdict_handoff(
                summary,
                script_dir=script_dir,
                run_dir=run_dir,
                ledger_path=ledger_path,
                audit_summary_path=audit_summary_path,
                results_path=results_path,
                service_preflight_path=service_preflight_path,
                service_runtime_path=service_runtime_path,
                plan_audit_summary_path=plan_audit_summary_path,
                defects_path=defects_path,
                requirement_coverage_path=requirement_coverage_path,
                adapter_context_path=adapter_context_path,
                adapter_probes_path=adapter_probes_path,
                cycle_error_path=cycle_error_path,
                verdict_path=verdict_path,
                require_environment_boundary=args.require_environment_boundary,
                current_artifacts=current_artifacts,
            )
            status = (summary.get("verdict") or {}).get("verdict") or "audit_failed"
            return fail(summary, "Evidence audit failed; inspect audit-summary.json before claiming pass.", summary_path, status=status)

    defects_result = run_command(
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
        cwd=run_dir,
    )
    add_step(summary, "generate_defects", defects_result)
    if defects_result["exit_code"] != 0:
        return fail_with_cycle_handoff("Defect generation failed.", phase="generate_defects", result=defects_result)
    _, defects_load_error = read_current_json_artifact(defects_path, current_artifacts)
    if defects_load_error:
        return fail_with_cycle_handoff(
            f"Defects artifact is unreadable after generate_defects.py: {defects_path} ({defects_load_error}).",
            phase="generate_defects",
            code="helper_output_unreadable",
            result=defects_result,
        )

    next_probes_result = run_command(
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
            str(next_probes_path),
        ],
        cwd=run_dir,
    )
    add_step(summary, "generate_next_probes", next_probes_result)
    if next_probes_result["exit_code"] != 0:
        return fail_with_cycle_handoff("Next-probe generation failed.", phase="generate_next_probes", result=next_probes_result)
    _, next_probes_load_error = read_current_json_artifact(next_probes_path, current_artifacts)
    if next_probes_load_error:
        return fail_with_cycle_handoff(
            f"Next-probes artifact is unreadable after generate_next_probes.py: {next_probes_path} ({next_probes_load_error}).",
            phase="generate_next_probes",
            code="helper_output_unreadable",
            result=next_probes_result,
        )

    verdict_cmd = [
        sys.executable,
        str(script_dir / "generate_verdict.py"),
        "--ledger",
        str(ledger_path),
        "--audit-summary",
        str(audit_summary_path),
        "--results",
        str(results_path),
        "--defects",
        str(defects_path),
        "--plan-audit-summary",
        str(plan_audit_summary_path),
        "--requirement-coverage",
        str(requirement_coverage_path),
        "--out",
        str(verdict_path),
    ]
    if adapter_context_path.exists():
        verdict_cmd.extend(["--adapter-context", str(adapter_context_path)])
    if adapter_probes_path.exists():
        verdict_cmd.extend(["--adapter-probes", str(adapter_probes_path)])
    if service_preflight_path.exists():
        verdict_cmd.extend(["--service-preflight", str(service_preflight_path)])
    if service_runtime_path.exists():
        verdict_cmd.extend(["--service-runtime", str(service_runtime_path)])
    if args.require_environment_boundary:
        verdict_cmd.append("--require-environment-boundary")
    verdict_result = run_command(verdict_cmd, cwd=run_dir)
    add_step(summary, "generate_verdict", verdict_result)
    if verdict_result["exit_code"] != 0:
        return fail_with_cycle_handoff("Verdict generation failed.", phase="generate_verdict", result=verdict_result, code="verdict_generation_failed")
    verdict, verdict_load_error = read_current_json_artifact(verdict_path, current_artifacts)
    if verdict_load_error:
        return fail_with_cycle_handoff(
            f"Verdict artifact is unreadable after generate_verdict.py: {verdict_path} ({verdict_load_error}).",
            phase="generate_verdict",
            code="helper_output_unreadable",
            result=verdict_result,
        )
    summary["verdict"] = verdict

    if args.skip_report:
        add_step(summary, "generate_report", {"skipped": True, "exit_code": 0})
    else:
        report_cmd = [
            sys.executable,
            str(script_dir / "generate_report.py"),
            "--plan",
            str(plan_path),
            "--results",
            str(results_path),
            "--ledger",
            str(ledger_path),
            "--audit-summary",
            str(audit_summary_path),
            "--defects",
            str(defects_path),
            "--next-probes",
            str(next_probes_path),
            "--verdict",
            str(verdict_path),
            "--out",
            str(report_path),
        ]
        if requirement_coverage_path.exists():
            report_cmd.extend(["--requirement-coverage", str(requirement_coverage_path)])
        if next_probe_application_path.exists():
            report_cmd.extend(["--next-probe-application", str(next_probe_application_path)])
        if requirement_path.exists():
            report_cmd.extend(["--requirement", str(requirement_path)])
        if adapter_context_path.exists():
            report_cmd.extend(["--adapter-context", str(adapter_context_path)])
        if adapter_probes_path.exists():
            report_cmd.extend(["--adapter-probes", str(adapter_probes_path)])
        if service_preflight_path.exists():
            report_cmd.extend(["--service-preflight", str(service_preflight_path)])
        if service_runtime_path.exists():
            report_cmd.extend(["--service-runtime", str(service_runtime_path)])
        if business_model_path.exists():
            report_cmd.extend(["--business-model", str(business_model_path)])
        if oracle_model_path.exists():
            report_cmd.extend(["--oracle-model", str(oracle_model_path)])
        if qa_metrics_path.exists():
            report_cmd.extend(["--qa-metrics", str(qa_metrics_path)])
        if closeout_candidates_path.exists():
            report_cmd.extend(["--closeout-candidates", str(closeout_candidates_path)])
        report_result = run_command(report_cmd, cwd=run_dir)
        add_step(summary, "generate_report", report_result)
        if report_result["exit_code"] != 0:
            return fail_with_cycle_handoff("Report generation failed.", phase="generate_report", result=report_result)

    verdict = summary.get("verdict") or {}
    summary["status"] = verdict.get("verdict") or "attention"
    summary["finished_at"] = datetime.now().isoformat(timespec="seconds")
    write_json(summary_path, summary)
    print(summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
