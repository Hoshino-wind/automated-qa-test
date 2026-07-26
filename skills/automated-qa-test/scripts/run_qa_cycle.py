#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from qa_common import atomic_write_json, file_sha256, is_within
from qa_core.contracts.artifacts import ARTIFACT_FILENAMES
from qa_core.pipeline import CycleContext, CycleOptions, StageRunner, parse_cycle_options
from qa_core.proof import (
    ProofVerificationResult,
    canonical_json_sha256,
    input_file_sha256,
    verify_run_proof,
)
from qa_core.runtime import (
    CYCLE_OUTPUT_NAMES,
    CYCLE_OWNER_PREFIX,
    AttemptStore,
    CycleAttemptError,
    CycleAttemptResult,
    ProcessExecutor,
    RunBudget,
    RunSession,
    RunStateCoordinator,
    commit_cycle_attempt,
)
from qa_core.runtime.lease import RunLeaseError
from qa_core.state import EventLogError
from qa_core.tools import build_default_tool_registry

CONTROL_BOUNDARY_EXIT_CODE = 73
COMPONENT_VERSIONS = {
    "qa_cycle": "2",
    "run_budget": "1",
    "run_lease": "1",
    "run_state": "1",
}


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
    atomic_write_json(path, value)


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


def plan_probe_count(plan_path: Path) -> int:
    """计算本轮执行器将接收的计划步骤数。"""

    plan = load_json(plan_path)
    scenarios = plan.get("scenarios")
    if not isinstance(scenarios, list):
        return 0
    return sum(
        len(steps)
        for scenario in scenarios
        if isinstance(scenario, dict)
        and isinstance((steps := scenario.get("steps")), list)
    )


def derive_run_goal(requirement_path: Path) -> str:
    """从需求首个非空标题派生稳定目标，读取失败时使用保守默认值。"""

    if requirement_path.is_file():
        try:
            for line in requirement_path.read_text(
                encoding="utf-8",
            ).splitlines():
                normalized = line.strip().lstrip("#").strip()
                if normalized:
                    return normalized[:500]
        except OSError:
            pass
    return "Execute a proof-carrying QA cycle without unsupported pass claims"


def control_boundary_error(
    error: BaseException,
    *,
    phase: str,
) -> dict[str, Any]:
    """把租约或状态故障投影为稳定、可机器消费的错误。"""

    payload: dict[str, Any] = {
        "schema_version": 1,
        "error": "qa_control_boundary_error",
        "phase": phase,
        "type": type(error).__name__,
        "message": str(error),
    }
    if isinstance(error, EventLogError):
        payload["detail"] = error.to_dict()
    current = getattr(error, "current", None)
    if current is not None and hasattr(current, "to_dict"):
        payload["current_lease"] = current.to_dict()
    return payload


def print_control_boundary_error(
    error: BaseException,
    *,
    phase: str,
) -> None:
    print(
        json.dumps(
            control_boundary_error(error, phase=phase),
            ensure_ascii=False,
        ),
        file=sys.stderr,
    )


def fail(summary: dict[str, Any], message: str, out_path: Path, *, status: str = "failed") -> int:
    summary["status"] = status
    summary["error"] = message
    summary["finished_at"] = datetime.now().isoformat(timespec="seconds")
    write_json(out_path, summary)
    print(out_path)
    print(message, file=sys.stderr)
    return 1


def clear_stale_terminal_outputs(summary: dict[str, Any], artifacts: list[tuple[str, Path]]) -> list[dict[str, str]]:
    cleared: list[dict[str, str]] = []
    blocked: list[dict[str, str]] = []
    for name, path in artifacts:
        if not path.exists():
            continue
        artifact_kind = "directory" if path.is_dir() and not path.is_symlink() else "file"
        if artifact_kind == "directory":
            blocked.append({"name": name, "path": str(path), "kind": artifact_kind, "reason": "output_path_is_directory"})
            continue
        path.unlink()
        cleared.append({"name": name, "path": str(path), "kind": artifact_kind})
    if cleared:
        summary["cleared_stale_outputs"] = cleared
    if blocked:
        summary["blocked_output_paths"] = blocked
    return blocked


def external_output_paths(run_dir: Path, artifacts: list[tuple[str, Path]]) -> list[dict[str, str]]:
    return [
        {"name": name, "path": str(path), "reason": "output_path_outside_run_dir"}
        for name, path in artifacts
        if not is_within(path, run_dir)
    ]


def apply_environment_boundary_args(context_path: Path, runtime_mode: str | None, data_boundary_status: str | None) -> str | None:
    if not (runtime_mode or data_boundary_status):
        return None
    if context_path.exists():
        context, load_error = try_load_json(context_path)
        if load_error:
            return load_error
    else:
        context = {
            "schema_version": 1,
            "adapter": "explicit_environment_boundary",
        }
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
            for key in (
                "command",
                "cwd",
                "started_at",
                "finished_at",
                "exit_code",
                "raw_exit_code",
                "timed_out",
                "termination_reason",
                "budget_error",
                "stdout",
                "stderr",
                "stdout_bytes",
                "stderr_bytes",
            )
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
    stage_runner: StageRunner,
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
    allow_missing_requirement_coverage: bool,
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
    if allow_missing_requirement_coverage:
        verdict_cmd.append("--allow-missing-requirement-coverage")
    stage_runner.run("generate_verdict_handoff", verdict_cmd, cwd=run_dir)
    summary.setdefault("paths", {})["verdict"] = str(verdict_path) if verdict_path.exists() else None
    if verdict_path.exists():
        current_artifacts.add(verdict_path.resolve())
        verdict, load_error = try_load_json(verdict_path)
        if load_error:
            summary["verdict_load_error"] = {"path": str(verdict_path), "error": load_error}
        else:
            summary["verdict"] = verdict


class CycleRuntime:
    """拥有单次 QA 周期的选项、路径与当前产物状态。"""

    def __init__(
        self,
        args: CycleOptions,
        *,
        session: RunSession,
    ) -> None:
        self.args = args
        self.context = CycleContext.from_namespace(script_dir=Path(__file__).resolve().parent, args=args)
        self.script_dir = self.context.script_dir
        self.artifacts = self.context.artifacts
        self.run_dir = self.artifacts.run_dir
        self.plan_path = self.artifacts.plan
        self.matrix_path = self.artifacts.matrix
        self.requirement_path = self.artifacts.requirement
        self.results_path = self.artifacts.results
        self.ledger_path = self.artifacts.ledger
        self.audit_summary_path = self.artifacts.audit_summary
        self.requirement_coverage_path = self.artifacts.requirement_coverage
        self.plan_audit_summary_path = self.artifacts.plan_audit_summary
        self.adapter_context_path = self.artifacts.adapter_context
        self.adapter_probes_path = self.artifacts.adapter_probes
        self.service_preflight_path = self.artifacts.service_preflight
        self.service_runtime_path = self.artifacts.service_runtime
        self.defects_path = self.artifacts.defects
        self.next_probes_path = self.artifacts.next_probes
        self.next_probe_application_path = self.artifacts.next_probe_application
        self.business_model_path = self.artifacts.business_model
        self.oracle_model_path = self.artifacts.oracle_model
        self.qa_metrics_path = self.artifacts.qa_metrics
        self.closeout_candidates_path = self.artifacts.closeout_candidates
        self.semantic_artifacts_summary_path = self.artifacts.semantic_artifacts_summary
        self.cycle_error_path = self.artifacts.cycle_error
        self.verdict_path = self.artifacts.verdict
        self.report_path = self.artifacts.report
        self.summary_path = self.artifacts.summary
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.summary = self.context.summary
        self.budget = RunBudget(
            total_timeout=args.total_timeout_seconds,
            default_stage_timeout=args.stage_timeout_seconds,
            max_probes=args.max_probes,
            max_output_bytes=args.max_output_bytes,
        )
        self.summary["budget"] = self.budget.snapshot().to_dict()
        self.session = session
        self.cycle_options_sha256 = canonical_json_sha256(
            asdict(self.args)
        )
        self.tool_registry_sha256 = (
            build_default_tool_registry().canonical_sha256
        )
        self.state = RunStateCoordinator.open(
            session,
            goal=derive_run_goal(self.requirement_path),
            scope=[
                str(self.plan_path),
                str(self.matrix_path),
                str(self.requirement_path),
            ],
            component_versions={
                **COMPONENT_VERSIONS,
                "cycle_options_sha256": self.cycle_options_sha256,
                "tool_registry_sha256": self.tool_registry_sha256,
            },
            initial_budget=self.summary["budget"],
        )
        self.summary["run_session"] = session.to_dict()
        self.summary["run_state"] = self.state.projection()
        self.stage_runner = StageRunner(
            self.summary,
            run_command,
            stage_executor=self.execute_stage,
        )
        self.current_artifacts = self.context.current_artifacts

    def enter_phase(self, phase: str) -> None:
        """在执行顶层阶段前推进租约心跳与可恢复状态。"""

        self.state.before_stage(phase)
        self.summary["run_state"] = self.state.projection()

    def execute_stage(
        self,
        name: str,
        command: list[str],
        cwd: Path | None,
        probe_count: int,
    ) -> dict[str, Any]:
        """统一执行阶段并持续投影预算消耗。"""

        self.state.before_stage(name)
        result = ProcessExecutor(
            self.budget,
            name,
            termination_grace=self.args.termination_grace_seconds,
        ).run(
            command,
            cwd=cwd,
            probe_count=probe_count,
        )
        self.summary["budget"] = self.budget.snapshot().to_dict()
        self.state.update_budget(self.summary["budget"])
        self.summary["run_state"] = self.state.projection()
        if result.get("termination_reason"):
            boundary_error = {
                "stage": name,
                "termination_reason": result.get("termination_reason"),
                "budget_error": result.get("budget_error"),
                "exit_code": result.get("exit_code"),
                "raw_exit_code": result.get("raw_exit_code"),
            }
            self.summary.setdefault(
                "execution_boundary_errors",
                [],
            ).append(boundary_error)
            if not self.summary.get("cycle_error"):
                code = (
                    "cycle_budget_exceeded"
                    if result.get("budget_error")
                    else "cycle_execution_boundary_failed"
                )
                message = (
                    f"Stage {name} stopped at the execution boundary: "
                    f"{result.get('termination_reason')}."
                )
                cycle_error = write_cycle_error(
                    self.cycle_error_path,
                    code=code,
                    phase=name,
                    message=message,
                    result=result,
                )
                self.summary["cycle_error"] = cycle_error
                self.summary.setdefault(
                    "paths",
                    {},
                )["cycle_error"] = str(self.cycle_error_path)
                self.current_artifacts.add(
                    self.cycle_error_path.resolve()
                )
                self.summary["verdict"] = write_minimal_error_verdict(
                    self.verdict_path,
                    self.cycle_error_path,
                    code=code,
                    phase=name,
                    message=message,
                )
                self.current_artifacts.add(self.verdict_path.resolve())
        return result

    def complete_state(self, exit_code: int) -> int:
        """先发布不可变 attempt，再把最终裁决绑定到事件链。"""

        budget = self.budget.snapshot().to_dict()
        self.summary["budget"] = budget
        attempt_ref: dict[str, Any] | None = None
        verdict_committed = False
        effective_exit_code = exit_code
        try:
            self.state.before_stage("commit_cycle_attempt")
            committed = self.commit_attempt(exit_code)
            self.summary["attempt_commit"] = committed.to_dict()
            verdict_hash = file_sha256(self.verdict_path)
            verdict_committed = any(
                artifact.name == "qa-verdict.json"
                and artifact.sha256 == verdict_hash
                for artifact in committed.attempt.artifacts
            )
            attempt_ref = {
                "attempt_id": committed.attempt.attempt_id,
                "attempt_manifest_sha256": (
                    committed.attempt.manifest_sha256
                ),
                "run_manifest_sequence": (
                    committed.run_manifest_sequence
                ),
                "run_manifest_sha256": (
                    committed.run_manifest_sha256
                ),
            }
        except CycleAttemptError as error:
            effective_exit_code = 1
            self.record_attempt_failure(error)
        self.state.finish(
            exit_code=effective_exit_code,
            verdict_path=self.verdict_path,
            verdict_is_current=(
                self.verdict_path.exists()
                and self.verdict_path.resolve() in self.current_artifacts
            ),
            final_budget=budget,
            attempt_ref=attempt_ref,
            verdict_committed=verdict_committed,
        )
        if self.state.state.status == "passed":
            proof = verify_run_proof(self.run_dir)
            self.summary["proof_verification"] = proof.to_dict()
            if not proof.can_claim_pass:
                effective_exit_code = 1
                self.record_proof_failure(proof)
                reason_codes = ",".join(
                    error["code"] for error in proof.errors
                )
                self.state.invalidate_pass(
                    reason=reason_codes or "proof_graph_invalid",
                )
        self.summary["run_state"] = self.state.projection()
        self.summary["status"] = self.state.state.status
        return effective_exit_code

    def commit_attempt(self, exit_code: int) -> CycleAttemptResult:
        """把本轮 current 输出提交到内容校验后的不可变视图。"""

        output_names = self.current_output_names()
        if not output_names:
            raise CycleAttemptError(
                "cycle_outputs_empty",
                "select_outputs",
                "no canonical current cycle outputs are available",
            )
        try:
            current_manifest = AttemptStore(
                self.run_dir
            ).read_run_manifest()
        except Exception as error:
            raise CycleAttemptError(
                "cycle_manifest_preflight_failed",
                "manifest_preflight",
                str(error),
                details={"cause_type": type(error).__name__},
            ) from error
        expected_sequence = (
            int(current_manifest["sequence"])
            if current_manifest is not None
            else 0
        )
        return commit_cycle_attempt(
            run_dir=self.run_dir,
            run_id=self.session.run_id,
            lease_owner=self.session.owner,
            generation=self.session.generation,
            iteration=expected_sequence + 1,
            stage=(
                "cycle_complete"
                if exit_code == 0
                else "cycle_handoff"
            ),
            tool="run_qa_cycle",
            input_hashes=self.input_hashes(),
            expected_sequence=expected_sequence,
            output_names=output_names,
            current_artifacts=self.current_artifacts,
        )

    def current_output_names(self) -> list[str]:
        """仅选择 run-dir 内本轮明确标记 current 的标准输出。"""

        selected: list[str] = []
        for name in sorted(CYCLE_OUTPUT_NAMES - {"summary"}):
            actual = getattr(self.artifacts, name)
            canonical = self.run_dir / ARTIFACT_FILENAMES[name]
            if (
                actual == canonical
                and actual.is_file()
                and actual.resolve() in self.current_artifacts
            ):
                selected.append(name)
        return selected

    def input_hashes(self) -> dict[str, str]:
        """绑定最终执行配置、工具注册表与所有可用直接输入。"""

        hashes = {
            "cycle_options": self.cycle_options_sha256,
            "tool_registry": self.tool_registry_sha256,
        }
        for name, path in (
            ("plan", self.plan_path),
            ("matrix", self.matrix_path),
            ("requirement", self.requirement_path),
            ("adapter_context", self.adapter_context_path),
        ):
            hashes[name] = input_file_sha256(name, path)
        return hashes

    def record_attempt_failure(self, error: CycleAttemptError) -> None:
        """Artifact Store 失败时覆盖任何已有 PASS 并保留诊断。"""

        message = f"Cycle artifact commit failed: {error}"
        self.summary["attempt_commit"] = error.to_dict()
        cycle_error = write_cycle_error(
            self.cycle_error_path,
            code="cycle_attempt_commit_failed",
            phase=error.phase,
            message=message,
        )
        self.summary["cycle_error"] = cycle_error
        self.summary.setdefault("paths", {})["cycle_error"] = str(
            self.cycle_error_path
        )
        self.current_artifacts.add(self.cycle_error_path.resolve())
        self.summary["verdict"] = write_minimal_error_verdict(
            self.verdict_path,
            self.cycle_error_path,
            code="cycle_attempt_commit_failed",
            phase=error.phase,
            message=message,
        )
        self.current_artifacts.add(self.verdict_path.resolve())
        self.summary["error"] = message

    def record_proof_failure(
        self,
        proof: ProofVerificationResult,
    ) -> None:
        """最终 proof graph 不闭合时撤销 PASS 并生成非通过交接。"""

        codes = [error["code"] for error in proof.errors]
        message = (
            "Final proof graph verification failed: "
            + ", ".join(codes or ["unknown"])
        )
        cycle_error = write_cycle_error(
            self.cycle_error_path,
            code="proof_graph_invalid",
            phase="proof_verification",
            message=message,
        )
        self.summary["cycle_error"] = cycle_error
        self.summary.setdefault("paths", {})["cycle_error"] = str(
            self.cycle_error_path
        )
        self.current_artifacts.add(self.cycle_error_path.resolve())
        self.summary["verdict"] = write_minimal_error_verdict(
            self.verdict_path,
            self.cycle_error_path,
            code="proof_graph_invalid",
            phase="proof_verification",
            message=message,
        )
        self.current_artifacts.add(self.verdict_path.resolve())
        self.summary["error"] = message

    def emergency_state_failure(
        self,
        error: EventLogError,
        *,
        phase: str,
    ) -> int:
        """租约仍有效但状态不可写时，直接覆盖为非 PASS 交接。"""

        message = f"Run state failed closed during {phase}: {error}"
        cycle_error = write_cycle_error(
            self.cycle_error_path,
            code="run_state_unavailable",
            phase=phase,
            message=message,
        )
        self.summary["cycle_error"] = cycle_error
        self.summary.setdefault("paths", {})["cycle_error"] = str(
            self.cycle_error_path
        )
        self.summary["verdict"] = write_minimal_error_verdict(
            self.verdict_path,
            self.cycle_error_path,
            code="run_state_unavailable",
            phase=phase,
            message=message,
        )
        self.summary["status"] = "inconclusive"
        self.summary["error"] = message
        self.summary["finished_at"] = datetime.now().isoformat(
            timespec="seconds"
        )
        write_json(self.summary_path, self.summary)
        print(self.summary_path)
        print_control_boundary_error(error, phase=phase)
        return 1

    def fail_with_cycle_handoff(
        self,
        message: str,
        *,
        phase: str,
        result: dict[str, Any] | None = None,
        code: str = "cycle_helper_failed",
    ) -> int:
        boundary_error = bool(
            result
            and result.get("termination_reason")
            and isinstance(self.summary.get("cycle_error"), dict)
        )
        if boundary_error:
            cycle_error = self.summary["cycle_error"]
        else:
            cycle_error = write_cycle_error(
                self.cycle_error_path,
                code=code,
                phase=phase,
                message=message,
                result=result,
            )
        self.summary["cycle_error"] = cycle_error
        self.summary.setdefault("paths", {})["cycle_error"] = str(self.cycle_error_path)
        self.current_artifacts.add(self.cycle_error_path.resolve())
        generate_verdict_handoff(
            self.summary,
            stage_runner=self.stage_runner,
            script_dir=self.script_dir,
            run_dir=self.run_dir,
            ledger_path=self.ledger_path,
            audit_summary_path=self.audit_summary_path,
            results_path=self.results_path,
            service_preflight_path=self.service_preflight_path,
            service_runtime_path=self.service_runtime_path,
            plan_audit_summary_path=self.plan_audit_summary_path,
            defects_path=self.defects_path,
            requirement_coverage_path=self.requirement_coverage_path,
            adapter_context_path=self.adapter_context_path,
            adapter_probes_path=self.adapter_probes_path,
            cycle_error_path=self.cycle_error_path,
            verdict_path=self.verdict_path,
            require_environment_boundary=self.args.require_environment_boundary,
            allow_missing_requirement_coverage=self.args.allow_missing_requirement_coverage,
            current_artifacts=self.current_artifacts,
        )
        if not self.summary.get("verdict"):
            self.summary["verdict"] = write_minimal_error_verdict(
                self.verdict_path,
                self.cycle_error_path,
                code=code,
                phase=phase,
                message=message,
            )
            self.current_artifacts.add(self.verdict_path.resolve())
        status = (self.summary.get("verdict") or {}).get("verdict") or "inconclusive"
        return fail(self.summary, message, self.summary_path, status=status)


def prepare_cycle(runtime: CycleRuntime) -> int | None:
    """校验输出边界、环境上下文与必需输入。"""
    args = runtime.args
    context = runtime.context
    artifacts = runtime.artifacts
    run_dir = runtime.run_dir
    plan_path = runtime.plan_path
    matrix_path = runtime.matrix_path
    adapter_context_path = runtime.adapter_context_path
    summary_path = runtime.summary_path
    summary = runtime.summary
    current_artifacts = runtime.current_artifacts
    fail_with_cycle_handoff = runtime.fail_with_cycle_handoff

    output_artifacts = artifacts.named_outputs()
    rejected_external = (
        []
        if args.allow_external_output_paths
        else external_output_paths(run_dir, output_artifacts)
    )
    if rejected_external:
        summary["blocked_output_paths"] = rejected_external
        summary["status"] = "blocked"
        summary["error"] = "Generated output paths must stay within --run-dir unless --allow-external-output-paths is explicit."
        summary["finished_at"] = datetime.now().isoformat(timespec="seconds")
        fallback_summary_path = run_dir / "qa-run-summary.json"
        write_json(fallback_summary_path, summary)
        print(fallback_summary_path)
        print(summary["error"], file=sys.stderr)
        return 1
    blocked_terminal_outputs = clear_stale_terminal_outputs(
        summary,
        artifacts.terminal_outputs(),
    )
    if blocked_terminal_outputs:
        summary["status"] = "blocked"
        summary["error"] = "A terminal output target is a directory; it was preserved and the cycle was blocked."
        summary["finished_at"] = datetime.now().isoformat(timespec="seconds")
        write_json(summary_path, summary)
        print(summary_path)
        print(summary["error"], file=sys.stderr)
        return 1
    write_json(summary_path, summary)
    context.mark_current(summary_path)
    current_artifacts = context.current_artifacts
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
        summary.setdefault("paths", {})["adapter_context"] = str(adapter_context_path)
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
    return None


def run_requirement_coverage_stage(runtime: CycleRuntime) -> int | None:
    """执行需求来源覆盖审计。"""
    args = runtime.args
    script_dir = runtime.script_dir
    run_dir = runtime.run_dir
    matrix_path = runtime.matrix_path
    requirement_path = runtime.requirement_path
    results_path = runtime.results_path
    ledger_path = runtime.ledger_path
    audit_summary_path = runtime.audit_summary_path
    requirement_coverage_path = runtime.requirement_coverage_path
    plan_audit_summary_path = runtime.plan_audit_summary_path
    adapter_context_path = runtime.adapter_context_path
    adapter_probes_path = runtime.adapter_probes_path
    service_preflight_path = runtime.service_preflight_path
    service_runtime_path = runtime.service_runtime_path
    defects_path = runtime.defects_path
    cycle_error_path = runtime.cycle_error_path
    verdict_path = runtime.verdict_path
    summary_path = runtime.summary_path
    summary = runtime.summary
    stage_runner = runtime.stage_runner
    current_artifacts = runtime.current_artifacts
    fail_with_cycle_handoff = runtime.fail_with_cycle_handoff

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
        coverage_result = stage_runner.run("audit_requirement_coverage", coverage_cmd, cwd=run_dir)
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
                stage_runner=stage_runner,
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
                allow_missing_requirement_coverage=args.allow_missing_requirement_coverage,
                current_artifacts=current_artifacts,
            )
            return fail(summary, "Requirement source coverage audit failed; map every requirement.md behavior point before executing probes.", summary_path, status="blocked")
    elif not requirement_path.exists():
        stage_runner.skip("audit_requirement_coverage", "requirement file is missing")
    else:
        stage_runner.skip("audit_requirement_coverage", "--skip-requirement-coverage")
    return None


def run_preflight_stage(runtime: CycleRuntime) -> int | None:
    """执行运行时预检与受控服务启动。"""
    args = runtime.args
    script_dir = runtime.script_dir
    run_dir = runtime.run_dir
    plan_path = runtime.plan_path
    results_path = runtime.results_path
    ledger_path = runtime.ledger_path
    audit_summary_path = runtime.audit_summary_path
    requirement_coverage_path = runtime.requirement_coverage_path
    plan_audit_summary_path = runtime.plan_audit_summary_path
    adapter_context_path = runtime.adapter_context_path
    adapter_probes_path = runtime.adapter_probes_path
    service_preflight_path = runtime.service_preflight_path
    service_runtime_path = runtime.service_runtime_path
    defects_path = runtime.defects_path
    cycle_error_path = runtime.cycle_error_path
    verdict_path = runtime.verdict_path
    summary_path = runtime.summary_path
    summary = runtime.summary
    stage_runner = runtime.stage_runner
    current_artifacts = runtime.current_artifacts
    fail_with_cycle_handoff = runtime.fail_with_cycle_handoff

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
        preflight_result = stage_runner.run("preflight_runtime", preflight_cmd, cwd=run_dir)
        summary["paths"]["service_preflight"] = str(service_preflight_path) if service_preflight_path.exists() else None
        if service_preflight_path.exists():
            current_artifacts.add(service_preflight_path.resolve())
        if preflight_result["exit_code"] != 0:
            generate_verdict_handoff(
                summary,
                stage_runner=stage_runner,
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
                allow_missing_requirement_coverage=args.allow_missing_requirement_coverage,
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
            runtime_result = stage_runner.run("service_runtime_start", runtime_cmd, cwd=run_dir)
            summary["paths"]["service_runtime"] = str(service_runtime_path) if service_runtime_path.exists() else None
            if runtime_result["exit_code"] != 0:
                generate_verdict_handoff(
                    summary,
                    stage_runner=stage_runner,
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
                    allow_missing_requirement_coverage=args.allow_missing_requirement_coverage,
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
            preflight_after_start_result = stage_runner.run(
                "preflight_runtime_after_start",
                preflight_after_start_cmd,
                cwd=run_dir,
            )
            summary["paths"]["service_preflight"] = str(service_preflight_path) if service_preflight_path.exists() else None
            if preflight_after_start_result["exit_code"] != 0:
                generate_verdict_handoff(
                    summary,
                    stage_runner=stage_runner,
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
                    allow_missing_requirement_coverage=args.allow_missing_requirement_coverage,
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
    return None


def run_adapter_stage(runtime: CycleRuntime) -> int | None:
    """合成适配器探针并应用安全的下一探针。"""
    args = runtime.args
    script_dir = runtime.script_dir
    run_dir = runtime.run_dir
    plan_path = runtime.plan_path
    matrix_path = runtime.matrix_path
    ledger_path = runtime.ledger_path
    adapter_context_path = runtime.adapter_context_path
    adapter_probes_path = runtime.adapter_probes_path
    defects_path = runtime.defects_path
    next_probes_path = runtime.next_probes_path
    next_probe_application_path = runtime.next_probe_application_path
    summary = runtime.summary
    stage_runner = runtime.stage_runner
    current_artifacts = runtime.current_artifacts
    fail_with_cycle_handoff = runtime.fail_with_cycle_handoff

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
        synth_result = stage_runner.run("synthesize_adapter_probes", synth_cmd, cwd=run_dir)
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
            stage_runner.skip("apply_next_probes", f"Missing next-probes.json: {next_probes_path}")
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
            apply_next_result = stage_runner.run("apply_next_probes", apply_next_cmd, cwd=run_dir)
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
    return None


def run_planning_stage(runtime: CycleRuntime) -> int | None:
    """刷新语义产物并验证计划。"""
    args = runtime.args
    script_dir = runtime.script_dir
    run_dir = runtime.run_dir
    plan_path = runtime.plan_path
    matrix_path = runtime.matrix_path
    requirement_path = runtime.requirement_path
    results_path = runtime.results_path
    ledger_path = runtime.ledger_path
    audit_summary_path = runtime.audit_summary_path
    requirement_coverage_path = runtime.requirement_coverage_path
    plan_audit_summary_path = runtime.plan_audit_summary_path
    adapter_context_path = runtime.adapter_context_path
    adapter_probes_path = runtime.adapter_probes_path
    service_preflight_path = runtime.service_preflight_path
    service_runtime_path = runtime.service_runtime_path
    defects_path = runtime.defects_path
    business_model_path = runtime.business_model_path
    oracle_model_path = runtime.oracle_model_path
    qa_metrics_path = runtime.qa_metrics_path
    closeout_candidates_path = runtime.closeout_candidates_path
    semantic_artifacts_summary_path = runtime.semantic_artifacts_summary_path
    cycle_error_path = runtime.cycle_error_path
    verdict_path = runtime.verdict_path
    summary_path = runtime.summary_path
    summary = runtime.summary
    stage_runner = runtime.stage_runner
    current_artifacts = runtime.current_artifacts
    fail_with_cycle_handoff = runtime.fail_with_cycle_handoff

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
    semantic_result = stage_runner.run("refresh_semantic_artifacts", semantic_cmd, cwd=run_dir)
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
    if args.project_root:
        validate_cmd.extend(["--project-root", args.project_root])
    validate_result = stage_runner.run("validate_plan", validate_cmd, cwd=run_dir)
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
            stage_runner=stage_runner,
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
            allow_missing_requirement_coverage=args.allow_missing_requirement_coverage,
            current_artifacts=current_artifacts,
        )
        return fail(summary, "Plan validation failed; fix plan/matrix before executing probes.", summary_path, status="blocked")
    return None


def run_probe_stage(runtime: CycleRuntime) -> int | None:
    """执行或复用探针结果。"""
    args = runtime.args
    script_dir = runtime.script_dir
    run_dir = runtime.run_dir
    plan_path = runtime.plan_path
    results_path = runtime.results_path
    plan_audit_summary_path = runtime.plan_audit_summary_path
    summary = runtime.summary
    stage_runner = runtime.stage_runner
    current_artifacts = runtime.current_artifacts
    fail_with_cycle_handoff = runtime.fail_with_cycle_handoff

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
        stage_runner.record("probe", {"skipped": True, "exit_code": 0, "results": str(results_path)})
        if results_path.exists():
            current_artifacts.add(results_path.resolve())
    else:
        probe_cwd = Path(args.project_root).expanduser().resolve() if args.project_root else run_dir
        probe_result = stage_runner.run(
            "probe",
            [
                args.node_bin,
                str(script_dir / "playwright_probe.mjs"),
                "--plan",
                str(plan_path),
                "--plan-audit-summary",
                str(plan_audit_summary_path),
            ],
            cwd=probe_cwd,
            probe_count=plan_probe_count(plan_path),
        )
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
    runtime.results_path = results_path
    return None


def run_evidence_stage(runtime: CycleRuntime) -> int | None:
    """生成并严格审计证据账本。"""
    args = runtime.args
    script_dir = runtime.script_dir
    run_dir = runtime.run_dir
    matrix_path = runtime.matrix_path
    results_path = runtime.results_path
    ledger_path = runtime.ledger_path
    audit_summary_path = runtime.audit_summary_path
    requirement_coverage_path = runtime.requirement_coverage_path
    plan_audit_summary_path = runtime.plan_audit_summary_path
    adapter_context_path = runtime.adapter_context_path
    adapter_probes_path = runtime.adapter_probes_path
    service_preflight_path = runtime.service_preflight_path
    service_runtime_path = runtime.service_runtime_path
    defects_path = runtime.defects_path
    cycle_error_path = runtime.cycle_error_path
    verdict_path = runtime.verdict_path
    summary_path = runtime.summary_path
    summary = runtime.summary
    stage_runner = runtime.stage_runner
    current_artifacts = runtime.current_artifacts
    fail_with_cycle_handoff = runtime.fail_with_cycle_handoff

    ledger_result = stage_runner.run(
        "ledger_from_probe",
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
    audit_result = stage_runner.run("audit_evidence", audit_cmd, cwd=run_dir)
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
            stage_runner.record("audit_runtime_disposition_handoff", {
                "exit_code": 0,
                "reason": "Continuing after strict runtime disposition failure so defects, next probes, verdict, and report can be generated.",
            })
        else:
            generate_verdict_handoff(
                summary,
                stage_runner=stage_runner,
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
                allow_missing_requirement_coverage=args.allow_missing_requirement_coverage,
                current_artifacts=current_artifacts,
            )
            status = (summary.get("verdict") or {}).get("verdict") or "audit_failed"
            return fail(summary, "Evidence audit failed; inspect audit-summary.json before claiming pass.", summary_path, status=status)
    return None


def run_conclusion_stage(runtime: CycleRuntime) -> int | None:
    """生成缺陷、下一探针、终局与报告。"""
    args = runtime.args
    script_dir = runtime.script_dir
    run_dir = runtime.run_dir
    plan_path = runtime.plan_path
    matrix_path = runtime.matrix_path
    requirement_path = runtime.requirement_path
    results_path = runtime.results_path
    ledger_path = runtime.ledger_path
    audit_summary_path = runtime.audit_summary_path
    requirement_coverage_path = runtime.requirement_coverage_path
    plan_audit_summary_path = runtime.plan_audit_summary_path
    adapter_context_path = runtime.adapter_context_path
    adapter_probes_path = runtime.adapter_probes_path
    service_preflight_path = runtime.service_preflight_path
    service_runtime_path = runtime.service_runtime_path
    defects_path = runtime.defects_path
    next_probes_path = runtime.next_probes_path
    next_probe_application_path = runtime.next_probe_application_path
    business_model_path = runtime.business_model_path
    oracle_model_path = runtime.oracle_model_path
    qa_metrics_path = runtime.qa_metrics_path
    closeout_candidates_path = runtime.closeout_candidates_path
    verdict_path = runtime.verdict_path
    report_path = runtime.report_path
    summary = runtime.summary
    stage_runner = runtime.stage_runner
    current_artifacts = runtime.current_artifacts
    fail_with_cycle_handoff = runtime.fail_with_cycle_handoff

    defects_result = stage_runner.run(
        "generate_defects",
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
    next_probes_result = stage_runner.run(
        "generate_next_probes",
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
    if args.allow_missing_requirement_coverage:
        verdict_cmd.append("--allow-missing-requirement-coverage")
    verdict_result = stage_runner.run("generate_verdict", verdict_cmd, cwd=run_dir)
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
        stage_runner.skip("generate_report", "--skip-report")
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
        report_result = stage_runner.run("generate_report", report_cmd, cwd=run_dir)
        if report_result["exit_code"] != 0:
            return fail_with_cycle_handoff("Report generation failed.", phase="generate_report", result=report_result)
    return None


def finalize_cycle(runtime: CycleRuntime) -> int:
    """写入最终摘要并返回周期状态。"""
    summary_path = runtime.summary_path
    summary = runtime.summary

    verdict = summary.get("verdict") or {}
    state_status = (summary.get("run_state") or {}).get("status")
    summary["status"] = (
        state_status
        if isinstance(state_status, str) and state_status
        else verdict.get("verdict") or "attention"
    )
    summary["finished_at"] = datetime.now().isoformat(timespec="seconds")
    write_json(summary_path, summary)
    print(summary_path)
    return 0


def run_with_session(
    args: CycleOptions,
    session: RunSession,
) -> int:
    """在已持有的单写租约内执行完整周期。"""

    try:
        runtime = CycleRuntime(args, session=session)
    except EventLogError as error:
        print_control_boundary_error(error, phase="state_initialization")
        return CONTROL_BOUNDARY_EXIT_CODE

    outcome: int | None = None
    for stage in (
        prepare_cycle,
        run_requirement_coverage_stage,
        run_preflight_stage,
        run_adapter_stage,
        run_planning_stage,
        run_probe_stage,
        run_evidence_stage,
        run_conclusion_stage,
    ):
        try:
            runtime.enter_phase(stage.__name__)
            outcome = stage(runtime)
        except RunLeaseError as error:
            print_control_boundary_error(
                error,
                phase=stage.__name__,
            )
            return CONTROL_BOUNDARY_EXIT_CODE
        except EventLogError as error:
            return runtime.emergency_state_failure(
                error,
                phase=stage.__name__,
            )
        if outcome is not None:
            break

    exit_code = 0 if outcome is None else outcome
    try:
        exit_code = runtime.complete_state(exit_code)
    except RunLeaseError as error:
        print_control_boundary_error(error, phase="state_completion")
        return CONTROL_BOUNDARY_EXIT_CODE
    except EventLogError as error:
        return runtime.emergency_state_failure(
            error,
            phase="state_completion",
        )

    if outcome is not None:
        write_json(runtime.summary_path, runtime.summary)
        return exit_code
    if exit_code != 0:
        runtime.summary["finished_at"] = datetime.now().isoformat(
            timespec="seconds"
        )
        write_json(runtime.summary_path, runtime.summary)
        print(runtime.summary_path)
        return exit_code
    return finalize_cycle(runtime)


def main() -> int:
    args = parse_cycle_options()
    try:
        session = RunSession.open(
            Path(args.run_dir),
            owner_prefix=CYCLE_OWNER_PREFIX,
            allow_parent_inheritance=True,
        )
    except (RunLeaseError, EventLogError) as error:
        print_control_boundary_error(error, phase="session_acquire")
        return CONTROL_BOUNDARY_EXIT_CODE

    exit_code = CONTROL_BOUNDARY_EXIT_CODE
    try:
        exit_code = run_with_session(args, session)
    finally:
        try:
            session.close()
        except RunLeaseError as error:
            print_control_boundary_error(error, phase="session_release")
            exit_code = CONTROL_BOUNDARY_EXIT_CODE
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
