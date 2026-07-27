#!/usr/bin/env python3
"""Deterministic, offline fault checks for fail-closed runtime boundaries."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from qa_common import atomic_write_json, safe_output_path
from qa_core.runtime import ProcessExecutor, RunBudget
from qa_core.runtime.lease import (
    LeaseAlreadyHeldError,
    LeaseRecordError,
    RunLease,
)

Scenario = Callable[[], dict[str, Any]]


def _python_command(source: str) -> list[str]:
    return [sys.executable, "-c", source]


def _timeout() -> dict[str, Any]:
    result = ProcessExecutor(
        RunBudget(total_timeout=2, stage_timeouts={"fault_timeout": 0.08}),
        "fault_timeout",
        poll_interval=0.01,
        termination_grace=0.03,
    ).run(_python_command("import time; time.sleep(60)"))
    passed = (
        result["started"] is True
        and result["exit_code"] == 124
        and result["timed_out"] is True
        and result["termination_reason"] == "stage_timeout"
        and result["budget_error"]["reason"] == "stage_timeout"
        and result["term_sent"] is True
    )
    return {
        "status": "passed" if passed else "failed",
        "expected_boundary": "stage_timeout",
        "observed": {
            "started": result["started"],
            "exit_code": result["exit_code"],
            "timed_out": result["timed_out"],
            "termination_reason": result["termination_reason"],
            "term_sent": result["term_sent"],
        },
    }


def _output_limit_and_truncation() -> dict[str, Any]:
    result = ProcessExecutor(
        RunBudget(total_timeout=2, max_output_bytes=128),
        "fault_output",
        tail_bytes=32,
        poll_interval=0.01,
        termination_grace=0.03,
        read_size=4096,
    ).run(
        _python_command(
            "import os, time; os.write(1, b'x' * 4096); time.sleep(60)"
        )
    )
    passed = (
        result["started"] is True
        and result["exit_code"] == 125
        and result["termination_reason"] == "output_byte_limit"
        and result["budget_error"]["reason"] == "output_byte_limit"
        and result["stdout_bytes"] == 4096
        and result["stdout_truncated"] is True
        and len(result["stdout"].encode("utf-8")) == 32
        and result["term_sent"] is True
    )
    return {
        "status": "passed" if passed else "failed",
        "expected_boundary": "output_byte_limit",
        "observed": {
            "started": result["started"],
            "exit_code": result["exit_code"],
            "termination_reason": result["termination_reason"],
            "stdout_bytes": result["stdout_bytes"],
            "stdout_tail_bytes": len(result["stdout"].encode("utf-8")),
            "stdout_truncated": result["stdout_truncated"],
            "term_sent": result["term_sent"],
        },
    }


def _lease_conflict() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="qa-nightly-lease-conflict-") as raw:
        lease = RunLease(Path(raw) / "run-lease.json", clock=lambda: 100.0)
        first = lease.acquire("nightly-run", "worker-a", pid=101)
        rejected = False
        current_matches = False
        try:
            lease.acquire("nightly-run", "worker-b", pid=202)
        except LeaseAlreadyHeldError as error:
            rejected = True
            current_matches = error.current == first
        current = lease.read()
    passed = (
        rejected
        and current_matches
        and current == first
        and first.generation == 1
        and first.owner == "worker-a"
    )
    return {
        "status": "passed" if passed else "failed",
        "expected_boundary": "single_writer_lease",
        "observed": {
            "second_writer_rejected": rejected,
            "original_lease_preserved": current_matches and current == first,
            "generation": first.generation,
            "owner": first.owner,
        },
    }


def _process_crash() -> dict[str, Any]:
    result = ProcessExecutor(
        RunBudget(total_timeout=2),
        "fault_crash",
        poll_interval=0.01,
        termination_grace=0.03,
    ).run(_python_command("raise SystemExit(23)"))
    passed = (
        result["started"] is True
        and result["exit_code"] == 23
        and result["raw_exit_code"] == 23
        and result["timed_out"] is False
        and result["termination_reason"] is None
    )
    return {
        "status": "passed" if passed else "failed",
        "expected_boundary": "child_exit_propagation",
        "observed": {
            "started": result["started"],
            "exit_code": result["exit_code"],
            "raw_exit_code": result["raw_exit_code"],
            "timed_out": result["timed_out"],
            "termination_reason": result["termination_reason"],
        },
    }


def _corrupt_lease() -> dict[str, Any]:
    malformed = b'{"run_id":"nightly-run"}\n'
    with tempfile.TemporaryDirectory(prefix="qa-nightly-lease-corrupt-") as raw:
        lease_path = Path(raw) / "run-lease.json"
        lease_path.write_bytes(malformed)
        rejected = False
        try:
            RunLease(lease_path, clock=lambda: 100.0).acquire(
                "nightly-run",
                "worker-a",
                pid=101,
            )
        except LeaseRecordError:
            rejected = True
        preserved = lease_path.read_bytes() == malformed
    passed = rejected and preserved
    return {
        "status": "passed" if passed else "failed",
        "expected_boundary": "corrupt_lease_rejected",
        "observed": {
            "acquire_rejected": rejected,
            "malformed_bytes_preserved": preserved,
        },
    }


SCENARIOS: dict[str, Scenario] = {
    "timeout": _timeout,
    "output-limit-and-truncation": _output_limit_and_truncation,
    "lease-conflict": _lease_conflict,
    "process-crash": _process_crash,
    "corrupt-lease": _corrupt_lease,
}


def run_fault_suite(selected: list[str] | None = None) -> dict[str, Any]:
    """Run selected scenarios in stable declaration order."""

    requested = set(selected or SCENARIOS)
    unknown = sorted(requested - set(SCENARIOS))
    if unknown:
        raise ValueError(f"unknown fault scenarios: {', '.join(unknown)}")

    results: list[dict[str, Any]] = []
    for scenario_id, scenario in SCENARIOS.items():
        if scenario_id not in requested:
            continue
        try:
            result = scenario()
        except Exception as error:  # the suite itself must report failures
            result = {
                "status": "failed",
                "expected_boundary": "scenario_completed",
                "observed": {"exception_type": type(error).__name__},
            }
        results.append({"id": scenario_id, **result})

    passed = bool(results) and all(item["status"] == "passed" for item in results)
    return {
        "schema_version": 1,
        "suite": "nightly_fail_closed_fault_injection",
        "not_evidence": True,
        "status": "passed" if passed else "failed",
        "scenario_count": len(results),
        "scenarios": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run deterministic offline fail-closed fault scenarios.",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        choices=tuple(SCENARIOS),
        help="Run one named scenario; repeat to select multiple.",
    )
    parser.add_argument("--out")
    args = parser.parse_args(argv)

    try:
        report = run_fault_suite(args.scenario)
        if args.out:
            output_path = safe_output_path(
                Path(args.out),
                protected_paths=[Path(__file__)],
            )
            atomic_write_json(output_path, report)
    except (OSError, ValueError) as error:
        print(f"fault injection error: {error}", file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
