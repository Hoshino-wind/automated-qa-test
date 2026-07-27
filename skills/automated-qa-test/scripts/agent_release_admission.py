#!/usr/bin/env python3
"""Recompute both production gates and issue a P2 release-only admission."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

from qa_common import atomic_write_json, safe_output_path
from qa_core.observability import (
    ObservabilityError,
    SloSamplingContract,
    SloThresholds,
)
from qa_eval import (
    EvaluationContractError,
    evaluate_p2_release_admission,
    read_json_object,
    require_distinct_inputs,
)

_INPUT_LIMITS = {
    "manifest": 32 * 1024 * 1024,
    "observations": 64 * 1024 * 1024,
    "baseline": 4 * 1024 * 1024,
    "registration": 256 * 1024,
    "trust_config": 1024 * 1024,
    "evaluation_report": 32 * 1024 * 1024,
    "slo_report": 64 * 1024 * 1024,
    "thresholds": 1024 * 1024,
    "sampling_contract": 64 * 1024,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Recompute the signed held-out evaluation and proof-backed SLO "
            "gate before admitting P2 parallel/multi-agent release."
        ),
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--observations", required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--registration", required=True)
    parser.add_argument("--trust-config", required=True)
    parser.add_argument("--evaluation-report", required=True)
    parser.add_argument("--slo-report", required=True)
    parser.add_argument("--slo-sampling-contract", required=True)
    parser.add_argument("--evaluator-bundle-dir", required=True)
    parser.add_argument("--run-dir", action="append", required=True)
    parser.add_argument("--thresholds")
    parser.add_argument("--test-verification-now")
    parser.add_argument(
        "--allow-test-clock-override",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    raw_inputs = {
        "manifest": args.manifest,
        "observations": args.observations,
        "baseline": args.baseline,
        "registration": args.registration,
        "trust_config": args.trust_config,
        "evaluation_report": args.evaluation_report,
        "slo_report": args.slo_report,
        "sampling_contract": args.slo_sampling_contract,
        **(
            {"thresholds": args.thresholds}
            if args.thresholds is not None
            else {}
        ),
    }
    try:
        output_path = safe_output_path(
            Path(args.out),
            protected_paths=tuple(
                Path(value) for value in raw_inputs.values()
            ),
            protected_roots=(
                *tuple(Path(value) for value in args.run_dir),
                Path(args.evaluator_bundle_dir),
            ),
        )
    except ValueError as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "error": "release_admission_output_boundary_error",
                    "message": str(exc),
                    "not_authorization": True,
                    "admission_allowed": False,
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 2

    try:
        snapshots = {
            label: read_json_object(
                value,
                label=label,
                maximum_bytes=_INPUT_LIMITS[label],
            )
            for label, value in raw_inputs.items()
        }
        require_distinct_inputs(snapshots.values())
        thresholds = (
            SloThresholds.from_dict(snapshots["thresholds"].value)
            if "thresholds" in snapshots
            else SloThresholds()
        )
        sampling_contract = SloSamplingContract.from_dict(
            snapshots["sampling_contract"].value
        )
        if (
            args.test_verification_now
            and not args.allow_test_clock_override
        ):
            raise EvaluationContractError(
                "test_clock_override_not_enabled",
                (
                    "--test-verification-now requires the explicit "
                    "--allow-test-clock-override test guard"
                ),
            )
        verification_now = (
            _parse_test_now(args.test_verification_now)
            if args.test_verification_now
            else None
        )
        admission = evaluate_p2_release_admission(
            manifest=snapshots["manifest"].value,
            observations=snapshots["observations"].value,
            baseline=snapshots["baseline"].value,
            production_registration=snapshots["registration"].value,
            evaluator_trust=snapshots["trust_config"].value,
            supplied_evaluation_report=snapshots[
                "evaluation_report"
            ].value,
            supplied_slo_report=snapshots["slo_report"].value,
            run_dirs=args.run_dir,
            slo_sampling_contract=sampling_contract,
            evaluator_bundle_root=args.evaluator_bundle_dir,
            slo_thresholds=thresholds,
            additional_slo_input_hashes=(
                {
                    (
                        "thresholds:"
                        f"{snapshots['thresholds'].path}"
                    ): snapshots["thresholds"].sha256
                }
                if "thresholds" in snapshots
                else None
            ),
            verification_now=verification_now,
        )
        if verification_now is not None:
            test_unsigned = {
                **{
                    key: value
                    for key, value in admission.items()
                    if key != "admission_sha256"
                },
                "decision": "rejected",
                "admission_allowed": False,
                "not_authorization": True,
                "test_clock_override": True,
                "gate_failures": [
                    *admission["gate_failures"],
                    {
                        "gate": "provenance",
                        "code": "test_clock_override_not_production",
                    },
                ],
            }
            admission = {
                **test_unsigned,
                "admission_sha256": hashlib.sha256(
                    json.dumps(
                        test_unsigned,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        allow_nan=False,
                    ).encode("utf-8")
                ).hexdigest(),
            }
    except (
        EvaluationContractError,
        ObservabilityError,
        OSError,
    ) as exc:
        payload = (
            exc.to_dict()
            if isinstance(exc, (EvaluationContractError, ObservabilityError))
            else {
                "schema_version": 1,
                "error": "release_admission_input_error",
                "message": str(exc),
            }
        )
        payload["not_authorization"] = True
        payload["admission_allowed"] = False
        atomic_write_json(output_path, payload)
        print(output_path)
        print(str(exc), file=sys.stderr)
        return 2
    atomic_write_json(output_path, admission)
    print(output_path)
    return 0 if admission["admission_allowed"] else 1


def _parse_test_now(value: str) -> datetime:
    if not value.endswith("Z"):
        raise EvaluationContractError(
            "test_clock_override_invalid",
            "--test-verification-now must end in Z",
        )
    try:
        parsed = datetime.fromisoformat(
            value.removesuffix("Z") + "+00:00"
        )
    except ValueError as exc:
        raise EvaluationContractError(
            "test_clock_override_invalid",
            "--test-verification-now must be RFC3339 UTC",
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise EvaluationContractError(
            "test_clock_override_invalid",
            "--test-verification-now must use UTC",
        )
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
