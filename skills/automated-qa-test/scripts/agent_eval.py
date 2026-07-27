#!/usr/bin/env python3
"""从独立 evaluator 记录生成 QA Agent 发布门报告。"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

from qa_common import atomic_write_json, safe_output_path
from qa_eval import (
    EvaluationContractError,
    read_json_object,
    require_distinct_inputs,
    score_evaluation,
)

_MAX_MANIFEST_BYTES = 32 * 1024 * 1024
_MAX_OBSERVATIONS_BYTES = 64 * 1024 * 1024
_MAX_BASELINE_BYTES = 4 * 1024 * 1024
_MAX_REGISTRATION_BYTES = 256 * 1024
_MAX_TRUST_CONFIG_BYTES = 1024 * 1024


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score normalized, evaluator-owned QA Agent observations.",
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--observations", required=True)
    parser.add_argument("--baseline")
    parser.add_argument(
        "--registration",
        help="Evaluator-signed production registration JSON.",
    )
    parser.add_argument(
        "--trust-config",
        help="Public-key allowlist for independent evaluator authorities.",
    )
    parser.add_argument(
        "--evaluator-bundle-dir",
        help=(
            "Evaluator-owned regular-file tree; required in production so "
            "evaluator_bundle_sha256 is recomputed rather than trusted."
        ),
    )
    parser.add_argument(
        "--test-verification-now",
        help=(
            "Test-only RFC3339 UTC clock override. Requires "
            "--allow-test-clock-override and can never produce qualification."
        ),
    )
    parser.add_argument(
        "--allow-test-clock-override",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--production",
        action="store_true",
        help="Enforce the 200-scenario, three-seed production corpus contract.",
    )
    args = parser.parse_args(argv)
    input_paths = [
        Path(value)
        for value in (
            args.manifest,
            args.observations,
            args.baseline,
            args.registration,
            args.trust_config,
        )
        if value is not None
    ]
    try:
        output_path = safe_output_path(
            Path(args.out),
            protected_paths=tuple(input_paths),
            protected_roots=(
                (Path(args.evaluator_bundle_dir),)
                if args.evaluator_bundle_dir
                else ()
            ),
        )
    except ValueError as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "error": "evaluation_output_boundary_error",
                    "message": str(exc),
                    "not_authorization": True,
                    "p2_admission_allowed": False,
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 2
    try:
        if args.production and not all(
            (
                args.baseline,
                args.registration,
                args.trust_config,
                args.evaluator_bundle_dir,
            )
        ):
            raise EvaluationContractError(
                "production_inputs_missing",
                (
                    "--production requires --baseline, --registration, "
                    "--trust-config, and --evaluator-bundle-dir"
                ),
            )
        if not args.production and (
            args.registration is not None
            or args.trust_config is not None
            or args.evaluator_bundle_dir is not None
        ):
            raise EvaluationContractError(
                "production_mode_required",
                "--registration and --trust-config require --production",
            )
        if args.test_verification_now and not args.allow_test_clock_override:
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
        manifest = read_json_object(
            args.manifest,
            label="manifest",
            maximum_bytes=_MAX_MANIFEST_BYTES,
        )
        observations = read_json_object(
            args.observations,
            label="observations",
            maximum_bytes=_MAX_OBSERVATIONS_BYTES,
        )
        baseline = (
            read_json_object(
                args.baseline,
                label="baseline",
                maximum_bytes=_MAX_BASELINE_BYTES,
            )
            if args.baseline
            else None
        )
        registration = (
            read_json_object(
                args.registration,
                label="registration",
                maximum_bytes=_MAX_REGISTRATION_BYTES,
            )
            if args.registration
            else None
        )
        trust_config = (
            read_json_object(
                args.trust_config,
                label="trust_config",
                maximum_bytes=_MAX_TRUST_CONFIG_BYTES,
            )
            if args.trust_config
            else None
        )
        require_distinct_inputs(
            snapshot
            for snapshot in (
                manifest,
                observations,
                baseline,
                registration,
                trust_config,
            )
            if snapshot is not None
        )
        report = score_evaluation(
            manifest.value,
            observations.value,
            baseline=baseline.value if baseline is not None else None,
            production=args.production,
            production_registration=(
                registration.value
                if registration is not None
                else None
            ),
            evaluator_trust=(
                trust_config.value
                if trust_config is not None
                else None
            ),
            evaluator_bundle_root=args.evaluator_bundle_dir,
            verification_now=verification_now,
        )
        if verification_now is not None:
            report = {
                **report,
                "qualified": False,
                "test_clock_override": True,
                "test_clock_override_not_production": True,
                "gate_failures": [
                    *report["gate_failures"],
                    {
                        "gate": "provenance",
                        "code": "test_clock_override_not_production",
                    },
                ],
            }
    except (EvaluationContractError, OSError) as exc:
        payload = (
            exc.to_dict()
            if isinstance(exc, EvaluationContractError)
            else {
                "schema_version": 1,
                "error": "evaluation_input_error",
                "message": str(exc),
            }
        )
        payload["not_authorization"] = True
        payload["p2_admission_allowed"] = False
        atomic_write_json(output_path, payload)
        print(output_path)
        print(str(exc), file=sys.stderr)
        return 2
    atomic_write_json(output_path, report)
    print(output_path)
    return 0 if report["qualified"] else 1


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
