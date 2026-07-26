#!/usr/bin/env python3
"""从独立 evaluator 记录生成 QA Agent 发布门报告。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from qa_common import atomic_write_json
from qa_eval import EvaluationContractError, score_evaluation


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EvaluationContractError(
            "input_not_object",
            f"JSON root must be an object: {path}",
        )
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Score normalized, evaluator-owned QA Agent observations.",
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--observations", required=True)
    parser.add_argument("--baseline")
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--production",
        action="store_true",
        help="Enforce the 200-scenario, three-seed production corpus contract.",
    )
    args = parser.parse_args()
    output_path = Path(args.out).expanduser().resolve()
    try:
        report = score_evaluation(
            load_object(Path(args.manifest).expanduser().resolve()),
            load_object(Path(args.observations).expanduser().resolve()),
            baseline=(
                load_object(Path(args.baseline).expanduser().resolve())
                if args.baseline
                else None
            ),
            production=args.production,
        )
    except (
        EvaluationContractError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        payload = (
            exc.to_dict()
            if isinstance(exc, EvaluationContractError)
            else {
                "schema_version": 1,
                "error": "evaluation_input_error",
                "message": str(exc),
            }
        )
        atomic_write_json(output_path, payload)
        print(output_path)
        print(str(exc), file=sys.stderr)
        return 2
    atomic_write_json(output_path, report)
    print(output_path)
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
