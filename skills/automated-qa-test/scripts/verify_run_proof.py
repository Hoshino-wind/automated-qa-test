#!/usr/bin/env python3
"""只读验证一个 QA run 的最终 proof graph。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from qa_common import atomic_write_json
from qa_core.proof import verify_run_proof


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify state, attempt, verdict and current input hash closure."
        )
    )
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--out")
    args = parser.parse_args()

    result = verify_run_proof(Path(args.run_dir))
    payload = result.to_dict()
    if args.out:
        output = Path(args.out).expanduser().resolve()
        atomic_write_json(output, payload)
        print(output)
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if result.can_claim_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
