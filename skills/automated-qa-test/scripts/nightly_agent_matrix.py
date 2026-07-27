#!/usr/bin/env python3
"""Build the checked-in, capability-aware nightly reliability matrix.

The workflow deliberately dispatches targets by stable ``id`` instead of
executing the ``command`` field as a shell string.  ``command`` is retained as
an auditable contract and is represented as an argv array.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from qa_common import atomic_write_json, safe_output_path


class MatrixDefinitionError(RuntimeError):
    """The repository cannot satisfy a required nightly target."""


@dataclass(frozen=True, slots=True)
class NightlyTarget:
    id: str
    capability: str
    command: tuple[str, ...]
    timeout_minutes: int
    requires_chromium: bool = False
    required_path: str | None = None
    optional: bool = False

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["command"] = list(self.command)
        return value


_REQUIRED_TARGETS = (
    NightlyTarget(
        id="full-regression",
        capability="full_regression",
        command=(
            "python3",
            "skills/automated-qa-test/scripts/regression_check.py",
        ),
        timeout_minutes=30,
        required_path="skills/automated-qa-test/scripts/regression_check.py",
    ),
    NightlyTarget(
        id="chromium-regression",
        capability="chromium_browser_regression",
        command=(
            "python3",
            "skills/automated-qa-test/scripts/regression_check.py",
            "--with-browser",
        ),
        timeout_minutes=45,
        requires_chromium=True,
        required_path="skills/automated-qa-test/scripts/regression_check.py",
    ),
    NightlyTarget(
        id="fault-injection",
        capability="fail_closed_fault_injection",
        command=(
            "python3",
            "skills/automated-qa-test/scripts/nightly_fault_injection.py",
            "--out",
            "artifacts/nightly/fault-injection.json",
        ),
        timeout_minutes=10,
        required_path="skills/automated-qa-test/scripts/nightly_fault_injection.py",
    ),
)

# 这些历史基准按能力探测；当前仓库未提供它们。以后补充入口时会自动暴露目标，
# 同时不会把本次夜间任务未覆盖的能力误报为已覆盖。
_OPTIONAL_TARGETS = (
    NightlyTarget(
        id="browser-policy-benchmark",
        capability="browser_policy_benchmark",
        command=("python3", "scripts/run_browser_policy_benchmark.py"),
        timeout_minutes=30,
        requires_chromium=True,
        required_path="scripts/run_browser_policy_benchmark.py",
        optional=True,
    ),
    NightlyTarget(
        id="component-surface-verifier",
        capability="component_surface_verifier",
        command=("node", "scripts/run_component_surface_verifier_benchmark.cjs"),
        timeout_minutes=30,
        requires_chromium=True,
        required_path="scripts/run_component_surface_verifier_benchmark.cjs",
        optional=True,
    ),
    NightlyTarget(
        id="component-resilience-verifier",
        capability="component_resilience_verifier",
        command=("node", "scripts/run_component_resilience_verifier_benchmark.cjs"),
        timeout_minutes=30,
        requires_chromium=True,
        required_path="scripts/run_component_resilience_verifier_benchmark.cjs",
        optional=True,
    ),
)


def build_nightly_definition(repo_root: Path) -> dict[str, Any]:
    """Return a deterministic matrix and explicit unsupported capabilities."""

    root = repo_root.expanduser().resolve()
    if not root.is_dir():
        raise MatrixDefinitionError(f"repository root is not a directory: {root}")

    enabled: list[NightlyTarget] = []
    for target in _REQUIRED_TARGETS:
        assert target.required_path is not None
        if not (root / target.required_path).is_file():
            raise MatrixDefinitionError(
                f"required nightly target {target.id!r} is unavailable: "
                f"{target.required_path}"
            )
        enabled.append(target)

    unsupported: list[dict[str, str]] = []
    for target in _OPTIONAL_TARGETS:
        assert target.required_path is not None
        if (root / target.required_path).is_file():
            enabled.append(target)
        else:
            unsupported.append(
                {
                    "id": target.id,
                    "capability": target.capability,
                    "reason": "entrypoint_not_present",
                    "required_path": target.required_path,
                }
            )

    return {
        "schema_version": 1,
        "suite": "nightly_agent_reliability",
        "not_evidence": True,
        "include": [target.to_dict() for target in enabled],
        "unsupported_optional_targets": unsupported,
    }


def github_matrix(definition: dict[str, Any]) -> dict[str, Any]:
    """Project the full definition into GitHub Actions' matrix contract."""

    include = definition.get("include")
    if not isinstance(include, list) or not include:
        raise MatrixDefinitionError("nightly matrix must include at least one target")
    return {"include": include}


def _write_github_output(path: Path, matrix: dict[str, Any]) -> None:
    compact = json.dumps(matrix, sort_keys=True, separators=(",", ":"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"matrix={compact}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the deterministic nightly Agent reliability matrix.",
    )
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[3]),
    )
    parser.add_argument("--out")
    parser.add_argument(
        "--github-output",
        help="Append a compact matrix value to the supplied GITHUB_OUTPUT file.",
    )
    args = parser.parse_args(argv)

    try:
        root = Path(args.repo_root).expanduser().resolve()
        definition = build_nightly_definition(root)
        if args.out:
            output_path = safe_output_path(
                Path(args.out),
                protected_paths=[
                    Path(__file__),
                    *(root / target.required_path for target in _REQUIRED_TARGETS if target.required_path),
                ],
            )
            atomic_write_json(output_path, definition)
        if args.github_output:
            github_output = safe_output_path(
                Path(args.github_output),
                protected_paths=[Path(__file__)],
            )
            _write_github_output(github_output, github_matrix(definition))
    except (MatrixDefinitionError, OSError, ValueError) as error:
        print(f"nightly matrix error: {error}", file=sys.stderr)
        return 2

    print(json.dumps(definition, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
