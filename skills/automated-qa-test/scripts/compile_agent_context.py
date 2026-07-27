#!/usr/bin/env python3
"""编译供 Planner/Critic 消费的只读 ContextSnapshot。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from qa_common import atomic_write_json, safe_output_path
from qa_core.context import ContextCompileError, compile_context_snapshot
from qa_core.contracts.artifacts import ARTIFACT_FILENAMES
from qa_core.human_runtime import (
    HumanRuntimeError,
    KnowledgeRuntimeConfig,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compile a deterministic, not-evidence Agent context",
    )
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--project-root", type=Path)
    parser.add_argument(
        "--out",
        type=Path,
        help="Defaults to <run-dir>/agent-context.json",
    )
    parser.add_argument(
        "--allow-unconfirmed-environment-boundary",
        action="store_true",
    )
    parser.add_argument(
        "--allow-missing-requirement",
        action="store_true",
    )
    parser.add_argument(
        "--max-repository-files",
        type=int,
        default=2000,
    )
    parser.add_argument(
        "--max-repository-bytes",
        type=int,
        default=64 * 1024 * 1024,
    )
    parser.add_argument(
        "--knowledge-store",
        type=Path,
        help="Confirmed KnowledgeStore directory to query.",
    )
    parser.add_argument(
        "--knowledge-trust-config",
        type=Path,
        help="Public Ed25519 trust allowlist for the KnowledgeStore.",
    )
    parser.add_argument(
        "--knowledge-scope",
        action="append",
        help="Exact knowledge scope dimension; repeat for every dimension.",
    )
    parser.add_argument(
        "--knowledge-journal-mode",
        choices=("local-test", "production"),
        default="local-test",
    )
    parser.add_argument(
        "--knowledge-checkpoint",
        type=Path,
        help="Independent signed production KnowledgeStore checkpoint.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    run_dir = args.run_dir.expanduser().resolve()
    requested_output = (
        args.out.expanduser().resolve()
        if args.out is not None
        else run_dir / "agent-context.json"
    )
    protected_paths = [
        run_dir / filename
        for name, filename in ARTIFACT_FILENAMES.items()
        if name != "agent_context"
    ]
    protected_paths.extend(
        run_dir / filename
        for filename in (
            ".qa-run-lease.json",
            ".run-manifest.guard",
            "agent-trace.jsonl",
            "run-events.jsonl",
            "run-manifest.json",
            "run-state.json",
        )
    )
    try:
        output = safe_output_path(
            requested_output,
            protected_paths=tuple(protected_paths),
            protected_roots=(run_dir / "attempts",),
        )
    except ValueError as error:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "error": "context_output_boundary_error",
                    "code": "output_alias_rejected",
                    "message": str(error),
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 2
    try:
        knowledge_config = _knowledge_config(args)
        snapshot = compile_context_snapshot(
            run_dir,
            project_root=args.project_root,
            require_environment_boundary=not (
                args.allow_unconfirmed_environment_boundary
            ),
            require_requirement=not args.allow_missing_requirement,
            max_repository_files=args.max_repository_files,
            max_repository_bytes=args.max_repository_bytes,
            knowledge_config=knowledge_config,
        )
        atomic_write_json(output, snapshot.to_dict())
    except (
        ContextCompileError,
        HumanRuntimeError,
        OSError,
        ValueError,
    ) as error:
        payload = (
            error.to_dict()
            if isinstance(
                error,
                (ContextCompileError, HumanRuntimeError),
            )
            else {
                "schema_version": 1,
                "error": "context_compile_error",
                "code": "context_compile_failed",
                "message": str(error),
            }
        )
        print(json.dumps(payload, ensure_ascii=False), file=sys.stderr)
        return 2
    print(output)
    return 0 if snapshot.ready else 1


def _knowledge_config(
    args: argparse.Namespace,
) -> KnowledgeRuntimeConfig | None:
    configured = any(
        value
        for value in (
            args.knowledge_store,
            args.knowledge_trust_config,
            args.knowledge_scope,
            args.knowledge_checkpoint,
        )
    )
    if not configured:
        return None
    if (
        args.knowledge_store is None
        or args.knowledge_trust_config is None
        or not args.knowledge_scope
    ):
        raise HumanRuntimeError(
            "knowledge_configuration_incomplete",
            (
                "knowledge context requires --knowledge-store, "
                "--knowledge-trust-config, and at least one "
                "--knowledge-scope"
            ),
        )
    return KnowledgeRuntimeConfig(
        store_dir=args.knowledge_store,
        scope=tuple(args.knowledge_scope),
        trust_config_path=args.knowledge_trust_config,
        journal_mode=args.knowledge_journal_mode,
        checkpoint_path=args.knowledge_checkpoint,
    )


if __name__ == "__main__":
    raise SystemExit(main())
