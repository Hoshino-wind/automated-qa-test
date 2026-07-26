"""只读验证 run state、attempt manifest 与当前输入形成闭合证明图。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from qa_common import file_sha256
from qa_core.contracts.artifacts import ARTIFACT_FILENAMES
from qa_core.runtime.attempts import AttemptStore
from qa_core.state import RunEventType, RunStateStore
from qa_core.tools import build_default_tool_registry

from .hashes import canonical_json_sha256, input_file_sha256

_REQUIRED_INPUT_HASHES = frozenset(
    {
        "cycle_options",
        "tool_registry",
        "plan",
        "matrix",
        "requirement",
        "adapter_context",
    }
)


@dataclass(frozen=True, slots=True)
class ProofVerificationResult:
    """确定性的证明图验证结果；错误列表为空才允许 PASS。"""

    run_id: str | None
    can_claim_pass: bool
    errors: tuple[dict[str, str], ...]
    verified_refs: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": 1,
            "run_id": self.run_id,
            "can_claim_pass": self.can_claim_pass,
            "errors": [dict(error) for error in self.errors],
            "verified_refs": self.verified_refs,
        }
        return {
            **payload,
            "proof_graph_sha256": canonical_json_sha256(payload),
        }


def verify_run_proof(run_dir: Path) -> ProofVerificationResult:
    """验证当前磁盘视图；任何缺失、篡改或父哈希漂移均返回非 PASS。"""

    resolved = run_dir.expanduser().resolve()
    errors: list[dict[str, str]] = []
    refs: dict[str, Any] = {}
    run_id: str | None = None

    try:
        store = RunStateStore(resolved)
        events = store.load_events()
        state = store.load_state()
        run_id = state.run_id
        refs["state"] = {
            "sequence": state.sequence,
            "last_event_hash": state.last_event_hash,
            "status": state.status,
        }
    except Exception as error:
        _add_error(errors, "run_state_invalid", error)
        return _result(run_id, errors, refs)

    if state.status != "passed":
        _add_error(
            errors,
            "run_not_passed",
            f"run state is {state.status!r}",
        )
        return _result(run_id, errors, refs)
    if not events or events[-1].event_type is not RunEventType.STATUS_CHANGED:
        _add_error(
            errors,
            "pass_not_terminal",
            "the final event is not status_changed",
        )
        return _result(run_id, errors, refs)
    status_payload = events[-1].payload
    if (
        status_payload.get("status") != "passed"
        or status_payload.get("authority") != "deterministic_verdict"
    ):
        _add_error(
            errors,
            "pass_authority_invalid",
            "the terminal status event lacks deterministic verdict authority",
        )
        return _result(run_id, errors, refs)

    try:
        manifest = AttemptStore(resolved).read_run_manifest()
        if manifest is None:
            raise ValueError("run manifest is missing")
        refs["run_manifest"] = {
            "sequence": manifest["sequence"],
            "generation": manifest["generation"],
            "sha256": manifest["manifest_sha256"],
        }
    except Exception as error:
        _add_error(errors, "run_manifest_invalid", error)
        return _result(run_id, errors, refs)

    attempt_ref = status_payload.get("attempt_ref")
    if not isinstance(attempt_ref, dict):
        _add_error(
            errors,
            "attempt_ref_missing",
            "passed status lacks attempt_ref",
        )
        return _result(run_id, errors, refs)
    if attempt_ref.get("run_manifest_sequence") != manifest["sequence"]:
        _add_error(
            errors,
            "run_manifest_sequence_mismatch",
            "status attempt_ref does not reference current manifest sequence",
        )
    if attempt_ref.get("run_manifest_sha256") != manifest["manifest_sha256"]:
        _add_error(
            errors,
            "run_manifest_hash_mismatch",
            "status attempt_ref does not reference current manifest hash",
        )

    attempt_id = attempt_ref.get("attempt_id")
    try:
        attempt = AttemptStore(resolved).load_attempt(str(attempt_id))
        refs["attempt"] = {
            "attempt_id": attempt.attempt_id,
            "manifest_sha256": attempt.manifest_sha256,
            "generation": attempt.generation,
            "iteration": attempt.iteration,
        }
    except Exception as error:
        _add_error(errors, "attempt_invalid", error)
        return _result(run_id, errors, refs)

    if attempt_ref.get("attempt_manifest_sha256") != attempt.manifest_sha256:
        _add_error(
            errors,
            "attempt_manifest_hash_mismatch",
            "status attempt_ref does not match committed attempt",
        )
    references = {
        item.get("attempt_id"): item.get("manifest_sha256")
        for item in manifest.get("attempts", [])
        if isinstance(item, dict)
    }
    if references.get(attempt.attempt_id) != attempt.manifest_sha256:
        _add_error(
            errors,
            "attempt_not_current",
            "current run manifest does not reference the passed attempt",
        )
    if attempt.run_id != state.run_id or manifest["run_id"] != state.run_id:
        _add_error(
            errors,
            "run_id_mismatch",
            "state, run manifest and attempt must share run_id",
        )
    if attempt.generation != manifest["generation"]:
        _add_error(
            errors,
            "generation_mismatch",
            "attempt is not from the current manifest generation",
        )
    if attempt.iteration != manifest["sequence"]:
        _add_error(
            errors,
            "attempt_not_latest",
            "passed attempt iteration does not match current manifest sequence",
        )
    if attempt.stage != "cycle_complete" or attempt.tool != "run_qa_cycle":
        _add_error(
            errors,
            "attempt_authority_invalid",
            "passed attempt must be a completed run_qa_cycle",
        )

    _verify_parent_hashes(
        resolved,
        state.component_versions,
        attempt.input_hashes,
        errors,
        refs,
    )
    _verify_verdict(
        resolved,
        status_payload.get("verdict_ref"),
        attempt,
        errors,
        refs,
    )
    return _result(run_id, errors, refs)


def _verify_parent_hashes(
    run_dir: Path,
    component_versions: dict[str, Any],
    observed: dict[str, str],
    errors: list[dict[str, str]],
    refs: dict[str, Any],
) -> None:
    if set(observed) != _REQUIRED_INPUT_HASHES:
        _add_error(
            errors,
            "input_hash_set_invalid",
            "attempt input hash names are incomplete or unknown",
        )
        return
    expected = {
        "cycle_options": component_versions.get(
            "cycle_options_sha256"
        ),
        "tool_registry": build_default_tool_registry().canonical_sha256,
        "plan": input_file_sha256(
            "plan",
            run_dir / ARTIFACT_FILENAMES["plan"],
        ),
        "matrix": input_file_sha256(
            "matrix",
            run_dir / ARTIFACT_FILENAMES["matrix"],
        ),
        "requirement": input_file_sha256(
            "requirement",
            run_dir / ARTIFACT_FILENAMES["requirement"],
        ),
        "adapter_context": input_file_sha256(
            "adapter_context",
            run_dir / ARTIFACT_FILENAMES["adapter_context"],
        ),
    }
    refs["input_hashes"] = expected
    if component_versions.get("tool_registry_sha256") != expected["tool_registry"]:
        _add_error(
            errors,
            "tool_registry_version_mismatch",
            "state component version does not match the current tool registry",
        )
    for name, expected_hash in expected.items():
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            _add_error(
                errors,
                "state_component_hash_missing",
                f"state lacks a valid {name} hash",
            )
        elif observed.get(name) != expected_hash:
            _add_error(
                errors,
                "input_hash_mismatch",
                f"current {name} does not match the passed attempt",
            )


def _verify_verdict(
    run_dir: Path,
    raw_ref: Any,
    attempt: Any,
    errors: list[dict[str, str]],
    refs: dict[str, Any],
) -> None:
    if not isinstance(raw_ref, dict):
        _add_error(errors, "verdict_ref_missing", "passed state lacks verdict_ref")
        return
    verdict_path = run_dir / ARTIFACT_FILENAMES["verdict"]
    if Path(str(raw_ref.get("path"))).expanduser().resolve() != verdict_path:
        _add_error(
            errors,
            "verdict_path_invalid",
            "passed verdict must use the canonical run path",
        )
        return
    verdict_hash = file_sha256(verdict_path)
    refs["verdict"] = {
        "path": str(verdict_path),
        "sha256": verdict_hash,
    }
    if verdict_hash is None or raw_ref.get("sha256") != verdict_hash:
        _add_error(
            errors,
            "verdict_hash_mismatch",
            "current verdict does not match the terminal state event",
        )
        return
    artifact = next(
        (
            item
            for item in attempt.artifacts
            if item.name == ARTIFACT_FILENAMES["verdict"]
        ),
        None,
    )
    if artifact is None or artifact.sha256 != verdict_hash:
        _add_error(
            errors,
            "verdict_not_committed",
            "current verdict is not the verdict committed in the attempt",
        )
    try:
        verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _add_error(errors, "verdict_invalid", error)
        return
    if (
        not isinstance(verdict, dict)
        or verdict.get("schema_version") != 1
        or verdict.get("verdict") != "passed"
        or verdict.get("can_claim_pass") is not True
    ):
        _add_error(
            errors,
            "verdict_not_passed",
            "canonical verdict is not an explicit schema-v1 pass",
        )


def _result(
    run_id: str | None,
    errors: list[dict[str, str]],
    refs: dict[str, Any],
) -> ProofVerificationResult:
    return ProofVerificationResult(
        run_id=run_id,
        can_claim_pass=not errors,
        errors=tuple(errors),
        verified_refs=refs,
    )


def _add_error(
    errors: list[dict[str, str]],
    code: str,
    error: BaseException | str,
) -> None:
    errors.append(
        {
            "code": code,
            "message": str(error),
        }
    )
